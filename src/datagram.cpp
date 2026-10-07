#include "datagram.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"

#include <bit>
#include <span>

namespace oxen::quic
{

    Datagrams::Datagrams(Connection& c, Endpoint& e, dgram_data_callback data_cb, size_t dgram_queue_limit_) :
            IOChannel{c, e},
            dgram_data_cb{std::move(data_cb)},
            recv_buffer{endpoint.datagram_bufsize(), endpoint.datagram_reorder_limit()},
            _packet_splitting(_conn->packet_splitting_enabled())
    {
        if (dgram_queue_limit_)
            dgram_queue_limit = dgram_queue_limit_;
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
    }

    Datagrams::~Datagrams()
    {
        // Must precede destruction of the members our queued jobs reference; see IOChannel.
        job_queue.stop();
    }

    bool Datagrams::is_closing_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return false;
    }
    size_t Datagrams::unsent_impl() const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return _send_buffer.pending_bytes();
    }
    bool Datagrams::has_unsent_impl() const
    {
        return not is_empty_impl();
    }
    void Datagrams::early_data_begin()
    {
        _send_buffer.early_data_begin();
    }
    void Datagrams::early_data_retry()
    {
        _send_buffer.early_data_retry();
    }
    void Datagrams::early_data_end(bool accepted)
    {
        _send_buffer.early_data_end(accepted);
    }

    void Datagrams::set_split_datagram_lookahead(int n)
    {
        job_queue.call([this, val = n >= 0 ? static_cast<size_t>(n) : dgram::queue::DEFAULT_SPLIT_LOOKAHEAD] {
            log::debug(log_cat, "Changing split datagram lookahead from {} to {}", _send_buffer.split_lookahead, val);
            _send_buffer.split_lookahead = val;
        });
    }
    int Datagrams::get_split_datagram_lookahead() const
    {
        return job_queue.call_get([this] { return static_cast<int>(_send_buffer.split_lookahead); });
    }

    void Datagrams::send_impl(std::span<const std::byte> data, std::shared_ptr<void> keep_alive)
    {
        job_queue.call([this, data, keep_alive = std::move(keep_alive)]() mutable {
            if (!_conn)
            {
                log::debug(log_cat, "Unable to send datagram: connection has gone away");
                return;
            }

            if (unsent_impl() > dgram_queue_limit)
            {
                auto n = ++dgram_drop_count;
                if (n == 1 || n % 100 == 0)
                    log::debug(log_cat, "Dropping datagram, queue over limit (drop #{})", n);
                else
                    log::trace(log_cat, "Dropping datagram, queue over limit (drop #{})", n);
                return;
            }

            auto base_dgid = _next_dgram_counter++ << 2;
            _next_dgram_counter %= 1 << 14;

            log::trace(
                    log_cat,
                    "Connection ({}) queuing datagram with base dgid={:04x}: {}",
                    _conn->reference_id(),
                    base_dgid,
                    buffer_printer{data});

            _send_buffer.emplace(data, base_dgid, std::move(keep_alive));

            _conn->packet_io_ready();
        });
    }

    std::optional<dgram::prepared> Datagrams::pending(bool prefer_small)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        return _send_buffer.fetch(_conn->get_max_datagram_piece(), prefer_small);
    }

    void Datagrams::confirm_datagram_sent()
    {
        _send_buffer.confirm_sent();
    }

    std::optional<std::vector<std::byte>> Datagrams::to_buffer(std::span<const std::byte> data, uint16_t dgid)
    {
        assert(job_queue.inside());
        assert(_conn);

        if (_conn->debug_datagram_drop_enabled && recv_buffer.completes(dgid))
        {
            log::debug(log_cat, "enable_datagram_drop_test is true, inducing packet loss");
            _conn->debug_datagram_counter++;
            return std::nullopt;
        }

        return recv_buffer.receive(data, dgid);
    }

    namespace dgram
    {
        namespace
        {
            // The two least-significant bits of the dgid indicating whether packet splitting happened.
            // 00 means no splitting, the 0b10 bit means this is a split packet, and the 0b01 bit
            // indicates this is the second part.
            constexpr uint16_t DGID_SPLIT_FIRST = 0b10;
            constexpr uint16_t DGID_SPLIT_SECOND = 0b11;
        }  // namespace

        rotating_buffer::rotating_buffer(int bufsize, int reorder_limit) :
                bufsize{bufsize},
                block_shift{std::countr_zero(static_cast<unsigned>(bufsize / 2))},
                nblocks{(1 << 14) >> block_shift},
                reorder_blocks{(reorder_limit + bufsize / 2 - 1) >> block_shift}
        {}

        bool rotating_buffer::held_block(int block) const
        {
            // How far `block` is behind the newest one, counting back around the counter wrap.
            int behind = (*newest - block) & (nblocks - 1);
            return behind <= 1;
        }

        bool rotating_buffer::advance(uint16_t counter)
        {
            int block = counter >> block_shift;
            if (!newest)
            {
                newest = block;
                return true;
            }
            if (held_block(block))
                return true;
            if (((*newest - block) & (nblocks - 1)) < reorder_blocks)
                return false;

            // A newer block, or one too far back to be late, which can only mean that the IDs jumped
            // forward after a burst of losses.  Whatever the half this block uses holds is now too
            // old, as is the other half if the jump skipped the block in between.
            clear_half(block & 1);
            if (((block - *newest) & (nblocks - 1)) > 1)
                clear_half((block - 1) & 1);
            newest = block;
            return true;
        }

        void rotating_buffer::clear_half(int half)
        {
            if (!held[half])
                return;
            log::trace(log_cat, "Clearing {} unpaired datagram pieces", held[half]);
            const int block_size = bufsize / 2;
            for (auto& slot : std::span{slots}.subspan(half * block_size, block_size))
                if (slot)
                {
                    release_piece(slot - 1);
                    slot = 0;
                }
            held[half] = 0;
        }

        uint16_t rotating_buffer::take_piece()
        {
            if (free_head == NO_PIECE)
            {
                pieces.emplace_back();
                return static_cast<uint16_t>(pieces.size() - 1);
            }
            auto index = free_head;
            free_head = pieces[index].next_free;
            return index;
        }

        void rotating_buffer::release_piece(uint16_t index)
        {
            auto& p = pieces[index];
            p.data = {};
            p.next_free = free_head;
            free_head = index;
        }

        void rotating_buffer::observe(uint16_t dgid)
        {
            advance(dgid >> 2);
        }

        bool rotating_buffer::completes(uint16_t dgid) const
        {
            uint16_t counter = dgid >> 2;
            if (slots.empty() || !held_block(counter >> block_shift))
                return false;
            auto slot = slots[counter & (bufsize - 1)];
            return slot && pieces[slot - 1].first != ((dgid & 0b11) == DGID_SPLIT_FIRST);
        }

        std::optional<std::vector<std::byte>> rotating_buffer::receive(std::span<const std::byte> data, uint16_t dgid)
        {
            uint16_t counter = dgid >> 2;
            if (!advance(counter))
            {
                log::debug(log_cat, "Dropping late split datagram piece (ID: {})", dgid);
                return std::nullopt;
            }

            if (slots.empty())
                slots.resize(bufsize);
            auto& slot = slots[counter & (bufsize - 1)];
            auto& count = held[(counter >> block_shift) & 1];
            const bool first = (dgid & 0b11) == DGID_SPLIT_FIRST;

            if (!slot)
            {
                log::trace(log_cat, "Storing split datagram piece (ID: {})", dgid);
                auto index = take_piece();
                auto& p = pieces[index];
                p.data.assign(data.begin(), data.end());
                p.first = first;
                slot = index + 1;
                ++count;
                return std::nullopt;
            }

            auto& p = pieces[slot - 1];
            if (p.first == first)
            {
                log::debug(log_cat, "Dropping duplicate split datagram piece (ID: {})", dgid);
                return std::nullopt;
            }

            log::trace(log_cat, "Pairing split datagram piece (ID: {}) with its other half", dgid);
            std::span<const std::byte> stored{p.data};
            auto head = p.first ? stored : data, tail = p.first ? data : stored;
            std::vector<std::byte> out;
            out.reserve(head.size() + tail.size());
            out.insert(out.end(), head.begin(), head.end());
            out.insert(out.end(), tail.begin(), tail.end());

            release_piece(slot - 1);
            slot = 0;
            --count;
            return out;
        }

        void queue::early_data_begin()
        {
            assert(buf.empty());
            early_data_head = std::make_optional<size_t>(0);
        }

        void queue::early_data_retry()
        {
            if (!early_data_head)
                return;

            // This is the furthest index we could have (partially) marked as sent:
            size_t max_i = *early_data_head + (packet_splitting ? split_lookahead : 0);
            size_t i = 0;
            for (auto& pkt : buf)
            {
                unsent_bytes += pkt.size() - pkt.unsent_size();
                pkt.unsend();
                if (++i > max_i)
                    break;
            }
            *early_data_head = 0;
        }

        void queue::early_data_end(bool accepted)
        {
            if (!early_data_head)
                return;

            if (!accepted)
            {
                // Early data was rejected, which means any 0-RTT datagrams we sent got dropped on
                // the floor and we should unmark them as sent so that they get sent properly under
                // 1-RTT.
                early_data_retry();
            }
            else
            {
                // Early data accepted, so now we can discard all the sent packets (which will be
                // everything up, but not including, `early_data_head`).  They were fully sent, so
                // none of them contribute to unsent_bytes.
                buf.erase(buf.begin(), buf.begin() + *early_data_head);
            }
            early_data_head.reset();
        }

        void queue::emplace(std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive)
        {
            unsent_bytes += payload.size();
            buf.emplace_back(payload, base_dgid, std::move(keepalive));
        }

        bool queue::empty() const
        {
            return early_data_head.value_or(0) >= buf.size();
        }

        prepared::prepared(bool splitting_enabled, uint16_t id, std::span<const std::byte> data) : id{id}, bufs_len{1}
        {
            auto vit = bufs.begin();
            if (splitting_enabled)
            {
                bufs_len++;
                oxenc::write_host_as_big(id, dgid.data());
                vit->base = dgid.data();
                vit->len = 2;
                ++vit;
            }
            vit->base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(data.data()));
            vit->len = data.size();
        }

        std::optional<prepared> queue::fetch(size_t max_dgram_piece, bool prefer_small)
        {
            log::trace(log_cat, "{} called with ({}, {})", __PRETTY_FUNCTION__, max_dgram_piece, prefer_small);

            if (!buf.empty() && buf.front().unsendable(max_dgram_piece, packet_splitting)) [[unlikely]]
            {
                size_t before = buf.size();
                do
                {
                    unsent_bytes -= buf.front().unsent_size();
                    buf.pop_front();
                } while (!buf.empty() && buf.front().unsendable(max_dgram_piece, packet_splitting));
                log::warning(
                        log_cat,
                        "Dropped {} unsendable datagrams that exceed the max datagram size of {}",
                        before - buf.size(),
                        max_dgram_piece * (packet_splitting ? 2 : 1));
            }

            std::optional<prepared> result;

            const size_t i = early_data_head.value_or(0);
            if (i >= buf.size())
                return result;

            if (prefer_small && packet_splitting)
            {
                auto it = buf.begin() + i;
                for (size_t off = 0; off <= split_lookahead && it != buf.end(); ++off, ++it)
                {
                    auto& dgram = *it;
                    // A lookahead can only ever have its small second part sent from here, and its
                    // first part only gets sent once it becomes the head (below).  So skipping any
                    // datagram whose second part has gone leaves lookaheads that are entirely
                    // unsent, which is what keeps a lookahead from completing before earlier
                    // datagrams and inducing out-of-order delivery.
                    if (dgram.sent_second())
                        continue;
                    assert(off == 0 || dgram.status == SendStatus::Unsent);
                    std::span<const std::byte> part;
                    if (dgram.status == SendStatus::SentFirst)
                        // Already partially sent so we return the second part (the first split part is
                        // already away so the split position is now set in stone).
                        part = dgram.payload.subspan(dgram.split_pos);
                    else if (dgram.payload.size() > max_dgram_piece)
                        part = dgram.payload.subspan(dgram.split_pos = max_dgram_piece);
                    else
                        continue;

                    last_i = i + off;
                    last_sent = SendStatus::SentSecond;
                    result.emplace(true, it->base_dgid | DGID_SPLIT_SECOND, part);
                    break;
                }
            }

            if (!result)
            {
                // Either we don't want, or we didn't find, a suitable small piece so return the head,
                // preferring the big piece if it needs splitting and we have a choice.
                last_i = i;
                auto& head = buf[i];
                assert(!head.sent());
                if (packet_splitting)
                {
                    if (head.status == SendStatus::SentFirst)
                    {
                        // Already split and first part sent, so we return the predetermined second part.
                        result.emplace(true, head.base_dgid | DGID_SPLIT_SECOND, head.payload.subspan(head.split_pos));
                        last_sent = SendStatus::SentSecond;
                    }
                    else if (head.status == SendStatus::SentSecond)
                    {
                        // Already split and second part sent, so we return the predetermined first part.
                        result.emplace(true, head.base_dgid | DGID_SPLIT_FIRST, head.payload.subspan(0, head.split_pos));
                        last_sent = SendStatus::SentFirst;
                    }
                    else if (head.size() > max_dgram_piece)
                    {
                        // Unsent and needs splitting, so we get to choose the size of the first part.
                        head.split_pos = max_dgram_piece;
                        result.emplace(true, head.base_dgid | DGID_SPLIT_FIRST, head.payload.subspan(0, head.split_pos));
                        last_sent = SendStatus::SentFirst;
                    }
                }
                if (!result)
                {
                    // Splitting disabled, or head doesn't need to be split so we sent the whole thing
                    // in one go.
                    result.emplace(packet_splitting, head.base_dgid, head.payload);
                    last_sent = SendStatus::Sent;
                }
            }

            last_size = result->payload().size();
            log::trace(
                    log_cat,
                    "Preparing datagram (id: {}) payload (size: {}): {}",
                    result->id,
                    last_size,
                    buffer_printer{result->payload()});
            return result;
        }

        void queue::confirm_sent()
        {
            assert(last_i < buf.size());
            auto& b = buf[last_i];
            b.status |= last_sent;
            unsent_bytes -= last_size;

            if (b.sent())
            {
                // If this packet is fully sent then it should be the head of the queue; otherwise it
                // means we messed up and sent datagrams out of order.
                assert(last_i == early_data_head.value_or(0));

                if (early_data_head)
                    ++*early_data_head;
                else
                    buf.pop_front();
            }

            last_i = std::numeric_limits<size_t>::max();
        }

        size_t queue::pending_bytes() const
        {
            return unsent_bytes;
        }

        storage::storage(std::span<const std::byte> payload, uint16_t base_dgid, std::shared_ptr<void> keepalive) :
                base_dgid{base_dgid}, payload{payload}, keep_alive{std::move(keepalive)}
        {}
    }  // namespace dgram
}  // namespace oxen::quic
