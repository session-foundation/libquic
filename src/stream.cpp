#include "stream.hpp"

#include "connection.hpp"
#include "endpoint.hpp"
#include "internal.hpp"
#include "result.hpp"

#include <ngtcp2/ngtcp2.h>

#include <cstddef>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace oxen::quic
{
    void Stream::handle_opt(stream_data_callback data_cb)
    {
        _data_callback = std::move(data_cb);
    }
    void Stream::handle_opt(stream_close_callback close_cb)
    {
        _close_callback = std::move(close_cb);
    }
    void Stream::handle_opt(opt::stream_notify_t)
    {
        _notify = true;
        _had_notify = true;
    }
    void Stream::handle_opt(opt::stream_fin_callback fcb)
    {
        log::trace(log_cat, "{} fin callback", fcb.cb ? "Setting" : "Not setting (callback is nullptr)");
        _fin_callback = std::move(fcb.cb);
    }
    Stream::Stream(Connection& conn, Endpoint& ep, base_ctor) : IOChannel{conn, ep}, reference_id{conn.reference_id()}
    {
        log::trace(log_cat, "Creating Stream object...");
    }
    void Stream::set_default_callbacks()
    {
        if (!_data_callback)
            _data_callback = _conn->get_default_data_callback();

        if (!_close_callback)
            _close_callback = [](Stream&, uint64_t error_code) {
                log::debug(log_cat, "Default stream close callback called ({})", quic_strerror(error_code));
            };

        log::trace(log_cat, "Stream object created");
    }

    Stream::~Stream()
    {
        log::trace(log_cat, "Destroying stream {}", _stream_id);
        job_queue.stop();
    }

    void Stream::enable_watermarks(
            size_t alarm, std::function<void(Stream&)> on_alarm, size_t clear, std::function<void(Stream&)> on_clear)
    {
        if (clear >= alarm)
            throw std::logic_error{
                    "Invalid enable_watermarks() call: alarm watermark ({}) must be > clear watermark ({})"_format(
                            alarm, clear)};
        job_queue.call_get([this, &on_alarm, &on_clear, alarm, clear] {
            if (_is_closing || _send_fin)
            {
                log::debug(log_cat, "Failed to set watermarks; stream is not active!");
                return;
            }

            if (!_watermarking)
                _watermark_alarm = false;
            // else leave it as-is
            _watermarking.emplace(alarm, clear);
            _watermark_on_alarm = std::move(on_alarm);
            _watermark_on_clear = std::move(on_clear);

            log::debug(
                    log_cat,
                    "Stream {} watermarks enabled ([{}, {}])",
                    _stream_id,
                    _watermarking->first,
                    _watermarking->second);

            // Invoke the check because the new limits might induce an immediate transition
            check_watermark();
        });
    }

    void Stream::disable_watermarks()
    {
        job_queue.call_get([this] {
            if (!_watermarking)
                return;
            _watermarking.reset();
            _watermark_alarm = false;
            _watermark_on_alarm = nullptr;
            _watermark_on_clear = nullptr;
            log::debug(log_cat, "Stream {} watermarking disabled", _stream_id);
        });
    }

    void Stream::pause()
    {
        job_queue.call_get([this]() {
            if (not _paused)
            {
                log::debug(log_cat, "Pausing stream ID:{}", _stream_id);
                assert(_paused_offset == 0);
                _paused = true;
            }
            else
                log::debug(log_cat, "Stream ID:{} already paused!", _stream_id);
        });
    }

    void Stream::resume()
    {
        job_queue.call_get([this]() {
            if (_paused)
            {
                log::debug(log_cat, "Resuming stream ID:{}", _stream_id);
                _paused = false;
                if (_conn)
                {
                    if (_paused_offset)
                        ngtcp2_conn_extend_max_stream_offset(*_conn, _stream_id, _paused_offset);

                    // Extending the offset only credits the peer inside ngtcp2; it cannot send
                    // again until a MAX_STREAM_DATA frame actually reaches it, and nothing here is
                    // otherwise about to write.  (The unpaused path gets this for free by extending
                    // from inside packet processing, where a write follows anyway.)  Without this
                    // the credit waits for an unrelated timer: the peer is flow-control blocked so
                    // it sends nothing to prompt us, leaving a delayed ACK if one happens to still
                    // be pending, and otherwise the peer's PTO -- seconds, not milliseconds.
                    _conn->packet_io_ready();
                }
                _paused_offset = 0;
            }
            else
                log::debug(log_cat, "Stream ID:{} is not paused!", _stream_id);
        });
    }

    bool Stream::is_paused() const
    {
        return job_queue.call_get([this]() { return _paused; });
    }

    uint64_t Stream::acked_bytes() const
    {
        return job_queue.call_get([this] { return _acked_bytes; });
    }

    size_t Stream::unacked_bytes() const
    {
        return job_queue.call_get([this] { return _unacked_size; });
    }

    size_t Stream::retained_bytes() const
    {
        return job_queue.call_get([this] { return retained_impl(); });
    }

    std::tuple<uint64_t, size_t, size_t, size_t> Stream::get_stats() const
    {
        return job_queue.call_get([this] { return std::tuple{_acked_bytes, _unacked_size, _unsent_size, retained_impl()}; });
    }

    bool Stream::writable() const
    {
        return job_queue.call_get([this] { return !(_is_closing || _send_fin || _sent_fin); });
    }
    bool Stream::readable() const
    {
        return job_queue.call_get([this] { return !(_is_closing || _received_fin); });
    }

    bool Stream::is_ready() const
    {
        return job_queue.call_get([this] { return _ready; });
    }

    std::optional<bool> Stream::watermark_status() const
    {
        return job_queue.call_get([this]() -> std::optional<bool> {
            if (!_watermarking)
                return std::nullopt;
            return _watermark_alarm;
        });
    }

    void Stream::on_fin()
    {
        _received_fin = true;
        if (_fin_callback)
            _fin_callback(*this);
    }

    void Stream::send_fin()
    {
        job_queue.call([this] {
            _send_fin = true;
            if (_conn)
                _conn->packet_io_ready();
        });
    }

    void Stream::close(uint64_t app_err_code)
    {
        if (app_err_code > APP_ERRCODE_MAX)
            throw std::invalid_argument{"Invalid application error code (too large)"};

        // NB: this *must* be a call (not a call_soon) because Connection calls on a short-lived
        // Stream that won't survive a return to the event loop.
        job_queue.call([this, app_err_code]() {
            log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

            if (_is_closing)
                log::trace(log_cat, "Stream is already closing");
            else
            {
                _send_fin = _is_closing = true;
                if (_conn)
                {
                    log::info(log_cat, "Closing stream (ID: {}) with: {}", _stream_id, quic_strerror(app_err_code));
                    ngtcp2_conn_shutdown_stream(*_conn, 0, _stream_id, app_err_code);
                }
            }
            _data_callback = nullptr;

            if (!_conn)
            {
                log::debug(log_cat, "Stream close ignored: the stream's connection is gone");
                return;
            }

            _conn->packet_io_ready();
        });
    }

    void Stream::set_data_callback(stream_data_callback cb)
    {
        job_queue.call_get([this, &cb] { _data_callback = std::move(cb); });
    }
    void Stream::set_close_callback(stream_close_callback cb)
    {
        job_queue.call_get([this, &cb] { _close_callback = std::move(cb); });
    }
    void Stream::set_fin_callback(std::function<void(Stream&)> cb)
    {
        job_queue.call_get([this, &cb] { _fin_callback = std::move(cb); });
    }

    void Stream::closed(uint64_t app_code)
    {
        if (_close_callback)
        {
            try
            {
                _close_callback(*this, app_code);
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception in stream close callback: {}", e.what());
            }
        }

        _conn = nullptr;
        _send_fin = _is_closing = true;
    }

    void Stream::check_watermark()
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        const auto& [alarm_thresh, clear_thresh] = *_watermarking;
        if (_watermark_alarm)
        {
            if (_unsent_size <= clear_thresh)
            {
                log::debug(log_cat, "Watermark ({} unsent) dropped <= clear threshold ({})", _unsent_size, clear_thresh);
                _watermark_alarm = false;
                if (_watermark_on_clear)
                    _watermark_on_clear(*this);
            }
        }
        else if (_unsent_size >= alarm_thresh)
        {
            log::debug(
                    log_cat,
                    "Watermark triggered alarm threshold ({} unsent >= alarm threshold {})",
                    _unsent_size,
                    alarm_thresh);
            _watermark_alarm = true;
            if (_watermark_on_alarm)
                _watermark_on_alarm(*this);
        }
    }

    void Stream::append_buffer(std::span<const std::byte> buffer, std::shared_ptr<void> keep_alive)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        assert(job_queue.inside());
        assert(_conn);

        _unsent_size += buffer.size();
        user_buffers.emplace_back(buffer, std::move(keep_alive));
        if (_watermarking)
            check_watermark();

        if (_ready)
            _conn->packet_io_ready();
        else
            log::debug(log_cat, "Stream not ready for broadcast yet, data appended to buffer and on deck");
    }

    void Stream::acknowledge(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Acking {} bytes of {}/{} unacked/unsent", bytes, _unacked_size, _unsent_size);

        assert(bytes <= _unacked_size);
        _unacked_size -= bytes;
        _acked_bytes += bytes;

        // Drop all fully-acked buffers that are no longer needed
        while (bytes && bytes >= user_buffers.front().first.size())
        {
            bytes -= user_buffers.front().first.size();
            user_buffers.pop_front();
            // Whatever had been trimmed off the old front is released along with it, and the new
            // front (if any) has never been trimmed:
            _front_trimmed = 0;
            assert(_current_buffer_index > 0);
            _current_buffer_index -= 1;
            log::trace(log_cat, "bytes: {}", bytes);
        }

        // Any remaining acked bytes are the leading bytes of the first buffer, so chop them off:
        if (bytes)
        {
            auto& front = user_buffers.front().first;
            front = front.subspan(bytes);
            _front_trimmed += bytes;
            if (_current_buffer_index == 0)
            {
                assert(_current_buffer_offset >= bytes);
                _current_buffer_offset -= bytes;
            }
        }

        log::trace(log_cat, "{} bytes acked, {} unacked remaining", bytes, _unacked_size);
    }

    void Stream::wrote(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);
        log::trace(log_cat, "Increasing _unacked_size by {}B", bytes);
        _unacked_size += bytes;
        _unsent_size -= bytes;
        if (_notify)
            _notify = false;
        if (_watermarking)
            check_watermark();
        while (_current_buffer_index < user_buffers.size() && bytes > 0)
        {
            size_t remaining = user_buffers[_current_buffer_index].first.size() - _current_buffer_offset;
            if (bytes < remaining)
            {
                _current_buffer_offset += bytes;
                return;
            }
            bytes -= remaining;
            _current_buffer_index += 1;
            _current_buffer_offset = 0;
        }
    }

    void Stream::revert_stream()
    {
        assert(job_queue.inside());
        log::trace(log_cat, "Stream (ID:{}) reverting after early data rejected...", _stream_id);
        _unsent_size += _unacked_size;
        _unacked_size = 0;
        _current_buffer_index = 0;
        _current_buffer_offset = 0;
        if (_had_notify)
            _notify = true;
        log::debug(log_cat, "Stream (ID:{}) has {}B in buffer, 0B unacked...", _stream_id, _unsent_size);
    }

    std::pair<std::vector<ngtcp2_vec>, bool> Stream::pending(size_t bytes)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::pair<std::vector<ngtcp2_vec>, bool> ret;
        auto& [nbufs, more] = ret;

        log::trace(log_cat, "unsent: {}", unsent());

        if (user_buffers.empty() || unsent() == 0)
        {
            if (_notify)
            {
                // If this is still set it means the stream is configured to notify the other end,
                // and we haven't done so yet, so return an empty buffer.
                nbufs.emplace_back(nullptr, 0);
            }
            more = false;
            return ret;
        }

        size_t total = 0;
        size_t i = 0;
        for (i = _current_buffer_index; i < user_buffers.size() && total < bytes; i++)
        {
            auto& temp = nbufs.emplace_back();
            size_t offset = (i == _current_buffer_index) ? _current_buffer_offset : 0;
            temp.base = const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(user_buffers[i].first.data() + offset));
            temp.len = user_buffers[i].first.size() - offset;
            total += temp.len;
        }
        more = i != user_buffers.size();
        return ret;
    }

    void Stream::send_impl(std::span<const std::byte> data, std::shared_ptr<void> keep_alive)
    {
        if (data.empty())
            return;

        // `this` needs no lifetime guard: the job queue is our own, so if the stream is destroyed
        // before this job runs then the job is discarded along with it.
        job_queue.call([this, data, ka = std::move(keep_alive)]() {
            if (_is_closing || _send_fin || _sent_fin)
            {
                log::debug(log_cat, "Stream {} is already finalized, dropping send data", _stream_id);
                return;
            }
            else if (!_conn || _conn->is_closing() || _conn->is_draining())
            {
                log::debug(log_cat, "Stream {} unable to send: connection is closed", _stream_id);
                return;
            }
            log::trace(log_cat, "Stream (ID: {}) sending message: {}", _stream_id, buffer_printer{data});
            append_buffer(data, std::move(ka));
        });
    }

    size_t Stream::unsent_impl() const
    {
        return _unsent_size;
    }

    void Stream::set_ready(bool ready)
    {
        if (_ready == ready)
            return;

        log::debug(log_cat, "Setting stream {}", ready ? "ready" : "unready");
        _ready = ready;
        if (ready)
            on_ready();
        else
            on_unready();
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message)
    {
        log::trace(log_cat, "{}:{} -- {}", file, lineno, message);
    }

    void _chunk_sender_trace(const char* file, int lineno, std::string_view message, size_t val)
    {
        log::trace(log_cat, "{}:{} -- {}{}", file, lineno, message, val);
    }

}  // namespace oxen::quic
