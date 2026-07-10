#include "btstream.hpp"

#include "internal.hpp"
#include "result.hpp"

#include <oxenc/bt_producer.h>

#include <event2/event.h>

#include <algorithm>
#include <cassert>
#include <charconv>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <type_traits>

namespace oxen::quic
{
    static std::pair<std::ptrdiff_t, std::size_t> get_location(std::vector<std::byte>& data, std::string_view substr)
    {
        auto* bsubstr = reinterpret_cast<const std::byte*>(substr.data());
        // Make sure the given substr actually is a substr of data:
        assert(bsubstr >= data.data() && bsubstr + substr.size() <= data.data() + data.size());
        return {bsubstr - data.data(), substr.size()};
    }

    message::message(BTRequestStream& bp, std::vector<std::byte> req, bool is_timeout) :
            data{std::move(req)}, return_sender{bp.weak_from_this()}, _rid{bp.reference_id}, timed_out{is_timeout}
    {
        if (!is_timeout)
        {
            oxenc::bt_list_consumer btlc{data};

            req_type = get_location(data, btlc.consume_string_view());
            req_id = btlc.consume_integer<int64_t>();

            if (type() == TYPE_COMMAND)
                ep = get_location(data, btlc.consume_string_view());

            req_body = get_location(data, btlc.consume_string_view());

            btlc.finish();
        }
    }

    void message::respond(std::span<const std::byte> body, bool error) const
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        if (auto ptr = return_sender.lock())
            ptr->respond(req_id, body, error);
        else
            log::debug(log_cat, "Dropping response: stream has gone away");
    }

    void BTRequestStream::handle_opt(std::function<void(message m)> request_handler)
    {
        log::debug(log_cat, "BTRequestStream set generic request handler");
        generic_handler = std::move(request_handler);
    }
    void BTRequestStream::respond(int64_t rid, std::span<const std::byte> body, bool error)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        send(sent_request{*this, encode_response(rid, body, error), rid}.data);
    }

    void BTRequestStream::check_timeouts(std::optional<std::chrono::steady_clock::time_point> now)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        std::list<std::shared_ptr<sent_request>> expired;
        auto it = req_expiries.begin();
        for (; it != req_expiries.end() && (!now || it->first <= *now); ++it)
        {
            auto id = it->second;

            if (auto srit = sent_reqs.find(id); srit != sent_reqs.end())
            {
                expired.push_back(std::move(srit->second));
                sent_reqs.erase(srit);
            }
        }
        req_expiries.erase(req_expiries.begin(), it);

        for (auto& sr : expired)
        {
            auto& f = *sr;
            try
            {
                f.cb(std::move(f).to_timeout());
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception from timeout response handler: {}", e.what());
            }
        }
    }

    void BTRequestStream::update_timeout()
    {
        if (req_expiries.empty())
        {
            if (timeout)
                event_del(timeout.get());
            return;
        }

        if (!timeout)
        {
            // If this is the first request timeout then set up the timeout event timer:
            timeout.reset(event_new(
                    loop.get_event_base(),
                    -1,          // Not attached to an actual socket
                    EV_TIMEOUT,  // Stays active (i.e. repeats) once fired
                    [](evutil_socket_t, short, void* self) {
                        auto* me = static_cast<BTRequestStream*>(self);
                        me->check_timeouts(std::chrono::steady_clock::now());
                        me->update_timeout();
                    },
                    this));
        }

        auto expires_in =
                std::chrono::ceil<std::chrono::microseconds>(req_expiries.begin()->first - std::chrono::steady_clock::now());
        if (expires_in < 0us)
            expires_in = 0us;
#ifdef _WIN32
        using suseconds_t = long;
#endif
        timeval exp_interval{
                .tv_sec = static_cast<time_t>(expires_in / 1s),
                .tv_usec = static_cast<suseconds_t>((expires_in % 1s).count())};

        event_add(timeout.get(), &exp_interval);
    }

    void BTRequestStream::receive(std::span<const std::byte> data)
    {
        log::trace(log_cat, "btreqstream recv data callback called!");

        if (is_closing())
            return;

        try
        {
            process_incoming(data);
        }
        catch (const std::exception& e)
        {
            log::error(log_cat, "Exception caught: {}", e.what());
            close(BTREQ_ERROR_EXCEPTION);
        }
    }

    void BTRequestStream::closed(uint64_t app_code)
    {
        log::debug(log_cat, "btreqstream closed with {}", quic_strerror(app_code));

        // First time out any pending requests, even if they haven't hit the timer, because we're
        // being closed and so they can never be answered.
        timeout.reset();
        check_timeouts(std::nullopt);

        Stream::close(app_code);
    }

    void BTRequestStream::register_handler(std::string ep, std::function<void(message)> func)
    {
        endpoint.job_queue.call([this, ep = std::move(ep), func = std::move(func)]() mutable {
            registered_endpoints[std::move(ep)] = std::move(func);
        });
    }

    void BTRequestStream::register_generic_handler(std::function<void(message)> request_handler)
    {
        log::debug(log_cat, "BTRequestStream set generic request handler");
        endpoint.job_queue.call([this, func = std::move(request_handler)]() mutable { generic_handler = std::move(func); });
    }

    void BTRequestStream::handle_input(message msg)
    {
        log::trace(log_cat, "{} called to handle {} input", __PRETTY_FUNCTION__, msg.type());

        if (auto type = msg.type(); type == message::TYPE_REPLY || type == message::TYPE_ERROR)
        {
            log::debug(log_cat, "Looking for request with req_id={}", msg.req_id);

            // It is quite common that we get responses in the same order that we made requests,
            // and so this optimization to check the front first, which will be the oldest
            // outstanding request, saving a log-n search in the map:
            auto it = sent_reqs.begin();
            if (it != sent_reqs.end() && it->first != msg.req_id)
                it = sent_reqs.find(msg.req_id);

            if (it == sent_reqs.end())
            {
                log::debug(
                        log_cat,
                        "Ignoring {} (req_id={}): no handler found; probably a late, already-timed-out response",
                        type == message::TYPE_REPLY ? "reply" : "error response",
                        msg.req_id);
                return;
            }

            log::debug(log_cat, "Successfully matched response (req_id={}) to sent request!", msg.req_id);
            auto req = std::move(it->second);
            sent_reqs.erase(it);

            bool was_front = false;
            for (auto [it, end] = req_expiries.equal_range(req->expiry); it != end; ++it)
            {
                if (it->second == req->req_id)
                {
                    was_front = it == req_expiries.begin();
                    req_expiries.erase(it);
                    break;
                }
            }
            if (was_front)
                update_timeout();
            // otherwise we didn't find it, or it wasn't at the front, so we don't need to reset
            // the timer (because the timer is synced with the first element).

            try
            {
                req->cb(std::move(msg));
            }
            catch (const std::exception& e)
            {
                log::error(log_cat, "Uncaught exception from response handler: {}", e.what());
            }
            return;
        }

        // `msg` likely isn't valid in the exception handlers below, so extract what we need to
        // send a response anyway:
        const auto req_id = msg.req_id;
        const std::string ep{msg.endpoint()};
        try
        {
            if (!registered_endpoints.empty())
            {
                if (auto itr = registered_endpoints.find(ep); itr != registered_endpoints.end())
                {
                    log::debug(log_cat, "Executing request endpoint {}", msg.endpoint());
                    return itr->second(std::move(msg));
                }
            }
            if (generic_handler)
            {
                log::debug(log_cat, "Executing generic request handler for endpoint {}", msg.endpoint());
                return generic_handler(std::move(msg));
            }
            // We do this via a throw so that generic_handler can also throw it to induce no such
            // endpoint handling:
            throw no_such_endpoint{};
        }
        catch (const no_such_endpoint&)
        {
            log::warning(log_cat, "No handler found for endpoint {}, returning error response", ep);
            respond(req_id, "Invalid endpoint '{}'"_format(ep), true);
        }
        catch (const std::exception& e)
        {
            log::error(
                    log_cat,
                    "Handler for {} threw an uncaught exception ({}); returning a generic error message",
                    ep,
                    e.what());
            respond(req_id, "An error occurred while processing the request", true);
        }
    }

    std::optional<size_t> prefix_accumulator(std::string& partial, std::span<const std::byte>& req)
    {
        std::optional<size_t> s;
        auto it = req.begin();
        for (; it != req.end(); ++it)
        {
            if (*it >= std::byte{'0'} && *it <= std::byte{'9'})
            {
                partial += static_cast<char>(*it);
                if (partial.size() > MAX_REQ_LEN_ENCODED)
                    throw std::invalid_argument{"invalid encoded data length"};
            }
            else if (*it == std::byte{':'})
            {
                if (partial.size() > 1 && partial.front() == '0')
                    throw std::invalid_argument{"bt-encoded string size cannot begin with 0"};
                [[maybe_unused]] auto [ptr, ec] =
                        std::from_chars(partial.data(), partial.data() + partial.size(), s.emplace());
                // These should be guaranteed by the parsing above
                assert(ec == std::errc{});
                assert(ptr == partial.data() + partial.size());
                partial.clear();
                ++it;
                break;
            }
            else
                throw std::invalid_argument{"invalid input: expected bt-encoded data block"};
        }

        req = {it, req.end()};
        return s;
    }

    bool data_accumulator(std::vector<std::byte>& buf, std::span<const std::byte>& req, size_t size)
    {
        assert(buf.size() < size);
        auto old_size = buf.size();
        auto new_size = std::min(old_size + req.size(), size);
        buf.resize(new_size);
        std::memcpy(buf.data() + old_size, req.data(), new_size - old_size);
        req = req.subspan(new_size - old_size);

        return buf.size() == size;
    }

    void BTRequestStream::process_incoming(std::span<const std::byte> req)
    {
        log::trace(log_cat, "{} called", __PRETTY_FUNCTION__);

        while (not req.empty())
        {
            if (current_len == 0)
            {
                if (auto s = prefix_accumulator(size_buf, req))
                {
                    current_len = *s;
                    if (current_len == 0)
                    {
                        log::debug(log_cat, "Ignoring 0-length btstream body");
                        return;
                    }
                    if (current_len > MAX_REQ_LEN)
                        throw std::invalid_argument{"Request exceeds maximum size!"};
                }
                else
                    return;

                assert(current_len > 0);  // We shouldn't get out of the above without knowing this
                buf.reserve(current_len);
            }

            if (data_accumulator(buf, req, current_len))
            {
                handle_input(message{*this, std::move(buf)});
                buf.clear();

                // Back to the top to try processing another request that might have arrived in
                // the same stream buffer
                current_len = 0;
            }
        }
    }

    std::string BTRequestStream::encode_command(std::string_view endpoint, int64_t rid, std::span<const std::byte> body)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(message::TYPE_COMMAND);
        btlp.append(rid);
        btlp.append(endpoint);
        btlp.append(body);

        return std::move(btlp).str();
    }

    std::string BTRequestStream::encode_response(int64_t rid, std::span<const std::byte> body, bool error)
    {
        oxenc::bt_list_producer btlp;

        btlp.append(error ? message::TYPE_ERROR : message::TYPE_REPLY);
        btlp.append(rid);
        btlp.append(body);

        return std::move(btlp).str();
    }

    sent_request* BTRequestStream::add_sent_request(std::shared_ptr<sent_request> req)
    {
        if (is_closing())
        {
            // The stream is already dead, so fire the failure callback as a timeout right away and
            // drop the request, since we know it can never complete.  (This isn't necessarily the
            // application's fault: the closing could have started while queuing this new command
            // for the event loop).
            auto& f = *req;
            if (f.cb)
            {
                try
                {
                    f.cb(std::move(f).to_timeout());
                }
                catch (const std::exception& e)
                {
                    log::error(log_cat, "Uncaught exception from closed-stream sent request response handler: {}", e.what());
                }
            }
            return nullptr;
        }
        auto req_id = req->req_id;
        auto& sent_req = sent_reqs[req_id];
        sent_req = std::move(req);

        // We hint at the end because it is an extremely common pattern that you use the same
        // timeout for all (or most) requests in which case each new request timeout *does* land at
        // the end.
        req_expiries.emplace_hint(req_expiries.end(), sent_req->expiry, req_id);

        // If the expiry entry landed at the beginning of the map -- either because it was empty, or
        // because this has a shorter timeout than what's already in there -- then we need to
        // (re)schedule the event to this request's timeout.
        if (req_expiries.begin()->second == req_id)
            update_timeout();

        return sent_req.get();
    }

    size_t BTRequestStream::num_pending() const
    {
        return call_get_accessor(&BTRequestStream::num_pending_impl);
    }

    size_t BTRequestStream::num_awaiting_response() const
    {
        return call_get_accessor(&BTRequestStream::num_awaiting_response_impl);
    }

}  // namespace oxen::quic
