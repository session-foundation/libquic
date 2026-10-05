#pragma once

// IWYU pragma: begin_exports
#include "address.hpp"
#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <fmt/format.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#ifndef _WIN32
extern "C"
{
#include <sys/time.h>
}
#endif

namespace oxen::quic
{
    inline auto log_cat = oxen::log::Cat("quic");

    namespace log = oxen::log;

    using namespace log::literals;

    inline constexpr size_t MAX_BATCH =
#if defined(OXEN_LIBQUIC_UDP_SENDMMSG) || defined(OXEN_LIBQUIC_UDP_GSO)
            DATAGRAM_BATCH_SIZE;
#else
            1;
#endif

    class Connection;

    // The batch of outgoing packets for an endpoint: built during one connection's flush and sent
    // in a single socket call.  Every connection on the endpoint shares this, which works because
    // flushes only ever run on the endpoint's loop thread, one at a time (a flush never starts
    // another flush inline), and because the socket is shared too: when it blocks, nobody else
    // could send anyway.
    //
    // When the socket blocks, the unsent packets stay here (`stalled`) until the socket becomes
    // writable again, and no connection may build new packets in the meantime.
    struct send_batch
    {
        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD * MAX_BATCH> buf;
        std::array<size_t, MAX_BATCH> size;
        std::array<uint8_t, MAX_BATCH> ecn;
        size_t n_packets = 0;

        bool stalled = false;

        // The connection whose packets are stalled in `buf`.  Cleared when that connection halts
        // (see Connection::halt_events), in which case the stalled packets get discarded.
        Connection* owner = nullptr;

        // Connections that tried to flush during a stall, to be woken (in order) once it clears.
        std::vector<Connection*> waiters;

        // Packets dropped because they were too large for their path, or because a local queue had
        // no room for them (used to rate-limit their logging).
        size_t too_big_drops = 0;
        size_t no_buffer_drops = 0;

#ifndef NDEBUG
        // Set for the duration of a flush, to catch a flush starting inside another one.
        bool in_use = false;

        // Test hooks (see Endpoint::_debug_block_sends_for): sends report blocked until this time,
        // and counters of stalls, flushes skipped because of one, and stalled batches discarded
        // because their owner went away.
        std::chrono::steady_clock::time_point debug_block_until{};
        // The next `debug_partial_sends` socket sends of more than `debug_partial_max` packets only
        // send that many, reporting the rest as unsent (as sendmmsg does when a later message
        // fails); if `debug_partial_then_block` the immediate retry then reports EAGAIN (as a
        // nearly-full socket would).
        size_t debug_partial_sends = 0;
        size_t debug_partial_max = 0;
        bool debug_partial_then_block = true;
        bool debug_partial_block_next = false;
        // Packets larger than this (if non-zero) fail to send with EMSGSIZE, as they would on a path
        // with that MTU.
        size_t debug_mtu = 0;
        // The next `debug_fail_count` socket sends fail with `debug_fail_errno`.
        int debug_fail_errno = 0;
        size_t debug_fail_count = 0;
        // When set, looking up the local address used to reach a peer returns this (see
        // Endpoint::_debug_simulate_route_source).
        std::optional<Address> debug_route_source;
        // When set, received packets report this as the local address they arrived on (see
        // Endpoint::_debug_simulate_arrival_address).
        std::optional<Address> debug_arrival_address;
        // When set, packets sent without a pinned source go out from this address, as they would
        // once the kernel's routing changed (see Endpoint::_debug_simulate_send_source).
        std::optional<Address> debug_send_source;
        size_t debug_route_lookups = 0;
        // The next `debug_blocked_migrations` migrations fail as though there were no spare
        // connection ID.
        size_t debug_blocked_migrations = 0;
        size_t debug_stalls = 0;
        size_t debug_stall_skips = 0;
        size_t debug_stall_discards = 0;
#endif
    };

    inline timeval loop_time_to_timeval(std::chrono::microseconds t)
    {
        timeval tv;
        tv.tv_sec = t / 1s;
        tv.tv_usec = (t % 1s) / 1us;
        return tv;
    }

    // ngtcp2's timestamps are steady clock times in nanoseconds.
    inline uint64_t ngtcp2_ts(time_point t)
    {
        return std::chrono::nanoseconds{t.time_since_epoch()}.count();
    }

}  // namespace oxen::quic

// IWYU pragma: end_exports
