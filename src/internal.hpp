#pragma once

// IWYU pragma: begin_exports
#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <fmt/format.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
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

#ifndef NDEBUG
        // Set for the duration of a flush, to catch a flush starting inside another one.
        bool in_use = false;

        // Test hooks (see Endpoint::_debug_block_sends_for): sends report blocked until this time,
        // and counters of stalls, flushes skipped because of one, and stalled batches discarded
        // because their owner went away.
        std::chrono::steady_clock::time_point debug_block_until{};
        // The next `debug_partial_sends` socket sends of more than `debug_partial_max` packets only
        // send that many, reporting the rest as unsent (as a nearly-full socket would).
        size_t debug_partial_sends = 0;
        size_t debug_partial_max = 0;
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

}  // namespace oxen::quic

// IWYU pragma: end_exports
