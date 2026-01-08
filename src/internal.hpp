#pragma once

// IWYU pragma: begin_exports
#include "format.hpp"
#include "utils.hpp"

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include <fmt/format.h>

#include <cstddef>
#include <cstdint>

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

    inline timeval loop_time_to_timeval(std::chrono::microseconds t)
    {
#ifdef _WIN32
        using suseconds_t = long;
#endif
        return timeval{.tv_sec = static_cast<time_t>(t / 1s), .tv_usec = static_cast<suseconds_t>((t % 1s) / 1us)};
    }

}  // namespace oxen::quic

// IWYU pragma: end_exports
