#include "utils.hpp"

#include <oxenc/endian.h>

#include <event2/event.h>
#include <ngtcp2/ngtcp2.h>

#include <algorithm>
#include <chrono>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

namespace oxen::quic
{
    time_point get_time()
    {
        return std::chrono::steady_clock::now();
    }
    std::chrono::nanoseconds get_timestamp()
    {
        return std::chrono::steady_clock::now().time_since_epoch();
    }

    std::string str_tolower(std::string s)
    {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    void event_deleter::operator()(::event* e) const
    {
        if (e)
            ::event_free(e);
    }

    // We hard-code this constant in utils.hpp to avoid needing to include all of ngtcp2, but verify
    // here that it matches the ngtcp2 value.
    static_assert(MIN_UDP_PAYLOAD == NGTCP2_MAX_UDP_PAYLOAD_SIZE);

    // Connections without an opt::max_udp_payload use MAX_PMTUD_UDP_PAYLOAD as the default list's
    // largest size, and ngtcp2 asserts every probe size is above the minimum.
    static_assert(std::ranges::max(DEFAULT_PMTUD_PROBES) == MAX_PMTUD_UDP_PAYLOAD);
    static_assert(std::ranges::min(DEFAULT_PMTUD_PROBES) > MIN_UDP_PAYLOAD);

#ifdef _WIN32
    static bool running_under_wine_impl()
    {
        auto ntdll = GetModuleHandle("ntdll.dll");
        return ntdll && GetProcAddress(ntdll, "wine_get_version");
    }
    const bool EMULATING_HELL = running_under_wine_impl();
#endif

}  // namespace oxen::quic
