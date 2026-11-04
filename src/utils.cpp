#include "utils.hpp"

#include <oxenc/endian.h>

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

#ifdef _WIN32
    static bool running_under_wine_impl()
    {
        auto ntdll = GetModuleHandle("ntdll.dll");
        return ntdll && GetProcAddress(ntdll, "wine_get_version");
    }
    const bool EMULATING_HELL = running_under_wine_impl();
#endif

}  // namespace oxen::quic
