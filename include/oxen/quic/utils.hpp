#pragma once

#include <oxenc/common.h>

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <type_traits>
#include <vector>

struct event;

namespace oxen::quic
{

    enum class Direction { OUTBOUND = 0, INBOUND = 1 };

    enum class Splitting { NONE = 0, ACTIVE = 1 };

    using time_point = std::chrono::steady_clock::time_point;

    using namespace std::literals;

#ifdef _WIN32
    inline constexpr bool IN_HELL = true;
    extern const bool EMULATING_HELL;  // True if compiled for windows but running under WINE
#else
    inline constexpr bool IN_HELL = false;
    inline constexpr bool EMULATING_HELL = false;
#endif

    // SI (1000) and non-SI (1024-based) modifier prefix operators.  E.g.
    // 50_M is 50'000'000 and 50_Mi is 52'428'800.
    constexpr unsigned long long operator""_k(unsigned long long int x)
    {
        return x * 1000;
    }
    constexpr unsigned long long operator""_M(unsigned long long int x)
    {
        return x * 1000 * 1_k;
    }
    constexpr unsigned long long operator""_G(unsigned long long int x)
    {
        return x * 1000 * 1_M;
    }
    constexpr unsigned long long operator""_T(unsigned long long int x)
    {
        return x * 1000 * 1_G;
    }
    constexpr unsigned long long operator""_ki(unsigned long long int x)
    {
        return x * 1024;
    }
    constexpr unsigned long long operator""_Mi(unsigned long long int x)
    {
        return x * 1024 * 1_ki;
    }
    constexpr unsigned long long operator""_Gi(unsigned long long int x)
    {
        return x * 1024 * 1_Mi;
    }
    constexpr unsigned long long operator""_Ti(unsigned long long int x)
    {
        return x * 1024 * 1_Gi;
    }

    inline constexpr uint64_t DEFAULT_MAX_BIDI_STREAMS = 32;

    inline constexpr std::chrono::seconds DEFAULT_HANDSHAKE_TIMEOUT = 10s;
    inline constexpr std::chrono::seconds DEFAULT_IDLE_TIMEOUT = 30s;

    // NGTCP2 sets the path_pmtud_payload to 1200 on connection creation, then discovers upwards
    // to at most MAX_PMTUD_UDP_PAYLOAD. In 'lazy' mode, we take in split packets under the current
    // max pmtud size. In 'greedy' mode, we take in up to double the current pmtud size to split
    // amongst two datagrams. (Note: NGTCP2_MAX_UDP_PAYLOAD_SIZE is badly named, so we're using more
    // accurate ones)

    inline constexpr size_t MIN_UDP_PAYLOAD = 1200;  // == NGTCP2_MAX_UDP_PAYLOAD_SIZE
    inline constexpr size_t MIN_LAZY_UDP_PAYLOAD = MIN_UDP_PAYLOAD;
    inline constexpr size_t MIN_GREEDY_UDP_PAYLOAD = 2 * MIN_LAZY_UDP_PAYLOAD;
    // The largest UDP payload we send or receive: what a 1500-byte (i.e. Ethernet) MTU carries over
    // IPv4 (1500 - 20 - 8).
    inline constexpr size_t MAX_PMTUD_UDP_PAYLOAD = 1472;
    inline constexpr size_t MAX_GREEDY_PMTUD_UDP_PAYLOAD = 2 * MAX_PMTUD_UDP_PAYLOAD;
    // The largest UDP payload we send on IPv6 connections: what a 1500-byte MTU carries over IPv6
    // (1500 - 40 - 8).
    inline constexpr size_t MAX_IPV6_UDP_PAYLOAD = 1452;

    // The UDP payload sizes path MTU discovery probes.  ngtcp2 walks the list once, in order,
    // probing each size unless it is no larger than the largest size confirmed so far, or no
    // smaller than the smallest size that has failed; the order therefore decides the search.
    // MTUs below are IPv6 (payload + 48) unless stated otherwise.
    //
    // 1372 and 1324 are the smallest path sizes at which session-router can carry a tunnelled QUIC
    // connection's packets without splitting them; below them tunnels still work, but every
    // full-size packet is split across two datagram pieces.  Its tunnels pin the inner connection to
    // 1200-byte packets and send each one, with session-router's own headers added, as a single
    // datagram on a link connection that has datagram splitting enabled.  libquic sends a datagram
    // whole only if it fits in the path size after the link connection's own packet overhead: 46
    // bytes, i.e. DATAGRAM_OVERHEAD_1RTT plus 2 for the split ID.
    inline constexpr uint16_t DEFAULT_PMTUD_PROBES[] = {
            1452,  // 1500 (Ethernet) MTU; tried first because it also fits that MTU over IPv4
            1472,  // 1500 MTU over IPv4
            1372,  // 1420 MTU (WireGuard).  Also the split threshold (not a limit: smaller paths still
                   // work, by splitting) for session-router's UDP tunnel at the 1200 QUIC minimum,
                   // which adds 126 bytes to each packet (a 48-byte IPv6 + UDP header, 37 bytes of
                   // session layer and 41 of path layer): 1200 + 126, + 46 for the link connection's
                   // own packet overhead = 1372.
            1444,  // 1492 MTU (PPPoE)
            1406,  // 1454 MTU
            1342,  // 1390 MTU
            1324,  // The split threshold (not a limit: smaller paths still work, by splitting) for
                   // session-router's TCP tunnel at the 1200 QUIC minimum, which adds 78 bytes to each
                   // packet (37 of session layer and 41 of path layer, with no IP header): 1200 + 78,
                   // + 46 for the link connection's own packet overhead = 1324.
            1232,  // 1280 MTU, the IPv6 minimum
    };

    // This is the maximum overhead in the UDP packet of sending a packet containing only one single
    // datagram, and is used to determine the maximum datagram size we can send.
    //
    // Specifically this is:
    // + 1 byte for various short packet flags
    // + 20 bytes dcid
    // + 4 bytes (max) packet number
    // + 16 bytes AEAD tag
    // + 1 byte datagram frame type
    // + 2 bytes datagram length.  (This should be optional for the final datagram, but currently ngtcp2 always includes it).
    inline constexpr size_t DATAGRAM_OVERHEAD_1RTT = 1 + 20 + 4 + 16 + 1 + 2;

    // This is the same as DATAGRAM_OVERHEAD_1RTT, but applied in early data (0-RTT) mode.  This is:
    //
    // + 1 byte for various long packet flags
    // + 4 byte version
    // + 1 byte dcid length
    // + 20 bytes dcid
    // + 1 byte dcid length
    // + 20 bytes scid
    // + 2 bytes (max) length
    // + 4 bytes (max) packet number
    // + 1 byte datagram frame type
    // + 2 bytes datagram length.  (As above, should be optional but isn't with current ngtcp2).
    inline constexpr size_t DATAGRAM_OVERHEAD_0RTT = 1 + 4 + 1 + 20 + 1 + 20 + 2 + 4 + 1 + 2;

    // Maximum number of packets we can send in one batch when using sendmmsg/GSO.
    inline constexpr size_t DATAGRAM_BATCH_SIZE = 24;

    // Maximum number of packets we will receive at once before returning control to the event loop
    // to re-call the packet receiver if there are additional packets.  (This limit is to prevent
    // loop starvation in the face of heavy incoming packets.)  recvmmsg receives up to this many in
    // a single call.
    inline constexpr size_t MAX_RECEIVE_PER_LOOP = 64;

    // The minimum size stateless reset packet we will send, as proscribed by section 10.3.3 of the
    // RFC.  Each generated stateless reset packet is smaller than the one that triggered it, down
    // to this limit, to stop a potential infinite loop.
    inline constexpr size_t MIN_STATELESS_RESET_SIZE = 41;

    // Check if T is an instantiation of templated class `Class`; for example,
    // `is_instantiation<std::basic_string, std::string>` is true.
    template <template <typename...> class Class, typename T>
    inline constexpr bool is_instantiation = false;
    template <template <typename...> class Class, typename... Us>
    inline constexpr bool is_instantiation<Class, Class<Us...>> = true;

    template <oxenc::basic_char Out, oxenc::basic_char In, size_t Extent>
        requires(std::is_const_v<Out> || !std::is_const_v<In>)
    inline std::span<Out, Extent> reinterpret_span(std::span<In, Extent> in)
    {
        if constexpr (std::is_const_v<Out> && !std::is_const_v<In>)
            return std::span<Out, Extent>{reinterpret_cast<Out*>(const_cast<const In*>(in.data())), in.size()};
        else
            return std::span<Out, Extent>{reinterpret_cast<Out*>(const_cast<In*>(in.data())), in.size()};
    }
    // Templatize with `same_as` here so that we only match actual string_views and not things
    // convertible to string_view.
    template <oxenc::basic_char Out, std::same_as<std::string_view> In>
        requires std::is_const_v<Out>
    inline std::span<Out> reinterpret_span(In in)
    {
        return reinterpret_span<Out>(std::span{in});
    }

    time_point get_time();
    std::chrono::nanoseconds get_timestamp();

    template <typename unit_t>
    auto get_timestamp()
    {
        return std::chrono::duration_cast<unit_t>(get_timestamp());
    }

    std::string str_tolower(std::string s);

    /// Parses an integer of some sort from a string, requiring that the entire string be consumed
    /// during parsing.  Return false if parsing failed, sets `value` and returns true if the entire
    /// string was consumed.
    template <typename T>
    bool parse_int(const std::string_view str, T& value, int base = 10)
    {
        T tmp;
        auto* strend = str.data() + str.size();
        auto [p, ec] = std::from_chars(str.data(), strend, tmp, base);
        if (ec != std::errc() || p != strend)
            return false;
        value = tmp;
        return true;
    }

    struct event_deleter final
    {
        void operator()(::event* e) const;
    };

    using event_ptr = std::unique_ptr<::event, event_deleter>;

}  // namespace oxen::quic
