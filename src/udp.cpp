
extern "C"
{

#ifdef __linux__
#include <netinet/udp.h>
#endif

#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include <fcntl.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/uio.h>
#endif
}

#include "address.hpp"
#include "internal.hpp"
#include "result.hpp"
#include "udp.hpp"

#include <event2/event.h>

#include <array>
#include <cassert>
#include <cerrno>
#include <cstring>
#include <functional>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
#include <vector>

#ifndef NDEBUG
#include <deque>
#include <mutex>
#include <unordered_map>
#endif

#ifdef _WIN32

#define CMSG_FIRSTHDR(h) WSA_CMSG_FIRSTHDR(h)
#define CMSG_NXTHDR(h, c) WSA_CMSG_NXTHDR(h, c)
#define QUIC_CMSG_DATA(c) WSA_CMSG_DATA(c)  // conflicts without the QUIC_ prefix
#define CMSG_SPACE(c) WSA_CMSG_SPACE(c)
#define CMSG_LEN(c) WSA_CMSG_LEN(c)

#ifndef IPV6_RECVPKTINFO
#define IPV6_RECVPKTINFO IPV6_PKTINFO
#endif

#else  // not windows

#define QUIC_CMSG_DATA(c) CMSG_DATA(c)

#endif

// We support different compilation modes for trying different methods of UDP sending by setting
// these defines; these shouldn't be set directly but rather through the cmake -DLIBQUIC_SEND
// option.  At most one of these may be defined.
//
// OXEN_LIBQUIC_UDP_GSO -- support use either sendmmsg or GSO to batch-send packets.  GSO
// support can be opted-in at runtime.  Only works on Linux, and not always (i.e. depends on
// hardware and software support).  Will fall back to SENDMMSG if the required UDP_SEGMENT is
// not defined (i.e. on older Linux distros), or if GSO is not selected at runtime.
// CMake option: -DLIBQUIC_SEND=gso
//
// OXEN_LIBQUIC_UDP_SENDMMSG -- use sendmmsg (but not GSO) to batch-send packets.  Only works on
// Linux and FreeBSD.
// CMake option: -DLIBQUIC_SEND=sendmmsg
//
// If neither is defined we use plain sendmsg in a loop.

#if (defined(OXEN_LIBQUIC_UDP_GSO) + defined(OXEN_LIBQUIC_UDP_SENDMMSG)) > 1
#error Only one of OXEN_LIBQUIC_UDP_GSO and OXEN_LIBQUIC_UDP_SENDMMSG may be set at once
#endif

#if defined(OXEN_LIBQUIC_UDP_GSO) && !defined(UDP_SEGMENT)
#undef OXEN_LIBQUIC_UDP_GSO
#define OXEN_LIBQUIC_UDP_SENDMMSG
#endif

// Receiving with GRO is only implemented for recvmmsg, and needs UDP_GRO from the system headers.
#if defined(OXEN_LIBQUIC_RECVMMSG) && defined(UDP_GRO)
#define OXEN_LIBQUIC_UDP_GRO
#endif

namespace oxen::quic
{

#ifdef OXEN_LIBQUIC_UDP_GSO
    constexpr bool GSO_SUPPORTED = true;
#else
    constexpr bool GSO_SUPPORTED = false;
#endif

#ifdef OXEN_LIBQUIC_UDP_GRO
    // Each GRO buffer can hold many packets, so a few large slots replace the usual one-packet
    // ones.  8 x 64kB still fits in many CPUs' per-core L2 cache, so a full batch hasn't been
    // evicted by the time we process it.
    constexpr size_t GRO_SLOTS = 8;
    // The kernel never merges more than fits in one IP packet (whose length is 16 bits).
    constexpr size_t GRO_SLOT_SIZE = 64_ki;
#endif

#ifdef _WIN32
    static_assert(std::is_same_v<UDPSocket::socket_t, SOCKET>);
    constexpr int QUIC_IPV4_ECN = IP_ECN;
    constexpr int QUIC_IPV6_ECN = IPV6_ECN;
    constexpr uint8_t QUIC_ECN_MASK = 0xff;
#else
    constexpr uint8_t QUIC_ECN_MASK = IPTOS_ECN_MASK;
    constexpr int QUIC_IPV6_ECN = IPV6_TCLASS;
    constexpr int QUIC_IPV4_ECN =
#if defined(__APPLE__)  // Apple got --><-- this close to getting it right but then got it wrong
            IP_RECVTOS;
#else
            IP_TOS;
#endif
#endif

#ifndef NDEBUG
    // State for UDPSocket's test hooks, kept here rather than in UDPSocket so that the class's
    // layout doesn't depend on the build type.
    namespace
    {
        struct send_failures
        {
            std::deque<int> gso, plain;
        };
        std::mutex debug_send_failures_mutex;
        std::unordered_map<const UDPSocket*, send_failures> debug_send_failures;

        std::mutex debug_gro_merges_mutex;
        std::unordered_map<const UDPSocket*, size_t> debug_gro_merges;

        // Returns the next error queued for a GSO (or non-GSO) send on `sock`, or 0 if none.
        int take_debug_send_failure(const UDPSocket* sock, bool gso)
        {
            std::lock_guard lock{debug_send_failures_mutex};
            auto it = debug_send_failures.find(sock);
            if (it == debug_send_failures.end())
                return 0;
            auto& q = gso ? it->second.gso : it->second.plain;
            if (q.empty())
                return 0;
            int err = q.front();
            q.pop_front();
            return err;
        }
    }  // namespace
#endif

    bool UDPSocket::_debug_fail_sends(
            [[maybe_unused]] std::vector<int> gso_errors, [[maybe_unused]] std::vector<int> plain_errors)
    {
#ifndef NDEBUG
        std::lock_guard lock{debug_send_failures_mutex};
        auto& f = debug_send_failures[this];
        f.gso.insert(f.gso.end(), gso_errors.begin(), gso_errors.end());
        f.plain.insert(f.plain.end(), plain_errors.begin(), plain_errors.end());
        return true;
#else
        return false;
#endif
    }

    std::optional<size_t> UDPSocket::_debug_gro_merges() const
    {
#ifndef NDEBUG
        std::lock_guard lock{debug_gro_merges_mutex};
        auto it = debug_gro_merges.find(this);
        return it == debug_gro_merges.end() ? 0 : it->second;
#else
        return std::nullopt;
#endif
    }

    /// Checks rv for being -1 and, if so, raises a system_error from errno.  Otherwise returns it.
    static int check_rv(int rv, std::string_view action)
    {
        std::optional<std::error_code> ec;
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            ec.emplace(WSAGetLastError(), std::system_category());
#else
        if (rv == -1)
            ec.emplace(errno, std::system_category());

#endif
        if (ec)
        {
            log::error(log_cat, "Got error {} ({}) during {}", ec->value(), ec->message(), action);
            throw std::system_error{*ec};
        }

        return rv;
    }

    // Same as above, but just logs, doesn't throw.
    static void log_rv_error(int rv, std::string_view action)
    {
        std::optional<std::error_code> ec;
#ifdef _WIN32
        if (rv == SOCKET_ERROR)
            ec.emplace(WSAGetLastError(), std::system_category());
#else
        if (rv == -1)
            ec.emplace(errno, std::system_category());

#endif
        if (ec)
            log::error(log_cat, "Got error {} ({}) during {}", ec->value(), ec->message(), action);
    }

    // QUIC packets must not be fragmented (RFC 9000 §14).  With fragmentation, PMTUD can confirm a
    // size that the path only carries in pieces, and a packet too big for the path goes out in
    // fragments rather than being refused with EMSGSIZE.  This is best effort: where an option is
    // unavailable the OS default applies.
    static void set_dont_fragment(UDPSocket::socket_t sock, bool ipv6, bool dual_stack)
    {
        [[maybe_unused]] auto set = [sock](int level, int opt, int value, std::string_view what, bool required) {
#ifdef _WIN32
            const DWORD v = value;
            const auto* p = reinterpret_cast<const char*>(&v);
#else
            const int v = value;
            const auto* p = &v;
#endif
            int rv = setsockopt(sock, level, opt, p, sizeof(v));
            if (rv == 0)
                return;
            if (!required)
                log::debug(log_cat, "Unable to enable {} on a dual-stack socket", what);
            else
            {
#ifdef __APPLE__
                // Only a warning: systems before macOS 11 / iOS 14 don't have IP_DONTFRAG, even
                // when built with an SDK that defines it.
                log::warning(
                        log_cat,
                        "Unable to enable {} ({}); packets may be fragmented",
                        what,
                        std::error_code{errno, std::system_category()}.message());
#else
                log_rv_error(rv, what);
#endif
            }
        };

        // A dual-stack IPv6 socket sends to IPv4(-mapped) addresses under the IPv4 options, which not
        // every OS lets an IPv6 socket set.
        [[maybe_unused]] const bool v4 = !ipv6 || dual_stack;
        [[maybe_unused]] const bool v4_required = !ipv6;
#if defined(_WIN32)
        if (v4)
            set(IPPROTO_IP, IP_DONTFRAGMENT, 1, "IP_DONTFRAGMENT", v4_required);
        if (ipv6)
            set(IPPROTO_IPV6, IPV6_DONTFRAG, 1, "IPV6_DONTFRAG", true);
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
        // PROBE rather than DO: both set DF, but DO also makes sends fail with EMSGSIZE once ICMP
        // (which anyone who can guess the addresses can forge) reports a smaller path MTU, and an
        // EMSGSIZE for an ordinary packet closes the connection.  With PROBE it only reflects the
        // local interface's MTU.
        if (v4)
            set(IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE, "IP_MTU_DISCOVER", v4_required);
        if (ipv6)
            set(IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_PROBE, "IPV6_MTU_DISCOVER", true);
#elif defined(IP_DONTFRAG)
        if (v4)
            set(IPPROTO_IP, IP_DONTFRAG, 1, "IP_DONTFRAG", v4_required);
#ifdef IPV6_DONTFRAG
        if (ipv6)
            set(IPPROTO_IPV6, IPV6_DONTFRAG, 1, "IPV6_DONTFRAG", true);
#endif
#endif
    }

#ifdef _WIN32
    std::mutex get_wsa_mutex;
    LPFN_WSASENDMSG WSASendMsg = nullptr;
    LPFN_WSARECVMSG WSARecvMsg = nullptr;

    static void init_wsa_bs()
    {
        std::lock_guard lock{get_wsa_mutex};
        if (!(WSARecvMsg && WSASendMsg))
        {
            GUID recvmsg_guid = WSAID_WSARECVMSG;
            GUID sendmsg_guid = WSAID_WSASENDMSG;
            SOCKET tmpsock = INVALID_SOCKET;
            DWORD nothing = 0;
            tmpsock = socket(AF_INET, SOCK_DGRAM, 0);
            if (auto rv = WSAIoctl(
                        tmpsock,
                        SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &recvmsg_guid,
                        sizeof(recvmsg_guid),
                        &WSARecvMsg,
                        sizeof(WSARecvMsg),
                        &nothing,
                        nullptr,
                        nullptr);
                rv == SOCKET_ERROR)
            {
                log::critical(log_cat, "WSAIoctl magic BS failed to retrieve magic BS recvmsg wannabe function pointer!");
                throw std::runtime_error{"Unable to initialize windows recvmsg function pointer!"};
            }

            if (auto rv = WSAIoctl(
                        tmpsock,
                        SIO_GET_EXTENSION_FUNCTION_POINTER,
                        &sendmsg_guid,
                        sizeof(sendmsg_guid),
                        &WSASendMsg,
                        sizeof(WSASendMsg),
                        &nothing,
                        nullptr,
                        nullptr);
                rv == SOCKET_ERROR)
            {
                log::critical(log_cat, "WSAIoctl magic BS failed to retrieve magic BS sendmsg-wannabe function pointer!");
                throw std::runtime_error{"Unable to initialize windows sendmsg function pointer!"};
            }
        }
    }
#endif

    // This needs room for every control message we enable on the socket at once: the kernel
    // silently drops whichever ones don't fit (setting MSG_CTRUNC), and Linux delivers pktinfo
    // before the TOS/TCLASS ECN value, so undersizing this loses the ECN value on every packet.
    // (Dual-stack Windows sockets deliver both pktinfo types).
    struct alignas(cmsghdr) recv_cmsg_data
    {
        char ecn[CMSG_SPACE(sizeof(int))];  // a char most places but an int on windows because yay
        char pktinfo4[CMSG_SPACE(sizeof(in_pktinfo))];
        char pktinfo6[CMSG_SPACE(sizeof(in6_pktinfo))];
#ifdef OXEN_LIBQUIC_UDP_GRO
        char gro[CMSG_SPACE(sizeof(int))];
#endif
    };

    struct UDPSocket::receive_batch
    {
#ifdef OXEN_LIBQUIC_RECVMMSG
        receive_batch(size_t slots, size_t slot_size) :
                slot_size{slot_size}, data(slots * slot_size), peers(slots), iovs(slots), msgs(slots), cmsgs(slots)
        {
            for (size_t i = 0; i < slots; i++)
            {
                iovs[i].iov_base = slot(i);
                iovs[i].iov_len = slot_size;
                auto& h = msgs[i].msg_hdr;
                h.msg_iov = &iovs[i];
                h.msg_iovlen = 1;
                h.msg_name = &peers[i];
                h.msg_control = &cmsgs[i];
            }
        }

        const size_t slot_size;
        std::vector<std::byte> data;
        std::vector<sockaddr_in6> peers;
        std::vector<iovec> iovs;
        std::vector<mmsghdr> msgs;
        std::vector<recv_cmsg_data> cmsgs;

        std::byte* slot(size_t i) { return data.data() + i * slot_size; }

        // The kernel overwrites each message's address and control lengths, and its flags, with
        // what the packet it received used, so they need resetting before every call.
        void reset()
        {
            for (size_t i = 0; i < msgs.size(); i++)
            {
                auto& h = msgs[i].msg_hdr;
                h.msg_namelen = sizeof(peers[i]);
                h.msg_controllen = sizeof(cmsgs[i]);
                h.msg_flags = 0;
            }
        }
#endif
    };

    UDPSocket::UDPSocket(event_base* ev_loop, const Address& addr, options opts, receive_callback_t on_receive) :
            gso_{GSO_SUPPORTED && opts.allow_gso}, ev_{ev_loop}, receive_callback_{std::move(on_receive)}
    {
        assert(ev_);

        if (!receive_callback_)
            throw std::logic_error{"UDPSocket construction requires a non-empty receive callback"};

        const int sockopt_proto = addr.is_ipv6() ? IPPROTO_IPV6 : IPPROTO_IP;
        const unsigned int sockopt_on = 1;
        const unsigned int sockopt_off = 0;
        const size_t sockopt_onoff_size = sizeof(sockopt_on);
#ifdef _WIN32
        const auto* sockopt_on_ptr = (const char*)&sockopt_on;
        const auto* sockopt_off_ptr = (const char*)&sockopt_off;
#else
        const auto* sockopt_on_ptr = &sockopt_on;
        const auto* sockopt_off_ptr = &sockopt_off;
#endif

#ifdef _WIN32
        init_wsa_bs();
#endif

        sock_ = check_rv(socket(addr.is_ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM, 0), "socket creation");

        // Enable dual stack mode if appropriate:
        if (addr.is_ipv6())
        {
            const auto* v6only = addr.dual_stack ? sockopt_off_ptr : sockopt_on_ptr;
            check_rv(setsockopt(sock_, IPPROTO_IPV6, IPV6_V6ONLY, v6only, sockopt_onoff_size), "setting v6only flag");
        }

        set_dont_fragment(sock_, addr.is_ipv6(), addr.dual_stack);

        // Enable ECN notification on packets we receive:
#ifndef _WIN32
        check_rv(
                setsockopt(
                        sock_,
                        sockopt_proto,
                        addr.is_ipv6() ? IPV6_RECVTCLASS : IP_RECVTOS,
                        &sockopt_on,
                        sizeof(sockopt_on)),
                "enable ecn");
#else
        // Not supported before Windows 11 (and not in mingw)
        // check_rv(WSASetRecvIPEcn(sock_, 1), "enable ecn");
#endif

#ifdef __APPLE__
        // As usual, macOS is a pile of garbage: it is completely broken when trying to get pktinfo
        // on a dual-stack socket: instead of giving us useful packet info, it either gives us
        // invalid garbage that changes on every packet, or else just doesn't give us anything at
        // all.  Thus we turn this on only for IPv4 sockets; expect proper working OS APIs on macOS
        // is apparently a "you're holding it wrong" problem, so to hell with it: if you're a user
        // and you want it to work you need to upgrade (i.e. switch) to an OS made by someone who
        // realizes that making an OS involves more than deciding on right shade of lipstick to
        // apply to a pig.
        const bool broken_os = addr.is_ipv6();
#else
        constexpr bool broken_os = false;
#endif

        // Enable destination address info in the packet info:
        if (!broken_os)
        {
            check_rv(
                    setsockopt(
                            sock_,
                            sockopt_proto,
                            addr.is_ipv6() ? IPV6_RECVPKTINFO :
#if defined(IP_RECVDSTADDR) && !defined(_WIN32)
                                           IP_RECVDSTADDR,
#else
                                           IP_PKTINFO,
#endif
                            sockopt_on_ptr,
                            sockopt_onoff_size),
                    "enable dest addr info");

#ifdef _WIN32
            // On windows dual stack sockets we have to set IP_PKTINFO in addition to IPV6_PKTINFO
            // to ensure we get dest addr for IPv4-mapped-IPv6 addresses.  (Don't do this under
            // wine, though, because it completely breaks the socket under wine.)
            if (!EMULATING_HELL && addr.is_ipv6() && addr.dual_stack)
                check_rv(
                        setsockopt(sock_, IPPROTO_IP, IP_PKTINFO, sockopt_on_ptr, sockopt_onoff_size),
                        "enable ipv4 dest addr info");
#endif
        }

        // Bind!
        check_rv(bind(sock_, addr, addr.socklen()), "bind");
        check_rv(getsockname(sock_, bound_, bound_.socklen_ptr()), "getsockname");

        // Make the socket non-blocking:
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(sock_, FIONBIO, &mode);
#else
        check_rv(fcntl(sock_, F_SETFL, O_NONBLOCK), "set non-blocking");
#endif

#ifdef OXEN_LIBQUIC_RECVMMSG
        size_t recv_slots = MAX_RECEIVE_PER_LOOP, recv_slot_size = MAX_PMTUD_UDP_PAYLOAD;
#ifdef OXEN_LIBQUIC_UDP_GRO
        if (opts.allow_gro)
        {
            if (setsockopt(sock_, IPPROTO_UDP, UDP_GRO, &sockopt_on, sizeof(sockopt_on)) == 0)
            {
                gro_ = true;
                recv_slots = GRO_SLOTS;
                recv_slot_size = GRO_SLOT_SIZE;
            }
            else
                log::warning(log_cat, "Unable to enable UDP GRO ({}); receiving without it", std::strerror(errno));
        }
#endif
        recv_ = std::make_unique<receive_batch>(recv_slots, recv_slot_size);
#endif

        rev_.reset(event_new(
                ev_,
                sock_,
                EV_READ | EV_PERSIST,
                [](evutil_socket_t, short, void* self) {
#ifndef NDEBUG
                    log_rv_error(
#endif
                            static_cast<UDPSocket*>(self)
                                    ->receive()
#ifndef NDEBUG
                                    .error_code,
                            "udp::receive()")
#endif
                            ;
                },
                this));
        event_add(rev_.get(), nullptr);

        wev_.reset(event_new(
                ev_,
                sock_,
                EV_WRITE,
                [](evutil_socket_t, short, void* self_) {
                    auto* self = static_cast<UDPSocket*>(self_);
                    auto callbacks = std::move(self->writeable_callbacks_);
                    for (const auto& f : callbacks)
                        f();
                },
                this));
        // Don't event_add wev_ now: we only activate wev_ when something asks to be tied to writeability
    }

    UDPSocket::~UDPSocket()
    {
        // Make sure we reset these before continuing with destruction so that we cannot get any
        // packet processing queued on this object during destruction.
        rev_.reset();
        wev_.reset();
#ifdef _WIN32
        ::closesocket(sock_);
#else
        ::close(sock_);
#endif
#ifndef NDEBUG
        {
            std::lock_guard lock{debug_send_failures_mutex};
            debug_send_failures.erase(this);
        }
        std::lock_guard lock{debug_gro_merges_mutex};
        debug_gro_merges.erase(this);
#endif
    }

    std::optional<Address> UDPSocket::local_address_for(const Address& remote) const
    {
        if (!bound_.is_any_addr())
            return bound_;

        // A dual-stack socket reaches IPv4 peers at IPv4-mapped addresses, but not every OS lets an
        // IPv6 socket connect to one (Windows and some BSDs default to IPV6_V6ONLY), so we look up
        // the plain IPv4 address and map the answer back.
        const bool mapped = remote.is_ipv4_mapped_ipv6();
        const auto target = mapped ? remote.unmapped_ipv4_from_ipv6() : remote;

        // Connecting a UDP socket sends nothing, but makes the kernel choose the source address that
        // a send to `target` would use.
        auto sock = ::socket(target.is_ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
#ifdef _WIN32
        if (sock == INVALID_SOCKET)
#else
        if (sock == -1)
#endif
            return std::nullopt;

        std::optional<Address> source;
        auto addr = target.is_ipv6() ? Address{ipv6{}} : Address{ipv4{}};
        if (::connect(sock, target, target.socklen()) == 0 && ::getsockname(sock, addr, addr.socklen_ptr()) == 0)
        {
            if (mapped)
                addr.map_ipv4_as_ipv6();
            addr.set_port(bound_.port());
            source = addr;
        }

#ifdef _WIN32
        ::closesocket(sock);
#else
        ::close(sock);
#endif
        return source;
    }

    size_t UDPSocket::process_received(std::span<const std::byte> data, msghdr& hdr, std::optional<time_point> received)
    {
        if (data.empty())
        {
            // This is unexpected, and not something a proper libquic client would ever send so
            // just drop it.
            log::warning(log_cat, "Dropping empty UDP packet");
            return 0;
        }

        // This flag means the packet payload couldn't fit in max_payload_size, but that should
        // never happen (at least as long as the other end is a proper libquic client).
        if (MSG_TRUNC &
#ifdef _WIN32
            hdr.dwFlags
#else
            hdr.msg_flags
#endif
        )
        {
            log::warning(log_cat, "Dropping truncated UDP packet");
            return 1;
        }

        // The addresses and ECN value apply equally to every packet GRO merged, so the control
        // messages are only parsed once.
        Packet pkt{bound_, data, hdr};
        pkt.received = received;

        // GRO merges packets of the size it reports here, except that the last may be shorter.
        size_t segment = 0;
#ifdef OXEN_LIBQUIC_UDP_GRO
        if (gro_)
            for (auto* cm = CMSG_FIRSTHDR(&hdr); cm; cm = CMSG_NXTHDR(&hdr, cm))
                if (cm->cmsg_level == IPPROTO_UDP && cm->cmsg_type == UDP_GRO)
                {
                    int size;
                    std::memcpy(&size, CMSG_DATA(cm), sizeof(size));
                    segment = static_cast<size_t>(size);
                }
#endif
        if (segment == 0 || data.size() <= segment)
        {
            receive_callback_(std::move(pkt));
            return 1;
        }

        size_t n = 0;
        for (; !data.empty(); n++)
        {
            auto len = std::min(segment, data.size());
            Packet seg{pkt.path, data.first(len)};
            seg.pkt_info = pkt.pkt_info;
            seg.received = received;
            receive_callback_(std::move(seg));
            data = data.subspan(len);
        }
#ifndef NDEBUG
        std::lock_guard lock{debug_gro_merges_mutex};
        debug_gro_merges[this]++;
#endif
        return n;
    }

    io_result UDPSocket::receive()
    {
#ifdef OXEN_LIBQUIC_RECVMMSG
        // Without GRO the batch holds MAX_RECEIVE_PER_LOOP packets, so the first call reaches the
        // limit.  With it, each slot can hold many packets: we keep going while calls fill every
        // slot, so we can end up some way past the limit.
        auto& b = *recv_;
        size_t count = 0;
        do
        {
            b.reset();

            int nread;
            do
            {
                nread = recvmmsg(sock_, b.msgs.data(), b.msgs.size(), 0, nullptr);
            } while (nread == -1 && errno == EINTR);

            if (nread < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return io_result{};
                return io_result{errno};
            }

            auto received = get_time();
            for (int i = 0; i < nread; i++)
                count += process_received(std::span{b.slot(i), b.msgs[i].msg_len}, b.msgs[i].msg_hdr, received);

            if (static_cast<size_t>(nread) < b.msgs.size())
                break;  // The socket is drained
        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};

#else  // no recvmmsg

        sockaddr_storage peer{};
        std::array<std::byte, MAX_PMTUD_UDP_PAYLOAD> data;

        recv_cmsg_data cmsg{};

#ifdef _WIN32
        // Microsoft renames everything but uses the same structure just to be obtuse:
        WSABUF iov;
        iov.buf = reinterpret_cast<char*>(data.data());
        iov.len = data.size();
        WSAMSG hdr{};
        hdr.lpBuffers = &iov;
        hdr.dwBufferCount = 1;
        hdr.name = reinterpret_cast<sockaddr*>(&peer);
        hdr.namelen = sizeof(peer);
        hdr.Control.buf = (char*)&cmsg;
        hdr.Control.len = sizeof(cmsg);
#else
        iovec iov;
        iov.iov_base = data.data();
        iov.iov_len = data.size();
        msghdr hdr{};
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_name = &peer;
        hdr.msg_namelen = sizeof(peer);
        hdr.msg_control = &cmsg;
        hdr.msg_controllen = sizeof(cmsg);
#endif

        size_t count = 0;
        do
        {
#ifdef _WIN32
            DWORD nbytes;
            auto rv = WSARecvMsg(sock_, &hdr, &nbytes, nullptr, nullptr);
            if (rv == SOCKET_ERROR)
            {
                auto error = WSAGetLastError();
                if (error == WSAEWOULDBLOCK)
                    return io_result{};
                return io_result::wsa(error);
            }
#else
            int nbytes;
            do
            {
                nbytes = recvmsg(sock_, &hdr, 0);
            } while (nbytes == -1 && errno == EINTR);

            if (nbytes < 0)
            {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return io_result{};
                return io_result{errno};
            }
#endif

            process_received(std::span{data.data(), static_cast<size_t>(nbytes)}, hdr, std::nullopt);

            count++;

        } while (count < MAX_RECEIVE_PER_LOOP);

        return io_result{};
#endif
    }

    template <typename CM>
    static size_t set_ecn_cmsg(CM* cm, const int ecn, const bool ipv4)
    {
        if (ipv4)
        {
            cm->cmsg_level = IPPROTO_IP;
#ifdef _WIN32
            cm->cmsg_type = IP_ECN;
#else
            cm->cmsg_type = IP_TOS;
#endif
        }
        else
        {
            cm->cmsg_level = IPPROTO_IPV6;
#ifdef _WIN32
            cm->cmsg_type = IPV6_ECN;
#else
            cm->cmsg_type = IPV6_TCLASS;
#endif
        }
        cm->cmsg_len = CMSG_LEN(sizeof(ecn));
        std::memcpy(QUIC_CMSG_DATA(cm), &ecn, sizeof(ecn));
        return CMSG_SPACE(sizeof(ecn));
    }

    std::pair<io_result, size_t> UDPSocket::send(
            const Path& path,
            const std::byte* buf,
            const size_t* bufsize,
            const uint8_t* ecn,
            size_t n_pkts,
            bool pin_source)
    {
        auto* next_buf = const_cast<char*>(reinterpret_cast<const char*>(buf));
        int rv = 0;
        size_t sent = 0;

        const bool set_source_addr = pin_source && bound_.is_any_addr() && !path.local.is_any_addr();

#ifdef _WIN32
        // On Windows, when using a dual-stack socket, IPv4 destinations must always be
        // passed as IPv4-mapped-IPv6
        std::optional<Address> mapped_remote;
        if (bound_.is_ipv6() && path.remote.is_ipv4())
            mapped_remote = path.remote.mapped_ipv4_as_ipv6();
        const auto& remote = mapped_remote ? *mapped_remote : path.remote;
#else
        const auto& remote = path.remote;
#endif

        sockaddr* dest_sa = const_cast<Address&>(remote);

        const bool source_ipv4 = path.local.is_ipv4();
        union
        {
            in_pktinfo v4;
            in6_pktinfo v6;
        } source_addr;
        const size_t source_addrlen = source_ipv4 ? sizeof(in_pktinfo) : sizeof(in6_pktinfo);
        const int source_cmsg_level = source_ipv4 ? IPPROTO_IP : IPPROTO_IPV6;
        const int source_cmsg_type = source_ipv4 ? IP_PKTINFO : IPV6_PKTINFO;
        if (set_source_addr)
        {
            std::memset(&source_addr, 0, sizeof(source_addr));
            if (source_ipv4)
#ifdef _WIN32
                source_addr.v4.ipi_addr
#else
                source_addr.v4.ipi_spec_dst
#endif
                        = path.local.in4().sin_addr;
            else
                source_addr.v6.ipi6_addr = path.local.in6().sin6_addr;
        }

#ifdef OXEN_LIBQUIC_UDP_GSO

        // Set if the GSO send failed in a way that falls back to sending without GSO, below.
        int gso_error = 0;

        if (gso_)
        {

            // With GSO, we use *one* sendmmsg call which can contain multiple batches of packets; each
            // batch is of size n, where each of the n have the same size and ECN value (the ECN cmsg
            // applies to every segment of the batch), except that the last one may be shorter.
            //
            // We could have up to the full MAX_BATCH, with the worst case being every packet being a
            // different size or ECN value than the one before it.
            alignas(cmsghdr) std::array<
                    std::array<
                            char,
                            CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(uint16_t)) + CMSG_SPACE(sizeof(in6_pktinfo))>,
                    DATAGRAM_BATCH_SIZE>
                    controls{};
            std::array<uint16_t, MAX_BATCH> gso_sizes{};   // Size of each of the packets
            std::array<uint16_t, MAX_BATCH> gso_counts{};  // Number of packets

            std::array<mmsghdr, MAX_BATCH> msgs{};
            std::array<iovec, MAX_BATCH> iovs{};

            unsigned int msg_count = 0;
            size_t batch_bytes = 0;
            for (size_t i = 0; i < n_pkts; i++)
            {
                auto& gso_size = gso_sizes[msg_count];
                auto& gso_count = gso_counts[msg_count];
                gso_count++;
                batch_bytes += bufsize[i];
                if (gso_size == 0)
                    gso_size = bufsize[i];  // new batch

                // The next packet can join this batch if it's the same size or, once we have at least
                // two full-size packets, if it's shorter (it then has to be the last one).  Not
                // allowing a short packet after just one means a lone PMTUD probe (always larger than
                // everything else) can never start a batch, which would take the following packet
                // down with it when the kernel rejects the whole oversized message with EINVAL.
                if (i < n_pkts - 1 && bufsize[i] == gso_size && ecn[i + 1] == ecn[i] &&
                    (bufsize[i + 1] == gso_size || (bufsize[i + 1] < gso_size && gso_count >= 2)))
                    continue;

                auto& iov = iovs[msg_count];
                auto& msg = msgs[msg_count];
                auto& control = controls[msg_count];
                iov.iov_base = next_buf;
                iov.iov_len = batch_bytes;
                batch_bytes = 0;
                next_buf += iov.iov_len;
                msg_count++;
                auto& hdr = msg.msg_hdr;
                hdr.msg_iov = &iov;
                hdr.msg_iovlen = 1;
                hdr.msg_name = dest_sa;
                hdr.msg_namelen = remote.socklen();
                hdr.msg_control = control.data();
                hdr.msg_controllen = control.size();

                auto* cm = CMSG_FIRSTHDR(&hdr);
                size_t actual_size = set_ecn_cmsg(cm, ecn[i], source_ipv4);

                if (set_source_addr)
                {
                    cm = CMSG_NXTHDR(&hdr, cm);
                    cm->cmsg_level = source_cmsg_level;
                    cm->cmsg_type = source_cmsg_type;
                    cm->cmsg_len = CMSG_LEN(source_addrlen);
                    std::memcpy(CMSG_DATA(cm), &source_addr, source_addrlen);
                    actual_size += CMSG_SPACE(source_addrlen);
                }

                if (gso_count > 1)
                {
                    cm = CMSG_NXTHDR(&hdr, cm);
                    cm->cmsg_level = SOL_UDP;
                    cm->cmsg_type = UDP_SEGMENT;
                    cm->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                    actual_size += CMSG_SPACE(sizeof(uint16_t));
                    *reinterpret_cast<uint16_t*>(QUIC_CMSG_DATA(cm)) = gso_size;
                }
                hdr.msg_controllen = actual_size;
            }

            do
            {
#ifndef NDEBUG
                if (int err = take_debug_send_failure(this, true))
                {
                    rv = -1;
                    errno = err;
                    break;
                }
#endif
                rv = sendmmsg(sock_, msgs.data(), msg_count, 0);
                log::trace(log_cat, "sendmmsg returned {}", rv);
            } while (rv == -1 && errno == EINTR);

            // Figure out number of packets we actually sent:
            // rv is the number of `msgs` elements that were updated; within each, the `.msg_len` field
            // has been updated to the number of bytes that were sent (which we need to use to figure
            // out how many actual batched packets went out from our batch-of-batches).
#ifndef NDEBUG
            bool found_unsent = false;
#endif
            if (rv >= 0)
            {
                for (unsigned int i = 0; i < msg_count; i++)
                {
                    if (msgs[i].msg_len < iovs[i].iov_len)
                    {
#ifndef NDEBUG
                        // Once we encounter some unsent we expect to miss everything after that (i.e. we
                        // are expecting that contiguous packets 0 through X are accepted and X+1 through
                        // the end were not): so if this batch was partially sent then we shouldn't have
                        // been any partial sends before it.
                        assert(!found_unsent || msgs[i].msg_len == 0);
                        found_unsent = true;
#endif

                        // Partial packets consumed should be impossible:
                        assert(msgs[i].msg_len % gso_sizes[i] == 0);
                        sent += msgs[i].msg_len / gso_sizes[i];
                    }
                    else
                    {
                        assert(!found_unsent);
                        sent += gso_counts[i];
                    }
                }
                return {io_result{}, sent};
            }

            if (errno != EIO && errno != EINVAL)
                return {io_result{errno}, sent};

            // EIO means GSO can't work on this route (e.g. no checksum offload, before Linux 6.11,
            // or an IPsec route).  EINVAL is either that or a batch larger than the path MTU, and
            // resending without GSO tells them apart: the packets then fail one at a time with
            // EMSGSIZE if it was the size.
            gso_error = errno;
            log::debug(log_cat, "UDP GSO send failed ({}); resending without GSO", std::strerror(gso_error));
            next_buf = const_cast<char*>(reinterpret_cast<const char*>(buf));
        }
#endif

#if defined(OXEN_LIBQUIC_UDP_GSO) || defined(OXEN_LIBQUIC_UDP_SENDMMSG)
        // sendmmsg, but either no GSO support, or GSO not enabled at runtime.

        std::array<mmsghdr, MAX_BATCH> msgs{};
        std::array<iovec, MAX_BATCH> iovs{};

        alignas(cmsghdr) std::array<std::array<char, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(in6_pktinfo))>, MAX_BATCH>
                controls{};

        for (size_t i = 0; i < n_pkts; i++)
        {
            assert(bufsize[i] > 0);

            iovs[i].iov_base = next_buf;
            iovs[i].iov_len = bufsize[i];
            next_buf += bufsize[i];

            auto& hdr = msgs[i].msg_hdr;
            hdr.msg_iov = &iovs[i];
            hdr.msg_iovlen = 1;
            hdr.msg_name = dest_sa;
            hdr.msg_namelen = remote.socklen();

            auto& control = controls[i];
            hdr.msg_control = control.data();
            hdr.msg_controllen = control.size();

            auto* cm = CMSG_FIRSTHDR(&hdr);
            size_t actual_size = set_ecn_cmsg(cm, ecn[i], source_ipv4);

            if (set_source_addr)
            {
                cm = CMSG_NXTHDR(&hdr, cm);
                cm->cmsg_level = source_cmsg_level;
                cm->cmsg_type = source_cmsg_type;
                cm->cmsg_len = CMSG_LEN(source_addrlen);
                std::memcpy(CMSG_DATA(cm), &source_addr, source_addrlen);
                actual_size += CMSG_SPACE(source_addrlen);
            }
            hdr.msg_controllen = actual_size;
        }

        do
        {
#ifndef NDEBUG
            if (int err = take_debug_send_failure(this, false))
            {
                rv = -1;
                errno = err;
                break;
            }
#endif
            rv = sendmmsg(sock_, msgs.data(), n_pkts, MSG_DONTWAIT);
        } while (rv == -1 && errno == EINTR);

        sent = rv >= 0 ? rv : 0;

#ifdef OXEN_LIBQUIC_UDP_GSO
        // For EINVAL, GSO was the problem only if this resend went through.
        if (gso_error == EIO || (gso_error == EINVAL && sent == n_pkts))
        {
            int send_errno = errno;
            log::info(log_cat, "UDP GSO send failed ({}); disabling GSO on this socket", std::strerror(gso_error));
            gso_ = false;
            errno = send_errno;
        }
#endif

#else  // No sendmmsg at all, so we just use sendmsg in a loop

#ifdef _WIN32
        // Microsoft renames everything but uses the same structure just to be obtuse:
        WSAMSG hdr{};
        WSABUF iov;
        hdr.lpBuffers = &iov;
        hdr.dwBufferCount = 1;
        hdr.name = dest_sa;
        hdr.namelen = remote.socklen();
#else
        msghdr hdr{};
        iovec iov;
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;
        hdr.msg_name = dest_sa;
        hdr.msg_namelen = remote.socklen();
#endif
        alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(in6_pktinfo))> control{};
#ifdef _WIN32
        hdr.Control.buf = control.data();
        auto& hdr_msg_controllen = hdr.Control.len;
#else
        hdr.msg_control = control.data();
        auto& hdr_msg_controllen = hdr.msg_controllen;
#endif
        const bool ecn_ipv4 = remote.is_ipv4() || remote.is_ipv4_mapped_ipv6();

        for (size_t i = 0; i < n_pkts; ++i)
        {
            assert(bufsize[i] > 0);

            hdr_msg_controllen = control.size();
            auto* cm = CMSG_FIRSTHDR(&hdr);

            size_t actual_size = set_ecn_cmsg(cm, ecn[i], ecn_ipv4);

            if (set_source_addr)
            {
                cm = CMSG_NXTHDR(&hdr, cm);
                cm->cmsg_level = source_cmsg_level;
                cm->cmsg_type = source_cmsg_type;
                cm->cmsg_len = CMSG_LEN(source_addrlen);
                std::memcpy(QUIC_CMSG_DATA(cm), &source_addr, source_addrlen);
                actual_size += CMSG_SPACE(source_addrlen);
            }

            hdr_msg_controllen = actual_size;
#ifdef _WIN32
            iov.buf = next_buf;
            iov.len = bufsize[i];
            next_buf += bufsize[i];

            DWORD bytes_sent;
            rv = WSASendMsg(sock_, &hdr, 0, &bytes_sent, nullptr, nullptr);
            if (rv == SOCKET_ERROR)
                return {io_result::wsa(WSAGetLastError()), sent};
            assert(bytes_sent == bufsize[i]);

#else
            iov.iov_base = next_buf;
            iov.iov_len = bufsize[i];
            next_buf += bufsize[i];

            rv = sendmsg(sock_, &hdr, 0);
            if (rv < 0)
                break;
            assert(static_cast<size_t>(rv) == bufsize[i]);
#endif

            sent++;
        }
#endif

        return {io_result{rv < 0 ? errno : 0}, sent};
    }

    void UDPSocket::when_writeable(std::function<void()> cb)
    {
        writeable_callbacks_.push_back(std::move(cb));
        event_add(wev_.get(), nullptr);
    }

    Packet::Packet(const Address& local, std::span<const std::byte> data, msghdr& hdr) :
            path{local,
#ifdef _WIN32
                 {static_cast<const sockaddr*>(hdr.name), hdr.namelen}
#else
                 {static_cast<const sockaddr*>(hdr.msg_name), hdr.msg_namelen}
#endif
            },
            pkt_data{data}
    {
        assert(path.remote.is_ipv4() || path.remote.is_ipv6());

        for (auto cmsg = CMSG_FIRSTHDR(&hdr); cmsg; cmsg = CMSG_NXTHDR(&hdr, cmsg))
        {
            if (cmsg->cmsg_len == 0)
                continue;

            if (cmsg->cmsg_level == IPPROTO_IP)
            {
                if (cmsg->cmsg_type == QUIC_IPV4_ECN)
                    pkt_info.ecn = *reinterpret_cast<uint8_t*>(QUIC_CMSG_DATA(cmsg)) & QUIC_ECN_MASK;

#if defined(IP_RECVDSTADDR) && !defined(_WIN32)
                if (cmsg->cmsg_type == IP_RECVDSTADDR)
                    path.local.set_addr(reinterpret_cast<const struct in_addr*>(QUIC_CMSG_DATA(cmsg)));
#else
                if (cmsg->cmsg_type == IP_PKTINFO)
                    path.local.set_addr(&reinterpret_cast<const struct in_pktinfo*>(QUIC_CMSG_DATA(cmsg))->ipi_addr);
#endif
            }
            else if (cmsg->cmsg_level == IPPROTO_IPV6)
            {
                if (cmsg->cmsg_type == QUIC_IPV6_ECN)
                {
                    int tclass;
                    std::memcpy(&tclass, QUIC_CMSG_DATA(cmsg), sizeof(int));
                    pkt_info.ecn = static_cast<uint8_t>(tclass & QUIC_ECN_MASK);
                }

                if (cmsg->cmsg_type == IPV6_PKTINFO)
                    path.local.set_addr(&reinterpret_cast<const struct in6_pktinfo*>(QUIC_CMSG_DATA(cmsg))->ipi6_addr);
            }
        }
        log::trace(log_cat, "incoming packet path is {}", path);
    }

    void Packet::ensure_owned_data()
    {
        if (auto* data_sp = std::get_if<std::span<const std::byte>>(&pkt_data))
            pkt_data = std::vector(data_sp->begin(), data_sp->end());
    }

}  // namespace oxen::quic
