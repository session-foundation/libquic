extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif
}

#include "unit_test.hpp"

#include <unordered_map>

namespace oxen::quic::test
{
    namespace
    {
        // A plain IPv4 UDP socket bound to 0.0.0.0, standing in for some other process's socket.
        struct ipv4_wildcard_socket
        {
            UDPSocket::socket_t fd;
            uint16_t port;

            explicit ipv4_wildcard_socket(uint16_t want_port = 0)
            {
                fd = socket(AF_INET, SOCK_DGRAM, 0);
                REQUIRE(fd != static_cast<UDPSocket::socket_t>(-1));
                sockaddr_in sin{};
                sin.sin_family = AF_INET;
                sin.sin_addr.s_addr = htonl(INADDR_ANY);
                sin.sin_port = htons(want_port);
                REQUIRE(bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == 0);
#ifdef _WIN32
                int len = sizeof(sin);
#else
                socklen_t len = sizeof(sin);
#endif
                REQUIRE(getsockname(fd, reinterpret_cast<sockaddr*>(&sin), &len) == 0);
                port = ntohs(sin.sin_port);
            }

            ipv4_wildcard_socket(const ipv4_wildcard_socket&) = delete;
            ipv4_wildcard_socket& operator=(const ipv4_wildcard_socket&) = delete;

            ~ipv4_wildcard_socket()
            {
#ifdef _WIN32
                closesocket(fd);
#else
                close(fd);
#endif
            }
        };
    }  // namespace

    // A dual-stack socket sharing a port with an IPv4 socket would have the port's IPv4 traffic
    // delivered to the other socket instead (macOS allows exactly this unless we prevent it).

    TEST_CASE("023 - Dual-stack bind refuses a port held by an IPv4 wildcard socket", "[023][dualstack][bind]")
    {
        Loop loop;
        ipv4_wildcard_socket other;

        CHECK_THROWS(Endpoint::endpoint(loop, Address{other.port}));
    }

    TEST_CASE("023 - Dual-stack ephemeral bind avoids ports held by IPv4 wildcard sockets", "[023][dualstack][bind]")
    {
        Loop loop;

        // Kept well below macOS's default limit of 256 open files.
        std::unordered_map<uint16_t, std::unique_ptr<ipv4_wildcard_socket>> held;
        while (held.size() < 100)
        {
            auto s = std::make_unique<ipv4_wildcard_socket>();
            held.emplace(s->port, std::move(s));
        }

        // With ~16k ephemeral ports on macOS, an unprotected dual-stack bind would land on one of the
        // held ports about 6 times in this many attempts.
        int collisions = 0;
        for (int i = 0; i < 1000; i++)
        {
            auto ep = Endpoint::endpoint(loop, Address{});
            if (held.count(ep->local().port()))
                collisions++;
        }
        CHECK(collisions == 0);
    }

}  // namespace oxen::quic::test
