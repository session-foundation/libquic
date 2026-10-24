extern "C"
{
#ifdef _WIN32
#include <winsock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif
}

#include "unit_test.hpp"

#include <oxen/log/formatted_callback_sink.hpp>

#include <limits>
#include <mutex>

namespace oxen::quic::test
{
    namespace
    {
        constexpr size_t huge = std::numeric_limits<size_t>::max();

        int buffer_size(UDPSocket::socket_t sock, int optname)
        {
            int v = 0;
#ifdef _WIN32
            int len = sizeof(v);
            REQUIRE(getsockopt(sock, SOL_SOCKET, optname, reinterpret_cast<char*>(&v), &len) == 0);
#else
            socklen_t len = sizeof(v);
            REQUIRE(getsockopt(sock, SOL_SOCKET, optname, &v, &len) == 0);
#endif
            return v;
        }

        // The buffer size a fresh UDP socket of the endpoint's address family gets from the OS.
        int os_default_buffer_size(const Endpoint& ep, int optname)
        {
            auto sock = socket(ep.local().is_ipv6() ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
            int size = buffer_size(sock, optname);
#ifdef _WIN32
            closesocket(sock);
#else
            close(sock);
#endif
            return size;
        }

        // The buffer size a socket should end up with after the application requests `size`.
        // Outside Linux, this is only right for sizes within the OS's limit.
        int64_t expected_buffer_size(int optname, int64_t size)
        {
#ifdef __linux__
            // Linux caps a request at net.core.rmem_max/wmem_max and then doubles it, so asking a
            // fresh socket for as much as it can get reveals the cap.  (Containers don't always
            // let us read those sysctls from /proc.)
            auto sock = socket(AF_INET, SOCK_DGRAM, 0);
            int most = std::numeric_limits<int>::max();
            REQUIRE(setsockopt(sock, SOL_SOCKET, optname, &most, sizeof(most)) == 0);
            int64_t limit = buffer_size(sock, optname) / 2;
            close(sock);
            size = std::min(size, limit) * 2;
#else
            (void)optname;
#endif
            return size;
        }

        // Checks the receive buffer that libquic's default request gives, which never shrinks the
        // OS default; outside Linux we can't know the OS's limit, so only that it wasn't shrunk.
        void check_default_recv_buffer(Endpoint& ep)
        {
            auto size = buffer_size(TestHelper::get_sock(ep), SO_RCVBUF);
#ifdef __linux__
            auto requested = expected_buffer_size(SO_RCVBUF, DEFAULT_SOCKET_RECV_BUFFER);
            CHECK(size == std::max<int64_t>(requested, os_default_buffer_size(ep, SO_RCVBUF)));
#else
            CHECK(size >= os_default_buffer_size(ep, SO_RCVBUF));
#endif
        }

        // Counts libquic's socket buffer warnings while alive.  Not every oxen-logging version can
        // remove a sink, so a single sink, added on first use, feeds whichever one is current.
        struct buffer_warnings
        {
            inline static std::mutex mutex;
            inline static buffer_warnings* current = nullptr;

            log_level_lowerer level{log::Level::warn};
            size_t warnings = 0;  // Guarded by `mutex`

            static void on_log(std::string_view msg, std::string_view cat, log::Level lvl)
            {
                if (cat != "quic" || lvl < log::Level::warn || msg.find("UDP socket") == msg.npos ||
                    msg.find(" buffer ") == msg.npos)
                    return;
                std::lock_guard lock{mutex};
                if (current)
                    current->warnings++;
            }

            buffer_warnings()
            {
                [[maybe_unused]] static const bool sink_added =
                        (log::add_sink(std::make_shared<log::formatted_callback_sink>(on_log)), true);
                std::lock_guard lock{mutex};
                current = this;
            }

            ~buffer_warnings()
            {
                std::lock_guard lock{mutex};
                current = nullptr;
            }

            size_t count()
            {
                std::lock_guard lock{mutex};
                return warnings;
            }
        };
    }  // namespace

    TEST_CASE("019 - Endpoint socket buffer sizes", "[019][sockbuf]")
    {
        Network test_net{};

        SECTION("Small enough to be within every OS's limits")
        {
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.recv = 64_ki, .send = 32_ki});
            auto sock = TestHelper::get_sock(*ep);

            CHECK(buffer_size(sock, SO_RCVBUF) == expected_buffer_size(SO_RCVBUF, 64_ki));
            CHECK(buffer_size(sock, SO_SNDBUF) == expected_buffer_size(SO_SNDBUF, 32_ki));
        }

        SECTION("Sizes smaller than the OS defaults shrink the buffers")
        {
            // macOS's default UDP send buffer is only 9kiB.
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.recv = 4_ki, .send = 4_ki});
            auto sock = TestHelper::get_sock(*ep);

            CHECK(buffer_size(sock, SO_RCVBUF) == expected_buffer_size(SO_RCVBUF, 4_ki));
            CHECK(buffer_size(sock, SO_SNDBUF) == expected_buffer_size(SO_SNDBUF, 4_ki));
            CHECK(buffer_size(sock, SO_RCVBUF) < os_default_buffer_size(*ep, SO_RCVBUF));
            CHECK(buffer_size(sock, SO_SNDBUF) < os_default_buffer_size(*ep, SO_SNDBUF));
        }

        SECTION("0 leaves the OS defaults")
        {
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.recv = 0, .send = 0});
            auto sock = TestHelper::get_sock(*ep);

            CHECK(buffer_size(sock, SO_RCVBUF) == os_default_buffer_size(*ep, SO_RCVBUF));
            CHECK(buffer_size(sock, SO_SNDBUF) == os_default_buffer_size(*ep, SO_SNDBUF));
        }

        SECTION("libquic's defaults")
        {
            auto ep = test_net.endpoint(Address{});

            check_default_recv_buffer(*ep);
            CHECK(buffer_size(TestHelper::get_sock(*ep), SO_SNDBUF) == os_default_buffer_size(*ep, SO_SNDBUF));
        }

        SECTION("Only the receive size given")
        {
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.recv = 64_ki});
            auto sock = TestHelper::get_sock(*ep);

            CHECK(buffer_size(sock, SO_RCVBUF) == expected_buffer_size(SO_RCVBUF, 64_ki));
            CHECK(buffer_size(sock, SO_SNDBUF) == os_default_buffer_size(*ep, SO_SNDBUF));
        }

        SECTION("Only the send size given")
        {
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.send = 32_ki});

            check_default_recv_buffer(*ep);
            CHECK(buffer_size(TestHelper::get_sock(*ep), SO_SNDBUF) == expected_buffer_size(SO_SNDBUF, 32_ki));
        }
    }

    TEST_CASE("019 - Only socket buffer sizes the application gives warn when they fall short", "[019][sockbuf]")
    {
        Network test_net{};
        buffer_warnings warnings;

        SECTION("libquic's defaults")
        {
            auto ep = test_net.endpoint(Address{});
            CHECK(warnings.count() == 0);
        }

        // Windows has no limit to exceed.
#ifndef _WIN32
        SECTION("Sizes beyond the OS's limits")
        {
            auto ep = test_net.endpoint(Address{}, opt::socket_buffers{.recv = huge, .send = huge});
            CHECK(warnings.count() == 2);
        }
#endif
    }

    TEST_CASE("019 - Endpoints with any socket buffer sizes connect and transfer data", "[019][sockbuf]")
    {
        // The last is far beyond any OS limit, and gets capped (or stepped down) rather than failing.
        const auto buffers = GENERATE(
                opt::socket_buffers{},
                opt::socket_buffers{.recv = 0, .send = 0},
                opt::socket_buffers{.recv = 64_ki, .send = 32_ki},
                opt::socket_buffers{.recv = 4_Mi, .send = 1_Mi},
                opt::socket_buffers{.recv = huge, .send = huge});

        Network test_net{};

        std::string msg(1_Mi, '\0');
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<char>(i * 7 + i / 251);

        std::mutex received_mut;
        std::string received;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            received += view(dat);
            if (received.size() == msg.size())
                all_received.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::shared_ptr<Endpoint> server_endpoint, client_endpoint;
        REQUIRE_NOTHROW(server_endpoint = test_net.endpoint(Address{}, buffers));
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        REQUIRE_NOTHROW(client_endpoint = test_net.endpoint(Address{}, buffers, client_established));
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        conn->open_stream()->send(msg, nullptr);

        require_future(all_received.get_future(), 5s);
        std::lock_guard lock{received_mut};
        CHECK(bytes_diff(received, msg) == "");
    }

}  // namespace oxen::quic::test
