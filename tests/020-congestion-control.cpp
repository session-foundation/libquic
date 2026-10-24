#include "unit_test.hpp"

#include <mutex>

namespace oxen::quic::test
{
    TEST_CASE("020 - Connections transfer data with each congestion control algorithm", "[020][cc]")
    {
        const auto cc =
                GENERATE(opt::congestion_control::bbr, opt::congestion_control::cubic, opt::congestion_control::reno);

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

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb, cc));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        auto conn = client_endpoint->connect(server_remote, client_tls, cc);
        REQUIRE(client_established.wait());

        conn->open_stream()->send(msg, nullptr);

        require_future(all_received.get_future(), 5s);
        std::lock_guard lock{received_mut};
        CHECK(bytes_diff(received, msg) == "");
    }

}  // namespace oxen::quic::test
