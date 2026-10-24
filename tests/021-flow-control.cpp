#include "unit_test.hpp"

#include <ngtcp2/ngtcp2.h>

#include <mutex>
#include <tuple>

namespace oxen::quic::test
{
    TEST_CASE("021 - Connections advertise the configured initial flow control windows", "[021][flowcontrol]")
    {
        // The windows the server is configured with, and the initial ones it should advertise.
        auto [fc, conn_window, stream_window] = GENERATE(
                std::tuple<opt::flow_control, uint64_t, uint64_t>{
                        opt::flow_control{}, DEFAULT_INITIAL_CONN_WINDOW, DEFAULT_INITIAL_STREAM_WINDOW},
                std::tuple<opt::flow_control, uint64_t, uint64_t>{
                        opt::flow_control{.initial_conn_window = 64_Mi}, 64_Mi, DEFAULT_INITIAL_STREAM_WINDOW},
                std::tuple<opt::flow_control, uint64_t, uint64_t>{
                        opt::flow_control{.initial_conn_window = 32_ki, .initial_stream_window = 8_ki}, 32_ki, 8_ki});

        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, fc));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        auto params = client_endpoint->loop.call_get([&] { return *ngtcp2_conn_get_remote_transport_params(*conn); });
        CHECK(params.initial_max_data == conn_window);
        CHECK(params.initial_max_stream_data_bidi_local == stream_window);
        CHECK(params.initial_max_stream_data_bidi_remote == stream_window);
        CHECK(params.initial_max_stream_data_uni == stream_window);
    }

    TEST_CASE("021 - Transfers complete with any flow control windows", "[021][flowcontrol]")
    {
        const auto fc = GENERATE(
                // Small, and never auto-tuned upwards
                opt::flow_control{
                        .initial_conn_window = 64_ki,
                        .max_conn_window = 0,
                        .initial_stream_window = 16_ki,
                        .max_stream_window = 0},
                // Small, but auto-tuned up to the default maximums
                opt::flow_control{.initial_conn_window = 64_ki, .initial_stream_window = 16_ki},
                // Larger than the defaults
                opt::flow_control{
                        .initial_conn_window = 64_Mi,
                        .max_conn_window = 128_Mi,
                        .initial_stream_window = 32_Mi,
                        .max_stream_window = 64_Mi},
                // Initial windows above their maximums, which stay at their initial sizes
                opt::flow_control{
                        .initial_conn_window = 32_Mi,
                        .max_conn_window = 1_Mi,
                        .initial_stream_window = 8_Mi,
                        .max_stream_window = 1_Mi});

        Network test_net{};

        std::string msg(2_Mi, '\0');
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
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb, fc));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        auto conn = client_endpoint->connect(server_remote, client_tls, fc);
        REQUIRE(client_established.wait());

        conn->open_stream()->send(msg, nullptr);

        require_future(all_received.get_future(), 10s);
        std::lock_guard lock{received_mut};
        CHECK(bytes_diff(received, msg) == "");
    }

    TEST_CASE("021 - Invalid flow control windows are rejected", "[021][flowcontrol]")
    {
        const auto fc = GENERATE(
                opt::flow_control{.initial_conn_window = 0},
                opt::flow_control{.initial_stream_window = 0},
                opt::flow_control{.max_conn_window = uint64_t{1} << 62},
                opt::flow_control{.initial_stream_window = uint64_t{1} << 62});

        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        CHECK_THROWS_AS(server_endpoint->listen(server_tls, fc), std::invalid_argument);

        auto client_endpoint = test_net.endpoint(Address{});
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};
        CHECK_THROWS_AS(client_endpoint->connect(server_remote, client_tls, fc), std::invalid_argument);
    }

}  // namespace oxen::quic::test
