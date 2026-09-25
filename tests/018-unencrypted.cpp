#include "oxen/quic/unencrypted.hpp"
#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("018 - Unencrypted: handshake and stream data", "[018][unencrypted]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};
        auto server_established = callback_waiter{[](Connection&) {}};

        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            REQUIRE(view(dat) == good_msg);
            d_promise.set_value(true);
        };

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;

        Address server_local{};
        Address client_local{};

        opt::manual_routing client_sender{[&](const Path& p, std::span<const std::byte> d) {
            server_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        opt::manual_routing server_sender{[&](const Path& p, std::span<const std::byte> d) {
            client_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        auto creds = DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted();

        server_endpoint = test_net.endpoint(server_local, server_sender, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(creds, server_data_cb));

        // No pubkey to verify: an unencrypted connection authenticates nothing.
        RemoteAddress client_remote{""sv, server_local};

        client_endpoint = test_net.endpoint(client_local, client_sender, client_established);

        auto conn_interface = client_endpoint->connect(client_remote, creds);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto client_stream = conn_interface->open_stream();
        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));

        require_future(d_future);
    }

    TEST_CASE("018 - Unencrypted: bulk stream data", "[018][unencrypted][bulk]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};
        auto server_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        // Enough to need many packets, so that packet number encoding, ack handling and the
        // zero-overhead AEAD all get exercised beyond the handshake.
        constexpr size_t total = 2'000'000;
        std::string payload(total, 'x');
        for (size_t i = 0; i < total; i++)
            payload[i] = static_cast<char>('a' + (i % 26));

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();
        std::string received;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            received.append(reinterpret_cast<const char*>(dat.data()), dat.size());
            if (received.size() >= total)
                d_promise.set_value(received == payload);
        };

        std::shared_ptr<Endpoint> client_endpoint, server_endpoint;

        Address server_local{};
        Address client_local{};

        opt::manual_routing client_sender{[&](const Path& p, std::span<const std::byte> d) {
            server_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        opt::manual_routing server_sender{[&](const Path& p, std::span<const std::byte> d) {
            client_endpoint->manually_receive_packet(Packet{p.invert(), d});
        }};

        auto creds = DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted();

        server_endpoint = test_net.endpoint(server_local, server_sender, server_established);
        REQUIRE_NOTHROW(server_endpoint->listen(creds, server_data_cb));

        RemoteAddress client_remote{""sv, server_local};
        client_endpoint = test_net.endpoint(client_local, client_sender, client_established);

        auto conn_interface = client_endpoint->connect(client_remote, creds);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto client_stream = conn_interface->open_stream();
        REQUIRE_NOTHROW(client_stream->send(std::string{payload}));

        require_future(d_future, 30s);
        CHECK(bytes_diff(received, payload) == "");
    }

    // Checks the actual claim rather than a side effect of it: that stream data appears verbatim in
    // the packets handed to the sender.  The same exchange over ordinary credentials is used as a
    // control, since a search that finds nothing proves little on its own.
    TEST_CASE("018 - Unencrypted: packets really are plaintext", "[018][unencrypted][plaintext]")
    {
        constexpr auto canary = "PLAINTEXT-CANARY-9f3ab2c1"sv;

        auto run = [&](bool unencrypted) {
            auto client_established = callback_waiter{[](Connection&) {}};
            auto server_established = callback_waiter{[](Connection&) {}};

            Network test_net{};

            std::promise<bool> d_promise;
            std::future<bool> d_future = d_promise.get_future();

            stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte>) { d_promise.set_value(true); };

            std::shared_ptr<Endpoint> client_endpoint, server_endpoint;
            Address server_local{}, client_local{};

            bool found_on_wire = false;
            auto scan = [&](std::span<const std::byte> d) {
                std::string_view raw{reinterpret_cast<const char*>(d.data()), d.size()};
                if (raw.find(canary) != std::string_view::npos)
                    found_on_wire = true;
            };

            opt::manual_routing client_sender{[&](const Path& p, std::span<const std::byte> d) {
                scan(d);
                server_endpoint->manually_receive_packet(Packet{p.invert(), d});
            }};
            opt::manual_routing server_sender{[&](const Path& p, std::span<const std::byte> d) {
                client_endpoint->manually_receive_packet(Packet{p.invert(), d});
            }};

            std::shared_ptr<TLSCreds> client_creds, server_creds;
            std::string server_pubkey;
            if (unencrypted)
            {
                client_creds = server_creds = DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted();
            }
            else
            {
                auto [c, s] = defaults::tls_creds_from_ed_keys();
                client_creds = c;
                server_creds = s;
                server_pubkey = std::string{defaults::SERVER_PUBKEY};
            }

            server_endpoint = test_net.endpoint(server_local, server_sender, server_established);
            REQUIRE_NOTHROW(server_endpoint->listen(server_creds, server_data_cb));

            RemoteAddress client_remote{server_pubkey, server_local};
            client_endpoint = test_net.endpoint(client_local, client_sender, client_established);

            auto conn_interface = client_endpoint->connect(client_remote, client_creds);

            CHECK(client_established.wait());
            CHECK(server_established.wait());

            auto client_stream = conn_interface->open_stream();
            REQUIRE_NOTHROW(client_stream->send(std::string{canary}));

            require_future(d_future);
            return found_on_wire;
        };

        CHECK(run(true));    // unencrypted: the canary is right there on the wire
        CHECK(!run(false));  // encrypted control: it is not
    }

}  // namespace oxen::quic::test
