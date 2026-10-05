#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("010 - Migration", "[010][migration]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{}, client_secondary{}, client_local_b{};

        std::promise<void> d_promise;
        std::promise<void> conn_promise_a, conn_promise_b, conn_promise_c;

        auto d_future = d_promise.get_future();
        auto conn_future_a = conn_promise_a.get_future();
        auto conn_future_b = conn_promise_b.get_future();
        auto conn_future_c = conn_promise_c.get_future();

        std::atomic<bool> address_flipped = false, secondary_connected = false;

        std::shared_ptr<Endpoint> client_endpoint;
        std::shared_ptr<Connection> server_ci;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(view(dat) == good_msg);
            d_promise.set_value();
        };

        auto server_established = callback_waiter{[](Connection&) {}};
        auto client_established_b = callback_waiter{[](Connection&) { log::trace(test_cat, "LOOK ME UP BRO"); }};

        auto server_endpoint = test_net.endpoint(server_local, server_established);
        server_endpoint->listen(server_tls, server_data_cb);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_established = [&](Connection& ci) mutable {
            if (not address_flipped)
            {
                auto& conn = static_cast<Connection&>(ci);

                SECTION("NAT Rebinding")
                {
                    TestHelper::nat_rebinding(conn, client_secondary);
                }

                SECTION("Migration")
                {
                    TestHelper::migrate_connection(conn, client_secondary);
                }

                // Uncomment this when NGTCP2 releases v1.2.0
                SECTION("Immediate migration")
                {
                    TestHelper::migrate_connection_immediate(conn, client_secondary);
                }

                address_flipped = true;
                conn_promise_a.set_value();
            }
            else
            {
                if (not secondary_connected)
                {
                    log::trace(test_cat, "Skipping address flip!");
                    secondary_connected = true;
                    conn_promise_b.set_value();
                }
                else
                {
                    conn_promise_c.set_value();
                }
            }
        };

        client_endpoint = test_net.endpoint(client_local, client_established);
        auto original_addr = client_endpoint->local();
        client_endpoint->listen(client_tls);

        auto client_ci = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(server_established.wait());
        require_future(conn_future_a);

        auto client_stream = client_ci->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));
        require_future(d_future);

        server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        std::this_thread::sleep_for(5ms);
        RemoteAddress client_remote_b{defaults::CLIENT_PUBKEY, LOCALHOST, client_ci->local().port()};

        REQUIRE_FALSE(original_addr == client_ci->local());

        auto client_endpoint_b = test_net.endpoint(client_local_b, client_established_b);
        auto client_ci_b = client_endpoint_b->connect(client_remote_b, client_tls);

        require_future(conn_future_b);
        CHECK(client_established_b.wait());
    }

    TEST_CASE("010 - A change of the host's source address migrates the connection", "[010][migration][network]")
    {
        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::mutex received_mutex;
        std::string received;
        std::condition_variable received_cv;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mutex};
            received += view(dat);
            received_cv.notify_all();
        };
        auto wait_for_received = [&](std::string_view expected) {
            std::unique_lock lock{received_mutex};
            return received_cv.wait_for(lock, 5s, [&] { return received.ends_with(expected); });
        };

        auto server_endpoint = test_net.endpoint(Address{"127.0.0.1", 0});
        server_endpoint->listen(server_tls, server_data_cb);
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1", server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{ipv4{}}, client_established);
        if (!TestHelper::simulate_local_address(*client_endpoint, std::nullopt))
            SKIP("Simulating a change of the host's address requires a debug build of libquic");
        const auto port = client_endpoint->local().port();

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());
        CHECK(conn->local() == Address{"127.0.0.1", port});

        auto stream = conn->open_stream();
        stream->send("one"s);
        REQUIRE(wait_for_received("one"));
        // Let the server's acknowledgement arrive, so that nothing is in flight.
        std::this_thread::sleep_for(200ms);

        // The host moves to a different network.
        const Address new_local{"127.0.0.2", port};
        REQUIRE(TestHelper::simulate_local_address(*client_endpoint, new_local));

        SECTION("Noticed when a packet arrives on the new address")
        {
            // The server's acknowledgement of "two" arrives on the new address.
            stream->send("two"s);
            REQUIRE(wait_for_received("two"));
        }
        SECTION("Told by the application, before any packet arrives")
        {
            client_endpoint->network_changed();
        }
        SECTION("Once a later packet arrives, when there was no spare connection ID")
        {
            // Both the attempt when the server's acknowledgement first arrives on the new address,
            // and the retry once it has been read, find no spare connection ID.
            REQUIRE(TestHelper::block_migrations(*client_endpoint, 2));
            const auto lookups = TestHelper::route_lookups(*client_endpoint);
            stream->send("two"s);
            REQUIRE(wait_for_received("two"));
            std::this_thread::sleep_for(100ms);
            CHECK(conn->local() != new_local);

            // The acknowledgement of this one completes the migration, without looking up the
            // route again.
            stream->send("two again"s);
            REQUIRE(wait_for_received("two again"));
            for (int i = 0; i < 100 && conn->local() != new_local; i++)
                std::this_thread::sleep_for(10ms);
            CHECK(TestHelper::route_lookups(*client_endpoint) == lookups + 1);
        }

        for (int i = 0; i < 100 && conn->local() != new_local; i++)
            std::this_thread::sleep_for(10ms);
        CHECK(conn->local() == new_local);
        auto ngtcp2_local = TestHelper::ngtcp2_path_local(*conn);
        INFO("ngtcp2 path local: " << ngtcp2_local.to_string());
        CHECK(ngtcp2_local == new_local);

        stream->send("three"s);
        CHECK(wait_for_received("three"));
    }

    TEST_CASE(
            "010 - Packets arriving on another local address don't migrate the connection if the source is unchanged",
            "[010][migration][network]")
    {
        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::mutex received_mutex;
        std::string received;
        std::condition_variable received_cv;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mutex};
            received += view(dat);
            received_cv.notify_all();
        };
        auto wait_for_received = [&](std::string_view expected) {
            std::unique_lock lock{received_mutex};
            return received_cv.wait_for(lock, 5s, [&] { return received.ends_with(expected); });
        };

        auto server_endpoint = test_net.endpoint(Address{"127.0.0.1", 0});
        server_endpoint->listen(server_tls, server_data_cb);
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1", server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{ipv4{}}, client_established);
        if (!TestHelper::simulate_arrival_address(*client_endpoint, std::nullopt))
            SKIP("Simulating the address packets arrive on requires a debug build of libquic");
        const auto port = client_endpoint->local().port();

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());
        const auto original_local = conn->local();
        REQUIRE(original_local == Address{"127.0.0.1", port});

        auto stream = conn->open_stream();
        stream->send("one"s);
        REQUIRE(wait_for_received("one"));
        std::this_thread::sleep_for(200ms);

        // Replies start arriving on another of the host's addresses while it still sends from the
        // original one, as with asymmetric routing on a multi-homed host.
        REQUIRE(TestHelper::simulate_arrival_address(*client_endpoint, Address{"127.0.0.2", port}));
        const auto lookups = TestHelper::route_lookups(*client_endpoint);

        // Each is acknowledged, so several packets arrive on the other address.
        for (auto msg : {"two"s, "three"s, "four"s})
        {
            stream->send(std::string{msg});
            REQUIRE(wait_for_received(msg));
            std::this_thread::sleep_for(100ms);
        }

        CHECK(conn->local() == original_local);
        CHECK(TestHelper::ngtcp2_path_local(*conn) == original_local);
        // Only the first packet to arrive there makes the connection look up its route.
        CHECK(TestHelper::route_lookups(*client_endpoint) == lookups + 1);

        REQUIRE(TestHelper::simulate_arrival_address(*client_endpoint, std::nullopt));
        stream->send("five"s);
        CHECK(wait_for_received("five"));
    }

    TEST_CASE(
            "010 - A client migrates after the server has followed its change of source address",
            "[010][migration][network]")
    {
#ifndef __linux__
        SKIP("Sending from another loopback address needs Linux, where all of 127/8 is local");
#endif
        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::mutex received_mutex;
        std::string received;
        std::condition_variable received_cv;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mutex};
            received += view(dat);
            received_cv.notify_all();
        };
        auto wait_for_received = [&](std::string_view expected) {
            std::unique_lock lock{received_mutex};
            return received_cv.wait_for(lock, 5s, [&] { return received.ends_with(expected); });
        };

        auto server_endpoint = test_net.endpoint(Address{"127.0.0.1", 0});
        server_endpoint->listen(server_tls, server_data_cb);
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1", server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{ipv4{}}, client_established);
        if (!TestHelper::switch_source_address(*client_endpoint, std::nullopt))
            SKIP("Switching the host's source address requires a debug build of libquic");
        const auto port = client_endpoint->local().port();

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        auto stream = conn->open_stream();
        stream->send("one"s);
        REQUIRE(wait_for_received("one"));
        std::this_thread::sleep_for(200ms);
        auto server_conn = server_endpoint->get_all_conns(Direction::INBOUND).front();
        REQUIRE(TestHelper::ngtcp2_path_remote(*server_conn) == Address{"127.0.0.1", port});

        // The kernel starts sending from a new address before anything tells the client, so the
        // server sees the client's packets, with the connection ID it already knows, arrive from
        // somewhere new and follows them there; its replies then arrive on the new address.
        const Address new_local{"127.0.0.2", port};
        REQUIRE(TestHelper::switch_source_address(*client_endpoint, new_local));
        stream->send("two"s);
        REQUIRE(wait_for_received("two"));

        for (int i = 0; i < 100 && conn->local() != new_local; i++)
            std::this_thread::sleep_for(10ms);
        CHECK(conn->local() == new_local);
        CHECK(TestHelper::ngtcp2_path_local(*conn) == new_local);
        CHECK(TestHelper::ngtcp2_path_remote(*server_conn) == new_local);

        SECTION("The application reporting the change afterwards changes nothing")
        {
            client_endpoint->network_changed();
            std::this_thread::sleep_for(50ms);
            CHECK(conn->local() == new_local);
            CHECK(TestHelper::ngtcp2_path_local(*conn) == new_local);
        }

        stream->send("three"s);
        CHECK(wait_for_received("three"));
    }

    TEST_CASE(
            "010 - A packet refused as too big after a change of the host's source address migrates the connection",
            "[010][migration][network][pmtud]")
    {
        // Declared before the Network, which closes the connection (calling this) as it shuts down.
        std::promise<uint64_t> client_closed;
        std::atomic<bool> closed_once{false};
        connection_closed_callback on_client_closed = [&](Connection&, uint64_t ec) {
            if (!closed_once.exchange(true))
                client_closed.set_value(ec);
        };

        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        constexpr size_t msg_size = 100'000;
        std::promise<void> all_received;
        size_t received = 0;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            received += dat.size();
            if (received == msg_size)
                all_received.set_value();
        };

        auto server_endpoint = test_net.endpoint(Address{"127.0.0.1", 0});
        server_endpoint->listen(server_tls, server_data_cb);
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, "127.0.0.1", server_endpoint->local().port()};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_endpoint = test_net.endpoint(Address{ipv4{}}, client_established, on_client_closed);
        if (!TestHelper::simulate_local_address(*client_endpoint, std::nullopt))
            SKIP("Simulating a change of the host's address requires a debug build of libquic");
        const auto port = client_endpoint->local().port();

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());
        for (int i = 0; i < 50 && TestHelper::path_max_udp_payload(*conn) < MAX_PMTUD_UDP_PAYLOAD; i++)
            std::this_thread::sleep_for(20ms);
        REQUIRE(TestHelper::path_max_udp_payload(*conn) == MAX_PMTUD_UDP_PAYLOAD);
        // Let the last acknowledgements arrive, so that the first sign of the change is the refusal
        // rather than a packet arriving on the new address.
        std::this_thread::sleep_for(200ms);

        // The host moves to a network whose path refuses packets above 1400 bytes.
        const Address new_local{"127.0.0.2", port};
        REQUIRE(TestHelper::simulate_local_address(*client_endpoint, new_local));
        REQUIRE(TestHelper::simulate_mtu(*client_endpoint, 1400));

        auto stream = conn->open_stream();
        stream->send(std::string(msg_size, 'x'));

        auto closed = client_closed.get_future();
        require_future(all_received.get_future(), 5s);
        CHECK(closed.wait_for(0s) == std::future_status::timeout);
        CHECK(conn->local() == new_local);
        CHECK(TestHelper::send_stats(*client_endpoint).too_big_drops > 0);

        // The new path's size is discovered from scratch: 1452 fails, then 1372 succeeds.
        for (int i = 0; i < 50 && TestHelper::path_max_udp_payload(*conn) != 1372; i++)
            std::this_thread::sleep_for(50ms);
        CHECK(TestHelper::path_max_udp_payload(*conn) == 1372);
    }
}  // namespace oxen::quic::test
