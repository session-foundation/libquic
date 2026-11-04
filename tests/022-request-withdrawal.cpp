#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("022 - Timed-out requests that were never sent are withdrawn", "[022][bt][withdraw]")
    {
        Loop loop;

        // Several times the server's fixed stream window, so that with the server's stream paused
        // this request stalls part way through and everything queued behind it is wholly unsent.
        const std::string big(64_ki, 'A');

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        // Only ever touched from the event loop thread.  The stream is weak for the reason given in
        // 017: a shared_ptr declared here would outlive the endpoint.
        std::vector<std::string> received;
        std::weak_ptr<BTRequestStream> server_stream;
        bool alarmed = false, cleared = false;

        auto server_established = callback_waiter{[&](Connection& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler(TEST_ENDPOINT, [&](message m) {
                received.push_back(m.body().size() == big.size() ? "A"s : std::string{m.body()});
                m.respond("ok"sv);
            });
            s->pause();
            server_stream = s;
        }};
        auto client_established = callback_waiter{[](Connection&) {}};

        auto server_endpoint = Endpoint::endpoint(loop, server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(
                server_tls,
                connection_established_callback{server_established},
                opt::flow_control{.initial_stream_window = 16_ki, .max_stream_window = 0}));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = Endpoint::endpoint(loop, client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(server_established.wait());

        auto client = conn_interface->open_stream<BTRequestStream>();

        // acked + unacked + unsent: everything fed to the stream.  Withdrawing is the only thing
        // that takes from it.
        auto fed = [&] {
            auto [acked, unacked, unsent, retained] = client->get_stats();
            return acked + unacked + unsent;
        };

        auto timed_out = [](message m) { CHECK(m.timed_out); };
        auto a_timed_out = callback_waiter{timed_out};
        auto b_timed_out = callback_waiter{timed_out};
        auto d_timed_out = callback_waiter{timed_out};
        auto c_replied = callback_waiter{[](message m) { CHECK_FALSE(m.timed_out); }};

        // Long enough for the stall below to be reached before it expires.
        client->command(TEST_ENDPOINT, big, a_timed_out, 1s);
        // The whole window sent: from here on nothing more can be, so only withdrawing can take
        // from what is unsent.
        REQUIRE(wait_for(
                [&] {
                    auto [acked, unacked, unsent, retained] = client->get_stats();
                    return acked + unacked >= 16_ki;
                },
                500ms,
                5ms));

        // B is big enough that queueing it sounds this watermark, and that withdrawing it clears
        // it again with D and C still queued behind it.
        const std::string b_body(1_ki, 'B');

        // Queued and measured within one loop call so that nothing can be sent in between.
        auto [b_size, fed_before, alarmed_by_b] = loop.call_get([&] {
            auto before = fed();
            auto alarm = client->unsent() + b_body.size();
            client->enable_watermarks(alarm, [&](Stream&) { alarmed = true; }, alarm - 1, [&](Stream&) { cleared = true; });
            client->command(TEST_ENDPOINT, b_body, b_timed_out, 100ms);
            auto b_size = fed() - before;
            client->command(TEST_ENDPOINT, "D"sv, d_timed_out, 100ms, opt::send_after_timeout);
            client->command(TEST_ENDPOINT, "C"sv, c_replied);
            return std::tuple{b_size, fed(), alarmed && !cleared};
        });
        CHECK(b_size > 0);
        CHECK(alarmed_by_b);

        REQUIRE(a_timed_out.wait());
        REQUIRE(b_timed_out.wait());
        REQUIRE(d_timed_out.wait());

        // Only B goes: A was partly sent, and D asked to be sent anyway.
        CHECK(fed() == fed_before - b_size);
        CHECK(loop.call_get([&] { return cleared; }));

        auto srv = loop.call_get([&] { return server_stream.lock(); });
        REQUIRE(srv);
        srv->resume();
        srv.reset();

        REQUIRE(c_replied.wait());
        CHECK(loop.call_get([&] { return received; }) == std::vector{"A"s, "D"s, "C"s});
    }
}  //  namespace oxen::quic::test
