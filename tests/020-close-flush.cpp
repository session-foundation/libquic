#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("020 - Endpoint close flush", "[020][close][flush]")
    {
        Network test_net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        SECTION("Waiting close returns once flushed, not once torn down")
        {
            auto server_established = callback_waiter{[](Connection&) {}};
            auto server_closed = callback_waiter{[](Connection&, uint64_t) {}};

            auto server_endpoint = test_net.endpoint(Address{}, server_established, server_closed);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_established = callback_waiter{[](Connection&) {}};
            auto client_endpoint = test_net.endpoint(Address{}, client_established);
            auto conn = client_endpoint->connect(client_remote, client_tls);

            REQUIRE(client_established.wait());
            REQUIRE(server_established.wait());

            // A generous timeout that we expect *not* to be hit: on loopback the close packet never
            // blocks, so what releases us is the flush completing.  Were the wait wired up to the
            // connection teardown instead it would sit here for the 3*PTO cleanup timer.
            //
            // Note that the case the wait actually exists for -- a send that blocks and gets parked
            // on the socket until it is writeable -- is not reachable here, because a loopback
            // socket does not block.  What is covered is that the wait is released at all, and that
            // it is not released by the teardown timer.
            auto started = std::chrono::steady_clock::now();
            REQUIRE_NOTHROW(client_endpoint->close_conns(5s));
            auto elapsed = std::chrono::steady_clock::now() - started;

            CHECK(elapsed < 1s);
            CHECK(server_closed.wait());
        }

        SECTION("Waiting close with nothing to close returns immediately")
        {
            auto endpoint = test_net.endpoint(Address{});

            auto started = std::chrono::steady_clock::now();
            REQUIRE_NOTHROW(endpoint->close_conns(5s));
            CHECK(std::chrono::steady_clock::now() - started < 1s);
        }

        SECTION("Zero wait does not block")
        {
            auto server_endpoint = test_net.endpoint(Address{});
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_established = callback_waiter{[](Connection&) {}};
            auto client_endpoint = test_net.endpoint(Address{}, client_established);
            auto conn = client_endpoint->connect(client_remote, client_tls);
            REQUIRE(client_established.wait());

            auto started = std::chrono::steady_clock::now();
            REQUIRE_NOTHROW(client_endpoint->close_conns(0us));
            CHECK(std::chrono::steady_clock::now() - started < 1s);

            CHECK(wait_for([&] { return client_endpoint->get_all_conns().empty(); }, 5s));
        }

        SECTION("Waiting close from the event loop thread throws")
        {
            auto endpoint = test_net.endpoint(Address{});

            auto threw = endpoint->job_queue.call_get([&]() -> bool {
                try
                {
                    endpoint->close_conns(5s);
                    return false;
                }
                catch (const std::logic_error&)
                {
                    return true;
                }
            });

            CHECK(threw);

            // The non-waiting forms remain callable from inside the loop.
            REQUIRE_NOTHROW(endpoint->job_queue.call_get([&] { endpoint->close_conns(0us); }));
            REQUIRE_NOTHROW(endpoint->job_queue.call_get([&] { endpoint->close_conns(); }));
        }
    }
}  // namespace oxen::quic::test
