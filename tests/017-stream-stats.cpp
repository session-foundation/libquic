#include "unit_test.hpp"

namespace oxen::quic::test
{
    TEST_CASE("017 - Stream byte accounting", "[017][stats][streams]")
    {
        Loop loop;

        // Bigger than the 6 MiB initial stream flow control window, so that pausing the receiving
        // end leaves us stalled part-way through a single send() buffer.
        std::vector<std::byte> big(10 << 20, std::byte{'x'});

        auto client_established = callback_waiter{[](Connection&) {}};
        auto server_established = callback_waiter{[](Connection&) {}};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::atomic<size_t> server_received = 0;
        std::atomic<bool> pause_requested = false;
        // Only ever touched from the event loop thread.  Deliberately weak: a shared_ptr here would
        // outlive the endpoint (being declared before it) and ~Stream would then try to queue onto
        // an already-stopped loop.
        std::weak_ptr<Stream> server_stream;

        auto server_endpoint = Endpoint::endpoint(loop, server_local, server_established);
        server_endpoint->listen(server_tls, [&](Stream& s, std::span<const std::byte> dat) {
            server_received += dat.size();
            if (pause_requested.exchange(false))
            {
                server_stream = s.weak_from_this();
                s.pause();
            }
        });

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = Endpoint::endpoint(loop, client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        CHECK(client_established.wait());
        CHECK(server_established.wait());

        auto client_stream = conn_interface->open_stream();

        SECTION("idle stream reports zeroes")
        {
            auto [acked, unacked, unsent, retained] = client_stream->get_stats();
            CHECK(acked == 0);
            CHECK(unacked == 0);
            CHECK(unsent == 0);
            CHECK(retained == 0);
            CHECK(client_stream->retained_bytes() == 0);
        }

        SECTION("queued data is retained before it is sent")
        {
            // Checked inside the same call_get as the send so that the loop can't flush any of it
            // out from under us.
            loop.call_get([&] {
                client_stream->send(std::span{big}.first(1000), nullptr);
                auto [acked, unacked, unsent, retained] = client_stream->get_stats();
                CHECK(acked == 0);
                CHECK(unacked == 0);
                CHECK(unsent == 1000);
                CHECK(retained == 1000);
            });
        }

        SECTION("a partially acked buffer stays retained in full")
        {
            pause_requested = true;
            client_stream->send(big, nullptr);

            // The receiver pauses on its first data callback, so it stops extending our stream
            // window and we stall with part of this single buffer acked and the rest unsent.
            REQUIRE(wait_for(
                    [&] {
                        auto [acked, unacked, unsent, retained] = client_stream->get_stats();
                        return acked >= (4 << 20) && unsent > 0;
                    },
                    10s,
                    5ms));

            auto [acked, unacked, unsent, retained] = client_stream->get_stats();
            CHECK(acked > 0);
            CHECK(unsent > 0);
            // Nothing can be released yet: it is all one send() buffer, and a buffer is only
            // released once fully acked.
            CHECK(retained == big.size());
            CHECK(retained > unacked + unsent);
            // In this single-buffer case the pinned bytes are exactly the acked ones:
            CHECK(retained - unacked - unsent == acked);
            CHECK(acked + unacked + unsent == big.size());

            // Unblock and let it finish; now everything should be released.  The weak_ptr is read on
            // the loop thread (where it is written); resume() itself is safe to call from here.
            auto srv = loop.call_get([&] { return server_stream.lock(); });
            REQUIRE(srv);
            srv->resume();
            REQUIRE(wait_for([&] { return server_received.load() >= big.size(); }, 20s));
            REQUIRE(wait_for(
                    [&] {
                        auto [a, u, s, r] = client_stream->get_stats();
                        return a == big.size() && u == 0 && s == 0 && r == 0;
                    },
                    5s));
        }

        SECTION("retained never drops below unacked + unsent")
        {
            client_stream->send(big, nullptr);

            bool invariant_held = true;
            bool saw_in_flight = false;
            wait_for(
                    [&] {
                        auto [acked, unacked, unsent, retained] = client_stream->get_stats();
                        if (retained < unacked + unsent)
                            invariant_held = false;
                        if (acked + unacked + unsent != big.size())
                            invariant_held = false;
                        if (unacked > 0)
                            saw_in_flight = true;
                        return server_received.load() >= big.size();
                    },
                    20s,
                    1ms);

            CHECK(invariant_held);
            CHECK(saw_in_flight);
            REQUIRE(wait_for([&] { return client_stream->retained_bytes() == 0; }, 5s));
        }
    }
}  //  namespace oxen::quic::test
