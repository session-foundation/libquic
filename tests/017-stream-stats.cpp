#include "unit_test.hpp"

namespace oxen::quic::test
{
    // How long the 10 MiB below is allowed to take over loopback.  This is an assertion, not a
    // safety margin: the transfer runs in tens of milliseconds on a development machine and around
    // a second on our slowest CI builder (Rasp Pi 4, with a debug build), so anything approaching
    // this bound means something is waiting on a timer rather than moving data -- which is the
    // resume() stall this test exists to catch -- and that should fail rather than quietly pass
    // late.  Don't "fix" a failure here by reaching for tens of seconds; at that point the test has
    // stopped testing anything.
    constexpr auto TRANSFER_LIMIT{3s};

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
                    TRANSFER_LIMIT,
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
            // Deliberate, and the reason this section catches anything.  The receiver usually still
            // has a delayed-ACK timer pending (25ms by default), and the flow control credit that
            // resume() grants rides out on that ACK whether or not resume() prompts a write of its
            // own.  Sleeping past it removes that crutch, so this exercises resume() actually
            // waking the connection; without that the transfer stalls until the sender's PTO,
            // seconds later.  It is a race either way -- one that is lost rarely rather than never.
            //
            // Sized from measurement: with the resume() fix reverted, 50ms caught it 2 runs in 5,
            // 75ms and 100ms 5 in 5.  100ms leaves margin for a slow machine, where the ACK timer
            // being waited past is itself late.
            std::this_thread::sleep_for(100ms);
            srv->resume();
            REQUIRE(wait_for([&] { return server_received.load() >= big.size(); }, TRANSFER_LIMIT));
            REQUIRE(wait_for(
                    [&] {
                        auto [a, u, s, r] = client_stream->get_stats();
                        return a == big.size() && u == 0 && s == 0 && r == 0;
                    },
                    TRANSFER_LIMIT));
        }

        SECTION("retained never drops below unacked + unsent")
        {
            client_stream->send(big, nullptr);

            bool invariant_held = true;
            bool saw_in_flight = false;
            // Polls finer than the waits elsewhere in this file because it is sampling for a
            // transient violation rather than waiting for an end state -- but not so fine that the
            // sampling perturbs what it measures: each get_stats() is a call_get round trip through
            // the event loop doing the transfer.
            REQUIRE(wait_for(
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
                    TRANSFER_LIMIT,
                    2ms));

            CHECK(invariant_held);
            CHECK(saw_in_flight);
            REQUIRE(wait_for([&] { return client_stream->retained_bytes() == 0; }, TRANSFER_LIMIT));
        }
    }
}  //  namespace oxen::quic::test
