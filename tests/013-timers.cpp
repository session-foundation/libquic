#include "unit_test.hpp"

namespace oxen::quic::test
{
    constexpr int NUM_ITERATIONS{4};
    constexpr auto INTERVAL{10ms};
    constexpr auto DELAY{2 * NUM_ITERATIONS * INTERVAL};

    // Timings for the timer tests below, scaled by apple_sucks_factor: TICK is a repeat interval,
    // SETTLE is how long to wait before concluding that nothing further is going to fire, and
    // PATIENCE is the outer limit on waiting for something that should happen promptly.
    //
    // Anything asserting that something *did* happen waits for it via wait_for() rather than
    // sleeping and hoping; only the "and then nothing further happened" checks sleep, and a slow
    // machine can only make those more true.
    constexpr auto TICK{apple_sucks_factor * 10ms};
    constexpr auto SETTLE{apple_sucks_factor * 25ms};
    constexpr auto PATIENCE{apple_sucks_factor * 1s};
    // Poll interval for those waits.  Scaled like everything else here: the platform that needs the
    // longest timeouts is also the one least able to afford frequent wakeups.
    constexpr auto POLL{apple_sucks_factor * 5ms};

// Ticker and Wakeable are deprecated in favour of JobQueue::add_timer(), but are still tested until
// they are removed.  Delete this block, and the two cases below it, along with the classes.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

    TEST_CASE("013 - Ticker event repeater (deprecated)", "[013][ticker][deprecated]")
    {
        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<void> prom_a, prom_b;
        std::future<void> fut_a = prom_a.get_future(), fut_b = prom_b.get_future();

        std::atomic<int> recv_counter{}, send_counter{};

        std::shared_ptr<Ticker> handler;

        stream_data_callback server_data_cb = [&recv_counter](Stream&, std::span<const std::byte>) { recv_counter++; };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        handler = test_net.loop()->call_every(INTERVAL, [&]() {
            if (send_counter <= NUM_ITERATIONS)
            {
                send_counter += 1;
                client_stream->send(msg, nullptr);
            }
        });

        handler->start();

        test_net.loop()->call_later(DELAY, [&prom_a] { prom_a.set_value(); });

        require_future(fut_a, 5s);
        REQUIRE(recv_counter == send_counter);

        recv_counter = 0;
        send_counter = 0;

        REQUIRE(handler->start());

        test_net.loop()->call_later(DELAY, [&prom_b] { prom_b.set_value(); });

        require_future(fut_b, 5s);
        REQUIRE(recv_counter == send_counter);
    }

    TEST_CASE("013 - Wakeable event handler (deprecated)", "[013][wakeable][deprecated]")
    {
        Loop loop;

        std::promise<void> prom;
        std::atomic<int> i = 0;

        auto w = loop.make_wakeable([&i, &prom] {
            ++i;
            prom.set_value();
        });

        w->wake();
        auto fut = prom.get_future();

        require_future(fut, 1s);
        REQUIRE(i == 1);

        std::promise<void> prom2, prom5;
        w = loop.make_wakeable([&i, &prom2, &prom5] {
            auto v = ++i;
            if (v == 2)
                prom2.set_value();
            else if (v == 5)
                prom5.set_value();
        });

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });

        auto fut2 = prom2.get_future();
        require_future(fut2, 1s);
        REQUIRE(i == 2);

        loop.call_get([&w] {
            for (int i = 0; i < 100; i++)
                w->wake();
        });
        std::this_thread::sleep_for(25ms);
        w->wake();
        std::this_thread::sleep_for(25ms);
        w->wake();
        auto fut5 = prom5.get_future();
        require_future(fut5, 1s);
        REQUIRE(i == 5);
    }

#pragma GCC diagnostic pop

    TEST_CASE("013 - Timer: repeating", "[013][timer][repeat]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        auto id = loop.add_timer(TICK, [&] {
            if (++i == 4)
                prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, PATIENCE);

        REQUIRE(loop.stop(id));
        auto stopped_at = i.load();
        std::this_thread::sleep_for(2 * SETTLE);
        REQUIRE(i == stopped_at);

        // A stopped job is paused, not removed: it can be restarted.
        loop.repeat(id, TICK);
        REQUIRE(wait_for([&] { return i > stopped_at; }, PATIENCE, POLL));

        REQUIRE(loop.remove(id));
        REQUIRE_FALSE(loop.remove(id));
    }

    TEST_CASE("013 - Timer: manual trigger is idempotent", "[013][timer][wake]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        auto id = loop.add_wakeable([&] { ++i; });

        // No interval, so nothing should fire on its own.
        std::this_thread::sleep_for(SETTLE);
        REQUIRE(i == 0);

        loop.call_get([&] {
            for (int n = 0; n < 100; n++)
                loop.wake(id);
        });
        REQUIRE(wait_for([&] { return i >= 1; }, PATIENCE, POLL));
        std::this_thread::sleep_for(SETTLE);
        REQUIRE(i == 1);

        loop.wake(id);
        REQUIRE(wait_for([&] { return i >= 2; }, PATIENCE, POLL));
        std::this_thread::sleep_for(SETTLE);
        REQUIRE(i == 2);

        loop.remove(id);
    }

    TEST_CASE("013 - Timer: stopped timer is still wakeable", "[013][timer][wake][repeat]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        auto id = loop.add_timer(TICK, [&] {
            if (++i == 3)
                prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, PATIENCE);

        REQUIRE(loop.armed(id));

        // Descheduling leaves the timer registered, so it can still be fired by hand -- and doing
        // so must not start it repeating again.
        REQUIRE(loop.stop(id));
        REQUIRE_FALSE(loop.armed(id));
        auto stopped_at = i.load();
        std::this_thread::sleep_for(2 * SETTLE);
        REQUIRE(i == stopped_at);

        loop.wake(id);
        REQUIRE(wait_for([&] { return i >= stopped_at + 1; }, PATIENCE, POLL));
        std::this_thread::sleep_for(SETTLE);
        REQUIRE(i == stopped_at + 1);

        loop.wake(id);
        REQUIRE(wait_for([&] { return i >= stopped_at + 2; }, PATIENCE, POLL));
        std::this_thread::sleep_for(SETTLE);
        REQUIRE(i == stopped_at + 2);

        // Still not repeating on its own: waking does not arm it.
        REQUIRE_FALSE(loop.armed(id));
        std::this_thread::sleep_for(2 * SETTLE);
        REQUIRE(i == stopped_at + 2);

        loop.remove(id);
    }

    TEST_CASE("013 - Timer: waking a repeating timer resets its cycle", "[013][timer][wake][repeat]")
    {
        Loop loop;

        constexpr auto CYCLE{apple_sucks_factor * 200ms};

        std::atomic<size_t> fires{0};
        std::promise<void> prom;

        // Only ever touched from the loop thread (in the callback and in the call_get below), and
        // read here only after the promise has been fulfilled, so they need no synchronisation.
        size_t want{0};
        std::chrono::steady_clock::time_point manual{}, scheduled{};

        auto id = loop.add_timer(CYCLE, [&] {
            auto now = std::chrono::steady_clock::now();
            auto n = ++fires;
            if (want == 0)
                return;
            if (n == want - 1)
                manual = now;
            else if (n == want)
            {
                scheduled = now;
                prom.set_value();
            }
        });

        std::this_thread::sleep_for(CYCLE * 2 / 5);

        // Take the count and fire in one trip through the loop so no dispatch can land between the
        // two.  Ticks before this point are irrelevant: what is being measured is the gap between
        // the manual fire and the next scheduled one, which is a full cycle only if waking re-phased
        // the timer.  That makes the test independent of how promptly the sleep above returned --
        // an overrun can only make the gap larger, never smaller.
        loop.call_get([&] {
            want = fires + 2;
            loop.wake(id);
        });

        auto fut = prom.get_future();
        require_future(fut, 5 * PATIENCE);

        loop.remove(id);

        REQUIRE(scheduled - manual >= CYCLE * 4 / 5);
    }

    TEST_CASE("013 - Timer: removal from inside its own callback", "[013][timer][remove]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;
        TimerID id;

        loop.call_get([&] {
            id = loop.add_timer(TICK, [&] {
                if (++i == 3)
                {
                    loop.remove(id);
                    prom.set_value();
                }
            });
        });

        auto fut = prom.get_future();
        require_future(fut, PATIENCE);

        std::this_thread::sleep_for(2 * SETTLE);
        REQUIRE(i == 3);
        REQUIRE_FALSE(loop.remove(id));
    }

    TEST_CASE("013 - Timer: unknown ids", "[013][timer][errors]")
    {
        Loop loop;

        auto id = loop.add_timer([] {});
        REQUIRE(loop.remove(id));

        // Teardown operations and queries on a dead id are silent; scheduling ones throw.
        REQUIRE_FALSE(loop.armed(id));
        REQUIRE_FALSE(loop.stop(id));
        REQUIRE_FALSE(loop.remove(id));
        REQUIRE_THROWS(loop.wake(id));
        REQUIRE_THROWS(loop.repeat(id, 10ms));
    }

    TEST_CASE("013 - Timer: call_later still fires once", "[013][timer][call_later]")
    {
        Loop loop;

        std::atomic<int> i = 0;
        std::promise<void> prom;

        loop.call_later(TICK, [&] {
            ++i;
            prom.set_value();
        });

        auto fut = prom.get_future();
        require_future(fut, PATIENCE);

        std::this_thread::sleep_for(2 * SETTLE);
        REQUIRE(i == 1);
    }

}  //  namespace oxen::quic::test
