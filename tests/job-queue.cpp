#include "unit_test.hpp"
#include "utils.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <thread>

#ifndef _WIN32
extern "C"
{
#include <arpa/inet.h>
}
#endif

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("JobQueue - One extra queue", "[jobqueue]")
    {
        Loop loop;
        JobQueue jq{loop};

        SECTION("Extra queue jobs go away, others do not.")
        {
            callback_waiter queued{[]() {}};
            callback_waiter good{[]() {}};
            callback_waiter bad{[]() {}};
            callback_waiter main_ok{[]() {}};

            // queue 3 jobs:
            //
            // one should run then queue a job onto the main job queue, which
            // should later execute without issue
            //
            // the next should destroy the created job queue
            //
            // the third should not execute
            loop.call([&]() {
                jq.call_soon([&]() { good.call(); });

                jq.call_soon([&]() { jq.stop(); });

                jq.call_soon([&]() { bad.call(); });

                // call_soon so it gets queued, as it is being called from inside the loop.
                loop.call_soon([&]() { main_ok.call(); });

                queued.call();
            });

            REQUIRE(queued.wait());

            REQUIRE(good.wait());
            REQUIRE_FALSE(bad.wait(10ms));
            REQUIRE(main_ok.wait());
        }

        SECTION("call exception if invoked after JobQueue stopped")
        {
            callback_waiter stopped{[]() {}};
            bool soon_failed{false};
            bool later_failed{false};

            jq.call([&]() {
                jq.stop();

                try
                {
                    jq.call_soon([]() {});
                }
                catch (const std::exception& e)
                {
                    soon_failed = true;
                }

                try
                {
                    jq.call_later(1s, []() {});
                }
                catch (const std::exception& e)
                {
                    later_failed = true;
                }

                stopped.call();
            });

            REQUIRE(stopped.wait());

            REQUIRE(soon_failed);
            REQUIRE(later_failed);
            REQUIRE_THROWS_AS(jq.call([]() {}), std::runtime_error);
            REQUIRE_THROWS_AS(jq.call_soon([]() {}), std::runtime_error);
            REQUIRE_THROWS_AS(jq.call_get([]() { return 0; }), std::runtime_error);
            REQUIRE_THROWS_AS(jq.call_later(1s, []() {}), std::runtime_error);
        }

        SECTION("call_get exception if JobQueue goes away before fulfilled")
        {
            jq.call([&]() {
                // this needs to happen after the call_get below is queued.  hopefully there
                // won't be some fruit-flavored platform where this sleep is insufficient.
                std::this_thread::sleep_for(10ms);
                jq.stop();
            });

            bool success{false};
            try
            {
                jq.call_get([&]() {});
            }
            catch (const std::future_error& e)
            {
                success = true;
            }
            catch (const std::exception& e)
            {}

            CHECK_NOFAIL(success);
        }
    }

    TEST_CASE("JobQueue - posts from another thread racing a stop", "[jobqueue]")
    {
        // A post passes the stopped check and then wakes the queue; stop() frees the waker on the
        // loop thread.  The wake has to land before the free, or it reaches freed memory, which a
        // macOS build shows as an occasional crash in event_active and a Linux one, without a
        // sanitiser, does not show at all.  The window is a few instructions wide, so a plain or
        // ASan build rarely hits it; TSan reports the unsynchronised read and free on every run.
        Loop loop;
        for (int round = 0; round < 500; round++)
        {
            auto jq = std::make_unique<JobQueue>(loop);
            std::atomic<bool> posting{true};
            std::thread poster{[&] {
                while (posting)
                {
                    try
                    {
                        jq->call_soon([] {});
                    }
                    catch (const std::runtime_error&)
                    {
                        break;  // stopped: what a post after the stop is meant to get
                    }
                }
            }};
            jq->stop();
            posting = false;
            poster.join();
        }
        SUCCEED("no post reached a freed waker");
    }

    TEST_CASE("JobQueue - is_running says whether it has been stopped", "[jobqueue]")
    {
        Loop loop;
        JobQueue jq{loop};

        REQUIRE(jq.is_running());
        REQUIRE(loop.call_get([&] { return jq.is_running(); }));

        jq.stop();
        REQUIRE_FALSE(jq.is_running());
        REQUIRE_FALSE(loop.call_get([&] { return jq.is_running(); }));
        REQUIRE_THROWS_AS(jq.call_soon([] {}), std::runtime_error);

        // Stopping again is a no-op, and does not bring it back.
        jq.stop();
        REQUIRE_FALSE(jq.is_running());
    }

}  // namespace oxen::quic::test
