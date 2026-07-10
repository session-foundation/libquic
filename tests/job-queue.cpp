#include "unit_test.hpp"
#include "utils.hpp"

#include <mutex>

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

            REQUIRE(queued.wait(10ms));

            REQUIRE(good.wait(10ms));
            REQUIRE_FALSE(bad.wait(10ms));
            REQUIRE(main_ok.wait(10ms));
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

            CHECK_NOFAIL(stopped.wait(10ms));

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

}  // namespace oxen::quic::test
