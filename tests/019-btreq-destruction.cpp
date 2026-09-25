#include "utils.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>

namespace oxen::quic::test
{
    // A sent_request that expects a response is owed exactly one, whatever happens to it.  These
    // tests walk the ways one can die and check that the callback fires, once, with timed_out set.
    //
    // The interesting cases need the request to be in a particular place when the stream dies, and
    // the queued-command case additionally needs the stream to die between command() queueing the
    // job and the loop running it.  Both are arranged by parking the event loop on a promise: while
    // it is parked nothing is processed, and a command() from the test thread is queued rather than
    // run inline (command() only defers when it is not already on the loop thread).  The teardown
    // then happens from inside that same parked job, via the synchronous TestHelper entry points,
    // so it is strictly ordered before the queued command job gets its turn.

    namespace
    {
        // Counts callback invocations rather than using callback_waiter, whose promise throws if it
        // is set twice -- and that throw would be swallowed by sent_request::deliver, hiding
        // exactly the double-fire we want to catch.
        struct response_counter
        {
            std::atomic<int> calls{0};
            std::atomic<bool> timed_out{false};
            std::atomic<bool> stream_accessible{false};
            std::promise<void> first;
            std::future<void> fired{first.get_future()};

            std::function<void(message)> cb()
            {
                return [this](message m) {
                    timed_out = m.timed_out;
                    try
                    {
                        m.stream();
                        stream_accessible = true;
                    }
                    catch (const std::runtime_error&)
                    {
                        stream_accessible = false;
                    }
                    if (++calls == 1)
                        first.set_value();
                };
            }

            [[nodiscard]] bool wait(std::chrono::milliseconds timeout = 5s)
            {
                return fired.wait_for(timeout) == std::future_status::ready;
            }
        };

        // Parks the event loop until released, so that the test thread can queue work and tear
        // things down in a known order.  `during` runs on the loop thread, after the release,
        // before anything else queued in the meantime gets a turn.
        struct parked_loop
        {
            std::promise<void> gate;
            std::promise<void> done;
            std::future<void> finished{done.get_future()};

            parked_loop(Loop& loop, std::function<void()> during)
            {
                loop.call_soon([this, during = std::move(during)] {
                    gate.get_future().wait();
                    during();
                    done.set_value();
                });
            }

            void release() { gate.set_value(); }

            [[nodiscard]] bool wait(std::chrono::milliseconds timeout = 5s)
            {
                return finished.wait_for(timeout) == std::future_status::ready;
            }
        };

        struct client_setup
        {
            Network net{};
            std::shared_ptr<GNUTLSCreds> client_tls, server_tls;
            std::shared_ptr<Endpoint> server_ep, client_ep;
            std::shared_ptr<Connection> conn;
            std::shared_ptr<BTRequestStream> stream;

            client_setup()
            {
                std::tie(client_tls, server_tls) = defaults::tls_creds_from_ed_keys();
                server_ep = net.endpoint(Address{});
                server_ep->listen(server_tls);
                client_ep = net.endpoint(Address{});
                conn = client_ep->connect(
                        RemoteAddress{defaults::SERVER_PUBKEY, LOCALHOST, server_ep->local().port()}, client_tls);
                stream = conn->open_stream<BTRequestStream>();
            }
        };
    }  // namespace

    TEST_CASE("019 - command queued but discarded with its stream", "[019][btreq][destruction]")
    {
        // The crash this all started from: a command queued from off the loop, with the stream
        // destroyed before the job ran.  The job is now discarded along with the stream's own job
        // queue, so nothing ever calls add_sent_request -- the callback has to come from
        // ~sent_request destroying the request the discarded job was holding.
        client_setup t;

        auto* ep = t.client_ep.get();
        auto* conn = t.conn.get();
        parked_loop parked{t.client_ep->loop, [ep, conn] { TestHelper::drop_connection_now(*ep, *conn, 12345); }};

        response_counter resp;
        t.stream->command("never-sent", "body", resp.cb());

        // Drop the test's own references: the connection's stream map is now the only owner, so the
        // teardown inside the parked job releases the last one.  Neither reset destroys anything
        // here, which matters because their deleters would need the loop we have parked.
        t.stream.reset();
        t.conn.reset();

        parked.release();
        REQUIRE(parked.wait());

        REQUIRE(resp.wait());
        CHECK(resp.timed_out);
        CHECK(resp.calls == 1);

        // The stream is mid-destruction when this fires, so message::stream() throws rather than
        // returning it.  Applications must not reach back through the message on a failure: get at
        // the endpoint (or anything else still alive) some other way.
        CHECK_FALSE(resp.stream_accessible);
    }

    TEST_CASE("019 - registered request failed on quiet close", "[019][btreq][destruction]")
    {
        // A quietly-closing connection skips _execute_close_hooks, and so close_all_streams(), and
        // goes straight to dropping its streams: the request is sitting in sent_reqs with nothing
        // left that would ever time it out.  ~BTRequestStream has to catch it.
        client_setup t;

        response_counter resp;

        // Register the request first, from on the loop, so it lands in sent_reqs rather than
        // staying queued.
        t.client_ep->loop.call_get([&] { t.stream->command("registered", "body", resp.cb()); });

        t.conn->set_close_quietly();

        auto* ep = t.client_ep.get();
        auto* conn = t.conn.get();
        parked_loop parked{t.client_ep->loop, [ep, conn] { TestHelper::drop_connection_now(*ep, *conn, 12345); }};

        t.stream.reset();
        t.conn.reset();
        parked.release();
        REQUIRE(parked.wait());

        REQUIRE(resp.wait());
        CHECK(resp.timed_out);
        CHECK(resp.calls == 1);
    }

    TEST_CASE("019 - answered request is not failed again", "[019][btreq][destruction]")
    {
        // The fire-once half: a request that got a real reply must not be answered a second time
        // when the sent_request is destroyed.
        Network net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_ep = net.endpoint(Address{}, [](Connection& c) {
            auto ss = c.queue_incoming_stream<BTRequestStream>();
            ss->register_handler("echo", [](message m) { m.respond(m.body()); });
        });
        server_ep->listen(server_tls);

        auto client_ep = net.endpoint(Address{});
        auto conn =
                client_ep->connect(RemoteAddress{defaults::SERVER_PUBKEY, LOCALHOST, server_ep->local().port()}, client_tls);
        auto stream = conn->open_stream<BTRequestStream>();

        response_counter resp;
        stream->command("echo", "hi", resp.cb());

        REQUIRE(resp.wait());
        CHECK_FALSE(resp.timed_out);

        // Tear everything down; if ~sent_request fired again we would see a second call.
        stream.reset();
        conn->close_connection();
        conn.reset();
        std::this_thread::sleep_for(250ms);

        CHECK(resp.calls == 1);
    }

    TEST_CASE("019 - datagram queued but discarded with its channel", "[019][datagrams][destruction]")
    {
        // The datagram half of the per-channel job queue.  There is no callback to observe here:
        // the failure mode is a use-after-free inside the queued send, so this is a crash test,
        // and only really earns its keep under a sanitizer.
        Network net{};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_ep = net.endpoint(Address{}, opt::enable_datagrams{});
        server_ep->listen(server_tls);

        auto client_ep = net.endpoint(Address{}, opt::enable_datagrams{});
        auto conn =
                client_ep->connect(RemoteAddress{defaults::SERVER_PUBKEY, LOCALHOST, server_ep->local().port()}, client_tls);

        // Must be fetched before parking the loop: Connection::datagrams() is a call_get, which
        // would block the test thread against the very loop we are about to park.
        auto dgrams = conn->datagrams();

        auto* ep = client_ep.get();
        auto* cptr = conn.get();
        parked_loop parked{client_ep->loop, [ep, cptr] { TestHelper::drop_connection_now(*ep, *cptr, 12345); }};

        dgrams->send("dropped on the floor"s);

        dgrams.reset();
        conn.reset();
        parked.release();
        REQUIRE(parked.wait());

        // Give the loop a chance to run the discarded job, if it wrongly still holds one.
        std::this_thread::sleep_for(250ms);
        SUCCEED();
    }

}  // namespace oxen::quic::test
