// macOS only declares IPV6_DONTFRAG (checked by the don't-fragment test, and set by udp.cpp) when
// this is defined before any system header is included.
#ifdef __APPLE__
#define __APPLE_USE_RFC_3542
#endif

#include "unit_test.hpp"

#include <atomic>
#include <map>
#include <mutex>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][execute]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<bool> d_promise;
        std::future<bool> d_future = d_promise.get_future();

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(view(dat) == good_msg);
            d_promise.set_value(true);
        };

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

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));

        require_future(d_future);
    }

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][bidirectional]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        std::vector<std::promise<void>> d_promises{2};
        std::vector<std::future<void>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(view(dat) == good_msg);
            d_promises.at(index).set_value();
            index += 1;
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};
        Address client_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};

        auto server_ci = server_endpoint_b->connect(server_remote, server_tls);
        auto server_stream = server_ci->open_stream();

        server_stream->send(good_msg, nullptr);

        require_future(d_futures[0]);

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        // client make stream and send; message displayed by server_data_cb
        auto client_stream = conn_interface->open_stream();

        REQUIRE_NOTHROW(client_stream->send(good_msg, nullptr));

        require_future(d_futures[1]);
    }

    TEST_CASE("002 - Simple client to server transmission", "[002][simple][2x2]")
    {
        Network test_net{};
        constexpr auto good_msg = "hello from the other siiiii-iiiiide"sv;

        std::vector<std::promise<void>> d_promises{2};
        std::vector<std::future<void>> d_futures{2};

        for (int i = 0; i < 2; ++i)
            d_futures[i] = d_promises[i].get_future();

        std::atomic<int> index = 0;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Calling server stream data callback... data received...");
            REQUIRE(view(dat) == good_msg);
            d_promises.at(index).set_value();
            index += 1;
        };

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);
        REQUIRE_NOTHROW(server_endpoint_b->listen(server_tls, server_data_cb));

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};

        auto server_b_ci = server_endpoint_b->connect(server_remote_a, server_tls);
        auto server_b_stream = server_b_ci->open_stream();

        server_b_stream->send(good_msg, nullptr);

        require_future(d_futures[0]);

        auto server_a_ci = server_endpoint_a->connect(server_remote_b, server_tls);

        auto server_a_stream = server_a_ci->open_stream();

        server_a_stream->send(good_msg, nullptr);

        require_future(d_futures[1]);
    }

    TEST_CASE("002 - Client to server transmission, larger string ownership", "[002][simple][larger][ownership]")
    {
        Network test_net{};
        std::vector<std::byte> good_msg(2600);

        for (int i = 0; i < 100; i++)
            for (char c = 'a'; c <= 'z'; c++)
                good_msg.push_back(static_cast<std::byte>(c));

        constexpr int tests = 10;
        std::mutex received_mut;
        int good = 0, bad = 0;
        std::promise<void> done_receiving;

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            log::debug(test_cat, "Server stream data callback -- data received (len {})", dat.size());

            static std::vector<std::byte> partial;
            partial.insert(partial.end(), dat.begin(), dat.end());

            if (partial.size() < good_msg.size())
                return;

            std::lock_guard lock{received_mut};

            std::string_view partial_sv{reinterpret_cast<const char*>(partial.data()), good_msg.size()},
                    msg_sv{reinterpret_cast<const char*>(good_msg.data()), good_msg.size()};

            if (partial_sv == msg_sv)
                good++;
            else
                bad++;

            std::vector<std::byte> replace{std::next(partial.begin(), good_msg.size()), partial.end()};
            partial = std::move(replace);

            if (good + bad >= tests)
                done_receiving.set_value();
        };

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_a_local{}, server_b_local{};

        auto server_endpoint_a = test_net.endpoint(server_a_local);
        REQUIRE_NOTHROW(server_endpoint_a->listen(server_tls, server_data_cb));

        auto server_endpoint_b = test_net.endpoint(server_b_local);

        RemoteAddress server_remote_a{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_a->local().port()};
        RemoteAddress server_remote_b{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint_b->local().port()};

        auto conn_to_a = server_endpoint_b->connect(server_remote_a, server_tls);
        auto stream_to_a = conn_to_a->open_stream();

        SECTION("Sending byte span of long-lived buffer")
        {
            for (int i = 0; i < tests; i++)
            {
                // There is no ownership issue here: we're just viewing into our `good_msg` which we
                // are keeping alive already for the duration of this test.
                stream_to_a->send(good_msg, nullptr);
            }
        }
        SECTION("Sending std::vector<std::byte> buffer with transferred ownership")
        {
            for (int i = 0; i < tests; i++)
            {
                // Deliberately construct a new temporary string here, and move it into `send()` to
                // transfer ownership of it off to the stream to manage:
                std::vector<std::byte> copy{good_msg};
                stream_to_a->send(std::move(copy));
            }
        }
        SECTION("Sending byte span buffer with managed keep-alive")
        {
            for (int i = 0; i < tests; i++)
            {
                // Similar to the above, but keep the data alive via a manual shared_ptr keep-alive
                // object.
                auto ptr = std::make_shared<std::vector<std::byte>>(good_msg);
                auto& v = *ptr;
                stream_to_a->send(v, std::move(ptr));
            }
        }

        require_future(done_receiving.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            CHECK(good == tests);
            CHECK(bad == 0);
        }
    }

    TEST_CASE("002 - BTRequestStream Testing", "[002][btreq]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        SECTION("Client sends a command")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                    log::info(test_cat, "Server BTRequestStream received: {}", msg.body());
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s);

            REQUIRE(server_bp_cb.wait());
        }

        SECTION("Client sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Server BTRequestStream received: {}", msg.body());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Client BTRequestStream received: {}", msg.body());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                return e.loop.make_shared<BTRequestStream>(c, e);
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls, client_constructor);

            std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
        }

        SECTION("Client (alternate construction) sends a request, server sends a response")
        {
            auto server_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Server BTRequestStream received: {}", msg.body());
                    msg.respond("test_response"s);
                }
            }};

            auto client_bp_cb = callback_waiter{[&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "Client BTRequestStream received: {}", msg.body());
                    msg.respond("test_response"s);
                }
            }};

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_bp_cb);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command(TEST_ENDPOINT, "test_request_body"s, client_bp_cb);

            REQUIRE(server_bp_cb.wait());
            REQUIRE(client_bp_cb.wait());
        }

        SECTION("Timeouts and errors")
        {
            auto server_bp_cb = [&](message m) {
                if (m.body() == "hello")
                    m.respond("goodbye");
                else if (m.body() == "I need a reply crypto-soon")
                {
                }  // <-- Crypto-soon, defined.
                else if (m.body() == "I hate you")
                    m.respond("lol", true);
            };

            int saw_regular = 0, saw_timeout = 0, saw_error = 0;

            std::promise<void> done;

            auto client_bp_cb = [&](message msg) {
                if (msg)
                {
                    log::info(test_cat, "GOT REGULAR");
                    saw_regular++;
                }
                else if (msg.is_error())
                {
                    log::info(test_cat, "GOT ERROR");

                    saw_error++;
                }
                else if (msg.timed_out)
                {
                    log::info(test_cat, "GOT TIMEOUT");
                    saw_timeout++;
                }

                if (saw_regular + saw_error + saw_timeout >= 3)
                    done.set_value();
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler("test"s, server_bp_cb);
                return s;
            };

            stream_constructor_callback client_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                return e.loop.make_shared<BTRequestStream>(c, e);
            };

            auto server_endpoint = test_net.endpoint(server_local);
            server_endpoint->listen(server_tls, server_constructor);

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();

            client_bp->command("test"s, "hello"s, client_bp_cb);
            client_bp->command("test"s, "I need a reply crypto-soon"s, client_bp_cb, 100ms);
            client_bp->command("test"s, "I hate you"s, client_bp_cb);

            auto fut = done.get_future();
            require_future(fut);

            CHECK(saw_regular == 1);
            CHECK(saw_timeout == 1);
            CHECK(saw_error == 1);
        }
    }

    TEST_CASE("002 - BTRequestStream multi-request testing", "[002][btreq][multi]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        static constexpr int num_requests = 50;

        std::mutex mut;
        std::promise<void> done_prom;
        auto done = done_prom.get_future();
        int responses = 0, good_responses = 0;

        constexpr auto req_msg = "you will never get this, you will never get this, la la la la la"sv;
        constexpr auto res_msg = "he break a cage and he get this"sv;

        auto server_handler = [&](message msg) {
            if (msg)
            {
                log::info(test_cat, "Server BTRequestStream received: {}", msg.body());
                if (msg.body() == req_msg)
                    msg.respond(res_msg);
                else
                    msg.respond("that would not be funny in America");
            }
        };

        auto client_reply_handler = [&](message msg) {
            if (msg)
            {
                std::lock_guard lock{mut};
                responses++;
                log::debug(test_cat, "Client BTRequestStream received response {}: {}", responses, msg.body());
                if (msg.body() == res_msg)
                    good_responses++;
                if (responses == num_requests)
                    done_prom.set_value();
            }
            else
            {
                log::debug(test_cat, "got back a failed message response");
            }
        };

        stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
            auto s = e.loop.make_shared<BTRequestStream>(c, e);
            s->register_handler(TEST_ENDPOINT, server_handler);
            return s;
        };

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

        for (int i = 0; i < num_requests; i++)
        {
            client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler);
        }

        require_future(done);
        std::lock_guard lock{mut};
        CHECK(good_responses == num_requests);
        CHECK(responses == good_responses);
    }

    TEST_CASE("002 - BTRequestStream huge requests", "[002][btreq][huge]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        static constexpr int num_requests = 2;

        // Make sure debug logging is off for these because at debug log this produces so much log
        // output it can take too long to run the tests within our 5s future wait.
        log_level_raiser log_relief{log::Level::info};

        SECTION("Huge but not too huge")
        {
            std::promise<void> done_prom;
            auto done = done_prom.get_future();

            std::atomic<int> responses = 0, good_responses = 0;

            std::string req_msg(9'000'000, 'a');
            constexpr auto res_msg = "oh look some a's"sv;

            auto server_handler = [&](message msg) mutable {
                if (msg)
                {
                    if (msg.body() == req_msg)
                        msg.respond(res_msg);
                    else
                        msg.respond("where are all the a's?!");
                }
            };

            auto client_reply_handler = [&](message msg) mutable {
                if (msg)
                {
                    ++responses;
                    log::debug(test_cat, "Client BTRequestStream received response {}: {}", responses.load(), msg.body());
                    if (msg.body() == res_msg)
                        ++good_responses;
                    if (responses == num_requests)
                        done_prom.set_value();
                }
                else
                {
                    log::debug(test_cat, "got back a failed message response");
                }
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_handler);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();

            for (int i = 0; i < num_requests; i++)
            {
                client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler);
            }

            require_future(done, 10s);
            CHECK(good_responses == num_requests);
            CHECK(responses == good_responses);
        }

        SECTION("Too huge")
        {
            // Both ends of the stream get a limit small enough to test cheaply.  The bt encoding
            // adds a length prefix, so a body of exactly the limit is over it.
            constexpr size_t limit = 100'000;
            std::string req_msg(limit, 'a');

            auto server_handler = [&](message) mutable {
                REQUIRE(false);  // Should not get here!
            };

            auto client_reply_handler = [&](message msg) mutable {
                if (msg)
                    log::debug(test_cat, "Client BTRequestStream received response: {}", msg.body());
                else
                    log::debug(test_cat, "got back a failed message response");
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e, opt::max_request_size{limit});
                s->register_handler(TEST_ENDPOINT, server_handler);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            SECTION("Send failure")
            {
                std::shared_ptr<BTRequestStream> client_bp =
                        conn_interface->open_stream<BTRequestStream>(opt::max_request_size{limit});
                CHECK(client_bp->max_request_size() == limit);
                CHECK_THROWS_WITH(
                        client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler), "Request body too long!");
            }

            SECTION("Receive failure")
            {
                // Construct a bt request manually so that we can send invalid (too long) data at the
                // server (normally a client won't let us do that, as tested in the above section)
                std::string payload = "li123e1:C{}:{}e"_format(req_msg.size(), req_msg);
                payload = "{}:{}"_format(payload.size(), payload);

                std::atomic<uint64_t> close_err = -1;
                auto stream_close_cb = callback_waiter{[&](Stream&, uint64_t error_code) { close_err = error_code; }};
                auto str = conn_interface->open_stream<Stream>(stream_close_cb);

                str->send(std::move(payload));

                REQUIRE(stream_close_cb.wait());
                CHECK(close_err.load() == BTREQ_ERROR_EXCEPTION);
            }

            SECTION("Limit too large to encode")
            {
                CHECK_THROWS_WITH(
                        conn_interface->open_stream<BTRequestStream>(opt::max_request_size{1'000'000'000}),
                        "max_request_size must be positive and below 1000000000");
                CHECK_THROWS_WITH(
                        conn_interface->open_stream<BTRequestStream>(opt::max_request_size{0}),
                        "max_request_size must be positive and below 1000000000");
            }

            SECTION("Length prefix longer than any limit can need")
            {
                // Rejected on the digits alone, before any body arrives
                std::string payload = "99999999999:li123e1:C3:abce";

                std::atomic<uint64_t> close_err = -1;
                auto stream_close_cb = callback_waiter{[&](Stream&, uint64_t error_code) { close_err = error_code; }};
                auto str = conn_interface->open_stream<Stream>(stream_close_cb);

                str->send(std::move(payload));

                REQUIRE(stream_close_cb.wait());
                CHECK(close_err.load() == BTREQ_ERROR_EXCEPTION);
            }
        }

        SECTION("Default limit admits a 10 MB request")
        {
            // The limit used to be a fixed 10'000'000 bytes; the default is now 10 MiB.
            std::string req_msg(10'000'001, 'a');
            CHECK(req_msg.size() < DEFAULT_MAX_REQ_LEN);

            std::promise<void> prom;
            auto done = prom.get_future();
            std::atomic<size_t> received_size = 0;

            auto server_handler = [&](message m) {
                received_size = m.body().size();
                m.respond("ok"s);
            };

            auto client_reply_handler = [&](message msg) {
                CHECK(msg);
                CHECK(msg.body() == "ok"sv);
                prom.set_value();
            };

            stream_constructor_callback server_constructor = [&](Connection& c, Endpoint& e, std::optional<int64_t>) {
                auto s = e.loop.make_shared<BTRequestStream>(c, e);
                s->register_handler(TEST_ENDPOINT, server_handler);
                return s;
            };

            auto server_endpoint = test_net.endpoint(server_local);
            REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_constructor));

            RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

            auto client_endpoint = test_net.endpoint(client_local);
            auto conn_interface = client_endpoint->connect(client_remote, client_tls);

            auto client_bp = conn_interface->open_stream<BTRequestStream>();
            CHECK(client_bp->max_request_size() == DEFAULT_MAX_REQ_LEN);
            client_bp->command(TEST_ENDPOINT, req_msg, client_reply_handler);

            require_future(done, 30s);
            CHECK(received_size == req_msg.size());
        }
    }

    TEST_CASE("002 - BTRequestStream generic request handler", "[002][btreq][generic]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::promise<void> prom;
        auto done = prom.get_future();

        auto handler1 = [&](message m) { m.respond("h1-{}"_format(m.endpoint())); };

        auto handler2 = [&](message) { throw no_such_endpoint{}; };

        auto handler_generic = [&](message m) {
            if (m.endpoint() == "nuh uh")
                throw no_such_endpoint{};
            m.respond("hg-{}"_format(m.endpoint()));
        };

        std::function<void(Connection&)> server_conn_est;
        SECTION("generic handler via constructor")
        {
            server_conn_est = [&](Connection& c) {
                auto s = c.queue_incoming_stream<BTRequestStream>(std::move(handler_generic));
                s->register_handler("ep1"s, handler1);
                s->register_handler("ep2"s, handler2);
            };
        }
        SECTION("generic handler via method")
        {
            server_conn_est = [&](Connection& c) {
                auto s = c.queue_incoming_stream<BTRequestStream>();
                s->register_handler("ep1"s, handler1);
                s->register_handler("ep2"s, handler2);
                s->register_generic_handler(std::move(handler_generic));
            };
        }

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_conn_est);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::unordered_multiset<std::string> responses, errors;
        auto resp_handler = [&](message m) {
            if (m)
                responses.emplace(m.body());
            else
                errors.emplace(m.body());
            if (responses.size() + errors.size() >= 4)
                prom.set_value();
        };

        std::shared_ptr<BTRequestStream> client_bp = conn_interface->open_stream<BTRequestStream>();
        client_bp->command("ep1", "", resp_handler);
        client_bp->command("ep2", "", resp_handler);
        client_bp->command("ep3", "", resp_handler);
        client_bp->command("nuh uh", "", resp_handler);

        require_future(done);
        CHECK(responses == std::unordered_multiset{{"h1-ep1"s, "hg-ep3"s}});
        CHECK(errors == std::unordered_multiset{{"Invalid endpoint 'nuh uh'"s, "Invalid endpoint 'ep2'"s}});
    }

    TEST_CASE("002 - BTRequestStream connection close triggers timeout callback", "[002][btreq][close]")
    {
        Network test_net{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        std::thread slow_response;
        auto server_conn_est = [&](Connection& c) {
            auto s = c.queue_incoming_stream<BTRequestStream>();
            s->register_handler("sleep"s, [&](message m) {
                test_net.loop()->call_later(250ms, [m = std::move(m)] { m.respond("I'm slow"); });
            });
        };

        auto server_endpoint = test_net.endpoint(server_local);
        server_endpoint->listen(server_tls, server_conn_est);

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls, opt::idle_timeout{50ms});

        auto client_bp = conn_interface->open_stream<BTRequestStream>();

        bool got_timeout = false;
        callback_waiter reply_handler{[&](message response) { got_timeout = response.timed_out; }};
        client_bp->command("sleep"s, ""s, reply_handler);

        REQUIRE(reply_handler.wait());
        CHECK(got_timeout);

        if (slow_response.joinable())
            slow_response.join();
    }

    // A sent_request that expects a response is owed exactly one, whatever happens to it.  These
    // tests walk the ways one can die and check that the callback fires, once, with timed_out set.
    // The interesting cases need the request to be in a particular place when the stream dies, and
    // the queued-command case additionally needs the stream to die between command() queueing the
    // job and the loop running it; parked_loop arranges both.
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

        struct btreq_client_setup
        {
            Network net{};
            std::shared_ptr<GNUTLSCreds> client_tls, server_tls;
            std::shared_ptr<Endpoint> server_ep, client_ep;
            std::shared_ptr<Connection> conn;
            std::shared_ptr<BTRequestStream> stream;

            btreq_client_setup()
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

    TEST_CASE("002 - BTRequestStream command queued but discarded with its stream", "[002][btreq][destruction]")
    {
        // The crash this all started from: a command queued from off the loop, with the stream
        // destroyed before the job ran.  The job is now discarded along with the stream's own job
        // queue, so nothing ever calls add_sent_request -- the callback has to come from
        // ~sent_request destroying the request the discarded job was holding.
        btreq_client_setup t;

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

    TEST_CASE("002 - BTRequestStream registered request failed on quiet close", "[002][btreq][destruction]")
    {
        // A quietly-closing connection skips _execute_close_hooks, and so close_all_streams(), and
        // goes straight to dropping its streams: the request is sitting in sent_reqs with nothing
        // left that would ever time it out.  ~BTRequestStream has to catch it.
        btreq_client_setup t;

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

    TEST_CASE("002 - BTRequestStream answered request is not failed again", "[002][btreq][destruction]")
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

    TEST_CASE("002 - Each packet in a batch is sent with its own ECN marking", "[002][ecn]")
    {
        // Equal-sized packets, so that only the differing ECN values can keep GSO from sending
        // them all as a single batch (or GRO from merging them).
        const bool allow_gso = GENERATE(false, true);
        const bool allow_gro = GENERATE(false, true);
        const auto localhost = GENERATE("127.0.0.1"s, "::1"s);
        constexpr std::array<uint8_t, 6> ecns{0, 2, 2, 0, 1, 3};

        Loop loop;
        std::vector<std::pair<int, uint8_t>> received;  // (packet index, ecn); loop thread only
        std::promise<void> all_received;
        std::unique_ptr<UDPSocket> sender, receiver;

        loop.call_get([&] {
            receiver = std::make_unique<UDPSocket>(
                    loop.get_event_base(),
                    Address{localhost, 0},
                    UDPSocket::options{.allow_gro = allow_gro},
                    [&](Packet&& pkt) {
                        received.emplace_back(static_cast<int>(pkt.data()[0]), pkt.pkt_info.ecn);
                        if (received.size() == ecns.size())
                            all_received.set_value();
                    });
            sender = std::make_unique<UDPSocket>(
                    loop.get_event_base(), Address{localhost, 0}, UDPSocket::options{.allow_gso = allow_gso}, [](Packet&&) {
                    });

            std::array<std::byte, 100 * ecns.size()> bufs;
            std::array<size_t, ecns.size()> sizes;
            for (size_t i = 0; i < ecns.size(); i++)
            {
                std::fill_n(bufs.begin() + 100 * i, 100, static_cast<std::byte>(i));
                sizes[i] = 100;
            }
            auto [res, sent] = sender->send(
                    Path{sender->address(), receiver->address()},
                    bufs.data(),
                    sizes.data(),
                    ecns.data(),
                    ecns.size(),
                    false);
            REQUIRE(res.success());
            REQUIRE(sent == ecns.size());
        });

        require_future(all_received.get_future());

        loop.call_get([&] {
            for (size_t i = 0; i < received.size(); i++)
            {
                CHECK(received[i].first == static_cast<int>(i));
                CHECK(received[i].second == ecns[i]);
            }
            sender.reset();
            receiver.reset();
        });
    }

    TEST_CASE("002 - Batched packets of mixed sizes arrive intact", "[002][gso]")
    {
        // Covers each GSO batching decision: full-size runs ending in one shorter packet (after two
        // or more full ones), a shorter packet that may not join a single full one, and a larger
        // packet followed by a smaller one (as with a PMTUD probe), which must not form a batch.
        // On loopback a GRO socket receives each GSO batch as one merged buffer, which then has to
        // be split back into the same packets.
        const bool allow_gso = GENERATE(false, true);
        const bool allow_gro = GENERATE(false, true);
        constexpr std::array<size_t, 12> sizes{1000, 1000, 600, 1000, 1000, 1000, 500, 1000, 700, 1400, 600, 800};

        Loop loop;
        struct received_pkt
        {
            int index;
            size_t size;
            bool intact;
        };
        std::vector<received_pkt> received;  // loop thread only
        std::promise<void> all_received;
        std::unique_ptr<UDPSocket> sender, receiver;

        loop.call_get([&] {
            receiver = std::make_unique<UDPSocket>(
                    loop.get_event_base(),
                    Address{"127.0.0.1", 0},
                    UDPSocket::options{.allow_gro = allow_gro},
                    [&](Packet&& pkt) {
                        auto d = pkt.data();
                        bool intact = std::all_of(d.begin(), d.end(), [&](std::byte b) { return b == d[0]; });
                        received.push_back({static_cast<int>(d[0]), d.size(), intact});
                        if (received.size() == sizes.size())
                            all_received.set_value();
                    });
            sender = std::make_unique<UDPSocket>(
                    loop.get_event_base(),
                    Address{"127.0.0.1", 0},
                    UDPSocket::options{.allow_gso = allow_gso},
                    [](Packet&&) {});

            std::vector<std::byte> buf;
            for (size_t i = 0; i < sizes.size(); i++)
                buf.insert(buf.end(), sizes[i], static_cast<std::byte>(i));
            std::array<uint8_t, sizes.size()> ecns{};
            auto [res, sent] = sender->send(
                    Path{sender->address(), receiver->address()},
                    buf.data(),
                    sizes.data(),
                    ecns.data(),
                    sizes.size(),
                    false);
            REQUIRE(res.success());
            REQUIRE(sent == sizes.size());
        });

        require_future(all_received.get_future());

        loop.call_get([&] {
            for (size_t i = 0; i < received.size(); i++)
            {
                CHECK(received[i].index == static_cast<int>(i));
                CHECK(received[i].size == sizes[i]);
                CHECK(received[i].intact);
            }
            if (TestHelper::gso_enabled(*sender) && TestHelper::gro_enabled(*receiver))
                if (auto merges = TestHelper::gro_merges(*receiver))
                    CHECK(*merges > 0);
            sender.reset();
            receiver.reset();
        });
    }

    TEST_CASE("002 - A blocked socket stalls the endpoint's sends until it clears", "[002][stall]")
    {
        Network test_net{};

        constexpr int n_conns = 3;
        std::vector<std::byte> msg(100'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::map<Stream*, std::vector<std::byte>> received;
        int complete = 0;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream& s, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            auto& r = received[&s];
            r.insert(r.end(), dat.begin(), dat.end());
            if (r.size() == msg.size() && ++complete == n_conns)
                all_received.set_value();
        };

        std::atomic<int> established{0};
        std::promise<void> all_established;
        connection_established_callback client_established = [&](Connection&) {
            if (++established == n_conns)
                all_established.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        // All of the connections share one client endpoint, and so one send batch.
        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        std::vector<std::shared_ptr<Connection>> conns;
        for (int i = 0; i < n_conns; i++)
            conns.push_back(client_endpoint->connect(server_remote, client_tls));
        require_future(all_established.get_future());

        if (!TestHelper::block_sends_for(*client_endpoint, 250ms))
            SKIP("Send stall testing requires a debug build of libquic");

        std::vector<std::shared_ptr<Stream>> streams;
        for (auto& c : conns)
        {
            streams.push_back(c->open_stream());
            streams.back()->send(msg, nullptr);
        }

        require_future(all_received.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            for (auto& [s, r] : received)
                CHECK(r == msg);
        }

        auto stats = TestHelper::send_stats(*client_endpoint);
        CHECK(stats.stalls >= 1);
        // A waiting connection only retries its flush when something new wakes it (incoming
        // packets, new data to send, an already-armed timer); anything that kept re-waking waiters
        // during the stall would instead show up here as a skip on every loop iteration, which over
        // the 250ms stall is thousands of times.
        CHECK(stats.skips < 50);
        CHECK(stats.discards == 0);
    }

    TEST_CASE("002 - A stalled batch is discarded if its connection goes away", "[002][stall]")
    {
        Network test_net{};

        std::vector<std::byte> msg(10'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::map<Stream*, std::vector<std::byte>> received;
        std::promise<void> one_received;
        stream_data_callback server_data_cb = [&](Stream& s, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            auto& r = received[&s];
            r.insert(r.end(), dat.begin(), dat.end());
            if (r.size() == msg.size())
                one_received.set_value();
        };

        std::atomic<int> established{0};
        std::promise<void> both_established;
        connection_established_callback client_established = [&](Connection&) {
            if (++established == 2)
                both_established.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        auto conn_a = client_endpoint->connect(server_remote, client_tls);
        auto conn_b = client_endpoint->connect(server_remote, client_tls);
        require_future(both_established.get_future());

        if (!TestHelper::block_sends_for(*client_endpoint, 300ms))
            SKIP("Send stall testing requires a debug build of libquic");

        // A's first send blocks, so A's packets (all it ever gets to send) are the stalled batch.
        auto stream_a = conn_a->open_stream();
        stream_a->send(msg, nullptr);
        REQUIRE(wait_for([&] { return TestHelper::send_stats(*client_endpoint).stalls == 1; }, 200ms, 1ms));

        auto stream_b = conn_b->open_stream();
        stream_b->send(msg, nullptr);
        REQUIRE(wait_for([&] { return TestHelper::send_stats(*client_endpoint).skips >= 1; }, 200ms, 1ms));

        SECTION("owner closed during the stall")
        {
            conn_a->close_connection();
            REQUIRE(wait_for(
                    [&] { return client_endpoint->job_queue.call_get([&] { return conn_a->is_closing(); }); }, 200ms, 1ms));
        }
        SECTION("owner died during the stall")
        {
            TestHelper::mark_dead(*conn_a);
        }

        // B was waiting on the stall, so it gets woken (and sends) once the socket unblocks.
        require_future(one_received.get_future(), 5s);
        std::this_thread::sleep_for(100ms);

        CHECK(TestHelper::send_stats(*client_endpoint).discards == 1);
        {
            std::lock_guard lock{received_mut};
            REQUIRE(received.size() == 1);
            CHECK(received.begin()->second == msg);
        }

        conn_a->close_connection();
    }

    TEST_CASE("002 - A partly sent batch keeps its unsent packets intact", "[002][stall][partial]")
    {
        // Different sizes so that the unsent packets have to be moved by the right byte offset.
        constexpr std::array<size_t, 6> sizes{100, 200, 150, 300, 120, 80};
        constexpr std::array<uint8_t, 6> ecns{0, 2, 2, 0, 1, 3};

        // Whether the socket is then full (the rest must be kept for later), or the short count was
        // sendmmsg dropping an error and an immediate retry gets the rest away.
        const bool then_block = GENERATE(true, false);

        Network test_net{};
        auto ep = test_net.endpoint(Address{LOCALHOST, 0});

        if (!TestHelper::partial_sends(*ep, 1, 2, then_block))
            SKIP("Partial send testing requires a debug build of libquic with batched sends");

        struct received_pkt
        {
            int index;
            size_t size;
            uint8_t ecn;
            bool intact;
        };
        std::vector<received_pkt> received;  // loop thread only
        std::promise<void> all_received;
        std::unique_ptr<UDPSocket> receiver;
        test_net.loop()->call_get([&] {
            receiver = std::make_unique<UDPSocket>(
                    test_net.loop()->get_event_base(), Address{LOCALHOST, 0}, UDPSocket::options{}, [&](Packet&& pkt) {
                        auto d = pkt.data();
                        auto index = static_cast<int>(d[0]);
                        bool intact = std::all_of(d.begin(), d.end(), [&](std::byte b) { return b == d[0]; });
                        received.push_back({index, d.size(), pkt.pkt_info.ecn, intact});
                        if (received.size() == sizes.size())
                            all_received.set_value();
                    });
        });

        std::vector<std::byte> buf;
        std::array<size_t, 6> bufsize = sizes;
        std::array<uint8_t, 6> ecn = ecns;
        for (size_t i = 0; i < sizes.size(); i++)
            buf.insert(buf.end(), sizes[i], static_cast<std::byte>(i));

        Path path{ep->local(), test_net.loop()->call_get([&] { return receiver->address(); })};
        size_t n = sizes.size();

        auto res = TestHelper::send_packets(*ep, path, buf.data(), bufsize.data(), ecn.data(), n);
        if (then_block)
        {
            CHECK(res.blocked());
            REQUIRE(n == 4);
            for (size_t i = 0; i < n; i++)
            {
                CHECK(bufsize[i] == sizes[i + 2]);
                CHECK(ecn[i] == ecns[i + 2]);
            }
            CHECK(buf[0] == std::byte{2});
            CHECK(buf[sizes[2]] == std::byte{3});

            res = TestHelper::send_packets(*ep, path, buf.data(), bufsize.data(), ecn.data(), n);
        }
        CHECK(res.success());
        CHECK(n == 0);

        require_future(all_received.get_future());
        test_net.loop()->call_get([&] {
            for (size_t i = 0; i < received.size(); i++)
            {
                CHECK(received[i].index == static_cast<int>(i));
                CHECK(received[i].size == sizes[i]);
                CHECK(received[i].ecn == ecns[i]);
                CHECK(received[i].intact);
            }
            receiver.reset();
        });
    }

    TEST_CASE("002 - Streams survive repeatedly partly sent batches", "[002][stall][partial]")
    {
        Network test_net{};

        constexpr int n_conns = 2;
        std::vector<std::byte> msg(100'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::map<Stream*, std::vector<std::byte>> received;
        int complete = 0;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream& s, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            auto& r = received[&s];
            r.insert(r.end(), dat.begin(), dat.end());
            if (r.size() == msg.size() && ++complete == n_conns)
                all_received.set_value();
        };

        std::atomic<int> established{0};
        std::promise<void> all_established;
        connection_established_callback client_established = [&](Connection&) {
            if (++established == n_conns)
                all_established.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established);
        std::vector<std::shared_ptr<Connection>> conns;
        for (int i = 0; i < n_conns; i++)
            conns.push_back(client_endpoint->connect(server_remote, client_tls));
        require_future(all_established.get_future());

        if (!TestHelper::partial_sends(*client_endpoint, 30, 5))
            SKIP("Partial send testing requires a debug build of libquic with batched sends");

        std::vector<std::shared_ptr<Stream>> streams;
        for (auto& c : conns)
        {
            streams.push_back(c->open_stream());
            streams.back()->send(msg, nullptr);
        }

        require_future(all_received.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            for (auto& [s, r] : received)
                CHECK(r == msg);
        }

        auto stats = TestHelper::send_stats(*client_endpoint);
        CHECK(stats.stalls >= 1);
        CHECK(stats.discards == 0);
    }

    TEST_CASE("002 - Send errors that only lose packets don't close the connection", "[002][senderr]")
    {
        // "too big": with a 1300-byte MTU, ngtcp2's PMTUD probes above that fail with EMSGSIZE.
        // "no buffers": a few sends fail with ENOBUFS while the stream is being sent.
        const auto mode = GENERATE(as<std::string>{}, "too big", "no buffers");

        Network test_net{};

        std::vector<std::byte> msg(100'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::vector<std::byte> received;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            received.insert(received.end(), dat.begin(), dat.end());
            if (received.size() == msg.size())
                all_received.set_value();
        };

        auto client_established = callback_waiter{[](Connection&) {}};
        std::atomic<bool> client_closed{false};
        connection_closed_callback client_closed_cb = [&](Connection&, uint64_t) { client_closed = true; };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established, client_closed_cb);

        if (mode == "too big" && !TestHelper::simulate_mtu(*client_endpoint, 1300))
            SKIP("Send error testing requires a debug build of libquic");

        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        if (mode == "no buffers" && !TestHelper::fail_sends(*client_endpoint, ENOBUFS, 5))
            SKIP("Send error testing requires a debug build of libquic");

        auto stream = conn->open_stream();
        stream->send(msg, nullptr);

        require_future(all_received.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            CHECK(received == msg);
        }

        auto stats = TestHelper::send_stats(*client_endpoint);
        if (mode == "too big")
            CHECK(stats.too_big_drops > 0);
        else
            CHECK(stats.no_buffer_drops > 0);
        CHECK_FALSE(client_closed);
        CHECK_FALSE(client_endpoint->job_queue.call_get([&] { return conn->is_closing() || conn->is_draining(); }));
    }

    TEST_CASE("002 - Other send errors still close the connection", "[002][senderr]")
    {
        Network test_net{};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto client_closed = callback_waiter{[](Connection&, uint64_t) {}};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established, client_closed);
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        if (!TestHelper::fail_sends(*client_endpoint, EPERM, 1))
            SKIP("Send error testing requires a debug build of libquic");

        auto stream = conn->open_stream();
        stream->send("hello"s);

        CHECK(client_closed.wait());
    }

    TEST_CASE("002 - A failed GSO send falls back to sending without it", "[002][senderr][gso]")
    {
        // "EIO": GSO can't work on the route, so it gets disabled.
        // "EINVAL, unsupported": the resend without GSO works, so GSO was the problem: disabled.
        // "EINVAL, too big": the resend without GSO fails with EMSGSIZE, so it was the size: GSO
        //   stays on, and since the refused packets are within the path's confirmed size the
        //   connection closes.
        const auto mode = GENERATE(as<std::string>{}, "EIO", "EINVAL, unsupported", "EINVAL, too big");

        std::promise<uint64_t> client_closed;
        std::atomic<bool> closed_once{false};
        connection_closed_callback on_client_closed = [&](Connection&, uint64_t ec) {
            if (!closed_once.exchange(true))
                client_closed.set_value(ec);
        };

        Network test_net{};

        std::vector<std::byte> msg(100'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::vector<std::byte> received;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            received.insert(received.end(), dat.begin(), dat.end());
            if (received.size() == msg.size())
                all_received.set_value();
        };

        auto client_established = callback_waiter{[](Connection&) {}};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established, on_client_closed, opt::allow_gso{});
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());
        if (!TestHelper::gso_enabled(*client_endpoint))
            SKIP("This build of libquic does not support GSO");

        bool injected = mode == "EIO" ? TestHelper::fail_socket_sends(*client_endpoint, {EIO}, {})
                      : mode == "EINVAL, unsupported"
                              ? TestHelper::fail_socket_sends(*client_endpoint, {EINVAL}, {})
                              : TestHelper::fail_socket_sends(*client_endpoint, {EINVAL}, {EMSGSIZE});
        if (!injected)
            SKIP("Send error testing requires a debug build of libquic");

        auto stream = conn->open_stream();
        stream->send(msg, nullptr);

        if (mode == "EINVAL, too big")
        {
            auto closed = client_closed.get_future();
            require_future(closed, 5s);
            CHECK(closed.get() == CONN_MTU_EXCEEDED);
            CHECK(TestHelper::gso_enabled(*client_endpoint));
            CHECK(TestHelper::send_stats(*client_endpoint).too_big_drops > 0);
            return;
        }

        require_future(all_received.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            CHECK(received == msg);
        }
        CHECK_FALSE(TestHelper::gso_enabled(*client_endpoint));
    }

    TEST_CASE("002 - A stream arrives intact at an endpoint receiving with GRO", "[002][gro]")
    {
        Network test_net{};

        std::vector<std::byte> msg(1'000'000);
        for (size_t i = 0; i < msg.size(); i++)
            msg[i] = static_cast<std::byte>(i % 251);

        std::mutex received_mut;
        std::vector<std::byte> received;
        std::promise<void> all_received;
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> dat) {
            std::lock_guard lock{received_mut};
            received.insert(received.end(), dat.begin(), dat.end());
            if (received.size() == msg.size())
                all_received.set_value();
        };

        auto client_established = callback_waiter{[](Connection&) {}};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{}, opt::allow_gro{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));
        if (!TestHelper::gro_enabled(*server_endpoint))
            SKIP("This build of libquic does not support GRO");
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established, opt::allow_gso{});
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        conn->open_stream()->send(msg, nullptr);

        require_future(all_received.get_future(), 5s);
        {
            std::lock_guard lock{received_mut};
            CHECK(received == msg);
        }
        // On loopback the client's GSO batches reach the server's socket as merged buffers.
        if (TestHelper::gso_enabled(*client_endpoint))
            if (auto merges = TestHelper::gro_merges(*server_endpoint))
                CHECK(*merges > 0);
    }

    TEST_CASE("002 - max_udp_payload probe lists", "[002][pmtud]")
    {
        auto as_vector = [](const opt::max_udp_payload& mup) {
            return std::vector<uint16_t>{mup.probes().begin(), mup.probes().end()};
        };

        CHECK(as_vector(opt::max_udp_payload{1400}) == std::vector<uint16_t>{1372, 1342, 1324, 1232});
        CHECK(opt::max_udp_payload{1400}.max() == 1372);
        CHECK(as_vector(opt::max_udp_payload{9000}) ==
              std::vector<uint16_t>{std::begin(DEFAULT_PMTUD_PROBES), std::end(DEFAULT_PMTUD_PROBES)});
        CHECK(opt::max_udp_payload{9000}.max() == MAX_PMTUD_UDP_PAYLOAD);
        CHECK(opt::max_udp_payload{1231}.probes().empty());
        CHECK(opt::max_udp_payload::minimum().probes().empty());
        CHECK(opt::max_udp_payload::minimum().max() == 1200);
        CHECK(opt::max_udp_payload::ipv4(1500).max() == 1472);
        CHECK(opt::max_udp_payload::ipv6(1500).max() == 1452);
        CHECK_THROWS_AS(opt::max_udp_payload{1199}, std::invalid_argument);

        std::array<uint16_t, 2> explicit_list{1444, 1300};
        CHECK(as_vector(opt::max_udp_payload{explicit_list}) == std::vector<uint16_t>{1444, 1300});
        CHECK(opt::max_udp_payload{explicit_list}.max() == 1444);
        CHECK(opt::max_udp_payload{std::span<const uint16_t>{}}.probes().empty());
        for (uint16_t bad : {1200, 1473})
        {
            std::array<uint16_t, 2> list{1300, bad};
            CHECK_THROWS_AS(opt::max_udp_payload{list}, std::invalid_argument);
        }
    }

    TEST_CASE("002 - PMTUD reaches the largest probe size, with or without datagrams", "[002][pmtud]")
    {
        const bool datagrams = GENERATE(false, true);
        // Both endpoints are dual-stack, so over 127.0.0.1 the server sees an IPv4-mapped address.
        const auto localhost = GENERATE("127.0.0.1"s, "::1"s);
        const bool ipv6 = localhost == "::1";
        // The probe list on the client, and the size the client should end up at over loopback for
        // IPv4 and for IPv6 (which skips sizes above MAX_IPV6_UDP_PAYLOAD).
        const auto [list, expected_v4, expected_v6] = GENERATE(table<std::string, size_t, size_t>({
                {"default", MAX_PMTUD_UDP_PAYLOAD, MAX_IPV6_UDP_PAYLOAD},
                {"explicit default", MAX_PMTUD_UDP_PAYLOAD, MAX_IPV6_UDP_PAYLOAD},
                {"max 1330", 1324, 1324},
                {"max 9000", MAX_PMTUD_UDP_PAYLOAD, MAX_IPV6_UDP_PAYLOAD},
                {"only 1406", 1406, 1406},
                {"only 1472", 1472, 1200},
                {"minimum", 1200, 1200},
        }));
        const size_t expected = ipv6 ? expected_v6 : expected_v4;
        INFO("probe list: " << list << ", datagrams: " << datagrams << ", via " << localhost);

        Network test_net{};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        std::shared_ptr<Endpoint> server_endpoint, client_endpoint;
        std::optional<opt::enable_datagrams> dgrams;
        if (datagrams)
            dgrams.emplace(Splitting::ACTIVE);
        std::optional<opt::max_udp_payload> cap;
        const std::array<uint16_t, 1> only_1406{1406}, only_1472{1472};
        if (list == "explicit default")
            cap.emplace(std::span<const uint16_t>{DEFAULT_PMTUD_PROBES});
        else if (list == "max 1330")
            cap.emplace(1330);
        else if (list == "max 9000")
            cap.emplace(9000);
        else if (list == "only 1406")
            cap.emplace(only_1406);
        else if (list == "only 1472")
            cap.emplace(only_1472);
        else if (list == "minimum")
            cap.emplace(opt::max_udp_payload::minimum());

        server_endpoint = test_net.endpoint(Address{}, dgrams);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, localhost, server_endpoint->local().port()};

        client_endpoint = test_net.endpoint(Address{}, client_established, dgrams, cap);
        auto conn = client_endpoint->connect(server_remote, client_tls);
        REQUIRE(client_established.wait());

        // Give PMTUD (a few round trips over loopback) time to finish.
        std::this_thread::sleep_for(300ms);

        auto server_conns = server_endpoint->get_all_conns(Direction::INBOUND);
        REQUIRE(server_conns.size() == 1);
        CHECK(TestHelper::path_max_udp_payload(*conn) == expected);
        // The server probes with the default list, but is held to the client's limit by the
        // max_udp_payload_size the client advertises; it can still land below the client's size,
        // at the largest default size that fits.
        auto server_max = TestHelper::path_max_udp_payload(*server_conns.front());
        CHECK(server_max <= expected);
        if (list == "max 1330")
            CHECK(server_max == 1324);
        else if (list == "default" || list == "explicit default" || list == "max 9000")
            CHECK(server_max == expected);
    }

    TEST_CASE("002 - Packets refused as too big for the path", "[002][pmtud][senderr]")
    {
        // Declared before the Network, which closes the connection (calling this) as it shuts down.
        std::promise<uint64_t> client_closed;
        std::atomic<bool> closed_once{false};
        connection_closed_callback on_client_closed = [&](Connection&, uint64_t ec) {
            if (!closed_once.exchange(true))
                client_closed.set_value(ec);
        };

        Network test_net{};

        auto client_established = callback_waiter{[](Connection&) {}};
        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(Address{});
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));
        RemoteAddress server_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(Address{}, client_established, on_client_closed);
        if (!TestHelper::simulate_mtu(*client_endpoint, 0))
            SKIP("Simulating a path MTU requires a debug build of libquic");

        // Packets above 1400 bytes are refused, so the largest probe size that fits is 1372.
        constexpr size_t simulated_mtu = 1400;
        auto closed = client_closed.get_future();

        SECTION("Refused PMTUD probes are just dropped")
        {
            REQUIRE(TestHelper::simulate_mtu(*client_endpoint, simulated_mtu));
            auto conn = client_endpoint->connect(server_remote, client_tls);
            REQUIRE(client_established.wait());

            // 1452 fails, then 1372 succeeds, then 1444 and 1406 fail; each failure takes a few
            // PTOs to be given up on, but the refusals themselves happen as each probe is sent.
            for (int i = 0; i < 50 && TestHelper::path_max_udp_payload(*conn) < 1372; i++)
                std::this_thread::sleep_for(50ms);
            std::this_thread::sleep_for(1s);

            CHECK(TestHelper::path_max_udp_payload(*conn) == 1372);
            CHECK(TestHelper::send_stats(*client_endpoint).too_big_drops > 0);
            CHECK(closed.wait_for(0s) == std::future_status::timeout);
        }

        SECTION("A refused packet within the confirmed size closes the connection")
        {
            auto conn = client_endpoint->connect(server_remote, client_tls);
            REQUIRE(client_established.wait());
            for (int i = 0; i < 50 && TestHelper::path_max_udp_payload(*conn) < MAX_PMTUD_UDP_PAYLOAD; i++)
                std::this_thread::sleep_for(20ms);
            REQUIRE(TestHelper::path_max_udp_payload(*conn) == MAX_PMTUD_UDP_PAYLOAD);

            // ngtcp2 can't lower the size it has confirmed, so every full-size packet would keep
            // failing: the connection closes instead.
            REQUIRE(TestHelper::simulate_mtu(*client_endpoint, simulated_mtu));
            auto s = conn->open_stream();
            s->send(std::string(100'000, 'x'));

            REQUIRE(closed.wait_for(5s) == std::future_status::ready);
            CHECK(closed.get() == CONN_MTU_EXCEEDED);
        }
    }

    TEST_CASE("002 - UDP sockets are set not to fragment", "[002][dontfrag]")
    {
        // IPv4, IPv6 only, and dual-stack (an IPv6 socket that also carries IPv4-mapped traffic)
        const auto local = GENERATE("127.0.0.1"s, "::1"s, ""s);
        INFO("bound to [" << local << "]");
        const bool ipv4 = local == "127.0.0.1";
        const bool ipv6 = !ipv4;
        [[maybe_unused]] const bool dual_stack = local.empty();

        Network test_net{};
        auto ep = test_net.endpoint(Address{local, 0});
        auto sock = TestHelper::get_sock(*ep);

        auto get = [sock](int level, int opt) -> std::optional<int> {
#ifdef _WIN32
            DWORD v = 0;
            int len = sizeof(v);
            if (getsockopt(sock, level, opt, reinterpret_cast<char*>(&v), &len) != 0)
                return std::nullopt;
#else
            int v = 0;
            socklen_t len = sizeof(v);
            if (getsockopt(sock, level, opt, &v, &len) != 0)
                return std::nullopt;
#endif
            return static_cast<int>(v);
        };

#if defined(_WIN32)
        if (ipv4)
            CHECK(get(IPPROTO_IP, IP_DONTFRAGMENT) == 1);
        if (ipv6)
            CHECK(get(IPPROTO_IPV6, IPV6_DONTFRAG) == 1);
#elif defined(IP_MTU_DISCOVER) && defined(IP_PMTUDISC_PROBE)
        // Linux also takes the IPv4 option on a dual-stack IPv6 socket, for its IPv4-mapped traffic.
        if (ipv4 || dual_stack)
            CHECK(get(IPPROTO_IP, IP_MTU_DISCOVER) == IP_PMTUDISC_PROBE);
        if (ipv6)
            CHECK(get(IPPROTO_IPV6, IPV6_MTU_DISCOVER) == IPV6_PMTUDISC_PROBE);
#elif defined(IP_DONTFRAG)
        if (ipv4)
            CHECK(get(IPPROTO_IP, IP_DONTFRAG) == 1);
#ifdef IPV6_DONTFRAG
        if (ipv6)
            CHECK(get(IPPROTO_IPV6, IPV6_DONTFRAG) == 1);
#endif
#else
        SKIP("No don't-fragment socket option on this platform");
#endif
    }

    TEST_CASE("002 - Looking up the local address used to reach a peer", "[002][route]")
    {
        Loop loop;
        std::unique_ptr<UDPSocket> sock;
        auto bind = [&](Address addr) {
            loop.call_get([&] {
                sock = std::make_unique<UDPSocket>(loop.get_event_base(), addr, UDPSocket::options{}, [](Packet&&) {});
            });
            return sock->address().port();
        };

        SECTION("A socket bound to a specific address always uses it")
        {
            bind(Address{"127.0.0.1", 0});
            CHECK(sock->local_address_for(Address{"127.0.0.1", 4433}) == sock->address());
        }
        SECTION("An IPv4 any-address socket uses the routed source address")
        {
            auto port = bind(Address{ipv4{}});
            CHECK(sock->local_address_for(Address{"127.0.0.1", 4433}) == Address{"127.0.0.1", port});
        }
        SECTION("An IPv6-only any-address socket uses the routed source address")
        {
            auto port = bind(Address{ipv6{}});
            CHECK(sock->local_address_for(Address{"::1", 4433}) == Address{"::1", port});
        }
        SECTION("A dual-stack socket reaches IPv4 peers at IPv4-mapped addresses")
        {
            auto port = bind(Address{});
            CHECK(sock->local_address_for(Address{"127.0.0.1", 4433}.mapped_ipv4_as_ipv6()) ==
                  Address{"127.0.0.1", port}.mapped_ipv4_as_ipv6());
            CHECK(sock->local_address_for(Address{"::1", 4433}) == Address{"::1", port});
        }

        loop.call_get([&] { sock.reset(); });
    }
}  // namespace oxen::quic::test
