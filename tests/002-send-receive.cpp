#include "unit_test.hpp"

#include <atomic>

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
}  // namespace oxen::quic::test
