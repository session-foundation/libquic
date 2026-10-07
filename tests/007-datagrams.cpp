#include "unit_test.hpp"

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("007 - Datagram support: Default type construction", "[007][datagrams][types]")
    {
        Network test_net{};

        const int bsize = 256;

        opt::enable_datagrams default_dgram{},          // packet_splitting = false
                split_dgram{Splitting::ACTIVE},         // packet_splitting = true, policy = ::ACTIVE
                bsize_dgram{Splitting::ACTIVE, bsize};  // bufsize = 256
        Address default_addr{};

        auto [_, server_tls] = defaults::tls_creds_from_ed_keys();

        // datagrams = false, packet_splitting = false, splitting_policy = ::NONE
        auto vanilla_ep = test_net.endpoint(default_addr);
        REQUIRE_NOTHROW(vanilla_ep->listen(server_tls));

        REQUIRE_FALSE(vanilla_ep->datagrams_enabled());
        REQUIRE_FALSE(vanilla_ep->packet_splitting_enabled());
        REQUIRE(vanilla_ep->splitting_policy() == Splitting::NONE);

        // datagrams = true, packet_splitting = false, splitting_policy = ::NONE
        auto default_ep = test_net.endpoint(default_addr, default_dgram);
        REQUIRE_NOTHROW(default_ep->listen(server_tls));

        REQUIRE(default_ep->datagrams_enabled());
        REQUIRE_FALSE(default_ep->packet_splitting_enabled());
        REQUIRE(default_ep->splitting_policy() == Splitting::NONE);

        // datagrams = true, packet_splitting = true
        auto splitting_ep = test_net.endpoint(default_addr, split_dgram);
        REQUIRE_NOTHROW(splitting_ep->listen(server_tls));

        REQUIRE(splitting_ep->datagrams_enabled());
        REQUIRE(splitting_ep->packet_splitting_enabled());
        REQUIRE(splitting_ep->splitting_policy() == Splitting::ACTIVE);

        // datagrams = true, packet_splitting = true
        auto bufsize_ep = test_net.endpoint(default_addr, bsize_dgram);
        REQUIRE_NOTHROW(bufsize_ep->listen(server_tls));

        REQUIRE(bufsize_ep->datagrams_enabled());
        REQUIRE(bufsize_ep->packet_splitting_enabled());
        REQUIRE(bufsize_ep->splitting_policy() == Splitting::ACTIVE);
        REQUIRE(bufsize_ep->datagram_bufsize() == bsize);
    }

    TEST_CASE("007 - Datagram support: Query param info from datagram-disabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE_FALSE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE(conn_interface->get_max_datagram_size() == 0);
    }

    TEST_CASE("007 - Datagram support: Query param info from default datagram-enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        opt::enable_datagrams default_gram{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, default_gram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, default_gram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_PMTUD_UDP_PAYLOAD);
    }

    TEST_CASE("007 - Datagram support: Query params from split-datagram enabled endpoint", "[007][datagrams][types]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};
        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);
    }

    TEST_CASE("007 - Datagram support: Execute, No Splitting Policy", "[007][datagrams][execute][nosplit]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};
        constexpr auto msg = "hello from the other siiiii-iiiiide"sv;

        std::promise<void> data_promise;
        std::future<void> data_future = data_promise.get_future();

        dgram_data_callback recv_dgram_cb = [&](datagram) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            data_promise.set_value();
        };
        std::atomic<bool> bad_call = false;
        dgram_data_callback overridden_dgram_cb = [&](datagram) {
            log::critical(test_cat, "Wrong dgram callback invoked!");
            bad_call = true;
        };

        opt::enable_datagrams default_gram{};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, default_gram, overridden_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, default_gram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());
        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE_FALSE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() < MAX_GREEDY_PMTUD_UDP_PAYLOAD);

        conn_interface->datagrams()->send(msg, nullptr);

        require_future(data_future);
        CHECK_FALSE(bad_call);
    }

    TEST_CASE("007 - Datagram support: Execute, Packet Splitting Enabled", "[007][datagrams][execute][split][simple]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        std::atomic<int> data_counter{0};

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](datagram d) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");
            ++data_counter;
            if (view(d.data) == "final"sv)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, recv_dgram_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        auto init_max_size = conn_interface->max_datagram_size_changed();
        REQUIRE(init_max_size);
        CHECK(*init_max_size == 0);
        CHECK_FALSE(conn_interface->max_datagram_size_changed());

        REQUIRE(client_established.wait());
        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        auto max_size = conn_interface->get_max_datagram_size();

        std::string good_msg{}, oversize_msg{};
        char v = 0;

        while (good_msg.size() < max_size)
            good_msg += v++;
        v = 0;
        while (oversize_msg.size() < max_size * 2)
            oversize_msg += v++;

        auto max_size2 = conn_interface->max_datagram_size_changed();
        REQUIRE(max_size2);
        CHECK(*max_size2 == max_size);
        CHECK(*max_size2 > init_max_size);

        CHECK_FALSE(conn_interface->max_datagram_size_changed());

        CHECK(good_msg.size() <= max_size2);
        CHECK(oversize_msg.size() > max_size2);

        auto dg = conn_interface->datagrams();
        dg->send(std::move(good_msg));
        dg->send(std::move(oversize_msg));
        dg->send("final"s);

        require_future(data_promise.get_future());
        CHECK(data_counter == 2);
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Clearing Buffer", "[007][datagrams][execute][split][rotating][clear]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        int data_counter = 0;
        int bufsize = 64, n = (bufsize / 2) + 1;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](datagram) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            if (++data_counter == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE, bufsize};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        auto max_size = conn_interface->get_max_datagram_size();

        std::vector<std::byte> good_msg{};
        unsigned char v{0};

        while (good_msg.size() < max_size)
            good_msg.push_back(static_cast<std::byte>(v++));

        auto dgram = conn_interface->datagrams();
        for (int i = 0; i < n; ++i)
            dgram->send(good_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(data_counter == n);

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        REQUIRE(TestHelper::get_datagrams_stored(*server_ci->datagrams()) == 0);
    }

    TEST_CASE(
            "007 - Datagram support: Rotating Buffer, Mixed Datagrams", "[007][datagrams][execute][split][rotating][mixed]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        int data_counter = 0;
        int n = 5;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](datagram) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            if (++data_counter == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        REQUIRE(server_endpoint->datagrams_enabled());
        REQUIRE(client->datagrams_enabled());

        REQUIRE(conn_interface->datagrams_enabled());
        REQUIRE(conn_interface->packet_splitting_enabled());

        std::this_thread::sleep_for(5ms);
        auto max_size = conn_interface->get_max_datagram_size();

        std::vector<std::byte> big_msg{}, small_msg{};
        unsigned char v{0};

        while (big_msg.size() < max_size)
            big_msg.push_back(std::byte{v++});

        while (small_msg.size() < 500)
            small_msg.push_back(std::byte{v++});

        auto dgram = conn_interface->datagrams();
        dgram->send(big_msg, nullptr);
        dgram->send(big_msg, nullptr);
        dgram->send(small_msg, nullptr);
        dgram->send(big_msg, nullptr);
        dgram->send(small_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(data_counter == n);
    }

    TEST_CASE("007 - Datagram support: Rotating Buffer, Induced Loss", "[007][datagrams][execute][split][rotating][loss]")
    {
        if (disable_rotating_buffer)
            SKIP("Rotating buffer testing not enabled for this test iteration!");

        log::trace(test_cat, "Beginning the unit test from hell");
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        int bufsize = 64, quarter = bufsize / 4;

        int counter = 0;

        std::promise<void> data_promise;

        std::vector<std::byte> received;

        dgram_data_callback recv_dgram_cb = [&](datagram d) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            received = std::move(d).extract();

            if (++counter == bufsize)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE, (int)bufsize};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client = test_net.endpoint(client_local, split_dgram, client_established);
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        auto server_ci = server_endpoint->get_all_conns(Direction::INBOUND).front();

        std::vector<std::byte> dropped_msg(1500, std::byte{'-'});
        std::vector<std::byte> successful_msg(1500, std::byte{'+'});

        TestHelper::enable_dgram_drop(static_cast<Connection&>(*server_ci));

        auto dgram = conn_interface->datagrams();
        for (int i = 0; i < quarter; ++i)
            dgram->send(dropped_msg, nullptr);

        while (TestHelper::get_dgram_debug_counter(*server_ci) < quarter)
            std::this_thread::sleep_for(10ms);

        TestHelper::disable_dgram_drop(*server_ci);

        for (int i = 0; i < bufsize; ++i)
            dgram->send(successful_msg, nullptr);

        require_future(data_promise.get_future());

        REQUIRE(counter == bufsize);
        REQUIRE(bytes_diff(received, successful_msg) == "");
    }

    namespace
    {
        uint16_t first_id(int counter)
        {
            return static_cast<uint16_t>(counter << 2 | 0b10);
        }
        uint16_t second_id(int counter)
        {
            return static_cast<uint16_t>(counter << 2 | 0b11);
        }
        uint16_t unsplit_id(int counter)
        {
            return static_cast<uint16_t>(counter << 2);
        }
        std::span<const std::byte> bytes(const std::string& s)
        {
            return std::as_bytes(std::span{s});
        }
        // Gives the buffer the two pieces of a datagram whose data spells out which pieces they
        // were, returning the reassembled datagram (if any) as a string.
        std::optional<std::string> deliver(dgram::rotating_buffer& buf, uint16_t dgid, const std::string& data)
        {
            if (auto out = buf.receive(bytes(data), dgid))
                return std::string{view(*out)};
            return std::nullopt;
        }
    }  // namespace

    TEST_CASE("007 - Datagram support: Reassembly buffer", "[007][datagrams][rotating][reassembly]")
    {
        // Blocks of 256: the newest block and the one before it are held, and the two before that
        // are late.
        dgram::rotating_buffer buf{512, 1024};

        SECTION("Halves are reassembled in either order")
        {
            CHECK_FALSE(deliver(buf, first_id(5), "A5"));
            CHECK(buf.datagrams_stored() == 1);
            CHECK(deliver(buf, second_id(5), "a5") == "A5a5");
            CHECK(buf.datagrams_stored() == 0);

            CHECK_FALSE(deliver(buf, second_id(6), "a6"));
            CHECK(deliver(buf, first_id(6), "A6") == "A6a6");
            CHECK(buf.datagrams_stored() == 0);
        }

        SECTION("A repeated half is dropped rather than paired")
        {
            CHECK_FALSE(deliver(buf, first_id(7), "A7"));
            CHECK_FALSE(deliver(buf, first_id(7), "X7"));
            CHECK(buf.datagrams_stored() == 1);
            CHECK(deliver(buf, second_id(7), "a7") == "A7a7");
        }

        SECTION("A held piece lasts until its block is two blocks old")
        {
            // 255 is the last counter of block 0, so this is the shortest it can be held.
            CHECK_FALSE(deliver(buf, first_id(255), "A255"));
            buf.observe(unsplit_id(511));
            CHECK(deliver(buf, second_id(255), "a255") == "A255a255");

            CHECK_FALSE(deliver(buf, first_id(255), "A255"));
            buf.observe(unsplit_id(512));
            CHECK(buf.datagrams_stored() == 0);
            CHECK_FALSE(deliver(buf, second_id(255), "a255"));
            CHECK(buf.datagrams_stored() == 0);
        }

        SECTION("A piece at the start of its block is held for up to bufsize-1 newer IDs")
        {
            CHECK_FALSE(deliver(buf, first_id(0), "A0"));
            buf.observe(unsplit_id(511));
            CHECK(deliver(buf, second_id(0), "a0") == "A0a0");
        }

        SECTION("Late datagrams are dropped without clearing anything")
        {
            buf.observe(unsplit_id(778));  // block 3
            CHECK_FALSE(deliver(buf, first_id(780), "A780"));
            CHECK_FALSE(deliver(buf, first_id(300), "A300"));  // block 1: late
            buf.observe(unsplit_id(10));                       // block 0: late
            CHECK(buf.datagrams_stored() == 1);
            CHECK(deliver(buf, second_id(780), "a780") == "A780a780");
        }

        SECTION("A datagram older than the reorder limit means the IDs jumped forward")
        {
            buf.observe(unsplit_id(1024));  // block 4
            CHECK_FALSE(deliver(buf, first_id(1030), "A1030"));
            buf.observe(unsplit_id(5));  // block 0: four blocks back, too old to be late
            CHECK(buf.datagrams_stored() == 0);
            CHECK_FALSE(deliver(buf, second_id(1030), "a1030"));
        }

        SECTION("Halves are paired across the counter wrap")
        {
            CHECK_FALSE(deliver(buf, first_id(16383), "A16383"));
            buf.observe(unsplit_id(3));
            CHECK(deliver(buf, second_id(16383), "a16383") == "A16383a16383");
        }

        SECTION("A stale piece is not paired with the same ID a wrap later")
        {
            CHECK_FALSE(deliver(buf, first_id(5), "A5-old"));
            // Unsplit datagrams through a whole wrap of the counter, back into block 0.
            for (int counter = 200; counter < 16384; counter += 200)
                buf.observe(unsplit_id(counter));
            buf.observe(unsplit_id(0));
            CHECK(buf.datagrams_stored() == 0);
            CHECK_FALSE(deliver(buf, second_id(5), "a5-new"));
            CHECK(deliver(buf, first_id(5), "A5-new") == "A5-newa5-new");
        }

        SECTION("Without a late range, anything older than the held blocks is a forward jump")
        {
            dgram::rotating_buffer strict{512, 512};
            strict.observe(unsplit_id(600));  // block 2
            CHECK_FALSE(deliver(strict, first_id(610), "A610"));
            strict.observe(unsplit_id(10));  // block 0
            CHECK(strict.datagrams_stored() == 0);
        }
    }

    TEST_CASE("007 - Datagram support: Reassembly buffer options", "[007][datagrams][rotating][types]")
    {
        CHECK_THROWS(opt::enable_datagrams{Splitting::ACTIVE, 32});
        CHECK_THROWS(opt::enable_datagrams{Splitting::ACTIVE, 768});
        CHECK_THROWS(opt::enable_datagrams{Splitting::ACTIVE, 16384});
        CHECK_NOTHROW(opt::enable_datagrams{Splitting::ACTIVE, 8192});

        opt::enable_datagrams dgrams{Splitting::ACTIVE, 512};
        CHECK_THROWS(dgrams.reorder_limit(256));
        CHECK_THROWS(dgrams.reorder_limit(8193));
        CHECK_NOTHROW(dgrams.reorder_limit(768));
    }

    /*
       Packet coalescing test.  When we send split packets, we have various levels of lookahead as
       to how much we will coalesce into a single packet.

       E.g. if we have packets [Aa] [Bb] [Cc] ... where the full packet is too big to fit in
       one quic datagram then a naive half split would result in sending [A] [a] [B] [b] [C] [c] ...
       in 2 quic packets per datagram.  However by alternating the order in which we send the two
       parts of the split we can coalesce the small parts together and send:
           [A] [ab] [B] [C] [cd] [D] ...
       using 3 quic packets for per 2 split datagrams, rather than 4 per 2 split datagrams.

       But we actually go further, and look ahead to see if there are other small pieces that we can
       include when trying to fill up an outgoing, partially filled packet, so that we could send:

           [A] [abcdefghij] [B] [C] [D] [E] [F] [G] [H] [I] [J]

       i.e. 10 datagrams in 11 packets.  (This depends, on course, on all the small a-j pieces
       fitting into one datagram, which will only be the case if the packets being sent are not too
       much over the splitting limit).
    */
    TEST_CASE("007 - Datagram support: Rotating Buffer, packet coalescing", "[007][datagrams][split][coalesce]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        std::atomic<int> data_counter{0};
        int n = 60;
        int target_dgrams;

        std::promise<void> data_promise;

        dgram_data_callback recv_dgram_cb = [&](datagram) {
            log::debug(test_cat, "Calling endpoint receive datagram callback... data received...");

            int count = ++data_counter;
            log::trace(test_cat, "Data counter: {}", count);
            if (count == n)
                data_promise.set_value();
        };

        opt::enable_datagrams split_dgram{Splitting::ACTIVE};

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, split_dgram, recv_dgram_cb);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        // The packing arithmetic below is exact for a 1444-byte path, so PMTUD probes only that.
        const std::array<uint16_t, 1> probe_1444{1444};
        auto client = test_net.endpoint(client_local, split_dgram, client_established, opt::max_udp_payload{probe_1444});
        auto conn_interface = client->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        // Give the connection time to figure out PMTU
        for (int i = 0; i < 10 && conn_interface->get_max_datagram_size() < 2796; i++)
            std::this_thread::sleep_for(5ms);
        REQUIRE(conn_interface->get_max_datagram_size() == 2796);

        static constexpr size_t max_unsplit = 1398;
        // If we pack two small datagram pieces together then they get packed as:
        // QUIC OVERHEAD
        // DATAGRAM FRAME HEADER (3 bytes for datagrams >= 64B)
        // DGID (2 bytes)
        // DATA
        // DATAGRAM FRAME HEADER (3 bytes for datagrams >= 64B)
        // DGID (2 bytes)
        // DATA
        // and the 1398 is already accounting for the first three overhead lines.
        //
        // And so our maximum should be 696 because 1398 - 696 - 5 - 696 = 1 and so any big and we
        // should run over.  But that's not quite right, because that's a maximum while the actual
        // quic packet includes a 1-4 byte packet number.  Since this is a new connection, we can
        // assume the packets we test here will have 1-byte numbers, which gives us another 3 bytes
        // to work with, and that's where the `+3` comes from in this and later calculations.
        // (That's only for the first 256 quic packets, but that's enough for this test).
        static constexpr size_t max_two_packable = (max_unsplit + 3 - 5) / 2;
        size_t dgram_size = GENERATE(
                1,
                100,
                max_two_packable - 1,
                max_two_packable,
                max_two_packable + 1,
                1000,
                max_unsplit,
                max_unsplit + 1,
                max_unsplit + 50,
                max_unsplit + 100,
                max_unsplit + 500,
                max_unsplit + 1000,
                max_unsplit * 2);
        int lookahead = GENERATE(-1 /* should become the default, i.e. 8*/, 0, 1, 5, 10, 100);

        log::debug(log_cat, "DGRAM_SIZE: {}, LOOKAHEAD: {}", dgram_size, lookahead);
        conn_interface->set_split_datagram_lookahead(lookahead);

        if (dgram_size <= max_unsplit)
        {
            // max_unsplit already includes a deduction of 3 for the datagram frame and 2 for the
            // padding, so add those back in, then divide to see how many we can fit where each
            // include that 5 byte overhead:
            auto max_coalesced = (max_unsplit + 3 + 5) / (dgram_size + 5);
            log::debug(log_cat, "max coal: {}", max_coalesced);
            target_dgrams = n / max_coalesced;
        }
        else
        {
            // Packet splitting.  Every packet requires one full datagram for the big piece, but
            // then we also want to calculate how many small pieces we can coalesce together (with a
            // cap at lookahead + 2).
            auto packable = std::min<size_t>(
                    2 + (lookahead < 0 ? dgram::queue::DEFAULT_SPLIT_LOOKAHEAD : lookahead),
                    (max_unsplit + 3 + 5) / (dgram_size - max_unsplit + 5));
            log::debug(log_cat, "packable: {}", packable);
            target_dgrams = n + (n + packable - 1) / packable;
        }

        std::vector<std::byte> big;
        big.reserve(dgram_size);
        uint8_t v{0};

        while (big.size() < dgram_size)
            big.push_back(static_cast<std::byte>(v++));

        TestHelper::enable_dgram_counter(*conn_interface);

        std::promise<void> pr;

        test_net.loop()->call([&, dgram = conn_interface->datagrams()]() {
            for (int i = 0; i < n; i++)
                dgram->send(big, nullptr);

            pr.set_value();
        });

        require_future(pr.get_future());
        require_future(data_promise.get_future());

        REQUIRE(data_counter.load() == n);
        auto send_packet_count = TestHelper::disable_dgram_counter(*conn_interface);
        REQUIRE(send_packet_count >= target_dgrams);
        REQUIRE(send_packet_count <= target_dgrams + 5 /*fudge factor for other quic packet (ACKs, etc.)*/
#if defined(__APPLE__) && defined(__x86_64__)
                                             + 10  // extra fudge factor for who knows what amd64-macos does
#endif
        );
    }
    TEST_CASE("007 - Datagram support: Queue limit drops excess datagrams", "[007][datagrams][queue_limit]")
    {
        auto client_established = callback_waiter{[](Connection&) {}};

        Network test_net{};

        // Small enough that sending a handful of ~500B datagrams will blow past it.
        constexpr size_t queue_limit = 1000;

        // Fires once the server has received at least one datagram, confirming that the queue
        // drained between the two burst batches below.
        std::promise<void> server_received_some;
        std::atomic<bool> received_promise_set{false};
        dgram_data_callback server_recv_cb = [&](datagram) {
            if (!received_promise_set.exchange(true))
                server_received_some.set_value();
        };

        opt::enable_datagrams dgram_opt{};
        dgram_opt.queue_limit(queue_limit);

        Address server_local{};
        Address client_local{};

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        auto server_endpoint = test_net.endpoint(server_local, dgram_opt);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_recv_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local, dgram_opt, client_established);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        REQUIRE(client_established.wait());

        std::this_thread::sleep_for(5ms);

        // Each payload is slightly over half the limit, so the third one will be dropped; 10
        // sends guarantees we see several drops.
        std::vector<std::byte> payload(queue_limit / 2 + 1, std::byte{0xab});

        auto batch_send = [&] {
            // Send the whole batch atomically on the loop thread so every enqueue happens before
            // flush_packets() can drain any of them.
            std::promise<void> sent;
            test_net.loop()->call([&, dgrams = conn_interface->datagrams()]() {
                for (int i = 0; i < 10; ++i)
                    dgrams->send(payload, nullptr);
                sent.set_value();
            });
            require_future(sent.get_future());
        };

        // First burst: queue fills and some datagrams are dropped.
        batch_send();

        auto drop_count =
                test_net.loop()->call_get([&] { return TestHelper::get_dgram_drop_count(*conn_interface->datagrams()); });

        REQUIRE(drop_count > 0);

        // Wait for the server to receive something, confirming the queue has drained and the
        // connection is healthy before the second burst.
        require_future(server_received_some.get_future());

        // Second burst: drop count must increase again, confirming the limit is enforced
        // continuously and not just on the first overflow.
        batch_send();

        auto drop_count_2 =
                test_net.loop()->call_get([&] { return TestHelper::get_dgram_drop_count(*conn_interface->datagrams()); });

        REQUIRE(drop_count_2 > drop_count);
    }

    TEST_CASE("007 - Datagram support: Dropped unsendable datagrams leave the queue limit", "[007][datagrams][queue_limit]")
    {
        // The queue limit is enforced against pending_bytes(), so any bytes that a drop fails to
        // release would count against the limit for the rest of the connection.
        dgram::queue q{true};
        std::vector<std::byte> big(2000), small(100);
        q.emplace(big, 1 << 2, nullptr);
        q.emplace(big, 2 << 2, nullptr);
        q.emplace(small, 3 << 2, nullptr);
        REQUIRE(q.pending_bytes() == 4100);

        // Simulates a PMTU decrease: two 900-byte pieces can't carry the big ones any more.
        auto d = q.fetch(900, false);
        REQUIRE(d);
        CHECK(d->id == 3 << 2);
        CHECK(q.pending_bytes() == 100);

        q.confirm_sent();
        CHECK(q.empty());
        CHECK(q.pending_bytes() == 0);
    }

    TEST_CASE("007 - Datagram support: Pending bytes count only unsent split pieces", "[007][datagrams][queue_limit]")
    {
        dgram::queue q{true};
        std::vector<std::byte> payload(2000);
        q.emplace(payload, 1 << 2, nullptr);
        q.emplace(payload, 2 << 2, nullptr);
        REQUIRE(q.pending_bytes() == 4000);

        auto send = [&q](bool prefer_small) {
            auto d = q.fetch(1200, prefer_small);
            REQUIRE(d);
            q.confirm_sent();
            return d->id;
        };

        // Small pieces first: the head's, then the lookahead's.
        CHECK(send(true) == ((1 << 2) | 0b11));
        CHECK(q.pending_bytes() == 3200);
        CHECK(send(true) == ((2 << 2) | 0b11));
        CHECK(q.pending_bytes() == 2400);

        CHECK(send(false) == ((1 << 2) | 0b10));
        CHECK(q.pending_bytes() == 1200);
        CHECK(send(false) == ((2 << 2) | 0b10));
        CHECK(q.pending_bytes() == 0);
        CHECK(q.empty());
    }

    TEST_CASE("007 - Datagram support: Pending bytes across 0-RTT", "[007][datagrams][queue_limit][0rtt]")
    {
        dgram::queue q{true};
        q.early_data_begin();
        std::vector<std::byte> big(2000), small(100);
        q.emplace(big, 1 << 2, nullptr);
        q.emplace(small, 2 << 2, nullptr);
        q.emplace(small, 3 << 2, nullptr);
        REQUIRE(q.pending_bytes() == 2200);

        auto send = [&q] {
            auto d = q.fetch(1200, false);
            REQUIRE(d);
            q.confirm_sent();
        };

        // The big one goes out in two pieces, then the first small one goes out whole.
        send();
        CHECK(q.pending_bytes() == 1000);
        send();
        CHECK(q.pending_bytes() == 200);
        send();
        CHECK(q.pending_bytes() == 100);

        SECTION("accepted")
        {
            q.early_data_end(true);
            CHECK(q.size() == 1);
            CHECK(q.pending_bytes() == 100);
        }
        SECTION("rejected")
        {
            q.early_data_end(false);
            CHECK(q.size() == 3);
            CHECK(q.pending_bytes() == 2200);
        }
        SECTION("retried with a piece in flight")
        {
            q.emplace(big, 4 << 2, nullptr);
            send();  // the last small one
            send();  // first piece of the new big one
            CHECK(q.pending_bytes() == 800);
            q.early_data_retry();
            CHECK(q.size() == 4);
            CHECK(q.pending_bytes() == 4200);
        }
    }

    TEST_CASE("007 - Datagram support: queued datagram discarded with its channel", "[007][datagrams][destruction]")
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
