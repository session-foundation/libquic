/*
    Test server binary
*/

#include "utils.hpp"

#include <oxen/quic/opt.hpp>

#include <fmt/ranges.h>

#include <random>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest server"};

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_addr = DEFAULT_SPEEDTEST_ADDR.to_string();
    std::string seed_string;
    bool enable_0rtt;
    bool disable_pmtud;
    common_server_opts(cli, server_addr, seed_string, enable_0rtt, disable_pmtud);

    bool verify_datagrams = false;
    cli.add_flag("-V,--verify-datagrams", verify_datagrams, "Verify the value of each received datagrams");

    double flakiness = 0.0;
    cli.add_option("-f,--flakiness", flakiness, "Fail to respond to pings this proportion of the time.")
            ->capture_default_str()
            ->expected(0.0, 1.0);

    bool verbose_speed = false;
    cli.add_flag("--verbose-speed", verbose_speed, "Prints current speed on a connection every 100ms.");

    bool gso = false, gro = false;
    cli.add_flag("--gso", gso, "Send with GSO, if libquic was built with it and the OS supports it.");
    cli.add_flag("--gro", gro, "Receive with GRO, if libquic was built with it and the OS supports it.");
    cli.add_flag_callback("-G", [&] { gso = gro = true; }, "Same as --gso --gro.");

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    auto SPEEDTEST = log::Cat("SPEEDTEST");
    log::set_level(SPEEDTEST, log::Level::info);

    auto [seed, pubkey] = generate_ed25519(seed_string);
    auto server_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        server_tls->enable_inbound_0rtt();

    auto server_local = Address::parse(server_addr, DEFAULT_SPEEDTEST_ADDR.port());

    stream_open_callback stream_opened = [&](Stream& s) {
        log::warning(test_cat, "Stream {} opened!", s.stream_id());
        return 0;
    };

    struct recv_info
    {
        uint64_t n_expected = 0;
        uint64_t n_received = 0;
        uint64_t received = 0;
        uint64_t received_before_current_window = 0;
        std::chrono::time_point<std::chrono::steady_clock> start_time = std::chrono::steady_clock::now();
        std::chrono::time_point<std::chrono::steady_clock> last_print = std::chrono::steady_clock::now();
        size_t last_dgram_size = 0;
        bool ping = false;
        // The datagram test's control stream, once it has started.
        int64_t control_id = -1;
        bool reported = false;
    };

    std::unordered_map<ConnectionID, recv_info> conn_dgram_data;

    // Handles data on a datagram test's control stream: its header (when `header`) and then the
    // client's notice that all of its datagrams have gone out, which is answered right away with
    // how many arrived.
    auto dgram_control = [&](Stream& s, std::span<const std::byte> data, bool header) {
        auto& info = conn_dgram_data[s.reference_id];
        const auto peer = s.get_conn()->remote();
        if (header)
        {
            if (data.size() < 16)
            {
                log::error(test_cat, "Invalid datagram test header: expected 16 bytes, got {}", data.size());
                return;
            }
            info.control_id = s.stream_id();
            info.n_expected = oxenc::load_little_to_host<uint64_t>(data.data() + 8);
            log::warning(test_cat, "Datagram test from {}, expecting {} datagrams!", peer, info.n_expected);
            data = data.subspan(16);
        }
        if (data.empty())
            return;
        if (data.size() != 1 || data.front() != SPEEDTEST_DGRAMS_SENT || info.reported)
        {
            log::error(test_cat, "Unexpected {}B of data on datagram test control stream", data.size());
            return;
        }
        info.reported = true;
        log::critical(
                test_cat,
                "Datagram test complete for {}. Fidelity: {}\% ({} received of {} expected)",
                peer,
                info.n_expected ? 100.0 * info.n_received / info.n_expected : 0.0,
                info.n_received,
                info.n_expected);
        std::string reply(8, '\0');
        oxenc::write_host_as_little(info.n_received, reply.data());
        s.send(std::move(reply));
    };

    struct stream_info
    {
        uint64_t expected;
        uint64_t received = 0;
        uint64_t received_before_current_window = 0;
        std::chrono::time_point<std::chrono::steady_clock> start_time = std::chrono::steady_clock::now();
        std::chrono::time_point<std::chrono::steady_clock> last_print = std::chrono::steady_clock::now();
    };

    std::map<ConnectionID, std::map<int64_t, stream_info>> csd;

    stream_data_callback stream_data = [&](Stream& s, std::span<const std::byte> data) {
        if (auto dg = conn_dgram_data.find(s.reference_id);
            dg != conn_dgram_data.end() && dg->second.control_id == s.stream_id())
            return dgram_control(s, data, false);

        auto& sd = csd[s.reference_id];

        auto it = sd.find(s.stream_id());
        if (it == sd.end())
        {
            if (data.size() < sizeof(uint64_t))
            {
                log::error(
                        SPEEDTEST,
                        "Unexpected initial stream data on {}:{}: received {} < 8 bytes",
                        s.reference_id,
                        s.stream_id(),
                        data.size());
                return;
            }

            auto size = oxenc::load_little_to_host<uint64_t>(data.data());
            if (size == SPEEDTEST_DGRAM_CONTROL)
                return dgram_control(s, data, true);
            data = data.subspan(sizeof(uint64_t));

            it = sd.emplace(s.stream_id(), size).first;
            log::info(SPEEDTEST, "First data from new stream {}:{}, expecting {}B!", s.reference_id, s.stream_id(), size);
        }

        auto& [ignore, info] = *it;

        bool need_more = info.received < info.expected;

        info.received += data.size();

        if (verbose_speed)
        {
            auto now = std::chrono::steady_clock::now();
            if (now - info.last_print > 100ms)
            {
                auto elapsed = std::chrono::duration<double>{now - info.last_print}.count();
                info.last_print = now;
                auto recv = info.received - info.received_before_current_window;
                info.received_before_current_window = info.received;
                log::critical(SPEEDTEST, "Speed last ~100ms: {:.3f}MB/s", recv / 1'000'000.0 / elapsed);
                auto elapsed_overall = std::chrono::duration<double>{now - info.start_time}.count();
                log::critical(SPEEDTEST, "Overall speed: {:.3f}MB/s\n", info.received / 1'000'000.0 / elapsed_overall);
            }
        }

        if (info.received > info.expected)
        {
            log::error(
                    SPEEDTEST,
                    "Received too much data on stream {}:{}: ({}B > {}B)!",
                    s.reference_id,
                    s.stream_id(),
                    info.received,
                    info.expected);
            if (!need_more)
                return;
            data = data.first(data.size() - (info.received + info.expected));
        }

        if (info.received >= info.expected)
        {
            log::info(SPEEDTEST, "Data from stream {}:{} complete ({} B).", s.reference_id, s.stream_id(), info.received);
            s.send("\x00"s);
        }
    };

    std::vector<std::byte> dgram_rainbow;
    dgram_rainbow.resize(5000);
    for (size_t i = 0; i < dgram_rainbow.size(); i++)
        dgram_rainbow[i] = static_cast<std::byte>(i % 256);

    auto flake = [rng = std::mt19937_64{std::random_device{}()},
                  flake = std::bernoulli_distribution{flakiness},
                  &flakiness]() mutable -> bool { return flakiness > 0 ? flake(rng) : false; };

    dgram_data_callback recv_dgram_cb = [&](datagram&& dg) {
        auto& dgram_data = conn_dgram_data[dg.conn.reference_id()];

        const auto size = dg.data.size();

        // Pings are 4 bytes and a datagram test's datagrams at least 5, so a connection whose first
        // datagram has 4 bytes is pinging.
        if (dgram_data.n_received == 0 && size == 4)
            dgram_data.ping = true;
        if (dgram_data.ping)
        {
            if (size != 4)
            {
                log::error(test_cat, "Received invalid ping datagram of size {} (expected 4 bytes); ignoring", size);
                return;
            }
            auto ping_num = oxenc::load_little_to_host<uint32_t>(dg.data.data());
            if (flake())
                log::debug(test_cat, "received ping {} but simulating flakiness and not replying", ping_num);
            else
            {
                log::debug(test_cat, "received ping {}, reflecting it", ping_num);
                dg.datagrams.send(std::move(dg).extract());
            }
            return;
        }

        if (size != dgram_data.last_dgram_size)
        {
            log::warning(
                    test_cat, "Received a changed datagram size {}; last datagram was {}", size, dgram_data.last_dgram_size);
            dgram_data.last_dgram_size = size;
        }

        auto& info = dgram_data;

        info.received += size;
        if (verbose_speed)
        {
            auto now = std::chrono::steady_clock::now();
            if (now - info.last_print > 100ms)
            {
                auto elapsed = std::chrono::duration<double>{now - info.last_print}.count();
                info.last_print = now;
                auto recv = info.received - info.received_before_current_window;
                info.received_before_current_window = info.received;
                log::critical(SPEEDTEST, "Speed last ~100ms: {:.3f}MB/s", recv / 1'000'000.0 / elapsed);
                auto elapsed_overall = std::chrono::duration<double>{now - info.start_time}.count();
                log::critical(SPEEDTEST, "Overall speed: {:.3f}MB/s\n", info.received / 1'000'000.0 / elapsed_overall);
            }
        }

        if (verify_datagrams)
        {
            // The first byte value is itself the rainbow offset, and goes 1->250 repeatedly.
            size_t offset = static_cast<uint8_t>(dg.data[0]);
            bool bad = false;
            if (offset < 1 || offset > 250)
            {
                bad = true;
                log::error(log_cat, "Datagram {} verification found invalid first byte value {}", info.n_received, offset);
            }
            else if (view(dg.data) != view(std::span{dgram_rainbow}.subspan(offset, size)))
            {
                bad = true;
            }
            if (bad)
            {
                log::error(
                        test_cat,
                        "Datagram {} verification failed: expected byte rainbow, received {}",
                        info.n_received,
                        buffer_printer{dg.data});
            }
        }

        info.n_received++;

        // The expected count isn't known yet if the control stream's header hasn't arrived.
        if (info.n_expected && info.n_received > info.n_expected)
            log::critical(test_cat, "Received too many datagrams ({} > {})!", info.n_received, info.n_expected);
    };

    Loop loop;
    std::shared_ptr<Endpoint> server;
    try
    {
        std::optional<opt::max_udp_payload> mtu;
        if (disable_pmtud)
            mtu.emplace(opt::max_udp_payload::minimum());
        std::optional<opt::allow_gso> allow_gso;
        if (gso)
            allow_gso.emplace();
        std::optional<opt::allow_gro> allow_gro;
        if (gro)
            allow_gro.emplace();

        log::debug(test_cat, "Starting up endpoint");
        server = Endpoint::endpoint(
                loop,
                server_local,
                generate_static_secret(seed_string),
                opt::inbound_alpn("speedtests"),
                mtu,
                allow_gso,
                allow_gro,
                opt::enable_datagrams{Splitting::ACTIVE});
        server->listen(server_tls, stream_opened, stream_data, recv_dgram_cb);
    }
    catch (const std::exception& e)
    {
        log::critical(test_cat, "Failed to start server: {}!", e.what());
        return 1;
    }

    server_log_listening(server_local, DEFAULT_SPEEDTEST_ADDR, pubkey, seed_string, enable_0rtt);

    for (;;)
        std::this_thread::sleep_for(10min);
}
