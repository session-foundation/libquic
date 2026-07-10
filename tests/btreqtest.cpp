/*
 * Connects to a quic server, sends bt stream data, and waits for the response.
 */

#include "oxen/quic/opt.hpp"
#include "utils.hpp"

#include <gnutls/crypto.h>

#include <chrono>
#include <vector>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC stream speedtest client"};

    std::string local_addr, remote_addr, remote_pubkey, seed_string;
    bool enable_0rtt, disable_pmtud;
    std::filesystem::path zerortt_path;
    common_client_opts(cli, local_addr, remote_addr, remote_pubkey, seed_string, disable_pmtud, enable_0rtt, zerortt_path);

    std::string alpn;
    cli.add_option("-a,--alpn", alpn, "Client ALPN to use when negotiating the connection")->required();

    bool unauthenticated = false;
    cli.add_flag(
            "-U,--unauthenticated",
            unauthenticated,
            "Connect without any client authentication.  Without this, a randomly generated key is used for client-side "
            "keypair.");

    cli.allow_extras();

    std::string log_file, log_level = "warning;quic-test=info";
    add_log_opts(cli, log_file, log_level);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    std::vector<std::string> commands = cli.remaining();
    if (commands.empty() || commands.size() % 2)
    {
        std::cerr << (commands.empty() ? "No commands given" : "Invalid number of CMD BODY arguments")
                  << ".  Usage: " << argv[0] << " [options...] CMD BODY [CMD2 BODY2 ...]\n";
        return 1;
    }

    setup_logging(log_file, log_level);

    Loop loop;

    std::shared_ptr<GNUTLSCreds> client_tls;
    if (unauthenticated)
        client_tls = GNUTLSCreds::make_unauthenticated();
    else
    {
        auto [seed, pubkey] = generate_ed25519();
        client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    }

    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    Address client_local{};
    if (!local_addr.empty())
        client_local = Address::parse(local_addr);

    RemoteAddress server_addr{remote_pubkey, Address::parse(remote_addr)};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    std::optional<opt::max_udp_payload> mtu;
    if (disable_pmtud)
        mtu.emplace(opt::max_udp_payload::minimum());

    auto client =
            Endpoint::endpoint(loop, client_local, generate_static_secret(seed_string), opt::outbound_alpns{{alpn}}, mtu);
    log::info(test_cat, "Connecting to {}...", server_addr);
    std::atomic<bool> failed = false;
    std::promise<void> connected;
    auto conn = client->connect(
            server_addr,
            client_tls,
            [&](Connection&) {
                log::info(test_cat, "Connection established");
                connected.set_value();
            },
            [&](Connection&, uint64_t errcode) {
                if (errcode)
                {
                    log::error(test_cat, "Connection failed (ec={})", errcode);
                    failed = true;
                }
                else
                    log::info(test_cat, "Connection closed.");
            });

    connected.get_future().get();

    auto s = conn->open_stream<BTRequestStream>();

    for (auto it = commands.begin(); it != commands.end() && !failed;)
    {
        const auto& ep = *it++;
        const auto& body = *it++;

        if (ep == "sleep")
        {
            int sleep_seconds;
            if (auto [ptr, ec] = std::from_chars(body.data(), body.data() + body.size(), sleep_seconds); ec != std::errc{})
            {
                std::cerr << "Invalid 'sleep' pseudo-command: usage:  sleep SECONDS\n";
                return 1;
            }
            log::info(test_cat, "Sleeping for {}s", sleep_seconds);
            std::this_thread::sleep_for(sleep_seconds * 1s);
            continue;
        }

        log::info(test_cat, "Sending {} request...", ep);
        auto sent = std::chrono::steady_clock::now();
        std::promise<void> prom;
        s->command(ep, body, [&sent, &ep, &prom](message m) {
            double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - sent).count();

            if (m)
            {
                log::info(test_cat, "Received {}-byte {} response in {:.3f}s", m.body().size(), ep, elapsed);
                std::cout << m.body() << "\n";
            }
            else if (m.timed_out)
                log::warning(test_cat, "Request {} timed out in {:.3f}s", ep, elapsed);
            else
                log::warning(test_cat, "Request {} errored in {:.3f}s: {}", ep, elapsed, m.body());
            prom.set_value();
        });
        prom.get_future().wait();
    }

    return 0;
}
