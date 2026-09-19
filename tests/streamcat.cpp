/*
 * Connects to a quic server, sends bt stream data, and waits for the response.
 */

#include "utils.hpp"

#include <gnutls/crypto.h>

#include <random>
#include <span>
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

    std::string commands;
    cli.add_option("commands", commands, "Pairs of endpoint and body values to send.  Each pair makes one request")
            ->required()
            ->expected(2, -1);

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    if (commands.size() % 2)
    {
        std::cerr << "Invalid commands: expected even number of command/body pairs\n";
        return 1;
    }

    setup_logging(log_file, log_level);

    Loop loop;

    auto [seed, pubkey] = generate_ed25519();
    auto client_tls = GNUTLSCreds::make_from_ed_keys(seed, pubkey);
    if (enable_0rtt)
        zerortt_storage::enable(*client_tls, zerortt_path);

    Address client_local{};
    if (!local_addr.empty())
        client_local = Address::parse(local_addr);

    RemoteAddress server_addr{remote_pubkey, Address::parse(remote_addr)};

    log::debug(test_cat, "Constructing endpoint on {}", client_local);
    std::optional<opt::disable_mtu_discovery> mtu;
    if (disable_pmtud)
        mtu.emplace();

    auto client = Endpoint::endpoint(loop, client_local, generate_static_secret(seed_string), opt::alpns{"speedtest"}, mtu);
    log::debug(test_cat, "Connecting to {}...", server_addr);
    auto client_ci = client->connect(server_addr, client_tls, on_stream_data, stream_closed);

    auto per_stream = size / parallel;

    auto gen_data =
            [no_hash, no_checksum](
                    RNG& rng, size_t size, std::vector<std::byte>& data, gnutls_hash_hd_t& hasher, uint8_t& checksum) {
                assert(size > 0);

                using rng_value = RNG::result_type;

                static_assert(
                        RNG::min() == 0 && std::is_unsigned_v<rng_value> &&
                        RNG::max() == std::numeric_limits<rng_value>::max());

                constexpr size_t rng_size = sizeof(rng_value);
                const size_t rng_chunks = (size + rng_size - 1) / rng_size;
                const size_t size_data = rng_chunks * rng_size;

                // Generate some deterministic data from our rng; we're cheating a little here with the RNG
                // output value (which means this test won't be the same on different endian machines).
                data.resize(size_data);
                auto* rng_data = reinterpret_cast<rng_value*>(data.data());
                for (size_t i = 0; i < rng_chunks; i++)
                    rng_data[i] = static_cast<rng_value>(rng());
                data.resize(size);

                // Hash/checksum it (so that we can verify the hash response at the end)
                if (!no_checksum)
                {
                    uint64_t csum = 0;
                    const uint64_t* stuff = reinterpret_cast<const uint64_t*>(data.data());
                    for (size_t i = 0; i < data.size() / 8; i++)
                        csum ^= stuff[i];
                    for (int i = 0; i < 8; i++)
                        checksum ^= reinterpret_cast<const uint8_t*>(&csum)[i];
                    for (size_t i = data.size() & ~0b111; i < data.size(); i++)
                        checksum ^= static_cast<uint8_t>(data[i]);
                }

                if (!no_hash)
                    gnutls_hash(hasher, reinterpret_cast<unsigned char*>(data.data()), data.size());
            };

    if (pregenerate)
    {
        log::warning(test_cat, "Pregenerating data...");
    }

    for (size_t i = 0; i < parallel; i++)
    {
        uint64_t my_data = per_stream + (i == 0 ? size % parallel : 0);
        auto& s = *streams.emplace_back(std::make_unique<stream_data>(
                my_data, rng_seed + i, pregenerate ? my_data : chunk_size, pregenerate ? 1 : chunk_num));

        if (pregenerate)
        {
            gen_data(s.rng, my_data, s.bufs[0], s.sent_hasher, s.checksum);
            s.hash.resize(32);
            gnutls_hash_output(s.sent_hasher, reinterpret_cast<unsigned char*>(s.hash.data()));
        }
    }
    if (pregenerate)
    {
        log::warning(test_cat, "Data pregeneration done");
    }

    auto started_at = std::chrono::steady_clock::now();

    for (size_t i = 0; i < parallel; i++)
    {
        auto& s = *streams[i];
        s.stream = client_ci->open_stream();
        std::string remaining_str;
        remaining_str.resize(8);
        oxenc::write_host_as_little(s.remaining, remaining_str.data());
        s.stream->send(std::move(remaining_str));
        if (pregenerate)
        {
            s.remaining = 0;
            s.done_sending = true;
            s.stream->send(s.bufs[0], nullptr);
        }
        else
        {
            s.stream->send_chunks(
                    [&, i](const Stream&) -> std::vector<std::byte>* {
                        auto& sd = *streams[i];
                        auto& data = sd.bufs[sd.next_buf++];
                        sd.next_buf %= sd.bufs.size();

                        const auto size = std::min(sd.remaining, chunk_size);
                        if (size == 0)
                            return nullptr;

                        gen_data(sd.rng, size, data, sd.sent_hasher, sd.checksum);

                        sd.remaining -= size;

                        if (sd.remaining == 0)
                        {
                            sd.hash.resize(32);
                            gnutls_hash_output(sd.sent_hasher, reinterpret_cast<unsigned char*>(sd.hash.data()));
                            sd.done_sending = true;
                        }

                        return &data;
                    },
                    nullptr,
                    chunk_num);
        }
    }

    for (;;)
    {
        bool all_done = true;
        for (auto& s : streams)
        {
            if (!s->done)
            {
                all_done = false;
                s->running.get();
                break;
            }
        }
        if (all_done)
            break;
    }

    bool all_good = true;
    for (auto& s : streams)
    {
        if (s->failed)
        {
            all_good = false;
            break;
        }
    }

    if (!all_good)
        fmt::print("OMG failed!\n");

    auto elapsed = std::chrono::duration<double>{std::chrono::steady_clock::now() - started_at}.count();
    fmt::print("Elapsed time: {:.3f}s\n", elapsed);
    fmt::print("Speed: {:.3f}MB/s\n", size / 1'000'000.0 / elapsed);

    return 0;
}
