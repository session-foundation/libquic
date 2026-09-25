#include "utils.hpp"

#include <oxen/quic.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxenc/endian.h>
#include <oxenc/hex.h>

#include <CLI/Validators.hpp>

#include <sodium/crypto_sign_ed25519.h>

#include <chrono>
#include <future>
#include <random>
#include <thread>

using namespace oxen::quic;

int main(int argc, char* argv[])
{
    CLI::App cli{"libQUIC test client"};

    bool server = false;
    cli.add_option("--server", server, "Run in server (listen) mode instead of connecting out");

    std::string addr = "127.0.0.1:5511";
    cli.add_option("--addr", addr, "Address to listen on (if --server), or connect to (otherwise)")
            ->type_name("IP:PORT")
            ->capture_default_str();

    int timeout = 30;
    cli.add_option("--timeout", timeout, "Timeout (in seconds) for the connection idle timeout")
            ->type_name("SECONDS")
            ->capture_default_str();

    int ping = 0;
    cli.add_option("--ping", ping, "Keep-alive timer for PING frames to keep a connection alive; if 0 then don't send PINGs")
            ->type_name("SECONDS")
            ->capture_default_str();

    std::string log_file, log_level;
    add_log_opts(cli, log_file, log_level);

    std::string server_cert{"./servercert.pem"};
    cli.add_option("-c,--servercert", server_cert, "Path to server certificate to use")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    std::string cert{"./clientcert.pem"}, key{"./clientkey.pem"};
    cli.add_option("-C,--certificate", key, "Path to client certificate for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);
    cli.add_option("-K,--key", key, "Path to client key to use for client authentication")
            ->type_name("FILE")
            ->capture_default_str()
            ->check(CLI::ExistingFile);

    try
    {
        cli.parse(argc, argv);
    }
    catch (const CLI::ParseError& e)
    {
        return cli.exit(e);
    }

    setup_logging(log_file, log_level);

    Network net;
    std::string client_seed, client_sk, client_pubkey;
    std::string server_seed, server_sk, server_pubkey;
    client_sk.resize(64);
    client_pubkey.resize(32);
    client_seed = oxenc::from_hex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    server_sk.resize(64);
    server_pubkey.resize(32);
    server_seed = oxenc::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    crypto_sign_ed25519_seed_keypair(
            reinterpret_cast<unsigned char*>(client_pubkey.data()),
            reinterpret_cast<unsigned char*>(client_sk.data()),
            reinterpret_cast<unsigned char*>(client_seed.data()));

    auto tls = server ? GNUTLSCreds::make_from_ed_keys(server_seed, server_pubkey)
                      : GNUTLSCreds::make_from_ed_keys(client_seed, client_pubkey);

    Network client_net{};

    std::vector<std::unique_ptr<stream_data>> streams;
    streams.reserve(parallel);

    stream_close_callback stream_closed = [&](Stream& s, uint64_t errcode) {
        size_t i = s.stream_id() >> 2;
        log::critical(test_cat, "Stream {} (rawid={}) closed (error={})", i, s.stream_id(), errcode);
    };

    stream_data_callback on_stream_data = [&](Stream& s, bstring_view data) {
        size_t i = s.stream_id() >> 2;
        if (i >= parallel)
        {
            log::critical(test_cat, "Something getting wrong: got unexpected stream id {}", s.stream_id());
            return;
        }

        auto& sd = *streams[i];
        if (sd.done)
        {
            log::error(
                    test_cat, "Already got a hash from the other side of stream {}, what is this nonsense‽", s.stream_id());
            return;
        }

        if (!sd.done_sending)
        {
            log::error(
                    test_cat,
                    "Got a stream (stream {}) response ({}B) before we were done sending data!",
                    s.stream_id(),
                    data.size());
            sd.failed = true;
        }
        else if (data.size() != 33)
        {
            log::error(test_cat, "Got unexpected data from the other side: {}B != 32B", data.size());
            sd.failed = true;
        }
        else if (data.substr(0, 32) != sd.hash)
        {
            log::critical(
                    test_cat,
                    "Hash mismatch: other size said {}, we say {}",
                    oxenc::to_hex(data.begin(), data.end()),
                    oxenc::to_hex(sd.hash.begin(), sd.hash.end()));
            sd.failed = true;
        }
        else if (static_cast<uint8_t>(data[32]) != sd.checksum)
        {
            log::critical(test_cat, "Checksum mismatch: other size said {}, we say {}", data[32], sd.checksum);
            sd.failed = true;
        }
        else
        {
            sd.failed = false;
            log::critical(
                    test_cat,
                    "Hashes matched ({}, {}), hurray!\n",
                    oxenc::to_hex(sd.hash.begin(), sd.hash.end()),
                    sd.checksum);
        }

        sd.done = true;
        sd.run_prom.set_value();
    };

    Address client_local{};
    if (!local_addr.empty())
    {
        auto [a, p] = parse_addr(local_addr);
        client_local = Address{a, p};
    }

    auto [server_a, server_p] = parse_addr(remote_addr);
    RemoteAddress server_addr{server_a, server_p};

    log::debug(test_cat, "Calling 'client_connect'...");
    auto client = client_net.endpoint(client_local);
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
            s.stream->send(bstring_view{s.bufs[0].data(), s.bufs[0].size()});
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
