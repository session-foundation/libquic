#include "unit_test.hpp"

#include <iterator>

namespace oxen::quic::test
{
    using namespace std::literals;

    TEST_CASE("005 - Chunked stream sending: Execution", "[005][chunked][excecute]")
    {
        Network test_net{};

        std::mutex recv_mut;
        std::string received;
        std::string expected =
                "HELLO![CHUNK-1][CHUNK-2][CHUNK-3][Chunk-4][Chunk-5][Chunk-6][chunk-7][chunk-8][chunk-9][chunk-10]Goodbye."s;

        std::promise<void> finished_p;
        std::future<void> finished_f = finished_p.get_future();

        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> data) {
            std::lock_guard lock{recv_mut};
            received.append(reinterpret_cast<const char*>(data.data()), data.size());

            try
            {
                if (received.size() == expected.size())
                    finished_p.set_value();
            }
            catch (std::exception& e)
            {
                throw std::runtime_error(e.what());
            }
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        auto stream = conn_interface->open_stream();
        stream->send("HELLO!"s);

        int i = 0;
        constexpr size_t parallel_chunks = 2;
        std::array<std::vector<char>, parallel_chunks> bufs;

        stream->send_chunks(
                [&](const Stream& s) {
                    log::info(test_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                    if (i++ < 3)
                        return fmt::format("[CHUNK-{}]", i);
                    i--;
                    return ""s;
                },
                [&](Stream& s) {
                    auto pointer_chunks = [&](const Stream& s) -> std::vector<char>* {
                        log::info(test_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                        if (i++ < 6)
                        {
                            auto& vec = bufs[i % parallel_chunks];
                            vec.clear();
                            fmt::format_to(std::back_inserter(vec), "[Chunk-{}]", i);
                            return &vec;
                        }
                        i--;
                        return nullptr;
                    };

                    s.send_chunks(
                            pointer_chunks,
                            [&](Stream& s) {
                                auto smart_ptr_chunks = [&](const Stream& s) -> std::unique_ptr<std::vector<char>> {
                                    log::info(test_cat, "getting next chunk ({}) for stream {}", i, s.stream_id());
                                    if (i++ >= 10)
                                        return nullptr;
                                    auto vec = std::make_unique<std::vector<char>>();
                                    fmt::format_to(std::back_inserter(*vec), "[chunk-{}]", i);
                                    return vec;
                                };
                                s.send_chunks(
                                        smart_ptr_chunks,
                                        [&](Stream& s) {
                                            // (Lokinet RPC was here)
                                            log::info(test_cat, "All chunks done!");
                                            s.send("Goodbye."s);
                                        },
                                        parallel_chunks);
                            },
                            parallel_chunks);
                },
                parallel_chunks);

        // The stream is opened without waiting for the handshake, so one lost packet costs a ~1s
        // ngtcp2 retransmit timeout before the data can arrive.
        require_future(finished_f, 5s);

        {
            std::lock_guard lock{recv_mut};
            REQUIRE(received ==
                    "HELLO![CHUNK-1][CHUNK-2][CHUNK-3][Chunk-4][Chunk-5][Chunk-6][chunk-7][chunk-8][chunk-9][chunk-10]"
                    "Goodbye.");
        }
    }

    // The chunks in flight are owned by the stream's send buffers, and each one's destructor asks
    // for the next chunk.  When the stream is closed or destroyed with chunks pending, that must
    // not call back into the application (whose state may be gone) nor into the stream.
    TEST_CASE("005 - Chunked stream sending: stream closed mid-send", "[005][chunked][close]")
    {
        Network test_net{};

        std::atomic<size_t> received = 0;
        std::promise<void> some_received_p;
        auto some_received_f = some_received_p.get_future();
        stream_data_callback server_data_cb = [&](Stream&, std::span<const std::byte> data) {
            if (received.fetch_add(data.size()) == 0)
                some_received_p.set_value();
        };

        auto [client_tls, server_tls] = defaults::tls_creds_from_ed_keys();

        Address server_local{};
        Address client_local{};

        auto server_endpoint = test_net.endpoint(server_local);
        REQUIRE_NOTHROW(server_endpoint->listen(server_tls, server_data_cb));

        RemoteAddress client_remote{defaults::SERVER_PUBKEY, LOCALHOST, server_endpoint->local().port()};

        auto client_endpoint = test_net.endpoint(client_local);
        auto conn_interface = client_endpoint->connect(client_remote, client_tls);

        std::atomic<bool> closed = false;
        std::atomic<bool> chunk_after_close = false, done_called = false;
        std::atomic<int> chunks = 0;
        auto stream = conn_interface->open_stream<Stream>();

        // Never runs out of data
        stream->send_chunks(
                [&](const Stream&) {
                    if (closed)
                        chunk_after_close = true;
                    chunks++;
                    return std::string(1000, 'x');
                },
                [&](Stream&) { done_called = true; },
                4);

        require_future(some_received_f, 5s);
        CHECK(chunks >= 4);

        // On the loop, so that the stream is closing by the time this returns
        client_endpoint->loop.call_get([&] { stream->close(0); });
        closed = true;

        conn_interface->close_connection();
        stream.reset();
        conn_interface.reset();
        client_endpoint.reset();
        server_endpoint.reset();

        CHECK_FALSE(chunk_after_close);
        CHECK_FALSE(done_called);
    }
}  // namespace oxen::quic::test
