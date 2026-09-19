#include <oxen/quic.hpp>

using namespace oxen::quic;

int main()
{
    Network test_net{};
    auto good_msg = "hello from the other siiiii-iiiiide"_bsv;
    bstring_view bad_msg;

    stream_data_callback server_data_cb = [&](Stream&, bstring_view) { log::debug(log_cat, "server data received"); };

    auto server_tls = GNUTLSCreds::make("./serverkey.pem"s, "./servercert.pem"s, "./clientcert.pem"s);
    auto client_tls = GNUTLSCreds::make("./clientkey.pem"s, "./clientcert.pem"s, "./servercert.pem"s);

    opt::local_addr addr_a{}, addr_b{};

    auto server_endpoint_a = test_net.endpoint(addr_a);
    bool ok = server_endpoint_a->listen(server_tls, server_data_cb);
    assert(ok);

    auto server_endpoint_b = test_net.endpoint(addr_b);
    ok = server_endpoint_b->listen(server_tls, server_data_cb);
    assert(ok);

    opt::remote_addr client_remote{"127.0.0.1"s, server_endpoint_b->local().port()};
    opt::remote_addr server_remote{"127.0.0.1"s, server_endpoint_a->local().port()};

    auto server_ci = server_endpoint_b->connect(server_remote, server_tls);
    auto server_stream = server_ci->open_stream();

    server_stream->send(good_msg);

    REQUIRE(d_futures[0].get());

    auto client_endpoint = test_net.endpoint(client_local);
    auto conn_interface = client_endpoint->connect(client_remote, client_tls);

    // client make stream and send; message displayed by server_data_cb
    auto client_stream = conn_interface->open_stream();

    REQUIRE_NOTHROW(client_stream->send(good_msg));
    REQUIRE_THROWS(client_stream->send(bad_msg));

    REQUIRE(d_futures[1].get());
}
