import threading

import pytest

import seshquic as quic


def test_connect_and_echo(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    conn = endpoint.connect(echo_server.local, remote_pubkey=server_pubkey, creds=client_creds)

    assert conn.is_established
    assert not conn.is_closing
    assert not conn.is_inbound
    assert conn.remote == echo_server.local

    stream = conn.open_stream()
    stream.send(b"hello world")
    stream.send_fin()

    assert next(iter(stream)) == b"HELLO WORLD"


def test_read_all(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    conn = endpoint.connect(echo_server.local, remote_pubkey=server_pubkey, creds=client_creds)

    stream = conn.open_stream()
    body = b"".join(bytes([i % 256]) for i in range(5000))
    stream.send(body)
    stream.send_fin()

    # The server echoes and then closes its side once our FIN arrives, ending the iteration.
    assert stream.read_all(timeout=10) == body.upper()


def test_connect_accepts_address_forms(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    port = echo_server.local.port

    for remote in (f"127.0.0.1:{port}", ("127.0.0.1", port), quic.Address("127.0.0.1", port)):
        conn = endpoint.connect(remote, remote_pubkey=server_pubkey, creds=client_creds)
        assert conn.is_established
        conn.close()


def test_connect_to_nothing_times_out(endpoint, server_keys, client_creds):
    _, server_pubkey = server_keys
    # Port 1 on loopback: nothing is listening, so the handshake never completes.
    with pytest.raises(quic.ConnectionFailed):
        endpoint.connect(
            "127.0.0.1:1", remote_pubkey=server_pubkey, creds=client_creds, timeout=2.0
        )


def test_connect_wrong_pubkey_fails(endpoint, echo_server, client_keys, client_creds):
    _, wrong_pubkey = client_keys
    with pytest.raises(quic.ConnectionFailed):
        endpoint.connect(
            echo_server.local, remote_pubkey=wrong_pubkey, creds=client_creds, timeout=5.0
        )


def test_connect_without_wait_returns_immediately(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    established = threading.Event()

    conn = endpoint.connect(
        echo_server.local,
        remote_pubkey=server_pubkey,
        creds=client_creds,
        wait=False,
        on_connection=lambda c: established.set(),
    )

    assert established.wait(5)
    assert conn.is_established


def test_server_sees_connection(endpoint, server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys
    seen = []
    connected = threading.Event()

    def on_connection(conn):
        seen.append(conn)
        connected.set()

    with quic.Endpoint("127.0.0.1:0") as server:
        server.listen(server_creds, on_connection=on_connection)
        assert server.is_accepting

        conn = endpoint.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)
        assert connected.wait(5)

        assert seen[0].is_inbound
        assert seen[0].remote == conn.local


def test_connection_equality(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    seen = []
    connected = threading.Event()

    conn = endpoint.connect(
        echo_server.local,
        remote_pubkey=server_pubkey,
        creds=client_creds,
        on_connection=lambda c: (seen.append(c), connected.set()),
    )

    assert connected.wait(5)
    # The callback gets its own wrapper object around the same connection.
    assert seen[0] == conn
    assert seen[0] is not conn
    assert hash(seen[0]) == hash(conn)
    assert conn != "not a connection"


def test_alpn_negotiation(endpoint, server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    with quic.Endpoint("127.0.0.1:0", alpns=["mine", "other"]) as server:
        server.listen(server_creds)
        conn = endpoint.connect(
            server.local, remote_pubkey=server_pubkey, creds=client_creds, alpns=["mine"]
        )
        assert conn.alpn == b"mine"


def test_alpn_mismatch_fails(endpoint, server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    with quic.Endpoint("127.0.0.1:0", alpns=["mine"]) as server:
        server.listen(server_creds)
        with pytest.raises(quic.ConnectionFailed):
            endpoint.connect(
                server.local,
                remote_pubkey=server_pubkey,
                creds=client_creds,
                alpns=["yours"],
                timeout=5.0,
            )


def test_unencrypted_connection(server_keys):
    creds = quic.Credentials.dangerously_unencrypted()
    received = threading.Event()
    got = []

    def on_stream_data(stream, data):
        got.append(data)
        received.set()

    with quic.Endpoint("127.0.0.1:0") as server, quic.Endpoint("127.0.0.1:0") as client:
        server.listen(creds, on_stream_data=on_stream_data)
        conn = client.connect(server.local, creds=creds)
        assert conn.is_established

        conn.open_stream().send(b"in the clear")
        assert received.wait(5)
        assert got == [b"in the clear"]
