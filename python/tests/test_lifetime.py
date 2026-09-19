import gc
import sys
import threading

import pytest

import seshquic as quic


def test_handles_outliving_their_endpoint(server_creds, server_keys, client_creds):
    """A stream or connection kept past its endpoint must not be usable, but must not crash.

    libquic's endpoint owns its connections, which own their streams; a Python handle observes
    rather than owns, so closing the endpoint takes the objects with it.
    """
    _, server_pubkey = server_keys

    server = quic.Endpoint("127.0.0.1:0")
    server.listen(server_creds)
    client = quic.Endpoint("127.0.0.1:0")

    conn = client.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)
    stream = conn.open_stream()

    assert conn.is_alive
    assert stream.is_alive

    client.close()
    server.close()

    assert not conn.is_alive
    assert not stream.is_alive

    with pytest.raises(RuntimeError, match="no longer available"):
        stream.send(b"x")
    with pytest.raises(RuntimeError, match="no longer available"):
        conn.is_established
    with pytest.raises(RuntimeError, match="no longer available"):
        conn.open_stream()

    assert repr(stream) == "<Stream (closed)>"


def test_close_is_idempotent(server_creds):
    ep = quic.Endpoint("127.0.0.1:0")
    ep.listen(server_creds)
    ep.close()
    ep.close()
    ep.close(wait=0)


def test_endpoint_unusable_after_close(server_creds):
    ep = quic.Endpoint("127.0.0.1:0")
    ep.close()
    with pytest.raises(RuntimeError, match="closed"):
        ep.local


def test_shared_loop(server_creds, server_keys, client_creds):
    """Two endpoints on one loop, which must outlive both."""
    _, server_pubkey = server_keys
    loop = quic.Loop()

    server = quic.Endpoint("127.0.0.1:0", loop=loop)
    server.listen(server_creds)
    client = quic.Endpoint("127.0.0.1:0", loop=loop)

    conn = client.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)
    assert conn.is_established

    client.close()
    server.close()
    del loop


def test_exception_in_callback_does_not_propagate(
    endpoint, server_creds, server_keys, client_creds, monkeypatch
):
    """A callback that raises must not take the event loop thread down with it."""
    _, server_pubkey = server_keys

    escaped = []
    monkeypatch.setattr(sys, "unraisablehook", lambda u: escaped.append(u))

    second_call = threading.Event()

    # A stream is a byte stream, so two sends on one stream may arrive as a single callback; two
    # separate streams are what guarantees two separate invocations.
    def on_stream_data(stream, data):
        if data == b"boom":
            raise ValueError("deliberate")
        second_call.set()

    with quic.Endpoint("127.0.0.1:0") as server:
        server.listen(server_creds, on_stream_data=on_stream_data)
        conn = endpoint.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)

        conn.open_stream().send(b"boom")
        conn.open_stream().send(b"fine")

        # The second callback still runs, so the raise was contained rather than fatal.
        assert second_call.wait(5)

    assert escaped, "the exception should have been reported through sys.unraisablehook"
    assert isinstance(escaped[0].exc_value, ValueError)


def test_stream_identity_across_callbacks(endpoint, server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys
    seen = []
    arrived = threading.Event()

    def on_stream_data(stream, data):
        seen.append(stream)

    def on_stream_fin(stream):
        seen.append(stream)
        arrived.set()

    with quic.Endpoint("127.0.0.1:0") as server:
        server.listen(server_creds, on_stream_data=on_stream_data, on_stream_fin=on_stream_fin)
        conn = endpoint.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)

        stream = conn.open_stream()
        stream.send(b"one")
        stream.send_fin()
        assert arrived.wait(5)
        assert len(seen) == 2

    # Each callback gets a fresh wrapper, but they compare equal and hash alike.
    assert seen[0] is not seen[1]
    assert seen[0] == seen[1]
    assert len({seen[0], seen[1]}) == 1


def test_connection_keeps_its_endpoint_alive(echo_server, server_keys, client_creds):
    """A connection from a temporary endpoint must keep that endpoint alive.

    `Endpoint(...).connect(...)` leaves no Python reference to the endpoint, and a connection is
    only a weak handle on something the endpoint owns, so without a keep_alive the endpoint would
    be collected -- and the connection closed -- as the expression finished.
    """
    _, server_pubkey = server_keys

    conn = quic.Endpoint("127.0.0.1:0").connect(
        echo_server.local, remote_pubkey=server_pubkey, creds=client_creds
    )
    gc.collect()

    assert conn.is_alive
    assert conn.is_established


def test_stream_keeps_its_connection_alive(echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys

    conn = quic.Endpoint("127.0.0.1:0").connect(
        echo_server.local, remote_pubkey=server_pubkey, creds=client_creds
    )
    stream = conn.open_stream()
    del conn
    gc.collect()

    assert stream.is_alive
    stream.send(b"still works")
    stream.send_fin()
    assert stream.read_all(timeout=10) == b"STILL WORKS"
