import threading

import pytest

import seshquic as quic


@pytest.fixture
def dgram_pair(server_creds, server_keys, client_creds):
    """A connected client/server pair with datagrams enabled, and the server's received queue."""
    _, server_pubkey = server_keys
    received = []
    arrived = threading.Event()

    def on_datagram(conn, data):
        received.append(data)
        arrived.set()

    with quic.Endpoint("127.0.0.1:0", datagrams=True, on_datagram=on_datagram) as server:
        server.listen(server_creds)
        with quic.Endpoint("127.0.0.1:0", datagrams=True) as client:
            conn = client.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)
            yield conn, received, arrived


def test_send_and_receive(dgram_pair):
    conn, received, arrived = dgram_pair
    assert conn.datagrams_enabled

    conn.send_datagram(b"unreliable hello")
    assert arrived.wait(5)
    assert received == [b"unreliable hello"]


def test_max_datagram_size(dgram_pair):
    conn, _, _ = dgram_pair
    # Negotiated, and it grows as the path MTU is discovered; 1200 is the QUIC floor.
    assert conn.max_datagram_size >= 1000


def test_send_at_max_size(dgram_pair):
    conn, received, arrived = dgram_pair
    payload = b"x" * conn.max_datagram_size

    conn.send_datagram(payload)
    assert arrived.wait(5)
    assert received == [payload]


def test_datagrams_disabled_by_default(endpoint, echo_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    conn = endpoint.connect(echo_server.local, remote_pubkey=server_pubkey, creds=client_creds)

    assert not conn.datagrams_enabled
    with pytest.raises(RuntimeError, match="datagrams are not enabled"):
        conn.send_datagram(b"nope")


def test_datagram_options_require_enabling():
    with pytest.raises(ValueError, match="without datagrams=True"):
        quic.Endpoint("127.0.0.1:0", datagram_splitting=True)
    with pytest.raises(ValueError, match="without datagrams=True"):
        quic.Endpoint("127.0.0.1:0", datagram_queue_limit=1000)


def test_bufsize_requires_splitting():
    with pytest.raises(ValueError, match="datagram_splitting=True"):
        quic.Endpoint("127.0.0.1:0", datagrams=True, datagram_bufsize=4096)


def test_bad_bufsize_rejected():
    with pytest.raises(ValueError):
        quic.Endpoint("127.0.0.1:0", datagrams=True, datagram_splitting=True, datagram_bufsize=63)
    with pytest.raises(ValueError):
        # Must divide evenly between the four buffer rows.
        quic.Endpoint("127.0.0.1:0", datagrams=True, datagram_splitting=True, datagram_bufsize=4095)


def test_splitting_carries_a_larger_datagram(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys
    received = []
    arrived = threading.Event()

    def on_datagram(conn, data):
        received.append(data)
        arrived.set()

    opts = dict(datagrams=True, datagram_splitting=True, datagram_bufsize=4096)

    with quic.Endpoint("127.0.0.1:0", on_datagram=on_datagram, **opts) as server:
        server.listen(server_creds)
        with quic.Endpoint("127.0.0.1:0", **opts) as client:
            conn = client.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)

            # Splitting roughly doubles what fits, so this exceeds a single QUIC packet.
            assert conn.max_datagram_size > 2000
            payload = b"y" * conn.max_datagram_size

            conn.send_datagram(payload)
            assert arrived.wait(5)
            assert received == [payload]


def test_datagram_callback_gets_the_receiving_connection(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys
    seen = []
    arrived = threading.Event()

    def on_datagram(conn, data):
        seen.append(conn)
        arrived.set()

    with quic.Endpoint("127.0.0.1:0", datagrams=True, on_datagram=on_datagram) as server:
        server.listen(server_creds)
        with quic.Endpoint("127.0.0.1:0", datagrams=True) as client:
            conn = client.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)
            conn.send_datagram(b"ping")
            assert arrived.wait(5)

            # The callback gets the server's side of the connection the datagram arrived on.
            assert isinstance(seen[0], quic.Connection)
            assert seen[0].is_inbound
            assert seen[0].remote == conn.local


def test_send_datagram_accepts_any_buffer(dgram_pair):
    conn, received, arrived = dgram_pair
    conn.send_datagram(bytearray(b"from a bytearray"))
    assert arrived.wait(5)
    assert received == [b"from a bytearray"]
