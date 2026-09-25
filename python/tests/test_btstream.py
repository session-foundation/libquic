import threading

import pytest

import seshquic as quic


@pytest.fixture
def bt_server(server_creds):
    """A server that prepares a bt-request stream for whatever the other end opens."""

    def on_connection(conn):
        # Nothing needs to hold onto this: the connection owns the queued stream, and this handle
        # only observes it.
        bts = conn.queue_incoming_bt_stream()
        bts.register_handler("echo", lambda m: m.respond(m.body))
        bts.register_handler("upper", lambda m: m.respond(m.body.upper()))
        bts.register_handler("fail", lambda m: m.respond(b"nope", error=True))
        bts.register_handler("silent", lambda m: None)

    with quic.Endpoint("127.0.0.1:0") as ep:
        ep.listen(server_creds, on_connection=on_connection)
        yield ep


@pytest.fixture
def bt_client(endpoint, bt_server, server_keys, client_creds):
    _, server_pubkey = server_keys
    conn = endpoint.connect(bt_server.local, remote_pubkey=server_pubkey, creds=client_creds)
    return conn.open_bt_stream()


def test_request_returns_a_future(bt_client):
    future = bt_client.request("echo", b"hello")
    assert future.result(timeout=5) == b"hello"


def test_request_body_is_optional(bt_client):
    assert bt_client.request("echo").result(timeout=5) == b""


def test_requests_are_independent(bt_client):
    futures = [bt_client.request("upper", f"n{i}".encode()) for i in range(10)]
    assert [f.result(timeout=5) for f in futures] == [f"N{i}".encode() for i in range(10)]


def test_error_response_raises(bt_client):
    with pytest.raises(quic.RequestError) as excinfo:
        bt_client.request("fail", b"x").result(timeout=5)
    assert excinfo.value.body == b"nope"


def test_unknown_endpoint_is_an_error(bt_client):
    with pytest.raises(quic.RequestError):
        bt_client.request("no-such-endpoint", b"x").result(timeout=5)


def test_timeout_raises(bt_client):
    with pytest.raises(quic.RequestTimeout):
        bt_client.request("silent", b"x", timeout=0.5).result(timeout=5)


def test_timeout_is_a_builtin_timeout_error(bt_client):
    with pytest.raises(TimeoutError):
        bt_client.request("silent", b"x", timeout=0.5).result(timeout=5)


def test_command_expects_no_response(bt_client, bt_server):
    # Nothing to await; it is enough that it neither raises nor leaves a request outstanding.
    bt_client.command("echo", b"fire and forget")
    assert bt_client.num_awaiting_response == 0


def test_handler_decorator_and_reverse_direction(endpoint, server_creds, server_keys, client_creds):
    """Either side can open a stream and either side can serve; here the server asks the client."""
    _, server_pubkey = server_keys
    answered = threading.Event()
    answer = []

    def on_connection(conn):
        # The server opens its own outgoing bt stream, rather than waiting for one.
        bts = conn.open_bt_stream()
        bts.request("whoami").add_done_callback(
            lambda f: (answer.append(f.result()), answered.set())
        )

    with quic.Endpoint("127.0.0.1:0") as server:
        server.listen(server_creds, on_connection=on_connection)

        client_bt = []

        def on_stream_construct(conn, stream_id):
            return quic.BTRequestStream

        def on_stream_open(stream):
            client_bt.append(stream)

            @stream.handler("whoami")
            def _(message):
                message.respond(b"the client")

        conn = endpoint.connect(
            server.local,
            remote_pubkey=server_pubkey,
            creds=client_creds,
            on_stream_construct=on_stream_construct,
            on_stream_open=on_stream_open,
        )

        assert answered.wait(5)
        assert answer == [b"the client"]
        assert isinstance(client_bt[0], quic.BTRequestStream)


def test_stream_construct_chooses_per_stream_id(endpoint, server_creds, server_keys, client_creds):
    """The file-server shape: stream 0 is a bt-request stream, later streams are plain."""
    _, server_pubkey = server_keys

    kinds = {}
    plain_data = []
    saw_plain = threading.Event()
    streams = []

    def on_stream_construct(conn, stream_id):
        # Only the first incoming stream carries requests; the rest have their own framing.
        return quic.BTRequestStream if stream_id == 0 else None

    def on_stream_open(stream):
        streams.append(stream)
        kinds[stream.stream_id] = type(stream).__name__
        if isinstance(stream, quic.BTRequestStream):
            stream.register_handler("ping", lambda m: m.respond(b"pong"))

    def on_stream_data(stream, data):
        plain_data.append(data)
        saw_plain.set()

    with quic.Endpoint("127.0.0.1:0") as server:
        server.listen(
            server_creds,
            on_stream_construct=on_stream_construct,
            on_stream_open=on_stream_open,
            on_stream_data=on_stream_data,
        )

        conn = endpoint.connect(server.local, remote_pubkey=server_pubkey, creds=client_creds)

        bts = conn.open_bt_stream()
        assert bts.request("ping").result(timeout=5) == b"pong"

        plain = conn.open_stream()
        plain.send(b"raw bytes")
        assert saw_plain.wait(5)

    assert kinds[0] == "BTRequestStream"
    assert kinds[4] == "Stream"
    assert plain_data == [b"raw bytes"]


def test_message_attributes(bt_client):
    seen = []
    done = threading.Event()

    def capture(message):
        seen.append(message)
        done.set()

    bt_client._command("echo", b"hi", on_response=capture)
    assert done.wait(5)

    message = seen[0]
    assert message.body == b"hi"
    assert message.request_id == 0
    assert not message.is_error
    assert not message.timed_out
    assert bool(message)
    assert "reply" in repr(message)


def test_bt_stream_is_a_stream(bt_client):
    assert isinstance(bt_client, quic.Stream)
    assert bt_client.stream_id == 0
    assert bt_client.is_alive
