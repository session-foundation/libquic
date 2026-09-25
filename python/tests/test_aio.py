"""Tests for the optional asyncio layer.

Written with plain `asyncio.run` rather than pytest-asyncio so that the test suite keeps its two
dependencies (pytest and PyNaCl) and nothing more.
"""

import asyncio

import pytest

import seshquic
import seshquic.aio as aio


def run(coro):
    return asyncio.run(coro)


def test_importing_seshquic_does_not_import_asyncio_layer():
    """The whole point of the layer being separate: you do not have to use it."""
    import subprocess
    import sys

    out = subprocess.run(
        [sys.executable, "-c", "import seshquic, sys; print('seshquic.aio' in sys.modules)"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert out.stdout.strip() == "False"


def test_connect_and_stream(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    async def main():
        def on_stream_data(stream, data):
            stream.send(data.upper())

        def on_stream_fin(stream):
            stream.send_fin()

        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(server_creds, on_stream_data=on_stream_data, on_stream_fin=on_stream_fin)

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                assert conn.is_established

                stream = conn.open_stream()
                stream.send(b"hello async")
                stream.send_fin()
                return await stream.read_all(timeout=10)

    assert run(main()) == b"HELLO ASYNC"


def test_async_iteration(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    async def main():
        def on_stream_data(stream, data):
            stream.send(data)

        def on_stream_fin(stream):
            stream.send_fin()

        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(server_creds, on_stream_data=on_stream_data, on_stream_fin=on_stream_fin)

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                stream = conn.open_stream()
                stream.send(b"chunks")
                stream.send_fin()

                chunks = [chunk async for chunk in stream]
                return b"".join(chunks)

    assert run(main()) == b"chunks"


def test_connect_failure_raises(server_keys, client_creds):
    _, server_pubkey = server_keys

    async def main():
        async with aio.Endpoint("127.0.0.1:0") as client:
            with pytest.raises(seshquic.ConnectionFailed):
                await client.connect(
                    "127.0.0.1:1", remote_pubkey=server_pubkey, creds=client_creds, timeout=2.0
                )

    run(main())


def test_bt_request(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    async def main():
        def on_connection(conn):
            bts = conn.queue_incoming_bt_stream()

            # An async handler, to show that handlers run on the asyncio loop.
            @bts.handler("slow-echo")
            async def _(message):
                await asyncio.sleep(0.01)
                message.respond(message.body)

            bts.register_handler("fail", lambda m: m.respond(b"no", error=True))
            # Deliberately never answers, which is the only way to actually reach a timeout: an
            # unregistered endpoint gets a prompt not-found error instead.
            bts.register_handler("silent", lambda m: None)

        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(server_creds, on_connection=on_connection)

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                bts = conn.open_bt_stream()

                assert await bts.request("slow-echo", b"hi") == b"hi"

                with pytest.raises(seshquic.RequestError):
                    await bts.request("fail", b"x")

                with pytest.raises(seshquic.RequestError):
                    await bts.request("nothing-here-at-all", b"x")

                with pytest.raises(seshquic.RequestTimeout):
                    await bts.request("silent", b"x", timeout=0.5)

    run(main())


def test_concurrent_requests(server_creds, server_keys, client_creds):
    """Requests in flight together, which is the thing the async layer is actually for."""
    _, server_pubkey = server_keys

    async def main():
        def on_connection(conn):
            bts = conn.queue_incoming_bt_stream()

            @bts.handler("slow")
            async def _(message):
                await asyncio.sleep(0.05)
                message.respond(message.body.upper())

        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(server_creds, on_connection=on_connection)

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                bts = conn.open_bt_stream()

                results = await asyncio.gather(
                    *(bts.request("slow", f"n{i}".encode()) for i in range(20))
                )
                return results

    assert run(main()) == [f"N{i}".encode() for i in range(20)]


def test_datagrams(server_creds, server_keys, client_creds):
    _, server_pubkey = server_keys

    async def main():
        got = asyncio.get_running_loop().create_future()

        def on_datagram(conn, data):
            if not got.done():
                got.set_result(data)

        async with aio.Endpoint("127.0.0.1:0", datagrams=True, on_datagram=on_datagram) as server:
            server.listen(server_creds)

            async with aio.Endpoint("127.0.0.1:0", datagrams=True) as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                conn.send_datagram(b"async datagram")
                return await asyncio.wait_for(got, 5)

    assert run(main()) == b"async datagram"


def test_stream_construct_per_id(server_creds, server_keys, client_creds):
    """The file-server shape again, through the async layer."""
    _, server_pubkey = server_keys

    async def main():
        kinds = {}
        saw_plain = asyncio.get_running_loop().create_future()

        def on_stream_construct(conn, stream_id):
            # Runs on libquic's thread, so it does nothing but pick a type.
            return aio.BTRequestStream if stream_id == 0 else None

        def on_stream_open(stream):
            kinds[stream.stream_id] = type(stream).__name__
            if isinstance(stream, aio.BTRequestStream):
                stream.register_handler("ping", lambda m: m.respond(b"pong"))

        def on_stream_data(stream, data):
            if not saw_plain.done():
                saw_plain.set_result(data)

        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(
                server_creds,
                on_stream_construct=on_stream_construct,
                on_stream_open=on_stream_open,
                on_stream_data=on_stream_data,
            )

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )

                bts = conn.open_bt_stream()
                assert await bts.request("ping") == b"pong"

                plain = conn.open_stream()
                plain.send(b"raw")
                assert await asyncio.wait_for(saw_plain, 5) == b"raw"

        return kinds

    kinds = run(main())
    assert kinds[0] == "BTRequestStream"
    assert kinds[4] == "Stream"


def test_coroutine_stream_constructor_is_rejected():
    async def main():
        async def bad(conn, stream_id):
            return None

        async with aio.Endpoint("127.0.0.1:0") as ep:
            with pytest.raises(TypeError, match="cannot be a coroutine"):
                ep.listen(seshquic.Credentials.unauthenticated(), on_stream_construct=bad)

    run(main())


def test_raw_escape_hatch(server_creds, server_keys, client_creds):
    """Anything not wrapped is reachable through .raw."""
    _, server_pubkey = server_keys

    async def main():
        async with aio.Endpoint("127.0.0.1:0") as server:
            server.listen(server_creds)
            assert isinstance(server.raw, seshquic.Endpoint)

            async with aio.Endpoint("127.0.0.1:0") as client:
                conn = await client.connect(
                    server.local, remote_pubkey=server_pubkey, creds=client_creds
                )
                assert isinstance(conn.raw, seshquic.Connection)
                assert isinstance(conn.open_stream().raw, seshquic.Stream)
                # Unwrapped properties pass through.
                assert conn.alpn == b"default"

    run(main())
