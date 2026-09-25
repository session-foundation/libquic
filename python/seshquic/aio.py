"""asyncio wrappers for seshquic.

Entirely optional and entirely additive: importing `seshquic` does not import this, and nothing
here changes the behaviour of the classes in it.  These types wrap the ordinary ones, so a program
that never imports `seshquic.aio` needs no event loop and pays nothing for its existence::

    import seshquic.aio as quic

    async def main():
        async with quic.Endpoint("127.0.0.1:0") as client:
            conn = await client.connect("example.com:4242", remote_pubkey=pk, creds=creds)
            stream = conn.open_stream()
            stream.send(b"hello")
            stream.send_fin()
            print(await stream.read_all())

Only the operations that actually wait are coroutines -- connecting, closing, reading, and a
bt-request -- following asyncio's own convention where `StreamWriter.write` is synchronous and
only `drain` is awaited.  Sending queues data and returns, so it is not a coroutine here either.

**Which thread a callback runs on.** libquic runs its own event loop thread.  Callbacks that
merely report something -- `on_connection_closed`, `on_stream_data`, `on_stream_close`,
`on_stream_fin`, `on_datagram`, and bt-request handlers -- are handed to the asyncio loop, so they
may be coroutine functions and may use anything asyncio.

Three run on libquic's thread instead, synchronously, because deferring them would be wrong rather
than merely different:

* `on_stream_construct` has to return the stream type before libquic can build the stream.
* `on_connection` and `on_stream_open` are where you queue streams and register handlers.  Data
  can arrive the moment they return, so a handler registered after that point would miss it.

Those three must not be coroutine functions and must not block; register a handler or start a task
from them and let that do the waiting.  The objects they are given are the wrappers from this
module, so registering a handler from one still gets you a handler that runs on the asyncio loop.
"""

import asyncio
import functools
import inspect

from . import _core
from .errors import ConnectionFailed, StreamClosed

__all__ = ["Endpoint", "Connection", "Stream", "BTRequestStream"]

_FIN = object()
_CLOSED = object()

# Callbacks that libquic invokes as setup hooks, or for a return value, and which therefore run on
# its thread rather than being handed to the asyncio loop.  See the module docstring.
_SYNCHRONOUS = ("on_stream_construct", "on_connection", "on_stream_open")


def _dispatch(loop, fn, *args):
    """Runs a user callback on the asyncio loop, from libquic's loop thread.

    Accepts a coroutine function or a plain one.  A closed loop is ignored rather than raised
    through: this is called from a thread with nowhere to report to, during teardown as often as
    not.
    """
    if fn is None:
        return

    try:
        if inspect.iscoroutinefunction(fn):
            asyncio.run_coroutine_threadsafe(fn(*args), loop)
        else:
            loop.call_soon_threadsafe(functools.partial(fn, *args))
    except RuntimeError:
        pass


def _reject_coroutine(name, fn):
    if inspect.iscoroutinefunction(fn):
        raise TypeError(
            f"{name} cannot be a coroutine function: it runs on libquic's thread, before any data "
            "on the connection or stream is delivered.  Register a handler or start a task from it "
            "instead."
        )
    return fn


def _prepare_callbacks(loop, kwargs):
    """Adapts the on_* callbacks in `kwargs` for the asyncio layer.

    Each one is given the wrapper objects from this module in place of the underlying ones, and is
    then either dispatched onto the asyncio loop or left to run on libquic's thread, per
    `_SYNCHRONOUS`.
    """
    adapters = {
        "on_connection": lambda raw: Connection(raw, loop),
        "on_connection_closed": lambda raw: Connection(raw, loop),
        "on_datagram": lambda raw: Connection(raw, loop),
        "on_stream_open": lambda raw: _wrap_stream(raw, loop),
        "on_stream_data": lambda raw: _wrap_stream(raw, loop),
        "on_stream_close": lambda raw: _wrap_stream(raw, loop),
        "on_stream_fin": lambda raw: _wrap_stream(raw, loop),
    }

    for name, wrapper in adapters.items():
        fn = kwargs.get(name)
        if fn is None:
            continue
        if name in _SYNCHRONOUS:
            kwargs[name] = _adapt_first_arg(_reject_coroutine(name, fn), wrapper)
        else:
            kwargs[name] = functools.partial(_dispatch, loop, _adapt_first_arg(fn, wrapper))

    fn = kwargs.get("on_stream_construct")
    if fn is not None:
        kwargs["on_stream_construct"] = _adapt_stream_constructor(
            _reject_coroutine("on_stream_construct", fn), loop
        )

    return kwargs


def _adapt_first_arg(fn, wrapper):
    @functools.wraps(fn)
    def adapted(first, *rest):
        return fn(wrapper(first), *rest)

    return adapted


def _adapt_stream_constructor(fn, loop):
    @functools.wraps(fn)
    def adapted(conn, stream_id):
        want = fn(Connection(conn, loop), stream_id)
        # Accept either spelling of the type, since aio.BTRequestStream is what is in scope for
        # the caller.
        if want is BTRequestStream:
            return _core.BTRequestStream
        if want is Stream:
            return _core.Stream
        return want

    return adapted


def _wrap_stream(raw, loop):
    cls = BTRequestStream if isinstance(raw, _core.BTRequestStream) else Stream
    return cls(raw, loop)


class Stream:
    """A QUIC stream.  Wraps `seshquic.Stream`; reading is the only part that awaits."""

    def __init__(self, raw, loop):
        self._s = raw
        # Carried rather than looked up, because these objects are constructed on libquic's thread
        # in the setup callbacks, where there is no running asyncio loop to ask.
        self._loop = loop

    @property
    def raw(self):
        """The underlying `seshquic.Stream`, for anything not wrapped here."""
        return self._s

    def send(self, data):
        """Queues data for sending.  Not a coroutine: this never blocks."""
        self._s.send(data)

    def send_fin(self):
        self._s.send_fin()

    def close(self, error_code=0):
        self._s.close(error_code)

    @property
    def stream_id(self):
        return self._s.stream_id

    @property
    def is_alive(self):
        return self._s.is_alive

    def __aiter__(self):
        return self.iter_data()

    async def iter_data(self, timeout=None):
        """Yields data as it arrives, until the other end sends its FIN or the stream closes.

        Installs a data callback of its own, replacing any that was set, so a stream is either
        iterated or given an `on_data` callback -- not both.
        """
        loop = asyncio.get_running_loop()
        chunks = asyncio.Queue()

        def put(item):
            # Called on libquic's loop thread; Queue is not thread-safe, so hand it over.
            try:
                loop.call_soon_threadsafe(chunks.put_nowait, item)
            except RuntimeError:
                pass

        self._s._set_data_callback(lambda _stream, data: put(data))
        self._s._set_fin_callback(lambda _stream: put(_FIN))
        self._s._set_close_callback(lambda _stream, error_code: put((_CLOSED, error_code)))

        while True:
            if timeout is None:
                item = await chunks.get()
            else:
                item = await asyncio.wait_for(chunks.get(), timeout)

            if item is _FIN:
                return
            if isinstance(item, tuple) and item and item[0] is _CLOSED:
                error_code = item[1]
                if error_code:
                    raise StreamClosed(
                        f"stream closed with error code {error_code}", error_code=error_code
                    )
                return
            yield item

    async def read_all(self, timeout=None):
        """Reads until FIN or close and returns everything as one `bytes`."""
        return b"".join([chunk async for chunk in self.iter_data(timeout=timeout)])


class BTRequestStream(Stream):
    """A stream carrying bt-encoded requests.  `request` is a coroutine; `command` is not."""

    async def request(self, endpoint, body=b"", *, timeout=None):
        """Invokes `endpoint` on the other end and waits for the response body.

        Raises `RequestError` for an error response and `RequestTimeout` if none arrives in time.
        """
        # The underlying request hands back a concurrent.futures.Future, which is exactly what
        # wrap_future takes -- the reason the threaded layer returns one of those.
        return await asyncio.wrap_future(self._s.request(endpoint, body, timeout=timeout))

    def command(self, endpoint, body=b""):
        """Invokes `endpoint` without expecting a response.  Not a coroutine: nothing is awaited."""
        self._s.command(endpoint, body)

    def register_handler(self, endpoint, handler):
        """Registers a handler, which may be a coroutine function, for one endpoint.

        Safe to call from a setup callback running on libquic's thread; the handler itself runs on
        the asyncio loop when it fires.
        """
        self._s.register_handler(endpoint, functools.partial(_dispatch, self._loop, handler))

    def register_generic_handler(self, handler):
        self._s.register_generic_handler(functools.partial(_dispatch, self._loop, handler))

    def handler(self, endpoint):
        """Decorator form of `register_handler`."""

        def decorate(fn):
            self.register_handler(endpoint, fn)
            return fn

        return decorate


class Connection:
    """A QUIC connection.  Wraps `seshquic.Connection`."""

    def __init__(self, raw, loop):
        self._c = raw
        self._loop = loop

    @property
    def raw(self):
        """The underlying `seshquic.Connection`, for anything not wrapped here."""
        return self._c

    def open_stream(self, **kwargs):
        """Opens a stream.  Not a coroutine: nothing is waited for."""
        return Stream(
            self._c.open_stream(**_prepare_stream_callbacks(self._loop, kwargs)), self._loop
        )

    def open_bt_stream(self, **kwargs):
        raw = self._c.open_bt_stream(**_prepare_stream_callbacks(self._loop, kwargs))
        return BTRequestStream(raw, self._loop)

    def queue_incoming_bt_stream(self, **kwargs):
        raw = self._c.queue_incoming_bt_stream(**_prepare_stream_callbacks(self._loop, kwargs))
        return BTRequestStream(raw, self._loop)

    def send_datagram(self, data):
        self._c.send_datagram(data)

    def close(self, error_code=0):
        self._c.close(error_code)

    def __getattr__(self, name):
        # Read-only properties -- remote, alpn, is_established, max_datagram_size and the rest --
        # pass straight through; they are plain accessors with nothing to await.
        return getattr(self._c, name)


def _prepare_stream_callbacks(loop, kwargs):
    """The per-stream callbacks taken by open_stream and friends; all are notifications."""
    for name, wrapper in (
        ("on_data", lambda raw: _wrap_stream(raw, loop)),
        ("on_close", lambda raw: _wrap_stream(raw, loop)),
        ("on_fin", lambda raw: _wrap_stream(raw, loop)),
        ("on_request", lambda msg: msg),
    ):
        fn = kwargs.get(name)
        if fn is not None:
            kwargs[name] = functools.partial(_dispatch, loop, _adapt_first_arg(fn, wrapper))
    return kwargs


class Endpoint:
    """A bound UDP socket with its own libquic event loop thread.

    Takes the same keyword arguments as `seshquic.Endpoint`.  Must be constructed from inside a
    running loop; see the module docstring for which callbacks run where.
    """

    def __init__(self, local="", **kwargs):
        self._loop = asyncio.get_running_loop()
        self._ep = _core.Endpoint(local, **_prepare_callbacks(self._loop, kwargs))

    @property
    def raw(self):
        """The underlying `seshquic.Endpoint`, for anything not wrapped here."""
        return self._ep

    @property
    def local(self):
        return self._ep.local

    @property
    def is_accepting(self):
        return self._ep.is_accepting

    def listen(self, creds, **kwargs):
        """Starts accepting incoming connections.  Not a coroutine: nothing is waited for.

        An error code returned from `on_stream_open` is honoured, since that callback runs on
        libquic's thread; see the module docstring.
        """
        self._ep.listen(creds, **_prepare_callbacks(self._loop, kwargs))

    async def connect(self, remote, *, timeout=10.0, **kwargs):
        """Connects to `remote`, waiting for the handshake to complete.

        Raises `ConnectionFailed` if the connection closes first, or if neither happens within
        `timeout` seconds.
        """
        loop = asyncio.get_running_loop()
        settled = loop.create_future()

        user_established = kwargs.pop("on_connection", None)
        user_closed = kwargs.pop("on_connection_closed", None)
        if user_established is not None:
            _reject_coroutine("on_connection", user_established)

        def _established(conn):
            # On libquic's thread: the user's setup callback runs here, before any stream data,
            # and the future is resolved over on the asyncio loop.
            if user_established is not None:
                user_established(Connection(conn, loop))
            try:
                loop.call_soon_threadsafe(lambda: settled.done() or settled.set_result(None))
            except RuntimeError:
                pass

        def _closed(conn, error_code):
            def resolve():
                if not settled.done():
                    settled.set_exception(
                        ConnectionFailed(f"connection to {remote} failed", error_code=error_code)
                    )
                else:
                    # Already established, so this is an ordinary close rather than a failure.
                    settled.exception()

            try:
                loop.call_soon_threadsafe(resolve)
            except RuntimeError:
                pass
            _dispatch(loop, user_closed, Connection(conn, loop), error_code)

        raw = self._ep.connect(
            remote,
            wait=False,
            on_connection=_established,
            on_connection_closed=_closed,
            **_prepare_callbacks(loop, kwargs),
        )

        try:
            await asyncio.wait_for(settled, timeout)
        except asyncio.TimeoutError:
            raw.close()
            raise ConnectionFailed(f"connection to {remote} timed out after {timeout}s") from None

        return Connection(raw, loop)

    async def close(self, wait=0.5):
        """Closes every connection and shuts the endpoint down.

        Run in a worker thread: closing waits for the close packets to flush and then joins the
        libquic loop thread, which would otherwise stall the asyncio loop.
        """
        await asyncio.to_thread(self._ep.close, wait)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await self.close()
        return False
