"""The Pythonic half of the API.

The compiled layer binds libquic mechanically.  Everything here -- blocking connects, context
managers, iteration over a stream -- is added onto those same classes rather than wrapping them,
so that an object handed to a callback from the event loop thread has it too.
"""

import concurrent.futures
import queue
import threading

from ._core import BTRequestStream, Connection, Endpoint, Stream
from .errors import ConnectionFailed, RequestError, RequestTimeout, StreamClosed

# Sentinels pushed into a stream's queue by its close and FIN callbacks; distinct so that iteration
# can tell "the other end is done sending" from "the stream went away underneath us".
_FIN = object()
_CLOSED = object()


def _stream_iter_data(self, timeout=None):
    """Yields data as it arrives, until the other end sends its FIN or the stream closes.

    Installs a data callback of its own, replacing any that was set, so a stream is either iterated
    or given an ``on_data`` callback -- not both.  With a `timeout`, a gap of that many seconds with
    nothing arriving raises ``TimeoutError``.

    Raises `StreamClosed` if the stream closes with a non-zero error code before the FIN.
    """
    chunks = queue.Queue()

    self._set_data_callback(lambda _stream, data: chunks.put(data))
    self._set_fin_callback(lambda _stream: chunks.put(_FIN))
    self._set_close_callback(lambda _stream, error_code: chunks.put((_CLOSED, error_code)))

    while True:
        try:
            item = chunks.get(timeout=timeout)
        except queue.Empty:
            raise TimeoutError(f"no stream data for {timeout}s") from None

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


def _stream_read_all(self, timeout=None):
    """Reads until FIN or close and returns everything as one ``bytes``."""
    return b"".join(self.iter_data(timeout=timeout))


def _endpoint_connect(
    self,
    remote,
    *,
    wait=True,
    timeout=10.0,
    on_connection=None,
    on_connection_closed=None,
    **kwargs,
):
    """Connects to `remote`, by default blocking until the handshake completes.

    `remote` may be an `Address`, a "host:port" string, or a (host, port) tuple.  With `wait=False`
    this returns as soon as the connection is created, before the handshake, and it is up to the
    caller to watch `on_connection`.

    Raises `ConnectionFailed` if the connection closes before it is established, or if `timeout`
    seconds pass without either happening.
    """
    if not wait:
        return _endpoint_connect_raw(
            self,
            remote,
            on_connection=on_connection,
            on_connection_closed=on_connection_closed,
            **kwargs,
        )

    settled = threading.Event()
    outcome = {}

    def _established(conn):
        # setdefault rather than assignment: whichever callback fires first decides the outcome, so
        # that a connection that is established and then closed normally is not reported as failed.
        outcome.setdefault("ok", True)
        settled.set()
        if on_connection is not None:
            on_connection(conn)

    def _closed(conn, error_code):
        outcome.setdefault("ok", False)
        outcome.setdefault("error_code", error_code)
        settled.set()
        if on_connection_closed is not None:
            on_connection_closed(conn, error_code)

    conn = _endpoint_connect_raw(
        self, remote, on_connection=_established, on_connection_closed=_closed, **kwargs
    )

    if not settled.wait(timeout):
        conn.close()
        raise ConnectionFailed(f"connection to {remote} timed out after {timeout}s")

    if not outcome.get("ok"):
        raise ConnectionFailed(
            f"connection to {remote} failed", error_code=outcome.get("error_code")
        )

    return conn


def _endpoint_enter(self):
    return self


def _endpoint_exit(self, exc_type, exc, tb):
    self.close()
    return False


def _endpoint_serve_forever(self, wait=0.5):
    """Blocks until interrupted, then closes the endpoint.

    The event loop runs on its own thread and needs nothing from this one; this exists only so that
    a server script has something to sit on.  Returns normally on KeyboardInterrupt.
    """
    stop = threading.Event()
    try:
        # A bare wait() with no timeout is not reliably interruptible; waking periodically is.
        while not stop.wait(1.0):
            pass
    except KeyboardInterrupt:
        pass
    finally:
        self.close(wait=wait)


def _bt_request(self, endpoint, body=b"", *, timeout=None):
    """Invokes `endpoint` on the other end and returns a Future for the response.

    The future's result is the response body as ``bytes``.  An error response raises
    `RequestError`, and no response in time raises `RequestTimeout` -- which is also a builtin
    ``TimeoutError``, so ``except TimeoutError`` catches it.

    Nothing is sent until this returns, but the response arrives on the event loop thread, so use
    ``future.result(timeout)`` to wait for it or ``add_done_callback`` to be called back.
    """
    future = concurrent.futures.Future()

    def on_response(message):
        # Runs on the event loop thread.  set_* raises if the future was already resolved, which
        # cannot happen here: libquic answers a request exactly once.
        if message.timed_out:
            future.set_exception(RequestTimeout(f"no response to {endpoint!r} in time"))
        elif message.is_error:
            future.set_exception(RequestError(f"{endpoint!r} returned an error", body=message.body))
        else:
            future.set_result(message.body)

    self._command(endpoint, body, on_response=on_response, timeout=timeout)
    return future


def _bt_command(self, endpoint, body=b""):
    """Invokes `endpoint` on the other end without expecting a response."""
    self._command(endpoint, body)


def _bt_handler(self, endpoint):
    """Decorator form of `register_handler`::

    @stream.handler("ping")
    def ping(message):
        message.respond(b"pong")
    """

    def decorate(fn):
        self.register_handler(endpoint, fn)
        return fn

    return decorate


_endpoint_connect_raw = Endpoint.connect

Stream.iter_data = _stream_iter_data
Stream.__iter__ = _stream_iter_data
Stream.read_all = _stream_read_all

Connection.__enter__ = lambda self: self
Connection.__exit__ = lambda self, exc_type, exc, tb: (self.close(), False)[1]

BTRequestStream.request = _bt_request
BTRequestStream.command = _bt_command
BTRequestStream.handler = _bt_handler

Endpoint.connect = _endpoint_connect
Endpoint.__enter__ = _endpoint_enter
Endpoint.__exit__ = _endpoint_exit
Endpoint.serve_forever = _endpoint_serve_forever
