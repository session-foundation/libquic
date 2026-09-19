"""QUIC for Python, built on libquic.

An `Endpoint` is a bound UDP socket with its own event loop thread.  Call `listen()` on it to
accept connections, `connect()` to make one, or both::

    import seshquic as quic

    with quic.Endpoint("127.0.0.1:0") as client:
        conn = client.connect("example.com:4242", remote_pubkey=pk, creds=creds)
        stream = conn.open_stream()
        stream.send(b"hello")
        stream.send_fin()
        print(stream.read_all())

Callbacks are invoked on the event loop thread, not the thread that set them up.
"""

from ._core import (
    Address,
    BTRequestStream,
    Connection,
    Credentials,
    Endpoint,
    Loop,
    Message,
    Stream,
    __version__,
    enable_logging,
    flush_logs,
)
from .errors import ConnectionFailed, QuicError, RequestError, RequestTimeout, StreamClosed

# Imported for its side effect of adding the Pythonic methods onto the classes above.
from . import _pythonic  # noqa: F401  isort: skip

__all__ = [
    "Address",
    "BTRequestStream",
    "Connection",
    "ConnectionFailed",
    "Credentials",
    "Endpoint",
    "Loop",
    "Message",
    "QuicError",
    "RequestError",
    "RequestTimeout",
    "Stream",
    "StreamClosed",
    "__version__",
    "enable_logging",
    "flush_logs",
]
