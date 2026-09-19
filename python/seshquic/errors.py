"""Exceptions raised by seshquic."""

__all__ = ["QuicError", "ConnectionFailed", "StreamClosed", "RequestError", "RequestTimeout"]


class QuicError(Exception):
    """Base class for every error this package raises of its own accord.

    Bad arguments still come back as the standard ``ValueError``/``TypeError``.
    """


class ConnectionFailed(QuicError):
    """A connection closed or timed out before it was established."""

    def __init__(self, message="connection failed", error_code=None):
        super().__init__(message)
        self.error_code = error_code


class StreamClosed(QuicError):
    """The stream was closed before the operation could complete."""

    def __init__(self, message="stream closed", error_code=None):
        super().__init__(message)
        self.error_code = error_code


class RequestError(QuicError):
    """A bt-encoded request came back as an error response."""

    def __init__(self, message, body=b""):
        super().__init__(message)
        self.body = body


class RequestTimeout(RequestError, TimeoutError):
    """A bt-encoded request got no response in time.

    Also a builtin ``TimeoutError``, so ``except TimeoutError`` catches it.
    """

    def __init__(self, message="request timed out"):
        super().__init__(message)
