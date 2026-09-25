import pytest
from nacl.signing import SigningKey

import seshquic as quic


def ed25519_keypair():
    """Returns a (seed, pubkey) pair, which is what Credentials.from_ed_keys wants."""
    sk = SigningKey.generate()
    return sk.encode(), sk.verify_key.encode()


@pytest.fixture
def server_keys():
    return ed25519_keypair()


@pytest.fixture
def client_keys():
    return ed25519_keypair()


@pytest.fixture
def server_creds(server_keys):
    return quic.Credentials.from_ed_keys(*server_keys)


@pytest.fixture
def client_creds(client_keys):
    return quic.Credentials.from_ed_keys(*client_keys)


@pytest.fixture
def endpoint():
    """A client endpoint on an ephemeral loopback port, closed at the end of the test."""
    with quic.Endpoint("127.0.0.1:0") as ep:
        yield ep


@pytest.fixture
def echo_server(server_creds):
    """A listening endpoint that echoes each stream chunk back uppercased.

    It mirrors the client's FIN back so that a client reading to end-of-stream terminates.
    """

    def on_stream_data(stream, data):
        stream.send(data.upper())

    def on_stream_fin(stream):
        stream.send_fin()

    with quic.Endpoint("127.0.0.1:0") as ep:
        ep.listen(server_creds, on_stream_data=on_stream_data, on_stream_fin=on_stream_fin)
        yield ep


@pytest.fixture(autouse=True)
def _fail_on_unraisable(monkeypatch):
    """Turns an exception escaping a callback into a test failure rather than a stderr warning."""
    import sys

    escaped = []
    monkeypatch.setattr(sys, "unraisablehook", lambda unraisable: escaped.append(unraisable))
    yield
    assert not escaped, f"exception escaped a callback: {escaped[0].exc_value!r}"
