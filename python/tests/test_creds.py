import os

import pytest

from conftest import ed25519_keypair
from seshquic import Credentials


def test_from_ed_keys():
    seed, pubkey = os.urandom(32), os.urandom(32)
    assert Credentials.from_ed_keys(seed, pubkey) is not None


def test_from_ed_keys_accepts_any_buffer():
    seed, pubkey = os.urandom(32), os.urandom(32)
    assert Credentials.from_ed_keys(bytearray(seed), memoryview(pubkey)) is not None


def test_from_ed_keys_rejects_str():
    with pytest.raises(TypeError, match="encode it first"):
        Credentials.from_ed_keys("x" * 32, os.urandom(32))


def test_from_ed_keys_rejects_empty():
    with pytest.raises(ValueError):
        Credentials.from_ed_keys(b"", b"")


def test_from_ed_seckey():
    assert Credentials.from_ed_seckey(os.urandom(64)) is not None


def test_unauthenticated():
    assert Credentials.unauthenticated() is not None


def test_dangerously_unencrypted():
    assert Credentials.dangerously_unencrypted() is not None


def test_from_ed_keys_accepts_combined_seed():
    seed, pubkey = ed25519_keypair()
    assert Credentials.from_ed_keys(seed + pubkey, pubkey) is not None


def test_from_ed_keys_rejects_mismatched_combined_seed():
    seed, pubkey = ed25519_keypair()
    _, other_pubkey = ed25519_keypair()
    with pytest.raises(ValueError, match="does not match"):
        Credentials.from_ed_keys(seed + pubkey, other_pubkey)


def test_from_ed_keys_rejects_wrong_size():
    seed, pubkey = ed25519_keypair()
    with pytest.raises(ValueError, match="seed must be 32 bytes"):
        Credentials.from_ed_keys(seed[:16], pubkey)
    with pytest.raises(ValueError, match="pubkey must be 32 bytes"):
        Credentials.from_ed_keys(seed, pubkey[:16])


def test_from_ed_seckey_rejects_wrong_size():
    seed, _ = ed25519_keypair()
    with pytest.raises(ValueError):
        Credentials.from_ed_seckey(seed)
