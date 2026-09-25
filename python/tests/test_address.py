import pytest

from seshquic import Address


def test_default_is_any():
    a = Address()
    assert a.is_set
    assert a.is_any_addr
    assert a.is_any_port
    assert not a.is_addressable


def test_host_and_port():
    a = Address("127.0.0.1", 4242)
    assert a.host == "127.0.0.1"
    assert a.port == 4242
    assert a.is_ipv4
    assert not a.is_ipv6
    assert a.is_loopback
    assert a.is_addressable
    assert not a.is_public


def test_ipv6():
    a = Address("::1", 443)
    assert a.is_ipv6
    assert not a.is_ipv4
    assert a.is_loopback
    assert str(a) == "[::1]:443"


def test_parse():
    assert Address.parse("1.2.3.4:5678") == Address("1.2.3.4", 5678)
    assert Address.parse("[::1]:443") == Address("::1", 443)
    assert Address.parse("1.2.3.4", 99) == Address("1.2.3.4", 99)


def test_parse_requires_port_without_default():
    with pytest.raises(ValueError):
        Address.parse("1.2.3.4")


def test_parse_rejects_garbage():
    with pytest.raises(ValueError):
        Address.parse("not-an-address:1")


def test_bad_host():
    with pytest.raises(ValueError):
        Address("127.001", 4400)


def test_equality_and_hash():
    assert Address("::1", 5) == Address("::1", 5)
    assert Address("::1", 5) != Address("::1", 6)
    assert hash(Address("::1", 5)) == hash(Address("::1", 5))
    assert len({Address("::1", 5), Address("::1", 5)}) == 1


def test_ordering():
    assert Address("1.2.3.4", 1) < Address("1.2.3.4", 2)


def test_repr_roundtrips_through_parse():
    a = Address("1.2.3.4", 5678)
    assert repr(a) == "Address('1.2.3.4:5678')"
    assert Address.parse(str(a)) == a
