#include "common.hpp"

#include <oxen/quic/crypto.hpp>
#include <oxen/quic/gnutls_crypto.hpp>
#include <oxen/quic/unencrypted.hpp>

#include <pybind11/pybind11.h>

#include <memory>
#include <string>
#include <string_view>

namespace seshquic
{
    using oxen::quic::DangerouslyUnencryptedCreds;
    using oxen::quic::GNUTLSCreds;
    using oxen::quic::TLSCreds;

    namespace
    {
        std::string_view as_sv(const std::vector<std::byte>& v)
        {
            return {reinterpret_cast<const char*>(v.data()), v.size()};
        }
    }  // namespace

    void init_creds(py::module_& m)
    {
        py::class_<TLSCreds, std::shared_ptr<TLSCreds>>{m, "Credentials", R"(TLS credentials for an endpoint.

Build one with the static methods below and pass it as the `creds` argument to `Endpoint` (to
accept incoming connections) or `Endpoint.connect` (to identify yourself to a server).
)"}
                .def_static(
                        "from_ed_keys",
                        [](const py::object& seed, const py::object& pubkey) -> std::shared_ptr<TLSCreds> {
                            auto s = to_bytes(seed);
                            auto p = to_bytes(pubkey);
                            return GNUTLSCreds::make_from_ed_keys(as_sv(s), as_sv(p));
                        },
                        py::arg("seed"),
                        py::arg("pubkey"),
                        R"(Credentials from a 32-byte Ed25519 seed and 32-byte public key.

The seed may instead be the 64-byte libsodium seed+pubkey value, in which case `pubkey` must be
the one it carries.  Raises ValueError for a wrong-sized key or a mismatched pubkey.
)")
                .def_static(
                        "from_ed_seckey",
                        [](const py::object& seckey) -> std::shared_ptr<TLSCreds> {
                            auto sk = to_bytes(seckey);
                            return GNUTLSCreds::make_from_ed_seckey(as_sv(sk));
                        },
                        py::arg("seckey"),
                        "Credentials from a combined 64-byte Ed25519 seed+pubkey value.")
                .def_static(
                        "unauthenticated",
                        []() -> std::shared_ptr<TLSCreds> { return GNUTLSCreds::make_unauthenticated(); },
                        R"(Credentials that carry no identity.

Usable only for outgoing connections, and only to a server that does not require a client
certificate.
)")
                .def_static(
                        "dangerously_unencrypted",
                        []() -> std::shared_ptr<TLSCreds> {
                            return DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted();
                        },
                        R"(Turns QUIC's encryption off entirely.

Packets are neither encrypted nor authenticated and there is no peer authentication whatsoever;
everything on the wire is readable and modifiable by anything on the path.  This exists for a
connection already carried inside something that encrypts and authenticates it, where QUIC's own
crypto is pure overhead.  If you cannot name what provides confidentiality, integrity and peer
authentication for the carrier, you want one of the other credential types.

Both ends must use it: such a connection cannot talk to an ordinary QUIC endpoint.
)");
    }

}  // namespace seshquic
