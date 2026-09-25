#pragma once

#include "crypto.hpp"

#include <array>
#include <memory>

namespace oxen::quic
{
    class Connection;

    /**
      Credentials that turn QUIC's encryption OFF, entirely.  Packets are neither encrypted nor
      authenticated, and the TLS handshake is replaced by a fixed exchange carrying nothing but the
      QUIC transport parameters.  Everything on the wire is readable and modifiable by anything on
      the path: payloads, packet numbers, connection ids, the lot.  There is no peer authentication
      whatsoever, so "who am I talking to" is answered only by whatever carries the connection.

      This exists for a connection that is already inside something that encrypts and authenticates
      it, where QUIC's own crypto is pure overhead: a second AEAD pass on every packet, and a TLS
      handshake before any data can flow.  Tunnelling QUIC over an already-encrypted transport is
      the motivating case.

      Using this means asserting that the carrier provides the confidentiality, integrity and peer
      authentication that QUIC would otherwise provide.  If you cannot name what provides each of
      those three, you want GNUTLSCreds instead.

      Both ends must use it: such a connection cannot talk to an ordinary QUIC endpoint, and fails
      the handshake rather than silently falling back to anything.
     */
    class DangerouslyUnencryptedCreds : public TLSCreds
    {
      public:
        // Deliberately verbose: this should be unmistakable at the call site and in review.
        static std::shared_ptr<DangerouslyUnencryptedCreds> i_know_this_traffic_is_already_encrypted();

        std::unique_ptr<TLSSession> make_session(
                Connection& c,
                const IOContext& ctx,
                std::span<const std::string> alpns,
                std::optional<std::span<const unsigned char>> expected_remote_key) override;

        void store_session_ticket(Connection&, RemoteAddress, std::span<const unsigned char>) override {}
        std::optional<session_data> extract_session_data(const RemoteAddress&) override { return std::nullopt; }

        // There are no session tickets to resume from, so TLS-style 0-RTT does not apply.  (Nothing
        // is lost by that: there is no handshake secret to establish in the first place.)
        bool inbound_0rtt() const override { return false; }
        bool outbound_0rtt() const override { return false; }

        // Nothing to have, which is the entire point; reported as true so that connection setup,
        // which refuses credential-less inbound connections, accepts these in both directions.
        bool has_credentials() const override { return true; }
    };

    class DangerouslyUnencryptedSession : public TLSSession
    {
      public:
        // ngtcp2 is given no native TLS handle, and nothing ever calls into one.
        void* get_session() override { return nullptr; }
        bool get_early_data_accepted() const override { return false; }
        std::string_view selected_alpn() override { return {}; }
        std::span<const unsigned char> remote_key() override { return {}; }
        std::optional<std::vector<unsigned char>> extract_0rtt_tp_data() override { return std::nullopt; }
        void send_session_tickets() override {}
    };

    // Stands in for the TLS handshake at each encryption level.  Its job is to be something
    // recognisable, so that a peer which is *not* doing this fails here rather than proceeding into
    // a half-established connection.  The trailing byte is a version, so that a future change to
    // this exchange can either break cleanly or be handled compatibly.
    inline constexpr std::array<uint8_t, 8> unencrypted_handshake_magic{'n', 'o', 'c', 'r', 'y', 'p', 't', 0x01};

}  // namespace oxen::quic
