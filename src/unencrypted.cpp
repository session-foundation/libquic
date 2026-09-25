#include "oxen/quic/unencrypted.hpp"

#include "connection.hpp"
#include "internal.hpp"

#include <ngtcp2/ngtcp2.h>

#include <limits>

namespace oxen::quic
{
    std::shared_ptr<DangerouslyUnencryptedCreds> DangerouslyUnencryptedCreds::i_know_this_traffic_is_already_encrypted()
    {
        return std::make_shared<DangerouslyUnencryptedCreds>();
    }

    std::unique_ptr<TLSSession> DangerouslyUnencryptedCreds::make_session(
            Connection&, const IOContext&, std::span<const std::string>, std::optional<std::span<const unsigned char>>)
    {
        return std::make_unique<DangerouslyUnencryptedSession>();
    }

    namespace
    {
        // The no-op contexts and keys handed to ngtcp2 in place of real ones.  ngtcp2 keeps pointers
        // to the iv and contexts for the life of a connection, so this is a single immutable
        // instance rather than per-connection state.
        struct null_crypto
        {
            // At least 8 bytes: nonce construction writes the packet number into the last 8 bytes of
            // the iv, and ngtcp2 asserts on anything shorter.
            std::array<uint8_t, 8> iv{};

            ngtcp2_crypto_ctx ctx{};
            ngtcp2_crypto_aead aead{};
            ngtcp2_crypto_aead_ctx aead_ctx{};
            ngtcp2_crypto_cipher_ctx cipher_ctx{};

            null_crypto()
            {
                // Never rekey and never give up on decryption failures: neither can happen when
                // nothing is encrypted, and hitting either limit would close the connection.
                ctx.max_encryption = std::numeric_limits<uint64_t>::max();
                ctx.max_decryption_failure = std::numeric_limits<uint64_t>::max();

                // One byte of "overhead" that nothing ever writes: ngtcp2 before ~1.15 asserts on a
                // zero max_overhead when padding a packet out for the header protection sample, and
                // the cost of humouring it is a single wasted byte per packet.
                ctx.aead.max_overhead = 1;
                aead.max_overhead = 1;
            }
        };

        const null_crypto& nc()
        {
            static const null_crypto instance{};
            return instance;
        }
    }  // namespace

    void Connection::unencrypted_initial_keys()
    {
        auto& n = nc();
        ngtcp2_conn_set_initial_crypto_ctx(*this, &n.ctx);
        ngtcp2_conn_install_initial_key(
                *this, &n.aead_ctx, n.iv.data(), &n.cipher_ctx, &n.aead_ctx, n.iv.data(), &n.cipher_ctx, n.iv.size());

        if (!is_inbound())
            ngtcp2_conn_set_retry_aead(*this, &n.aead, &n.aead_ctx);

        ngtcp2_conn_set_crypto_ctx(*this, &n.ctx);
    }

    int Connection::unencrypted_version_negotiation(uint32_t version)
    {
        // ngtcp2 needs Initial keys for the version it settles on, and will not send a packet until
        // it has them (it asserts on a negotiated_version of zero).
        auto& n = nc();
        return ngtcp2_conn_install_vneg_initial_key(
                *this,
                version,
                &n.aead_ctx,
                n.iv.data(),
                &n.cipher_ctx,
                &n.aead_ctx,
                n.iv.data(),
                &n.cipher_ctx,
                n.iv.size());
    }

    // A handshake message is the magic, a two-byte big-endian payload length, then the payload.
    // Self-delimiting because ngtcp2 hands us contiguous chunks of the crypto stream rather than
    // whole messages, so we have to know when one is complete.
    namespace
    {
        constexpr size_t msg_header = unencrypted_handshake_magic.size() + 2;
    }

    int Connection::unencrypted_send(ngtcp2_encryption_level level, bool with_transport_params)
    {
        auto& buf = level == NGTCP2_ENCRYPTION_LEVEL_INITIAL ? _unencrypted_tx_initial : _unencrypted_tx_handshake;

        buf.assign(unencrypted_handshake_magic.begin(), unencrypted_handshake_magic.end());
        buf.resize(msg_header);

        if (with_transport_params)
        {
            buf.resize(msg_header + 512);
            auto len = ngtcp2_conn_encode_local_transport_params(*this, buf.data() + msg_header, buf.size() - msg_header);
            if (len < 0)
            {
                log::error(log_cat, "Failed to encode local transport params: {}", ngtcp2_strerror(static_cast<int>(len)));
                return static_cast<int>(len);
            }
            buf.resize(msg_header + static_cast<size_t>(len));
        }

        auto payload_len = buf.size() - msg_header;
        buf[msg_header - 2] = static_cast<uint8_t>(payload_len >> 8);
        buf[msg_header - 1] = static_cast<uint8_t>(payload_len & 0xff);

        return ngtcp2_conn_submit_crypto_data(*this, level, buf.data(), buf.size());
    }

    int Connection::unencrypted_handle_message(ngtcp2_encryption_level level, std::span<const uint8_t> payload)
    {
        const bool server = is_inbound();

        if (level == NGTCP2_ENCRYPTION_LEVEL_INITIAL)
        {
            // The client's transport params ride in its Initial, as a TLS ClientHello would carry
            // them: the server needs them before it can write any packet of its own.
            if (server && !payload.empty())
            {
                if (auto rv = ngtcp2_conn_decode_and_set_remote_transport_params(*this, payload.data(), payload.size());
                    rv != 0)
                {
                    log::error(log_cat, "Failed to read client transport params: {}", ngtcp2_strerror(rv));
                    return rv;
                }
            }

            auto& n = nc();
            if (auto rv = ngtcp2_conn_install_rx_handshake_key(*this, &n.aead_ctx, n.iv.data(), n.iv.size(), &n.cipher_ctx);
                rv != 0)
            {
                log::error(log_cat, "Failed to install handshake rx key: {}", ngtcp2_strerror(rv));
                return rv;
            }
            if (auto rv = ngtcp2_conn_install_tx_handshake_key(*this, &n.aead_ctx, n.iv.data(), n.iv.size(), &n.cipher_ctx);
                rv != 0)
            {
                log::error(log_cat, "Failed to install handshake tx key: {}", ngtcp2_strerror(rv));
                return rv;
            }

            if (server)
            {
                // The server can send 1-RTT data as soon as it has a key for it.
                if (auto rv = ngtcp2_conn_install_tx_key(
                            *this, n.iv.data(), n.iv.size(), &n.aead_ctx, n.iv.data(), n.iv.size(), &n.cipher_ctx);
                    rv != 0)
                {
                    log::error(log_cat, "Failed to install tx key: {}", ngtcp2_strerror(rv));
                    return rv;
                }

                if (auto rv = unencrypted_send(NGTCP2_ENCRYPTION_LEVEL_INITIAL, false); rv != 0)
                    return rv;
                if (auto rv = unencrypted_send(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, true); rv != 0)
                    return rv;
            }
            return 0;
        }

        // Handshake level: the peer's transport params, if it sent any.  The client echoes an empty
        // message back so that the server's handshake completes too.
        if (!payload.empty())
        {
            if (auto rv = ngtcp2_conn_decode_and_set_remote_transport_params(*this, payload.data(), payload.size()); rv != 0)
            {
                log::error(log_cat, "Failed to read remote transport params: {}", ngtcp2_strerror(rv));
                return rv;
            }
        }

        if (!server)
        {
            if (auto rv = unencrypted_send(NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE, false); rv != 0)
                return rv;
        }

        unencrypted_complete_handshake();
        return 0;
    }

    int Connection::unencrypted_client_initial()
    {
        unencrypted_initial_keys();

        return unencrypted_send(NGTCP2_ENCRYPTION_LEVEL_INITIAL, true);
    }

    int Connection::unencrypted_recv_client_initial()
    {
        unencrypted_initial_keys();
        return 0;
    }

    int Connection::unencrypted_recv_crypto_data(ngtcp2_encryption_level level, std::span<const uint8_t> data)
    {
        if (level == NGTCP2_ENCRYPTION_LEVEL_1RTT)
            return 0;
        if (level == NGTCP2_ENCRYPTION_LEVEL_0RTT)
        {
            log::warning(log_cat, "Unexpected 0-RTT crypto data on an unencrypted connection");
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        auto& buf = level == NGTCP2_ENCRYPTION_LEVEL_INITIAL ? _unencrypted_rx_initial : _unencrypted_rx_handshake;
        buf.insert(buf.end(), data.begin(), data.end());

        // Complete messages only: anything else waits for the rest of the stream.
        while (buf.size() >= msg_header)
        {
            if (!std::equal(unencrypted_handshake_magic.begin(), unencrypted_handshake_magic.end(), buf.begin()))
            {
                log::warning(log_cat, "Peer did not send the expected unencrypted-handshake magic");
                return NGTCP2_ERR_CALLBACK_FAILURE;
            }

            size_t payload_len = (static_cast<size_t>(buf[msg_header - 2]) << 8) | buf[msg_header - 1];
            if (buf.size() < msg_header + payload_len)
                break;

            if (auto rv = unencrypted_handle_message(level, {buf.data() + msg_header, payload_len}); rv != 0)
                return rv;

            buf.erase(buf.begin(), buf.begin() + static_cast<long>(msg_header + payload_len));
        }

        return 0;
    }

    void Connection::unencrypted_complete_handshake()
    {
        auto& n = nc();

        ngtcp2_conn_install_rx_key(*this, nullptr, 0, &n.aead_ctx, n.iv.data(), n.iv.size(), &n.cipher_ctx);
        if (!is_inbound())
            ngtcp2_conn_install_tx_key(
                    *this, n.iv.data(), n.iv.size(), &n.aead_ctx, n.iv.data(), n.iv.size(), &n.cipher_ctx);

        ngtcp2_conn_tls_handshake_completed(*this);
    }

}  // namespace oxen::quic
