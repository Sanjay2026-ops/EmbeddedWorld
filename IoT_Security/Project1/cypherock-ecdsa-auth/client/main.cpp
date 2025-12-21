#include <boost/asio.hpp>
#include <iostream>
#include <array>
#include <string>
#include <cstring>

extern "C" {
#include "auth.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
}

#include "crypto_util.h"
#include "pb_helpers.hpp"
#include "pb_io.hpp"

using boost::asio::ip::tcp;

/* ---- Helper types for nanopb callbacks ---- */

struct ByteSlice {
    const uint8_t* data;
    size_t size;
};

struct ByteBuffer {
    uint8_t* data;
    size_t capacity;
    size_t size;   // filled after decode
};

/* Encode callback: send raw bytes */
static bool encode_bytes_cb(pb_ostream_t* stream,
                            const pb_field_t* field,
                            void* const* arg)
{
    const ByteSlice* s = static_cast<const ByteSlice*>(*arg);
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, s->data, s->size);
}

/* Decode callback: read bytes into given buffer */
static bool decode_bytes_cb(pb_istream_t* stream,
                            const pb_field_t* field,
                            void** arg)
{
    (void)field; // unused
    ByteBuffer* buf = static_cast<ByteBuffer*>(*arg);

    size_t incoming = stream->bytes_left;
    if (incoming > buf->capacity) {
        std::cerr << "[PB] decode_bytes_cb: incoming=" << incoming
                  << " > capacity=" << buf->capacity << "\n";
        PB_SET_ERROR(stream, "bytes field too long");
        return false;
    }

    buf->size = incoming;
    if (!pb_read(stream, buf->data, buf->size)) {
        std::cerr << "[PB] decode_bytes_cb: pb_read failed\n";
        return false;
    }
    return true;
}

/* Pre-provisioned serial ID (identity of the client device) */
static const char CLIENT_SERIAL_ID[] = "CYX-TEST-CLIENT-0001";

int main()
{
    try {
        boost::asio::io_context io;

        tcp::resolver resolver(io);
        auto endpoints = resolver.resolve("127.0.0.1", "5555");

        tcp::socket socket(io);
        boost::asio::connect(socket, endpoints);

        std::cout << "[CLIENT] Connected to server\n";

        /* ===== Step 0: generate ECDSA keypair at runtime ===== */

        uint8_t client_priv[32];
        uint8_t client_pub[65];

        if (crypto_generate_keypair(client_priv, client_pub) != 0) {
            std::cerr << "[CLIENT] crypto_generate_keypair failed\n";
            return 1;
        }

        std::cout << "[CLIENT] Runtime ECDSA keypair generated\n";

        /* ===== Step 1: sign hash(serial_id) and send AuthInitRequest ===== */

        uint8_t digest[32];
        crypto_sha256(
            reinterpret_cast<const uint8_t*>(CLIENT_SERIAL_ID),
            strlen(CLIENT_SERIAL_ID),
            digest);

        uint8_t sig[64];
        if (crypto_sign_digest(client_priv, digest, sig) != 0) {
            std::cerr << "[CLIENT] crypto_sign_digest failed\n";
            return 1;
        }

        auth_AuthInitRequest init_req = auth_AuthInitRequest_init_default;

        // serial_id
        ByteSlice serial_slice {
            reinterpret_cast<const uint8_t*>(CLIENT_SERIAL_ID),
            strlen(CLIENT_SERIAL_ID)
        };
        init_req.serial_id.funcs.encode = &encode_bytes_cb;
        init_req.serial_id.arg          = &serial_slice;

        // signature over sha256(serial_id)
        ByteSlice sig_slice { sig, sizeof(sig) };
        init_req.signature.funcs.encode = &encode_bytes_cb;
        init_req.signature.arg          = &sig_slice;

        // client_pubkey (65-byte uncompressed pubkey)
        ByteSlice pub_slice { client_pub, sizeof(client_pub) };
        init_req.client_pubkey.funcs.encode = &encode_bytes_cb;
        init_req.client_pubkey.arg          = &pub_slice;

        cypherock::send_pb_message(socket,
                                   auth_AuthInitRequest_fields,
                                   &init_req);

        std::cout << "[CLIENT] Sent AuthInitRequest\n";

        /* ===== Step 2: receive AuthInitResponse (ok / error) ===== */

        auth_AuthInitResponse init_resp = auth_AuthInitResponse_init_default;

        // we don't care about error_msg, so no callbacks set
        cypherock::recv_pb_message(socket,
                                   auth_AuthInitResponse_fields,
                                   &init_resp);

        if (!init_resp.ok) {
            std::cerr << "[CLIENT] AuthInitResponse: FAILED\n";
            return 1;
        }

        std::cout << "[CLIENT] AuthInitResponse: OK\n";

        /* ===== Step 3: receive 32-byte random challenge from server ===== */

        auth_Challenge challenge = auth_Challenge_init_default;

        uint8_t nonce[32];
        ByteBuffer nonce_buf { nonce, sizeof(nonce), 0 };

        challenge.nonce.funcs.decode = &decode_bytes_cb;
        challenge.nonce.arg          = &nonce_buf;

        cypherock::recv_pb_message(socket,
                                   auth_Challenge_fields,
                                   &challenge);

        if (nonce_buf.size != 32) {
            std::cerr << "[CLIENT] Challenge nonce size != 32 ("
                      << nonce_buf.size << ")\n";
            return 1;
        }

        std::cout << "[CLIENT] Received challenge nonce\n";

        /* ===== Step 4: sign hash(nonce) and send ChallengeResponse ===== */

        uint8_t chal_digest[32];
        crypto_sha256(nonce, 32, chal_digest);

        uint8_t chal_sig[64];
        if (crypto_sign_digest(client_priv, chal_digest, chal_sig) != 0) {
            std::cerr << "[CLIENT] crypto_sign_digest (challenge) failed\n";
            return 1;
        }

        auth_ChallengeResponse chal_resp =
            auth_ChallengeResponse_init_default;

        ByteSlice serial2_slice {
            reinterpret_cast<const uint8_t*>(CLIENT_SERIAL_ID),
            strlen(CLIENT_SERIAL_ID)
        };
        chal_resp.serial_id.funcs.encode = &encode_bytes_cb;
        chal_resp.serial_id.arg          = &serial2_slice;

        ByteSlice chal_sig_slice { chal_sig, sizeof(chal_sig) };
        chal_resp.signature.funcs.encode = &encode_bytes_cb;
        chal_resp.signature.arg          = &chal_sig_slice;

        cypherock::send_pb_message(socket,
                                   auth_ChallengeResponse_fields,
                                   &chal_resp);

        std::cout << "[CLIENT] Sent ChallengeResponse, auth flow completed\n";
    } catch (const std::exception &ex) {
        std::cerr << "[CLIENT] Exception: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
