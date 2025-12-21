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

static bool encode_bytes_cb(pb_ostream_t* stream,
                            const pb_field_t* field,
                            void* const* arg)
{
    const ByteSlice* s = static_cast<const ByteSlice*>(*arg);
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, s->data, s->size);
}

static bool decode_bytes_cb(pb_istream_t* stream,
                            const pb_field_t* field,
                            void** arg)
{
    (void)field; // unused
    ByteBuffer* buf = static_cast<ByteBuffer*>(*arg);

    if (stream->bytes_left > buf->capacity) {
        PB_SET_ERROR(stream, "bytes field too long");
        return false;
    }

    buf->size = stream->bytes_left;
    return pb_read(stream, buf->data, buf->size);
}

/* For demo: still using fixed serial ID (identity) */
static const char CLIENT_SERIAL_ID[] = "CYX-TEST-CLIENT-0001";

int main()
{
    try {
        boost::asio::io_context io;

        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 5555));
        std::cout << "[SERVER] Listening on 127.0.0.1:5555\n";

        tcp::socket socket(io);
        acceptor.accept(socket);
        std::cout << "[SERVER] Client connected\n";

        /* ===== Step 1: receive AuthInitRequest ===== */

        auth_AuthInitRequest init_req = auth_AuthInitRequest_init_default;

        uint8_t serial_id_buf[64];
        uint8_t sig_buf_raw[64];
        uint8_t client_pub_buf[65];

        ByteBuffer serial_buf { serial_id_buf, sizeof(serial_id_buf), 0 };
        ByteBuffer sig_buf    { sig_buf_raw,    sizeof(sig_buf_raw),    0 };
        ByteBuffer pub_buf    { client_pub_buf, sizeof(client_pub_buf), 0 };

        // Decode serial_id
        init_req.serial_id.funcs.decode = &decode_bytes_cb;
        init_req.serial_id.arg          = &serial_buf;

        // Decode signature (over sha256(serial_id))
        init_req.signature.funcs.decode = &decode_bytes_cb;
        init_req.signature.arg          = &sig_buf;

        // Decode client_pubkey (65-byte uncompressed)
        init_req.client_pubkey.funcs.decode = &decode_bytes_cb;
        init_req.client_pubkey.arg          = &pub_buf;

        cypherock::recv_pb_message(socket,
                                   auth_AuthInitRequest_fields,
                                   &init_req);

        std::cout << "[SERVER] Received AuthInitRequest\n";

        /* Basic sanity checks */

        if (serial_buf.size == 0 || sig_buf.size != 64 || pub_buf.size != 65) {
            auth_AuthInitResponse resp = auth_AuthInitResponse_init_default;
            resp.ok = false;
            cypherock::send_pb_message(socket,
                                       auth_AuthInitResponse_fields,
                                       &resp);
            std::cerr << "[SERVER] Invalid field sizes in AuthInitRequest\n";
            return 0;
        }

        /* Check serial ID matches expected (demo-only policy) */

        if (serial_buf.size != strlen(CLIENT_SERIAL_ID) ||
            std::memcmp(serial_id_buf,
                        CLIENT_SERIAL_ID,
                        serial_buf.size) != 0) {

            auth_AuthInitResponse resp =
                auth_AuthInitResponse_init_default;
            resp.ok = false;

            cypherock::send_pb_message(socket,
                                       auth_AuthInitResponse_fields,
                                       &resp);

            std::cerr << "[SERVER] Serial ID mismatch, closing\n";
            return 0;
        }

        /* Verify signature on hash(serial_id) using client's runtime pubkey */

        uint8_t digest[32];
        crypto_sha256(serial_id_buf, serial_buf.size, digest);

        bool sig_ok = (crypto_verify_digest(client_pub_buf,
                                            digest,
                                            sig_buf_raw) == 0);

        if (!sig_ok) {
            auth_AuthInitResponse resp =
                auth_AuthInitResponse_init_default;
            resp.ok = false;

            cypherock::send_pb_message(socket,
                                       auth_AuthInitResponse_fields,
                                       &resp);

            std::cerr << "[SERVER] Invalid signature on serial_id, closing\n";
            return 0;
        }

        std::cout << "[SERVER] Initial signature verified\n";

        /* ===== Step 2: send AuthInitResponse(ok=true) ===== */

        auth_AuthInitResponse resp = auth_AuthInitResponse_init_default;
        resp.ok = true;
        cypherock::send_pb_message(socket,
                                   auth_AuthInitResponse_fields,
                                   &resp);

        /* ===== Step 3: generate 32-byte random nonce and send Challenge ===== */

        uint8_t nonce[32];
        crypto_random32(nonce);

        auth_Challenge challenge = auth_Challenge_init_default;

        ByteSlice nonce_slice { nonce, sizeof(nonce) };
        challenge.nonce.funcs.encode = &encode_bytes_cb;
        challenge.nonce.arg          = &nonce_slice;

        cypherock::send_pb_message(socket,
                                   auth_Challenge_fields,
                                   &challenge);

        std::cout << "[SERVER] Sent challenge nonce\n";

        /* ===== Step 4: receive ChallengeResponse ===== */

        auth_ChallengeResponse chal_resp =
            auth_ChallengeResponse_init_default;

        uint8_t chal_serial_buf[64];
        uint8_t chal_sig_buf[64];

        ByteBuffer chal_serial {
            chal_serial_buf, sizeof(chal_serial_buf), 0
        };
        ByteBuffer chal_sig {
            chal_sig_buf, sizeof(chal_sig_buf), 0
        };

        chal_resp.serial_id.funcs.decode = &decode_bytes_cb;
        chal_resp.serial_id.arg          = &chal_serial;

        chal_resp.signature.funcs.decode = &decode_bytes_cb;
        chal_resp.signature.arg          = &chal_sig;

        cypherock::recv_pb_message(socket,
                                   auth_ChallengeResponse_fields,
                                   &chal_resp);

        std::cout << "[SERVER] Received ChallengeResponse\n";

        /* Verify serial ID again */

        if (chal_serial.size != strlen(CLIENT_SERIAL_ID) ||
            std::memcmp(chal_serial_buf,
                        CLIENT_SERIAL_ID,
                        chal_serial.size) != 0) {

            std::cerr << "[SERVER] Serial ID mismatch in ChallengeResponse\n";
            return 0;
        }

        /* ===== Step 5: verify signature on hash(nonce) ===== */

        uint8_t chal_digest[32];
        crypto_sha256(nonce, sizeof(nonce), chal_digest);

        if (chal_sig.size != 64) {
            std::cerr << "[SERVER] Challenge signature size invalid\n";
            return 0;
        }

        bool chal_ok = (crypto_verify_digest(client_pub_buf,
                                             chal_digest,
                                             chal_sig_buf) == 0);

        if (!chal_ok) {
            std::cerr << "[SERVER] Challenge signature verification failed\n";
            return 0;
        }

        std::cout << "[SERVER] Client verified successfully! Serial ID = "
                  << CLIENT_SERIAL_ID << "\n";

    } catch (const std::exception &ex) {
        std::cerr << "[SERVER] Exception: " << ex.what() << "\n";
        return 1;
    }

    return 0;
}
