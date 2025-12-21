#ifndef CYPHEROCK_CRYPTO_UTIL_H
#define CYPHEROCK_CRYPTO_UTIL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SHA-256 helper */
void crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32]);

/* ECDSA sign: priv (32 bytes), digest (32 bytes) -> sig (64 bytes) */
int crypto_sign_digest(const uint8_t priv[32],
                       const uint8_t digest[32],
                       uint8_t sig[64]);

/* ECDSA verify: pub (65 bytes uncompressed), digest (32 bytes), sig (64 bytes) */
int crypto_verify_digest(const uint8_t pub[65],
                         const uint8_t digest[32],
                         const uint8_t sig[64]);

/* Generate 32 bytes of random data */
void crypto_random32(uint8_t out[32]);

/* Get uncompressed public key (65 bytes) from private key (32 bytes) */
void crypto_get_pubkey65(const uint8_t priv[32], uint8_t pub[65]);

/* Generate ECDSA keypair (secp256k1) at runtime */
int crypto_generate_keypair(uint8_t priv[32], uint8_t pub[65]);

#ifdef __cplusplus
}
#endif

#endif /* CYPHEROCK_CRYPTO_UTIL_H */
