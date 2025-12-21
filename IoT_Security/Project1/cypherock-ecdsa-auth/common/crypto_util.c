#include "crypto_util.h"

#include <string.h>

#include "sha2.h"
#include "ecdsa.h"
#include "rand.h"
#include "secp256k1.h"

/* Simple SHA-256 wrapper */
void crypto_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_Raw(data, len, out);
}

/* Trezor-crypto ecdsa_sign_digest has 6 parameters:
 * int ecdsa_sign_digest(const ecdsa_curve *curve,
 *                       const uint8_t *priv_key,
 *                       const uint8_t *digest,
 *                       uint8_t *sig,
 *                       uint8_t *pby,
 *                       int (*is_canonical)(uint8_t by, uint8_t sig[64]));
 */
int crypto_sign_digest(const uint8_t priv[32],
                       const uint8_t digest[32],
                       uint8_t sig[64])
{
    int rc = ecdsa_sign_digest(&secp256k1,
                               priv,
                               digest,
                               sig,
                               NULL,   /* pby not needed */
                               NULL);  /* is_canonical = default */

    return (rc == 0) ? 0 : -1;
}

/* Trezor-crypto ecdsa_verify_digest:
 * int ecdsa_verify_digest(const ecdsa_curve *curve,
 *                         const uint8_t *pub_key,
 *                         const uint8_t *sig,
 *                         const uint8_t *digest);
 */
int crypto_verify_digest(const uint8_t pub[65],
                         const uint8_t digest[32],
                         const uint8_t sig[64])
{
    int rc = ecdsa_verify_digest(&secp256k1,
                                 pub,
                                 sig,
                                 digest);
    return (rc == 0) ? 0 : -1;
}

/* 32 random bytes (using trezor-crypto RNG) */
void crypto_random32(uint8_t out[32])
{
    random_buffer(out, 32);
}

/* Get uncompressed (65-byte) public key from 32-byte private key */
void crypto_get_pubkey65(const uint8_t priv[32], uint8_t pub[65])
{
    ecdsa_get_public_key65(&secp256k1, priv, pub);
}

/* New: runtime keypair generation (simple version for this trezor-crypto) */
int crypto_generate_keypair(uint8_t priv[32], uint8_t pub[65])
{
    if (!priv || !pub) {
        return -1;
    }

    /* Generate random private key (32 bytes) */
    crypto_random32(priv);

    /* Derive corresponding uncompressed public key (65 bytes) */
    crypto_get_pubkey65(priv, pub);

    return 0;
}
