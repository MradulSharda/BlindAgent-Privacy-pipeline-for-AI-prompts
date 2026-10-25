/**
 * @file crypto_engine.h
 * @brief High-performance, constant-time Galois Field GF(2^8) and Shamir's Secret Sharing Engine.
 * 
 * Developed for "Mathematics for Systems Security" Hackathon.
 * Tracks: AI Pipeline Secret Sharing & Cryptographer.
 */

#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rijndael Irreducible Polynomial: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B) */
#define GF256_POLY 0x1B

/* GF(2^8) Field Arithmetic */
uint8_t gf256_add(uint8_t a, uint8_t b);
uint8_t gf256_sub(uint8_t a, uint8_t b);
uint8_t gf256_mul(uint8_t a, uint8_t b);
uint8_t gf256_inv(uint8_t a);
uint8_t gf256_div(uint8_t a, uint8_t b);
uint8_t gf256_pow(uint8_t base, uint8_t exp);

/* Polynomial Evaluation over GF(2^8)
 * poly[0] is constant term, poly[1] is x^1, etc.
 * deg_plus_one is the number of coefficients.
 */
uint8_t gf256_poly_eval(const uint8_t *poly, size_t deg_plus_one, uint8_t x);

/* Cryptographically Secure Random Bytes */
int secure_random_bytes(uint8_t *buf, size_t len);

/* Secure constant-time zeroization */
void secure_memzero(void *v, size_t n);

/**
 * @brief Shamir's Secret Sharing (k, n) Split over GF(2^8).
 * 
 * Splits `secret` of `secret_len` bytes into `n` shares requiring threshold `k`.
 * Each share is of length (1 + secret_len) bytes:
 *   Byte 0: x coordinate (1 to n)
 *   Bytes 1..secret_len: y values (f(x) for each secret byte)
 * 
 * @param secret Pointer to secret bytes
 * @param secret_len Length of secret in bytes
 * @param k Threshold (k <= n, k >= 2)
 * @param n Total shares to generate (2 <= n <= 255)
 * @param shares_out Output buffer of size n * (1 + secret_len) bytes
 * @return 0 on success, negative on error.
 */
int sss_split_secret(const uint8_t *secret, size_t secret_len, uint8_t k, uint8_t n, uint8_t *shares_out);

/**
 * @brief Shamir's Secret Sharing (k, n) Reconstruct over GF(2^8).
 * 
 * Reconstructs secret from k shares using Lagrange interpolation.
 * Each share must have format [x_coord, y_0, y_1, ..., y_{secret_len-1}].
 * 
 * @param shares_in Pointer to k shares concatenated (total size: k * share_len)
 * @param share_len Length of each individual share (1 + secret_len)
 * @param k Number of shares provided (must match original threshold)
 * @param secret_out Output buffer of size (share_len - 1) bytes
 * @return 0 on success, negative on error.
 */
int sss_combine_shares(const uint8_t *shares_in, size_t share_len, uint8_t k, uint8_t *secret_out);

/**
 * @brief Affine Homomorphic Blinding Transform over GF(2^8).
 * Computes: out[i] = (in[i] * alpha) + beta in GF(2^8)
 * alpha must be invertible (alpha != 0).
 */
int blind_affine_transform(const uint8_t *in, size_t len, uint8_t alpha, uint8_t beta, uint8_t *out);

/**
 * @brief Invert Affine Homomorphic Blinding Transform over GF(2^8).
 * Computes: out[i] = (in[i] - beta) * alpha^(-1) in GF(2^8)
 */
int unblind_affine_transform(const uint8_t *in, size_t len, uint8_t alpha, uint8_t beta, uint8_t *out);

/**
 * @brief Return engine version and compile-time features.
 */
const char* crypto_engine_version(void);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_ENGINE_H */
