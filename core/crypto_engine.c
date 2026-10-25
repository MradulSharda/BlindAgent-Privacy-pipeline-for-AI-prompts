/**
 * @file crypto_engine.c
 * @brief Constant-time Implementation of Galois Field GF(2^8) and Shamir's Secret Sharing.
 */

#include "crypto_engine.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#include <stdlib.h>
#define HAVE_ARC4RANDOM 1
#endif

const char* crypto_engine_version(void) {
    return "BlindAgent-CryptoEngine-v1.0 (GF256 + SSS + ConstantTime)";
}

void secure_memzero(void *v, size_t n) {
    if (!v) return;
    volatile uint8_t *p = (volatile uint8_t *)v;
    while (n--) {
        *p++ = 0;
    }
}

int secure_random_bytes(uint8_t *buf, size_t len) {
    if (!buf) return -1;
#if defined(HAVE_ARC4RANDOM)
    arc4random_buf(buf, len);
    return 0;
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    while (total < len) {
        ssize_t n = read(fd, buf + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }
    close(fd);
    return 0;
#endif
}

/* Addition in GF(2^8) is bitwise XOR */
uint8_t gf256_add(uint8_t a, uint8_t b) {
    return (uint8_t)(a ^ b);
}

/* Subtraction is identical to addition in characteristic 2 */
uint8_t gf256_sub(uint8_t a, uint8_t b) {
    return (uint8_t)(a ^ b);
}

/**
 * Constant-time Peasant multiplication in GF(2^8) modulo P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)
 * Executes exactly 8 unbranched iterations regardless of secret inputs.
 */
uint8_t gf256_mul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t cur_a = a;
    uint8_t cur_b = b;

    for (int i = 0; i < 8; i++) {
        /* Branchless conditional add: mask is 0xFF if bit 0 of b is 1, else 0x00 */
        uint8_t mask = (uint8_t)(-(cur_b & 1));
        p ^= (cur_a & mask);

        /* Branchless reduction: if high bit of cur_a is 1, mask is 0xFF, else 0x00 */
        uint8_t hi_bit = (uint8_t)(-(cur_a >> 7));
        cur_a = (uint8_t)((cur_a << 1) ^ (0x1B & hi_bit));

        cur_b >>= 1;
    }
    return p;
}

/**
 * Constant-time Multiplicative Inverse in GF(2^8)
 * Using Fermat's Little Theorem: a^(255) = 1 in GF(2^8)*
 * Therefore: a^(-1) = a^(254)
 * 254 = 11111110 in binary.
 * Computed via addition chain: 7 squarings and 6 multiplications (total 13 operations).
 * Guaranteed branchless & constant time.
 */
uint8_t gf256_inv(uint8_t a) {
    /* a^2 */
    uint8_t a2 = gf256_mul(a, a);
    /* a^3 = a^2 * a */
    uint8_t a3 = gf256_mul(a2, a);
    /* a^6 = (a^3)^2 */
    uint8_t a6 = gf256_mul(a3, a3);
    /* a^7 = a^6 * a */
    uint8_t a7 = gf256_mul(a6, a);
    /* a^14 = (a^7)^2 */
    uint8_t a14 = gf256_mul(a7, a7);
    /* a^15 = a^14 * a */
    uint8_t a15 = gf256_mul(a14, a);
    /* a^30 = (a^15)^2 */
    uint8_t a30 = gf256_mul(a15, a15);
    /* a^31 = a^30 * a */
    uint8_t a31 = gf256_mul(a30, a);
    /* a^62 = (a^31)^2 */
    uint8_t a62 = gf256_mul(a31, a31);
    /* a^63 = a^62 * a */
    uint8_t a63 = gf256_mul(a62, a);
    /* a^126 = (a^63)^2 */
    uint8_t a126 = gf256_mul(a63, a63);
    /* a^127 = a^126 * a */
    uint8_t a127 = gf256_mul(a126, a);
    /* a^254 = (a^127)^2 */
    uint8_t a254 = gf256_mul(a127, a127);

    return a254;
}

uint8_t gf256_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;
    return gf256_mul(a, gf256_inv(b));
}

uint8_t gf256_pow(uint8_t base, uint8_t exp) {
    uint8_t res = 1;
    uint8_t b = base;
    while (exp > 0) {
        if (exp & 1) {
            res = gf256_mul(res, b);
        }
        b = gf256_mul(b, b);
        exp >>= 1;
    }
    return res;
}

/**
 * Evaluate polynomial at x using Horner's rule:
 * poly(x) = poly[0] + poly[1]*x + ... + poly[deg]*x^deg
 */
uint8_t gf256_poly_eval(const uint8_t *poly, size_t deg_plus_one, uint8_t x) {
    if (!poly || deg_plus_one == 0) return 0;
    uint8_t result = poly[deg_plus_one - 1];
    for (size_t i = deg_plus_one - 1; i > 0; i--) {
        result = gf256_add(gf256_mul(result, x), poly[i - 1]);
    }
    return result;
}

int sss_split_secret(const uint8_t *secret, size_t secret_len, uint8_t k, uint8_t n, uint8_t *shares_out) {
    if (!secret || !shares_out || secret_len == 0) return -1;
    if (k < 2 || k > n || n > 255) return -2;

    size_t share_size = 1 + secret_len;

    /* Initialize x coordinates for each share: 1, 2, ..., n */
    for (uint8_t j = 0; j < n; j++) {
        shares_out[j * share_size] = (uint8_t)(j + 1);
    }

    /* Allocate buffer for polynomial coefficients: deg = k - 1 */
    uint8_t *poly = (uint8_t *)malloc(k);
    if (!poly) return -3;

    for (size_t m = 0; m < secret_len; m++) {
        /* poly[0] is the secret byte */
        poly[0] = secret[m];

        /* Sample k - 1 random bytes for higher order coefficients */
        if (secure_random_bytes(poly + 1, k - 1) != 0) {
            secure_memzero(poly, k);
            free(poly);
            return -4;
        }

        /* Evaluate polynomial at each share's x coordinate */
        for (uint8_t j = 0; j < n; j++) {
            uint8_t x = shares_out[j * share_size];
            uint8_t y = gf256_poly_eval(poly, k, x);
            shares_out[j * share_size + 1 + m] = y;
        }
    }

    secure_memzero(poly, k);
    free(poly);
    return 0;
}

int sss_combine_shares(const uint8_t *shares_in, size_t share_len, uint8_t k, uint8_t *secret_out) {
    if (!shares_in || !secret_out || share_len < 2 || k < 2) return -1;
    size_t secret_len = share_len - 1;

    /* Extract x coordinates and verify uniqueness */
    uint8_t *xs = (uint8_t *)malloc(k);
    if (!xs) return -2;

    for (uint8_t i = 0; i < k; i++) {
        xs[i] = shares_in[i * share_len];
        if (xs[i] == 0) {
            free(xs);
            return -3; /* x=0 is the secret itself, illegal share point */
        }
        for (uint8_t prev = 0; prev < i; prev++) {
            if (xs[prev] == xs[i]) {
                free(xs);
                return -4; /* Duplicate share x coordinate */
            }
        }
    }

    /* Precompute Lagrange basis coefficients evaluated at x = 0:
     * L_j(0) = product_{m != j} (x_m / (x_m ^ x_j))
     */
    uint8_t *basis = (uint8_t *)malloc(k);
    if (!basis) {
        free(xs);
        return -5;
    }

    for (uint8_t j = 0; j < k; j++) {
        uint8_t num = 1;
        uint8_t den = 1;
        for (uint8_t m = 0; m < k; m++) {
            if (m == j) continue;
            num = gf256_mul(num, xs[m]);
            den = gf256_mul(den, gf256_sub(xs[m], xs[j]));
        }
        basis[j] = gf256_div(num, den);
    }

    /* Reconstruct each byte of the secret:
     * Secret[b] = sum_{j=0}^{k-1} ( y_{j, b} * L_j(0) )
     */
    for (size_t b = 0; b < secret_len; b++) {
        uint8_t val = 0;
        for (uint8_t j = 0; j < k; j++) {
            uint8_t y = shares_in[j * share_len + 1 + b];
            val = gf256_add(val, gf256_mul(y, basis[j]));
        }
        secret_out[b] = val;
    }

    secure_memzero(xs, k);
    secure_memzero(basis, k);
    free(xs);
    free(basis);
    return 0;
}

int blind_affine_transform(const uint8_t *in, size_t len, uint8_t alpha, uint8_t beta, uint8_t *out) {
    if (!in || !out || alpha == 0) return -1;
    for (size_t i = 0; i < len; i++) {
        out[i] = gf256_add(gf256_mul(in[i], alpha), beta);
    }
    return 0;
}

int unblind_affine_transform(const uint8_t *in, size_t len, uint8_t alpha, uint8_t beta, uint8_t *out) {
    if (!in || !out || alpha == 0) return -1;
    uint8_t inv_alpha = gf256_inv(alpha);
    for (size_t i = 0; i < len; i++) {
        uint8_t sub = gf256_sub(in[i], beta);
        out[i] = gf256_mul(sub, inv_alpha);
    }
    return 0;
}
