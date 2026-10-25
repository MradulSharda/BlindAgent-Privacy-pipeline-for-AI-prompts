/**
 * @file test_engine.c
 * @brief Unit tests and mathematical validation for crypto_engine.c
 */

#include "crypto_engine.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

void test_field_axioms(void) {
    printf("[+] Testing GF(2^8) Field Axioms...\n");
    /* Test 1: Additive identity and self-inverse */
    for (int a = 0; a < 256; a++) {
        assert(gf256_add((uint8_t)a, 0) == (uint8_t)a);
        assert(gf256_add((uint8_t)a, (uint8_t)a) == 0);
    }

    /* Test 2: Multiplicative identity and inverse */
    assert(gf256_inv(0) == 0);
    for (int a = 1; a < 256; a++) {
        uint8_t inv = gf256_inv((uint8_t)a);
        uint8_t prod = gf256_mul((uint8_t)a, inv);
        if (prod != 1) {
            printf("FAIL: a=%d, inv=%d, prod=%d\n", a, inv, prod);
            assert(prod == 1);
        }
    }

    /* Test 3: Distributivity a*(b + c) == (a*b) + (a*c) */
    for (int a = 1; a < 30; a++) {
        for (int b = 1; b < 30; b++) {
            for (int c = 1; c < 30; c++) {
                uint8_t lhs = gf256_mul(a, gf256_add(b, c));
                uint8_t rhs = gf256_add(gf256_mul(a, b), gf256_mul(a, c));
                assert(lhs == rhs);
            }
        }
    }
    printf("    -> All GF(2^8) field axioms verified successfully!\n");
}

void test_sss(void) {
    printf("[+] Testing Shamir's Secret Sharing (k=3, n=5)...\n");
    const char *secret_str = "HACKATHON-SECRET-MASTER-KEY-2026";
    size_t sec_len = strlen(secret_str);
    uint8_t k = 3;
    uint8_t n = 5;
    size_t share_size = 1 + sec_len;

    uint8_t shares[5 * 33];
    int res = sss_split_secret((const uint8_t *)secret_str, sec_len, k, n, shares);
    assert(res == 0);

    /* Test reconstruction with subset {share 0, share 1, share 2} */
    uint8_t subset1[3 * 33];
    memcpy(subset1 + 0 * share_size, shares + 0 * share_size, share_size);
    memcpy(subset1 + 1 * share_size, shares + 1 * share_size, share_size);
    memcpy(subset1 + 2 * share_size, shares + 2 * share_size, share_size);

    uint8_t recovered[64] = {0};
    res = sss_combine_shares(subset1, share_size, k, recovered);
    assert(res == 0);
    assert(memcmp(secret_str, recovered, sec_len) == 0);

    /* Test reconstruction with non-consecutive subset {share 1, share 3, share 4} */
    uint8_t subset2[3 * 33];
    memcpy(subset2 + 0 * share_size, shares + 1 * share_size, share_size);
    memcpy(subset2 + 1 * share_size, shares + 3 * share_size, share_size);
    memcpy(subset2 + 2 * share_size, shares + 4 * share_size, share_size);

    memset(recovered, 0, sizeof(recovered));
    res = sss_combine_shares(subset2, share_size, k, recovered);
    assert(res == 0);
    assert(memcmp(secret_str, recovered, sec_len) == 0);

    printf("    -> Reconstructed secret correctly: '%s'\n", (char *)recovered);
}

void test_blinding(void) {
    printf("[+] Testing Homomorphic Affine Blinding...\n");
    const char *data = "SystemSensitiveToken994";
    size_t len = strlen(data);
    uint8_t blinded[64];
    uint8_t unblinded[64];

    uint8_t alpha = 0x4B; // coprime non-zero scalar
    uint8_t beta = 0x8F;

    assert(blind_affine_transform((const uint8_t *)data, len, alpha, beta, blinded) == 0);
    assert(memcmp(data, blinded, len) != 0); // Ciphertext must differ from plaintext
    assert(unblind_affine_transform(blinded, len, alpha, beta, unblinded) == 0);
    assert(memcmp(data, unblinded, len) == 0);

    printf("    -> Affine blinding and exact unblinding verified!\n");
}

int main(void) {
    printf("=========================================\n");
    printf("   CRYPTOGRAPHIC ENGINE VERIFICATION     \n");
    printf("=========================================\n");
    test_field_axioms();
    test_sss();
    test_blinding();
    printf("=========================================\n");
    printf("   ALL TESTS PASSED WITH ZERO ERRORS     \n");
    printf("=========================================\n");
    return 0;
}
