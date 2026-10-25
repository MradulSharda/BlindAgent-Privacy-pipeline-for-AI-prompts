"""
Mathematical verification of Galois Field GF(2^8) field axioms.
"""

from blindagent.crypto_bridge import gf256_add, gf256_sub, gf256_mul, gf256_inv, gf256_div


def test_additive_group():
    # Closure, identity, inverse, commutativity
    for a in range(256):
        assert gf256_add(a, 0) == a, "0 must be additive identity"
        assert gf256_add(a, a) == 0, "Each element is its own additive inverse"
        assert gf256_sub(a, 0) == a
        assert gf256_sub(a, a) == 0
        for b in range(0, 256, 17):
            assert gf256_add(a, b) == gf256_add(b, a), "Addition must commute"


def test_multiplicative_inverses():
    # 0 has no inverse (defined as 0 in constant-time)
    assert gf256_inv(0) == 0

    # For all a in GF(2^8)*, a * a^(-1) = 1
    for a in range(1, 256):
        inv = gf256_inv(a)
        prod = gf256_mul(a, inv)
        assert prod == 1, f"Multiplicative inverse failed for a={a}, got inv={inv}, prod={prod}"


def test_distributivity():
    # a * (b + c) = (a * b) + (a * c)
    test_values = [1, 2, 3, 7, 19, 42, 127, 255]
    for a in test_values:
        for b in test_values:
            for c in test_values:
                lhs = gf256_mul(a, gf256_add(b, c))
                rhs = gf256_add(gf256_mul(a, b), gf256_mul(a, c))
                assert lhs == rhs, f"Distributivity failed for {a}, {b}, {c}"


def test_division():
    for a in [5, 23, 77, 189]:
        for b in [1, 4, 15, 63, 255]:
            q = gf256_div(a, b)
            reconstructed = gf256_mul(q, b)
            assert reconstructed == a, f"Division failed: {a} / {b}"


if __name__ == "__main__":
    test_additive_group()
    test_multiplicative_inverses()
    test_distributivity()
    test_division()
    print("All GF(2^8) math tests passed!")
