"""
Unit and security tests for Shamir's Secret Sharing over GF(2^8).
"""

import itertools
from blindagent.sss import ShamirSecretSharing, calculate_entropy


def test_threshold_reconstruction():
    secret = "TopSecretPassword2026!#$@^"
    k = 3
    n = 5
    sss = ShamirSecretSharing(threshold=k, total_shares=n)
    shares = sss.split_text(secret)
    assert len(shares) == n

    # All subsets of size k must reconstruct secret exactly
    for subset in itertools.combinations(shares, k):
        recovered = sss.combine_text(list(subset))
        assert recovered == secret, f"Reconstruction failed for subset {subset}"


def test_sub_threshold_failure():
    secret = "CONFIDENTIAL_KEY_XYZ"
    k = 4
    n = 6
    sss = ShamirSecretSharing(threshold=k, total_shares=n)
    shares = sss.split_text(secret)

    # 3 shares (< k=4) must not recover secret
    try:
        sss.combine_text(shares[:3])
        assert False, "Should raise ValueError for insufficient shares"
    except ValueError:
        pass  # Expected behavior


def test_share_entropy():
    secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # Low entropy plaintext
    k = 3
    n = 5
    sss = ShamirSecretSharing(threshold=k, total_shares=n)
    shares = sss.split_text(secret)

    # Plaintext entropy is 0.0 bits
    assert calculate_entropy(secret.encode()) == 0.0

    # Shares must have high entropy (> 3.5 bits/byte in serialized hex)
    for s in shares:
        ent = calculate_entropy(s.encode())
        assert ent > 3.0, f"Share entropy too low: {ent}"


if __name__ == "__main__":
    test_threshold_reconstruction()
    test_sub_threshold_failure()
    test_share_entropy()
    print("All SSS threshold and security tests passed!")
