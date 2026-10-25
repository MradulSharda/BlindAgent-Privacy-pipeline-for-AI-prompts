"""
High-level Shamir's Secret Sharing interface over GF(2^8).
Handles string/byte conversions, share serialization, and verification.
"""

from typing import List, Tuple
from blindagent.crypto_bridge import sss_split, sss_combine


class ShamirSecretSharing:
    def __init__(self, threshold: int = 3, total_shares: int = 5):
        if not (2 <= threshold <= total_shares <= 255):
            raise ValueError(f"Invalid threshold (k={threshold}, n={total_shares})")
        self.k = threshold
        self.n = total_shares

    def split_text(self, secret_text: str) -> List[str]:
        raw_secret = secret_text.encode("utf-8")
        raw_shares = sss_split(raw_secret, self.k, self.n)
        serialized = []
        for s in raw_shares:
            x_coord = s[0]
            y_payload = s[1:].hex()
            # Format: SSS-<k>-<n>:<x>:<hex>
            serialized.append(f"SSS-k{self.k}n{self.n}:{x_coord:02x}:{y_payload}")
        return serialized

    def combine_text(self, share_strings: List[str]) -> str:
        if len(share_strings) < self.k:
            raise ValueError(f"Insufficient shares: got {len(share_strings)}, required {self.k}")

        raw_shares = []
        for s in share_strings[:self.k]:
            parts = s.strip().split(":")
            if len(parts) != 3:
                raise ValueError(f"Malformed share string format: {s}")
            x = int(parts[1], 16)
            y_bytes = bytes.fromhex(parts[2])
            raw_shares.append(bytes([x]) + y_bytes)

        recovered_bytes = sss_combine(raw_shares, self.k)
        return recovered_bytes.decode("utf-8", errors="replace")


def calculate_entropy(data: bytes) -> float:
    """
    Shannon entropy in bits per byte: H(X) = -sum(p(x) * log2(p(x)))
    Theoretical maximum for random uniform bytes is 8.0 bits.
    """
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy
