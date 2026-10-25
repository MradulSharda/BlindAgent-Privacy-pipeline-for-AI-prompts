"""
ctypes bridge to the native C/Clang cryptographic engine (libblindcrypto).
Provides constant-time GF(2^8) arithmetic, Shamir's Secret Sharing, and Affine Blinding.
"""

import os
import sys
import ctypes
from typing import List, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_LIB_CANDIDATES = [
    os.path.join(_ROOT, "libblindcrypto.dylib"),
    os.path.join(_ROOT, "libblindcrypto.so"),
    os.path.join(_ROOT, "target", "release", "libblindagent_crypto_core.dylib"),
    os.path.join(_ROOT, "target", "release", "libblindagent_crypto_core.so"),
]

_lib = None
for path in _LIB_CANDIDATES:
    if os.path.exists(path):
        try:
            _lib = ctypes.CDLL(path)
            break
        except Exception:
            continue

if _lib is None:
    # Try building via make if not found
    import subprocess
    try:
        subprocess.run(["make", "-C", _ROOT], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for path in _LIB_CANDIDATES:
            if os.path.exists(path):
                _lib = ctypes.CDLL(path)
                break
    except Exception as e:
        pass

if _lib is None:
    raise RuntimeError(
        "Could not load native cryptographic engine. Run 'make' in project root to compile libblindcrypto."
    )

# Function signatures
_lib.crypto_engine_version.restype = ctypes.c_char_p

_lib.gf256_add.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
_lib.gf256_add.restype = ctypes.c_uint8

_lib.gf256_sub.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
_lib.gf256_sub.restype = ctypes.c_uint8

_lib.gf256_mul.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
_lib.gf256_mul.restype = ctypes.c_uint8

_lib.gf256_inv.argtypes = [ctypes.c_uint8]
_lib.gf256_inv.restype = ctypes.c_uint8

_lib.gf256_div.argtypes = [ctypes.c_uint8, ctypes.c_uint8]
_lib.gf256_div.restype = ctypes.c_uint8

_lib.secure_random_bytes.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
_lib.secure_random_bytes.restype = ctypes.c_int

_lib.sss_split_secret.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_char_p
]
_lib.sss_split_secret.restype = ctypes.c_int

_lib.sss_combine_shares.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_char_p
]
_lib.sss_combine_shares.restype = ctypes.c_int

_lib.blind_affine_transform.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_char_p
]
_lib.blind_affine_transform.restype = ctypes.c_int

_lib.unblind_affine_transform.argtypes = [
    ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint8, ctypes.c_uint8, ctypes.c_char_p
]
_lib.unblind_affine_transform.restype = ctypes.c_int


def engine_version() -> str:
    return _lib.crypto_engine_version().decode("utf-8")


def gf256_add(a: int, b: int) -> int:
    return _lib.gf256_add(a & 0xFF, b & 0xFF)


def gf256_sub(a: int, b: int) -> int:
    return _lib.gf256_sub(a & 0xFF, b & 0xFF)


def gf256_mul(a: int, b: int) -> int:
    return _lib.gf256_mul(a & 0xFF, b & 0xFF)


def gf256_inv(a: int) -> int:
    return _lib.gf256_inv(a & 0xFF)


def gf256_div(a: int, b: int) -> int:
    return _lib.gf256_div(a & 0xFF, b & 0xFF)


def get_secure_random(length: int) -> bytes:
    buf = ctypes.create_string_buffer(length)
    res = _lib.secure_random_bytes(buf, length)
    if res != 0:
        raise OSError("Failed to generate secure random bytes")
    return buf.raw


def sss_split(secret: bytes, k: int, n: int) -> List[bytes]:
    """
    Split secret bytes into n shares requiring threshold k.
    Each share returned is (1 + len(secret)) bytes.
    Byte 0 is x coordinate; Remaining bytes are f(x).
    """
    if not (2 <= k <= n <= 255):
        raise ValueError(f"Invalid threshold parameters: k={k}, n={n} (must be 2 <= k <= n <= 255)")
    if len(secret) == 0:
        raise ValueError("Secret cannot be empty")

    share_len = 1 + len(secret)
    total_buf = ctypes.create_string_buffer(n * share_len)
    res = _lib.sss_split_secret(secret, len(secret), k, n, total_buf)
    if res != 0:
        raise RuntimeError(f"C engine sss_split_secret failed with code {res}")

    raw = total_buf.raw
    shares = [raw[i * share_len : (i + 1) * share_len] for i in range(n)]
    return shares


def sss_combine(shares: List[bytes], k: int) -> bytes:
    """
    Reconstruct secret from k shares using Galois Field Lagrange interpolation.
    """
    if len(shares) < k:
        raise ValueError(f"Need at least {k} shares, provided {len(shares)}")
    if k < 2:
        raise ValueError("Threshold k must be at least 2")

    share_len = len(shares[0])
    for s in shares[:k]:
        if len(s) != share_len:
            raise ValueError("All shares must have identical length")

    in_buf = b"".join(shares[:k])
    out_buf = ctypes.create_string_buffer(share_len - 1)
    res = _lib.sss_combine_shares(in_buf, share_len, k, out_buf)
    if res != 0:
        raise RuntimeError(f"C engine sss_combine_shares failed with code {res}")
    return out_buf.raw


def blind_affine(data: bytes, alpha: int, beta: int) -> bytes:
    if alpha == 0:
        raise ValueError("Alpha parameter must be non-zero in GF(2^8)")
    out_buf = ctypes.create_string_buffer(len(data))
    res = _lib.blind_affine_transform(data, len(data), alpha & 0xFF, beta & 0xFF, out_buf)
    if res != 0:
        raise RuntimeError("Failed to apply affine blinding")
    return out_buf.raw


def unblind_affine(data: bytes, alpha: int, beta: int) -> bytes:
    if alpha == 0:
        raise ValueError("Alpha parameter must be non-zero in GF(2^8)")
    out_buf = ctypes.create_string_buffer(len(data))
    res = _lib.unblind_affine_transform(data, len(data), alpha & 0xFF, beta & 0xFF, out_buf)
    if res != 0:
        raise RuntimeError("Failed to unblind affine transform")
    return out_buf.raw
