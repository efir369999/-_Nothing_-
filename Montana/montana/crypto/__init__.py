"""
Montana Cryptographic Primitives

Post-quantum secure cryptography per ATC Layer 0.
- SHA3-256, SHAKE256 (NIST FIPS 202)
- ML-DSA-65 (NIST FIPS 204) — Type B security
- ML-KEM-768 (NIST FIPS 203) [future]
"""

from montana.crypto.hash import (
    sha3_256,
    sha3_256_raw,
    shake256,
    shake256_hash,
    tagged_hash,
    double_sha3_256,
    HashBuilder,
    SHAKE256Builder,
)

from montana.crypto.mldsa import (
    mldsa_keygen,
    mldsa_sign,
    mldsa_verify,
    is_liboqs_available,
    MLDSA,
)

__all__ = [
    # Hash functions
    "sha3_256",
    "sha3_256_raw",
    "shake256",
    "shake256_hash",
    "tagged_hash",
    "double_sha3_256",
    "HashBuilder",
    "SHAKE256Builder",
    # ML-DSA (Type B security)
    "mldsa_keygen",
    "mldsa_sign",
    "mldsa_verify",
    "is_liboqs_available",
    "MLDSA",
]
