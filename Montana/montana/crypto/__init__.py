"""
Montana Cryptographic Primitives v3.8

Post-quantum secure cryptography per ATC Layer 0.

Hash Function Classification:
| Category        | Function        | Security Type | Use Case                   |
|-----------------|-----------------|---------------|----------------------------|
| Unkeyed         | SHA3-256        | Type C        | Block hashes, Merkle roots |
| Keyed (MAC)     | HMAC-SHA3-256   | Type B        | Message authentication     |
| Key Derivation  | HKDF-SHA3-256   | Type B        | Session keys, derived keys |

Other Primitives:
- ML-DSA-65 (NIST FIPS 204) — Type B security
- ML-KEM-768 (NIST FIPS 203) [future]
- Class Group VDF (Wesolowski 2019) — Type B security
"""

from montana.crypto.hash import (
    # Unkeyed hash (Type C)
    sha3_256,
    sha3_256_raw,
    shake256,
    shake256_hash,
    tagged_hash,
    double_sha3_256,
    # Keyed hash / MAC (Type B)
    hmac_sha3_256,
    hmac_sha3_256_hash,
    verify_hmac,
    # Key derivation (Type B)
    hkdf_sha3_256,
    hkdf_sha3_256_hash,
    # Builders
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
    # Unkeyed hash (Type C)
    "sha3_256",
    "sha3_256_raw",
    "shake256",
    "shake256_hash",
    "tagged_hash",
    "double_sha3_256",
    # Keyed hash / MAC (Type B)
    "hmac_sha3_256",
    "hmac_sha3_256_hash",
    "verify_hmac",
    # Key derivation (Type B)
    "hkdf_sha3_256",
    "hkdf_sha3_256_hash",
    # Builders
    "HashBuilder",
    "SHAKE256Builder",
    # ML-DSA (Type B security)
    "mldsa_keygen",
    "mldsa_sign",
    "mldsa_verify",
    "is_liboqs_available",
    "MLDSA",
]
