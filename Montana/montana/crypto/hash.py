"""
Ɉ Montana Protocol Hash Functions v3.8

Hash function classification per ATC Layer 0:

| Category        | Function        | Security Type | Use Case                    |
|-----------------|-----------------|---------------|-----------------------------|
| Unkeyed         | SHA3-256        | Type C        | Block hashes, Merkle roots  |
| Keyed (MAC)     | HMAC-SHA3-256   | Type B        | Message authentication      |
| Key Derivation  | HKDF-SHA3-256   | Type B        | Session keys, derived keys  |

Security Type Classification:
- Type C (Empirical): 10+ years cryptanalysis without attacks
- Type B (Proven Reduction): Secure if SHA3-256 is PRF
"""

from __future__ import annotations
import hashlib
import hmac
from typing import Union

from montana.constants import SHA3_256_OUTPUT_SIZE, SHAKE256_OUTPUT_SIZE
from montana.core.types import Hash


# ==============================================================================
# UNKEYED HASH (Type C)
# ==============================================================================
# Use for: block hashes, Merkle roots, commitments, VDF input
# Security: 128-bit classical, 85-bit quantum (Grover)


def sha3_256(data: Union[bytes, bytearray, memoryview]) -> Hash:
    """
    SHA3-256 unkeyed hash (Type C security).

    Per NIST FIPS 202.

    Args:
        data: Input data to hash

    Returns:
        Hash: 32-byte hash output wrapped in Hash type
    """
    hasher = hashlib.sha3_256()
    hasher.update(data)
    return Hash(hasher.digest())


def sha3_256_raw(data: Union[bytes, bytearray, memoryview]) -> bytes:
    """
    SHA3-256 unkeyed hash returning raw bytes (Type C security).

    Args:
        data: Input data to hash

    Returns:
        bytes: 32-byte hash output
    """
    return hashlib.sha3_256(data).digest()


def shake256(data: Union[bytes, bytearray, memoryview], output_length: int = SHAKE256_OUTPUT_SIZE) -> bytes:
    """
    SHAKE256 extendable output function (Type C security).

    Per NIST FIPS 202.

    Args:
        data: Input data
        output_length: Desired output length in bytes (default: 32)

    Returns:
        bytes: Output of specified length
    """
    hasher = hashlib.shake_256()
    hasher.update(data)
    return hasher.digest(output_length)


def shake256_hash(data: Union[bytes, bytearray, memoryview]) -> Hash:
    """
    SHAKE256 with 32-byte output (Type C security).

    Args:
        data: Input data

    Returns:
        Hash: 32-byte hash output
    """
    return Hash(shake256(data, SHA3_256_OUTPUT_SIZE))


def tagged_hash(tag: bytes, data: bytes) -> Hash:
    """
    Domain-separated hash (Type C security).

    Computes: SHA3-256(SHA3-256(tag) || SHA3-256(tag) || data)

    Provides domain separation to prevent cross-protocol attacks.

    Args:
        tag: Domain separation tag
        data: Data to hash

    Returns:
        Hash: Tagged hash output
    """
    tag_hash = sha3_256_raw(tag)
    return sha3_256(tag_hash + tag_hash + data)


def double_sha3_256(data: bytes) -> Hash:
    """
    Double SHA3-256 hash (Type C security).

    Args:
        data: Input data

    Returns:
        Hash: SHA3-256(SHA3-256(data))
    """
    return sha3_256(sha3_256_raw(data))


# ==============================================================================
# KEYED HASH / MAC (Type B)
# ==============================================================================
# Use for: message authentication, authenticated channels
# Security: Type B (proven secure if SHA3-256 is PRF)


def hmac_sha3_256(key: bytes, data: Union[bytes, bytearray, memoryview]) -> bytes:
    """
    HMAC-SHA3-256 keyed hash (Type B security).

    Proven secure if SHA3-256 is a PRF.

    Args:
        key: Secret key
        data: Data to authenticate

    Returns:
        bytes: 32-byte MAC
    """
    return hmac.new(key, data, hashlib.sha3_256).digest()


def hmac_sha3_256_hash(key: bytes, data: Union[bytes, bytearray, memoryview]) -> Hash:
    """
    HMAC-SHA3-256 keyed hash returning Hash type (Type B security).

    Args:
        key: Secret key
        data: Data to authenticate

    Returns:
        Hash: 32-byte MAC wrapped in Hash type
    """
    return Hash(hmac_sha3_256(key, data))


def verify_hmac(key: bytes, data: bytes, expected_mac: bytes) -> bool:
    """
    Constant-time HMAC verification (Type B security).

    Args:
        key: Secret key
        data: Data that was authenticated
        expected_mac: Expected MAC value

    Returns:
        bool: True if MAC is valid
    """
    computed = hmac_sha3_256(key, data)
    return hmac.compare_digest(computed, expected_mac)


# ==============================================================================
# KEY DERIVATION (Type B)
# ==============================================================================
# Use for: session keys, derived keys, key expansion
# Security: Type B (proven secure if HMAC is PRF)


def hkdf_sha3_256(
    ikm: bytes,
    salt: bytes,
    info: bytes,
    length: int = 32
) -> bytes:
    """
    HKDF-SHA3-256 key derivation (Type B security).

    Per RFC 5869 using SHA3-256.
    Proven secure if HMAC-SHA3-256 is a PRF.

    Args:
        ikm: Input key material
        salt: Salt (can be empty, but recommended)
        info: Context/application-specific info
        length: Output length in bytes

    Returns:
        bytes: Derived key material
    """
    # HKDF-Extract
    if not salt:
        salt = bytes(32)  # Default to zeros
    prk = hmac_sha3_256(salt, ikm)

    # HKDF-Expand
    output = b""
    t = b""
    counter = 1

    while len(output) < length:
        t = hmac_sha3_256(prk, t + info + bytes([counter]))
        output += t
        counter += 1

    return output[:length]


def hkdf_sha3_256_hash(
    ikm: bytes,
    salt: bytes,
    info: bytes
) -> Hash:
    """
    HKDF-SHA3-256 returning 32-byte Hash type (Type B security).

    Args:
        ikm: Input key material
        salt: Salt
        info: Context info

    Returns:
        Hash: 32-byte derived key
    """
    return Hash(hkdf_sha3_256(ikm, salt, info, 32))


class HashBuilder:
    """
    Builder pattern for constructing hashes from multiple inputs.

    Example:
        hash = HashBuilder().update(b"hello").update(b"world").finalize()
    """

    def __init__(self):
        self._hasher = hashlib.sha3_256()

    def update(self, data: bytes) -> "HashBuilder":
        """Add data to the hash computation."""
        self._hasher.update(data)
        return self

    def update_u8(self, value: int) -> "HashBuilder":
        """Add a u8 to the hash computation."""
        self._hasher.update(bytes([value]))
        return self

    def update_u16(self, value: int) -> "HashBuilder":
        """Add a u16 (big-endian) to the hash computation."""
        self._hasher.update(value.to_bytes(2, "big"))
        return self

    def update_u32(self, value: int) -> "HashBuilder":
        """Add a u32 (big-endian) to the hash computation."""
        self._hasher.update(value.to_bytes(4, "big"))
        return self

    def update_u64(self, value: int) -> "HashBuilder":
        """Add a u64 (big-endian) to the hash computation."""
        self._hasher.update(value.to_bytes(8, "big"))
        return self

    def update_hash(self, h: Hash) -> "HashBuilder":
        """Add another hash to the computation."""
        self._hasher.update(h.data)
        return self

    def finalize(self) -> Hash:
        """Complete the hash computation and return the result."""
        return Hash(self._hasher.digest())

    def finalize_raw(self) -> bytes:
        """Complete the hash computation and return raw bytes."""
        return self._hasher.digest()

    def copy(self) -> "HashBuilder":
        """Create a copy of the current state."""
        builder = HashBuilder()
        builder._hasher = self._hasher.copy()
        return builder


class SHAKE256Builder:
    """
    Builder pattern for SHAKE256 XOF.
    """

    def __init__(self):
        self._hasher = hashlib.shake_256()

    def update(self, data: bytes) -> "SHAKE256Builder":
        """Add data to the computation."""
        self._hasher.update(data)
        return self

    def finalize(self, output_length: int = SHAKE256_OUTPUT_SIZE) -> bytes:
        """Complete the computation and return output of specified length."""
        return self._hasher.digest(output_length)

    def finalize_hash(self) -> Hash:
        """Complete the computation and return 32-byte Hash."""
        return Hash(self._hasher.digest(SHA3_256_OUTPUT_SIZE))

    def copy(self) -> "SHAKE256Builder":
        """Create a copy of the current state."""
        builder = SHAKE256Builder()
        builder._hasher = self._hasher.copy()
        return builder
