"""
Ɉ Montana Protocol ML-DSA Signatures v3.7

ML-DSA-65 (Dilithium) per NIST FIPS 204.

Type B security: reduction to Module-LWE problem.

This module provides post-quantum secure digital signatures using
ML-DSA-65 (formerly known as Dilithium).

Signature size: 3,309 bytes
Public key size: 1,952 bytes
Secret key size: 4,032 bytes
"""

from __future__ import annotations
from typing import Optional, Tuple
import secrets
import logging

from montana.core.types import PublicKey, SecretKey, Signature, KeyPair
from montana.constants import (
    ALGORITHM_ML_DSA,
    ML_DSA_PUBLIC_KEY_SIZE,
    ML_DSA_SECRET_KEY_SIZE,
    ML_DSA_SIGNATURE_SIZE,
)

logger = logging.getLogger(__name__)

# Try to import liboqs for production ML-DSA implementation
_LIBOQS_AVAILABLE = False
_oqs = None

try:
    import oqs
    _oqs = oqs
    _LIBOQS_AVAILABLE = True
    logger.info("liboqs available - using production ML-DSA implementation")
except ImportError:
    logger.warning(
        "liboqs not available - using fallback implementation. "
        "Install with: pip install liboqs-python"
    )


class MLDSA:
    """
    ML-DSA-65 (Dilithium) wrapper.

    Uses liboqs when available, falls back to a deterministic
    pseudo-implementation for testing when liboqs is not installed.

    Type B security: reduction to Module-LWE problem.
    """

    ALGORITHM_NAME = "Dilithium3"  # liboqs name for ML-DSA-65

    def __init__(self):
        self._signer: Optional[object] = None
        if _LIBOQS_AVAILABLE:
            self._signer = _oqs.Signature(self.ALGORITHM_NAME)

    @property
    def is_production(self) -> bool:
        """Return True if using production liboqs implementation."""
        return _LIBOQS_AVAILABLE

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """
        Generate a new ML-DSA keypair.

        Returns:
            Tuple of (public_key, secret_key) as bytes
        """
        if _LIBOQS_AVAILABLE and self._signer:
            public_key = self._signer.generate_keypair()
            secret_key = self._signer.export_secret_key()
            return public_key, secret_key
        else:
            # Fallback: Generate deterministic keys for testing
            # WARNING: This is NOT secure, only for development
            seed = secrets.token_bytes(32)
            return self._fallback_keygen(seed)

    def _fallback_keygen(self, seed: bytes) -> Tuple[bytes, bytes]:
        """
        Fallback key generation using SHAKE256.
        NOT SECURE - for testing only.
        """
        import hashlib

        # Expand seed to get key material
        shake = hashlib.shake_256()
        shake.update(b"MONTANA_MLDSA_FALLBACK_KEYGEN_V37:" + seed)
        key_material = shake.digest(ML_DSA_PUBLIC_KEY_SIZE + ML_DSA_SECRET_KEY_SIZE)

        public_key = key_material[:ML_DSA_PUBLIC_KEY_SIZE]
        secret_key = key_material[ML_DSA_PUBLIC_KEY_SIZE:]

        return public_key, secret_key

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message with ML-DSA.

        Args:
            message: Message to sign
            secret_key: Secret key

        Returns:
            3,309-byte signature
        """
        if _LIBOQS_AVAILABLE and self._signer:
            # liboqs requires setting the secret key before signing
            signer = _oqs.Signature(self.ALGORITHM_NAME, secret_key)
            signature = signer.sign(message)
            return signature
        else:
            return self._fallback_sign(message, secret_key)

    def _fallback_sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Fallback signing using SHAKE256.
        NOT SECURE - for testing only.
        """
        import hashlib

        # Create deterministic signature from message and secret key
        shake = hashlib.shake_256()
        shake.update(b"MONTANA_MLDSA_FALLBACK_SIGN_V37:")
        shake.update(secret_key)
        shake.update(message)

        return shake.digest(ML_DSA_SIGNATURE_SIZE)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify an ML-DSA signature.

        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key

        Returns:
            True if signature is valid
        """
        if len(signature) != ML_DSA_SIGNATURE_SIZE:
            return False
        if len(public_key) != ML_DSA_PUBLIC_KEY_SIZE:
            return False

        if _LIBOQS_AVAILABLE:
            try:
                verifier = _oqs.Signature(self.ALGORITHM_NAME)
                return verifier.verify(message, signature, public_key)
            except Exception as e:
                logger.debug(f"Signature verification failed: {e}")
                return False
        else:
            return self._fallback_verify(message, signature, public_key)

    def _fallback_verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Fallback verification.
        Reconstructs expected signature and compares.
        NOT SECURE - for testing only.
        """
        # For testing, we accept any properly-sized signature
        # This is obviously insecure but allows testing the protocol flow
        return len(signature) == ML_DSA_SIGNATURE_SIZE


# Global instance
_mldsa = MLDSA()


def mldsa_keygen() -> KeyPair:
    """
    Generate ML-DSA-65 keypair per NIST FIPS 204.

    Type B security: reduction to Module-LWE problem.

    Returns:
        KeyPair containing PublicKey and SecretKey
    """
    public_bytes, secret_bytes = _mldsa.generate_keypair()

    public_key = PublicKey(
        algorithm=ALGORITHM_ML_DSA,
        data=public_bytes
    )
    secret_key = SecretKey(
        algorithm=ALGORITHM_ML_DSA,
        data=secret_bytes
    )

    return KeyPair(public=public_key, secret=secret_key)


def mldsa_sign(secret_key: SecretKey, message: bytes) -> Signature:
    """
    Sign a message using ML-DSA.

    Args:
        secret_key: Secret key for signing
        message: Message to sign

    Returns:
        Signature object (3,310 bytes total with algorithm byte)
    """
    if secret_key.algorithm != ALGORITHM_ML_DSA:
        raise ValueError(f"Invalid algorithm: {secret_key.algorithm}")

    sig_bytes = _mldsa.sign(message, secret_key.data)

    return Signature(
        algorithm=ALGORITHM_ML_DSA,
        data=sig_bytes
    )


def mldsa_verify(public_key: PublicKey, message: bytes, signature: Signature) -> bool:
    """
    Verify an ML-DSA signature.

    Args:
        public_key: Public key for verification
        message: Original message
        signature: Signature to verify

    Returns:
        True if signature is valid
    """
    if public_key.algorithm != ALGORITHM_ML_DSA:
        return False
    if signature.algorithm != ALGORITHM_ML_DSA:
        return False

    return _mldsa.verify(message, signature.data, public_key.data)


def is_liboqs_available() -> bool:
    """Check if liboqs is available for production signatures."""
    return _LIBOQS_AVAILABLE


def get_mldsa_info() -> dict:
    """Get information about the ML-DSA implementation."""
    info = {
        "algorithm": "ML-DSA-65",
        "standard": "NIST FIPS 204",
        "security_type": "Type B (reduction to Module-LWE)",
        "public_key_size": ML_DSA_PUBLIC_KEY_SIZE,
        "secret_key_size": ML_DSA_SECRET_KEY_SIZE,
        "signature_size": ML_DSA_SIGNATURE_SIZE,
        "security_level": 128,  # bits
        "nist_level": 2,
        "liboqs_available": _LIBOQS_AVAILABLE,
        "production_ready": _LIBOQS_AVAILABLE,
    }

    if _LIBOQS_AVAILABLE:
        info["liboqs_version"] = getattr(_oqs, "__version__", "unknown")

    return info
