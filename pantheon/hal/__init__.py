"""
Hal Humanity System - Proof of Human, Not Just Proof of Time

Named after Hal Finney (1956-2014), who understood Sybil resistance
before anyone else. He received the first Bitcoin transaction and
foresaw the need to prove humanity, not just cryptographic identity.

Montana v4.0 proves TIME (via EPOCHS).
Hal proves HUMANITY (via Graduated Trust + Time-Locked Identity).

Together, they create unforgeable proof that a unique human has
participated in the network over real-world time.

=== GRADUATED TRUST MODEL ===

    TIER 3: TIME-LOCKED (12 Apostles max, weight 1.0)
    ─────────────────────────────────────────────────
    • Survived 1+ Bitcoin halvings with valid commitment
    • UNFAKEABLE - requires actual time passage
    • Ultimate form of humanity proof

    TIER 2: SOCIAL (6 Apostles max, weight 0.6)
    ─────────────────────────────────────────────
    • Built social graph through handshakes
    • Sybil cost: real human connections over time
    • Bridge tier during bootstrap phase

    TIER 1: HARDWARE (3 Apostles max, weight 0.3)
    ─────────────────────────────────────────────
    • TPM/Secure Enclave/FIDO2 attestation
    • Sybil cost: physical device ($50-500)
    • Bootstrap tier for new participants

=== SYBIL ECONOMICS ===

Creating N fake identities requires:
- Tier 1: N physical devices ($50-500 each)
- Tier 2: N social networks (months/years to build)
- Tier 3: N Bitcoin halvings (4 years EACH)

At Tier 3: 100 fake identities = 400 years of waiting
This is the Hal Finney vision realized.

"Running bitcoin" - Hal Finney, 2009
"""

from .humanity import (
    HumanityTier,
    HumanityProof,
    HumanityVerifier,
    compute_humanity_score,
    get_max_apostles,
    verify_different_humans,
    # Constants
    MAX_APOSTLES_HARDWARE,
    MAX_APOSTLES_SOCIAL,
    MAX_APOSTLES_TIMELOCKED,
    HUMANITY_WEIGHT_HARDWARE,
    HUMANITY_WEIGHT_SOCIAL,
    HUMANITY_WEIGHT_TIMELOCKED,
    HANDSHAKE_MIN_HUMANITY,
)

from .hardware import (
    HardwareAttestation,
    HardwareType,
    TPMAttestation,
    SecureEnclaveAttestation,
    FIDO2Attestation,
    HardwareVerifier,
    create_hardware_proof,
    verify_hardware_proof,
)

from .social import (
    SocialProof,
    SocialGraph,
    SocialVerifier,
    create_social_proof,
    verify_social_proof,
    analyze_sybil_patterns,
)

from .timelock import (
    IdentityCommitment,
    TimeLockProof,
    TimeLockVerifier,
    create_identity_commitment,
    create_time_locked_proof,
    verify_time_locked_proof,
    # Constants
    HALVING_INTERVAL,
    MIN_EPOCHS_FOR_TIMELOCKED,
)

from .behavioral import (
    # Cluster detection (Layer 1 - pairwise correlation)
    ClusterDetector,
    ClusterInfo,
    ActionRecord,
    # Byzantine tracking (Layer 2 - behavioral fingerprinting)
    GlobalByzantineTracker,
    # Constants
    CORRELATION_WINDOW_SECONDS,
    MAX_CORRELATION_THRESHOLD,
    CORRELATION_PENALTY_FACTOR,
    MAX_CLUSTER_INFLUENCE,
    MAX_BYZANTINE_INFLUENCE,
    FINGERPRINT_SIMILARITY_THRESHOLD,
)

__all__ = [
    # Core
    'HumanityTier',
    'HumanityProof',
    'HumanityVerifier',
    'compute_humanity_score',
    'get_max_apostles',
    'verify_different_humans',
    # Hardware
    'HardwareAttestation',
    'HardwareType',
    'TPMAttestation',
    'SecureEnclaveAttestation',
    'FIDO2Attestation',
    'HardwareVerifier',
    'create_hardware_proof',
    'verify_hardware_proof',
    # Social
    'SocialProof',
    'SocialGraph',
    'SocialVerifier',
    'create_social_proof',
    'verify_social_proof',
    'analyze_sybil_patterns',
    # Time-lock
    'IdentityCommitment',
    'TimeLockProof',
    'TimeLockVerifier',
    'create_identity_commitment',
    'create_time_locked_proof',
    'verify_time_locked_proof',
    # Constants
    'MAX_APOSTLES_HARDWARE',
    'MAX_APOSTLES_SOCIAL',
    'MAX_APOSTLES_TIMELOCKED',
    'HUMANITY_WEIGHT_HARDWARE',
    'HUMANITY_WEIGHT_SOCIAL',
    'HUMANITY_WEIGHT_TIMELOCKED',
    'HANDSHAKE_MIN_HUMANITY',
    'HALVING_INTERVAL',
    'MIN_EPOCHS_FOR_TIMELOCKED',
    # Behavioral (Sybil detection)
    'ClusterDetector',
    'ClusterInfo',
    'ActionRecord',
    'GlobalByzantineTracker',
    'CORRELATION_WINDOW_SECONDS',
    'MAX_CORRELATION_THRESHOLD',
    'CORRELATION_PENALTY_FACTOR',
    'MAX_CLUSTER_INFLUENCE',
    'MAX_BYZANTINE_INFLUENCE',
    'FINGERPRINT_SIMILARITY_THRESHOLD',
]
