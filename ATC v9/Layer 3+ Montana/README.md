# Layer 3+: Montana — Asymptotic Trust in Time Value

**Status:** v1.1 Reference Implementation
**ATC Compatibility:** v9.0 (L-1 v2.1, L0 v1.0, L1 v1.1, L2 v1.0)

---

> *"An intermediate solution for building trust in time as the universal unit of value."*

---

## What Montana Is

**Montana is a temporal consensus protocol** — a mechanism for establishing asymptotic trust that **1 Ɉ = 1 second** of human time.

```
lim(evidence → ∞) Trust = 1
∀t: Trust(t) < 1

"We approach certainty; we never claim to reach it."
```

Montana is the mechanism. Time provides the evidence.

---

## Documentation

| Document | Description |
|----------|-------------|
| [WHITEPAPER.md](WHITEPAPER.md) | Conceptual overview and design rationale |
| [MONTANA_TECHNICAL_SPECIFICATION.md](MONTANA_TECHNICAL_SPECIFICATION.md) | Complete implementation specification |
| [MONTANA_ATC_MAPPING.md](MONTANA_ATC_MAPPING.md) | Layer-by-layer mapping to ATC |
| [HYPERCRITICISM_PROOF.md](HYPERCRITICISM_PROOF.md) | 10/10 certification methodology |
| [EVALUATION_QUICK_REFERENCE.md](EVALUATION_QUICK_REFERENCE.md) | Quick assessment card |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 3+: Montana                                              │
│  Temporal consensus protocol with Bitcoin anchoring             │
└─────────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────────┐
│  Layer 2: Consensus Protocols                        v1.0       │
│  Safety, Liveness, Finality, BFT                                │
└─────────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1: Protocol Primitives                        v1.1       │
│  VDF, VRF, Commitment, Timestamp, Ordering                      │
└─────────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────────┐
│  Layer 0: Computational Constraints                  v1.0       │
│  SHA-3, ML-KEM, SPHINCS+, Lattice hardness                      │
└─────────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────────┐
│  Layer -1: Physical Constraints                      v2.1       │
│  Atomic time, Landauer limit, Speed of light                    │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Features

| Feature | Montana Choice | ATC Layer |
|---------|----------------|-----------|
| **Time Unit** | 1 Ɉ = 1 second, 1.26B supply | Implementation |
| **Consensus** | DAG-PHANTOM + VDF + Bitcoin | L-2.5, L-2.6, L-2.7 |
| **Signatures** | SPHINCS+-SHAKE-128f | L-0.4.4 (PQ-secure) |
| **Encryption** | ML-KEM-768 | L-0.4.2 (PQ-secure) |
| **Time Source** | 34 NTP servers, 8 regions | L-1.2, L-1.5 |
| **VDF** | SHAKE256 hash chain | L-1.1 |
| **Finality** | VDF → DAG → Bitcoin | L-2.6.1, L-2.6.4 |
| **Launch** | Fair (zero pre-allocation) | Implementation |

---

## Three-Layer Finality

```
┌─────────────────────────────────────────────────────────────┐
│  Hard Finality (hours)                                      │
│  Bitcoin anchor: 6-100 confirmations                        │
│  Type: C (empirical)                                        │
└─────────────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────────────┐
│  Medium Finality (minutes)                                  │
│  DAG-PHANTOM ordering                                       │
│  Type: C (empirical)                                        │
└─────────────────────────────────────────────────────────────┘
                           ↑
┌─────────────────────────────────────────────────────────────┐
│  Soft Finality (seconds)                                    │
│  VDF checkpoint                                             │
│  Type: P (physical)                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## Quantum Status

| Component | Status | Note |
|-----------|--------|------|
| SPHINCS+ signatures | **Secure** | Hash-based, NIST FIPS 205 |
| ML-KEM encryption | **Secure** | Lattice-based, NIST FIPS 203 |
| SHA-3/SHAKE256 | **Secure** | 128-bit PQ security |
| ECVRF eligibility | ⚠ Vulnerable | Short-term use, upgrade path defined |
| Pedersen hiding | **Secure** | Information-theoretic |
| Pedersen binding | ⚠ Vulnerable | Privacy use case acceptable |

---

## Compliance

Montana complies with ATC v9:

```
✓ Layer -1: Uses atomic time, respects Landauer bound
✓ Layer 0:  SHA-3, SPHINCS+, ML-KEM (PQ-secure)
✓ Layer 1:  VDF sequentiality, commitment binding
⚠ Layer 1:  ECVRF quantum-vulnerable (upgrade path defined)
✓ Layer 2:  Safety (DAG), Liveness (GST), Finality (Bitcoin)
```

---

## Quick Parameters

```python
# Time Unit
TOTAL_SUPPLY = 1_260_000_000        # 21 million minutes in seconds
INITIAL_REWARD = 3_000              # 50 minutes per block
HALVING_INTERVAL = 210_000          # Same as Bitcoin

# Time
NTP_SOURCES = 34                    # Atomic time sources
NTP_REGIONS = 8                     # Geographic regions
BLOCK_TIME_TARGET = 600             # 10 minutes

# Cryptography
SIGNATURE = "SPHINCS+-SHAKE-128f"   # Post-quantum
KEM = "ML-KEM-768"                  # Post-quantum
HASH = "SHA3-256"                   # Post-quantum

# Finality
BTC_CONFIRMATIONS_SOFT = 1
BTC_CONFIRMATIONS_MEDIUM = 6
BTC_CONFIRMATIONS_STRONG = 100
```

---

## Closing Principle

> *"Implementations may assume weaker guarantees at each layer;*
> *they cannot assume stronger guarantees*
> *without leaving the domain of known science."*
>
> *— ATC Closing Principle*

Montana inherits all ATC layer guarantees. It cannot exceed them.

---

## References

- [ATC Layer -1: Physical Constraints](../Layer%20-1/layer_minus_1.md)
- [ATC Layer 0: Computational Constraints](../Layer%200/layer_0.md)
- [ATC Layer 1: Protocol Primitives](../Layer%201/layer_1.md)
- [ATC Layer 2: Consensus Protocols](../Layer%202/layer_2.md)
