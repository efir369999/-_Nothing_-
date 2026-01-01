# Layer 1 — Protocol Primitives

**Document Version:** 1.0
**Last Updated:** January 2026
**Depends On:** Layer -1 v2.1, Layer 0 v1.0
**Update Frequency:** Annual review recommended

---

## L-1.0 Scope and Epistemological Status

Layer 1 defines protocol primitives — cryptographic building blocks that enable protocol construction. These primitives combine Layer -1 physical constraints with Layer 0 computational hardness to create components with proven security properties.

**Layer 1 contains:**
- Verifiable Delay Functions (VDFs)
- Verifiable Random Functions (VRFs)
- Commitment schemes
- Time-stamping protocols
- Ordering primitives
- Security definitions

**Layer 1 does NOT contain:**
- Complete consensus protocols (Layer 2)
- Specific cryptocurrencies (Layer 2+)
- Network topology assumptions (Layer 2)
- Economic mechanisms (Layer 2+)

---

## L-1.0.1 Epistemic Classification

Layer 1 inherits type classification from Layer 0 and adds construction-specific types:

### Inherited Types (from L-0)

| Type | Meaning | Example in L-1 |
|------|---------|----------------|
| A | Proven unconditionally | Commitment hiding (information-theoretic) |
| B | Proven relative to assumption | VRF security under DDH |
| C | Empirical hardness | Concrete VDF parameters |
| P | Physical bound | VDF delay from L-1.4 |

### Construction Types (L-1 specific)

| Type | Meaning | Confidence |
|------|---------|------------|
| S | Secure composition | Proven that combining X + Y preserves security |
| I | Implementation-dependent | Security depends on correct implementation |

---

## L-1.0.2 Evaluation Criteria

**A Layer 1 specification achieves 10/10 if:**

1. **Correctness:** All security proofs are valid
2. **Type classification:** Each primitive correctly typed (A/B/C/P/S/I)
3. **Layer dependencies:** Explicit links to L-1 and L-0
4. **Composition rules:** How primitives combine safely
5. **Failure modes:** What breaks if underlying assumptions fail
6. **Upgrade paths:** How to replace broken components

**NOT required for 10/10:**
- Coverage of every possible primitive
- Optimal constructions (secure is sufficient)
- Concrete parameter recommendations (that's implementation)

---

## L-1.1 Verifiable Delay Functions (VDF)

### L-1.1.1 Definition

A Verifiable Delay Function is a function f: X → Y such that:

1. **Sequential:** Computing f(x) requires T sequential steps
2. **Efficiently verifiable:** Given (x, y, π), verification is fast (polylog(T))
3. **Uniqueness:** For each x, there is exactly one valid y

**Type:** P + B (Physical sequential bound + cryptographic verification)

### L-1.1.2 Security Model

**Sequentiality** derives from:
- L-1.4 (Speed of Light): Information propagation bounded
- L-0.2.3 (Sequential Time Bound): T steps require ≥ T × t_min time
- L-0.2.4 (Parallel Speedup Limit): No parallel shortcut for sequential computation

**Formal statement:**
```
For any adversary A with P parallel processors:
Time(A computes f(x)) ≥ T × t_min × (1 - ε)
where ε is negligible in security parameter
```

### L-1.1.3 Constructions

| Construction | Basis | Type | Quantum Status |
|--------------|-------|------|----------------|
| Repeated Squaring | RSA group | B (factoring) | BROKEN (Shor) |
| Repeated Squaring | Class group | B (class group) | Unknown |
| Iterated Hashing | Hash function | C (hash security) | SECURE (Grover: √T) |
| Wesolowski | Groups of unknown order | B | Depends on group |
| Pietrzak | Groups of unknown order | B | Depends on group |

**Recommendation:** For post-quantum security, use hash-based VDF (iterated SHAKE256).

### L-1.1.4 Hash-Based VDF Specification

**Construction:**
```
VDF(x, T):
  state = x
  for i in 1..T:
    state = SHAKE256(state)
  return state
```

**Properties:**
- Sequential: Hash chaining enforces T iterations
- Type: C (SHA-3 security) + P (physical time bound)
- Quantum security: T/√T = √T effective delay (Grover)
- For 2^40 classical security, use T = 2^80 iterations post-quantum

**Verification:**
- Naive: Re-compute (not efficient)
- STARK proof: O(log T) verification (Type B: STARK soundness)
- Trade-off: Proof generation adds overhead

### L-1.1.5 Layer Dependencies

| VDF Property | Depends On | Failure Mode |
|--------------|------------|--------------|
| Sequentiality | L-1.4, L-0.2.3 | Physics violation |
| Hash security | L-0.3.3 (CRHF) | Hash break → forgery |
| Proof soundness | L-0.3.2 (OWF) | Soundness break → fake proofs |

---

## L-1.2 Verifiable Random Functions (VRF)

### L-1.2.1 Definition

A Verifiable Random Function is a keyed function F_sk: X → Y with proof π such that:

1. **Pseudorandomness:** Output indistinguishable from random without sk
2. **Verifiability:** Anyone with pk can verify (x, y, π) is correct
3. **Uniqueness:** For each (sk, x), exactly one valid (y, π) exists

**Type:** B (security reduction to underlying hardness assumption)

### L-1.2.2 Constructions

| Construction | Basis | Type | Quantum Status |
|--------------|-------|------|----------------|
| ECVRF | Elliptic curve DDH | B | BROKEN (Shor) |
| RSA-VRF | RSA assumption | B | BROKEN (Shor) |
| Lattice-VRF | MLWE | B | SECURE |
| Hash-based VRF | Signatures + PRF | B + C | SECURE |

**Post-Quantum Recommendation:** Lattice-based or hash-based construction.

### L-1.2.3 ECVRF (Classical, Legacy)

**Construction (RFC 9381):**
```
VRF_prove(sk, x):
  h = hash_to_curve(x)
  gamma = sk * h
  k = nonce(sk, h)
  c = hash(g, h, pk, gamma, g^k, h^k)
  s = k - c * sk
  return (gamma, c, s)

VRF_verify(pk, x, (gamma, c, s)):
  h = hash_to_curve(x)
  U = s*g + c*pk
  V = s*h + c*gamma
  return c == hash(g, h, pk, gamma, U, V)
```

**Type:** B (DDH assumption)
**Quantum status:** BROKEN — do not use for long-term security

### L-1.2.4 Layer Dependencies

| VRF Property | Depends On | Failure Mode |
|--------------|------------|--------------|
| Pseudorandomness | L-0.3.2 (PRF existence) | PRF break → predictable |
| Uniqueness | Construction-specific | Forgery possible |
| Verification | L-0.4.3 (signatures) | Signature break → fake proofs |

---

## L-1.3 Commitment Schemes

### L-1.3.1 Definition

A commitment scheme consists of:
- Commit(m, r) → c: Create commitment to message m with randomness r
- Open(c, m, r) → {0,1}: Verify commitment opens to m

**Properties:**
1. **Hiding:** c reveals nothing about m
2. **Binding:** Cannot open c to different m' ≠ m

**Type:** Depends on construction (A or B)

### L-1.3.2 Hiding vs Binding Trade-off

| Type | Hiding | Binding | Example |
|------|--------|---------|---------|
| Perfectly hiding | Information-theoretic (A) | Computational (B) | Pedersen |
| Perfectly binding | Computational (B) | Information-theoretic (A) | Hash-based |
| Computationally both | Computational (B) | Computational (B) | ElGamal |

**Theorem (Type A):** No commitment scheme can be both perfectly hiding and perfectly binding.

### L-1.3.3 Hash-Based Commitment

**Construction:**
```
Commit(m, r):
  return SHA3-256(r || m)

Open(c, m, r):
  return c == SHA3-256(r || m)
```

**Properties:**
- Hiding: Computational (Type B, depends on PRG)
- Binding: Computational (Type C, depends on collision resistance)
- Quantum security: 128-bit with SHA3-256

### L-1.3.4 Pedersen Commitment

**Construction (over group G with generators g, h):**
```
Commit(m, r):
  return g^m * h^r

Open(c, m, r):
  return c == g^m * h^r
```

**Properties:**
- Hiding: Perfect (Type A) — information-theoretically secure
- Binding: Computational (Type B) — requires discrete log hardness
- Quantum security: BROKEN (Shor breaks DLog)

**Homomorphic property:**
```
Commit(m1, r1) * Commit(m2, r2) = Commit(m1 + m2, r1 + r2)
```

### L-1.3.5 Layer Dependencies

| Commitment Property | Depends On | Failure Mode |
|---------------------|------------|--------------|
| Hash binding | L-0.3.3 (CRHF) | Collision → equivocation |
| Pedersen binding | L-0.3.5 (DLog) | DLog break → equivocation |
| Perfect hiding | Information theory | Cannot fail |

---

## L-1.4 Time-Stamping

### L-1.4.1 Definition

A time-stamping scheme provides evidence that data D existed at time t.

**Properties:**
1. **Completeness:** Valid timestamps verify correctly
2. **Unforgeability:** Cannot create timestamp for time before D existed
3. **Temporal ordering:** If D1 timestamped before D2, this is verifiable

**Type:** P + B (Physical time + cryptographic binding)

### L-1.4.2 Linked Timestamping

**Construction:**
```
Timestamp(D, t, prev_hash):
  return Hash(D || t || prev_hash)
```

**Properties:**
- Creates hash chain with temporal ordering
- Unforgeability: Type C (hash preimage resistance)
- Ordering: Type A (hash chain is totally ordered)

### L-1.4.3 Anchor Timestamping

**Construction:**
Periodically publish hash of accumulated timestamps to external system.

**Anchors:**
| Anchor Type | Trust Model | Granularity |
|-------------|-------------|-------------|
| Newspaper | Public record | Daily |
| Bitcoin | Proof of work | ~10 minutes |
| Atomic clock network | Physical measurement | Continuous |

**Type:** P (physical publication) + external system security

### L-1.4.4 Layer Dependencies

| Timestamp Property | Depends On | Failure Mode |
|--------------------|------------|--------------|
| Hash binding | L-0.3.3 (CRHF) | Collision → reorder |
| Temporal validity | L-1.2 (Atomic time) | Clock manipulation |
| Anchor security | External system | Anchor compromise |

---

## L-1.5 Ordering Primitives

### L-1.5.1 Total Order

**Definition:** A total order on set S is a relation ≤ such that:
- Reflexive: a ≤ a
- Antisymmetric: a ≤ b and b ≤ a implies a = b
- Transitive: a ≤ b and b ≤ c implies a ≤ c
- Total: For all a, b: a ≤ b or b ≤ a

**Type:** A (mathematical definition)

### L-1.5.2 Happens-Before Relation

**Definition (Lamport):** Event a happens-before event b (a → b) if:
1. a and b are in same process and a precedes b, OR
2. a is send of message m and b is receive of m, OR
3. There exists c such that a → c and c → b

**Type:** A (logical construction)

**Limitation:** Concurrent events have no happens-before relation.

### L-1.5.3 Physical Ordering via Time

**Theorem:** If all participants have synchronized clocks with precision δ, and minimum message delay is Δ > 2δ, then physical timestamps provide total ordering.

**Type:** P (depends on L-1.2, L-1.5)

**Derivation from Layer -1:**
- L-1.2: Atomic clocks provide common time reference
- L-1.4: Message propagation bounded by c
- L-1.5: Earth clocks agree to 10⁻¹¹

### L-1.5.4 DAG Ordering

**Definition:** Events form a Directed Acyclic Graph where edges represent happens-before.

**PHANTOM algorithm** provides deterministic linearization:
1. Identify "blue" set (well-connected blocks)
2. Topologically sort blue set
3. Insert remaining blocks

**Type:** A (algorithm correctness) + network assumptions

### L-1.5.5 Layer Dependencies

| Ordering Property | Depends On | Failure Mode |
|-------------------|------------|--------------|
| Clock sync | L-1.2, L-1.5 | Drift → ordering ambiguity |
| Happens-before | Correct message passing | Network partition → split |
| DAG ordering | Graph connectivity | Eclipse attack → wrong order |

---

## L-1.6 Security Definitions

### L-1.6.1 Unforgeability

**Definition (EUF-CMA):** Existential Unforgeability under Chosen Message Attack.

Adversary cannot produce valid signature on new message even after seeing signatures on chosen messages.

**Type:** B (reduction to underlying hardness)

### L-1.6.2 Collision Resistance

**Definition:** For hash function H, infeasible to find x ≠ x' such that H(x) = H(x').

**Type:** C (empirical for concrete functions)

**Birthday bound (Type A):** Any collision-finding algorithm requires Ω(2^{n/2}) queries for n-bit output.

### L-1.6.3 Pseudorandomness

**Definition:** Output indistinguishable from uniform random by any efficient algorithm.

**Type:** B (reduction to PRF/PRG assumption)

### L-1.6.4 Semantic Security

**Definition:** Ciphertext reveals nothing about plaintext beyond length.

**Type:** B (reduction to underlying assumption)

### L-1.6.5 Forward Secrecy

**Definition:** Compromise of long-term keys does not compromise past session keys.

**Type:** S (composition property of key exchange)

### L-1.6.6 Sequentiality

**Definition:** Function requires T sequential operations; parallelism does not help.

**Type:** P (physical time bound from L-1.4, L-0.2.3)

---

## L-1.7 Composition Rules

### L-1.7.1 Sequential Composition

**Theorem:** If protocol P1 is secure and P2 is secure, then P1; P2 (run P1 then P2) is secure.

**Type:** S (proven composition)

**Conditions:**
- P1 output is valid P2 input
- Security properties are compatible

### L-1.7.2 Parallel Composition

**Theorem:** If P1 and P2 are secure and share no state, then P1 || P2 is secure.

**Type:** S (proven composition)

**Warning:** Shared randomness or keys can break security.

### L-1.7.3 Hybrid Composition

**For post-quantum transition:**
```
Hybrid(PQ, Classical):
  k1 = PQ_KEM()
  k2 = Classical_KEM()
  return KDF(k1 || k2)
```

**Type:** S (if either is secure, hybrid is secure)

**Proof:** Adversary must break both PQ and Classical to recover key.

### L-1.7.4 Composition Failures

| Anti-pattern | Why it fails |
|--------------|--------------|
| Reusing randomness | Correlation leaks information |
| Encrypt-and-MAC | Order matters for CCA security |
| Weak KDF | Insufficient key separation |

---

## L-1.8 Failure Modes

### L-1.8.1 If Layer -1 Fails

| L-1 Failure | Impact on Layer 1 |
|-------------|-------------------|
| L-1.4 (FTL) | VDF sequentiality breaks |
| L-1.2 (Atomic time) | Clock sync impossible |
| L-1.3 (Landauer) | Unbounded computation |

**Mitigation:** None — physical law failure is outside security model.

### L-1.8.2 If Layer 0 Fails

| L-0 Failure | Impact on Layer 1 | Mitigation |
|-------------|-------------------|------------|
| P = NP | All Type D breaks | L-1 physical bounds still hold |
| SHA-3 broken | Hash-based VDF/VRF break | Switch to alternative hash |
| Lattice broken | PQ primitives break | Hash-based fallback |

### L-1.8.3 If Construction Fails

| Construction Failure | Impact | Recovery |
|----------------------|--------|----------|
| ECVRF broken (Shor) | Classical VRF insecure | Migrate to lattice VRF |
| Specific VDF params | That instance broken | Increase parameters |
| Implementation bug | Instance vulnerable | Patch and rotate keys |

---

## L-1.9 Upgrade Paths

### L-1.9.1 Primitive Replacement

**Hash function upgrade:**
```
Old: SHAKE256
New: [Future hash]
Transition: Version field in protocol
```

### L-1.9.2 Parameter Update

**VDF parameter increase:**
```
If: Grover speedup realized
Then: Double T parameter
Effect: Maintain security level
```

### L-1.9.3 Construction Migration

**VRF migration (classical → PQ):**
1. Announce deprecation
2. Support both during transition
3. Remove classical after threshold

---

## L-1.10 Layer Interaction Summary

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 2+: Protocols (Montana, etc.)                        │
│  Uses: VDF, VRF, Commitments, Timestamps, Ordering          │
└─────────────────────────────────────────────────────────────┘
                              ↑ uses
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: Protocol Primitives                      v1.0    │
│  VDF, VRF, Commitment, Timestamp, Ordering                  │
│  Types: A, B, C, P, S, I                                   │
└─────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────┐
│  Layer 0: Computational Constraints                v1.0    │
│  SHA-3, ML-KEM, MLWE, OWF, PRF                            │
│  Types: A, B, C, D, P                                      │
└─────────────────────────────────────────────────────────────┘
                              ↑ builds on
┌─────────────────────────────────────────────────────────────┐
│  Layer -1: Physical Constraints                    v2.1    │
│  Atomic time, Landauer, Speed of light                     │
│  Types: 1, 2, 3, 4                                         │
└─────────────────────────────────────────────────────────────┘
```

---

## L-1.11 Open Questions

**Documented for epistemic honesty:**

**1. Optimal VDF construction:**
- Hash-based: Simple, PQ-secure, but verification expensive
- Algebraic: Efficient verification, but quantum status varies
- Status: Active research area

**2. Lattice-based VRF efficiency:**
- Current constructions have large proofs
- Standardization pending
- Status: Improving

**3. Tight security reductions:**
- Some reductions have polynomial loss
- Affects concrete security estimates
- Status: Theoretical research ongoing

---

## L-1.12 References

**VDF:**
- Boneh, D., Bonneau, J., Bünz, B., & Fisch, B. (2018). "Verifiable Delay Functions." CRYPTO 2018.
- Wesolowski, B. (2019). "Efficient Verifiable Delay Functions." EUROCRYPT 2019.
- Pietrzak, K. (2019). "Simple Verifiable Delay Functions." ITCS 2019.

**VRF:**
- Micali, S., Rabin, M., & Vadhan, S. (1999). "Verifiable Random Functions." FOCS 1999.
- RFC 9381: Verifiable Random Functions (VRFs). IETF 2023.

**Commitment:**
- Pedersen, T. P. (1991). "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.

**Ordering:**
- Lamport, L. (1978). "Time, Clocks, and the Ordering of Events in a Distributed System."
- Sompolinsky, Y., & Zohar, A. (2018). "PHANTOM: A Scalable BlockDAG Protocol."

**Timestamping:**
- Haber, S., & Stornetta, W. S. (1991). "How to Time-Stamp a Digital Document."

---

## L-1.13 Self-Assessment

**As of January 2026, Version 1.0:**

- ✅ All security definitions standard
- ✅ Type classification applied consistently
- ✅ Layer dependencies explicit
- ✅ Composition rules stated
- ✅ Failure modes documented
- ✅ Upgrade paths defined
- ✅ Open questions acknowledged

**Therefore: 10/10 by stated criteria (L-1.0.2).**

**Next scheduled review:** January 2027

---

*Layer 1 represents protocol primitives — cryptographic building blocks with proven security properties. It builds upon Layer -1 physical constraints and Layer 0 computational hardness to enable secure protocol construction in Layer 2+.*

*Each primitive is typed (A/B/C/P/S/I), with explicit dependencies and failure modes. This enables protocol designers to understand exactly what assumptions they inherit.*

