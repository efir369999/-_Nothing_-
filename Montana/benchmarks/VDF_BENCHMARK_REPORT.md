# Montana VDF Benchmark Report

**Date:** January 2026
**Benchmark Version:** 2.0
**VDF Type:** Class Group (Wesolowski 2019)

---

## Summary

Montana uses Class Group VDF with Wesolowski proof for O(log T) verification.

**Key Properties:**
- Type B security (reduction to class group order problem)
- No trusted setup required
- Verification: O(log T) using Wesolowski proof
- Quantum: Shor applies, but UTC finality model neutralizes speedup

---

## UTC Finality Model

VDF timing is **irrelevant** in Montana's UTC finality model:

```
Classical node:     VDF in 30 sec → waits 30 sec → 1 heartbeat/min
ASIC attacker:      VDF in 5 sec  → waits 55 sec → 1 heartbeat/min
Quantum attacker:   VDF in 0.001s → waits 59.999s → 1 heartbeat/min

Result: All receive exactly ONE heartbeat per finality window
```

**VDF proves participation eligibility within a UTC minute boundary.**
Faster hardware simply waits longer.

---

## VDF Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| Discriminant bits | 2048 | Security parameter |
| Challenge bits | 128 | Wesolowski proof security |
| Iterations T | 2^24 (16,777,216) | Target delay (~30 seconds) |

---

## Security Analysis

### Type B Security

```
Security reduction:
  "VDF shortcut exists" → "Class group order can be computed efficiently"

Class group order problem:
  Given discriminant Δ, compute |Cl(Δ)|

Status: Hard for 40+ years (Buchmann, Williams 1988)
  - Related to integer factorization
  - Best algorithms: subexponential L[1/2]
```

### Quantum Resistance

Class Group VDF is vulnerable to Shor's algorithm. Montana's UTC model neutralizes this:

| Attacker | VDF Computation | Heartbeats/Minute | Advantage |
|----------|-----------------|-------------------|-----------|
| Classical CPU | 30 seconds | 1 | Baseline |
| ASIC | 5 seconds | 1 | None (waits for UTC) |
| Quantum computer | 0.001 seconds | 1 | None (waits for UTC) |

**UTC boundary is the physical rate limiter.**

---

## Verification Performance

Wesolowski proof enables O(log T) verification:

| Operation | Complexity | Time (estimated) |
|-----------|------------|------------------|
| VDF Evaluation | O(T) | ~30 seconds |
| Proof Generation | O(T) + overhead | ~60 seconds |
| **Verification** | **O(log T)** | **< 100 ms** |

Verification is independent of VDF computation time.

---

## Finality Timing

Montana uses UTC boundaries for finality:

| Finality Level | UTC Boundaries | Time |
|----------------|----------------|------|
| Soft | 1 | 1 minute |
| Medium | 2 | 2 minutes |
| Hard | 3 | 3 minutes |

**Attack cost:** Requires advancing UTC (physically impossible).

---

## Comparison with Hash-Chain VDF (deprecated)

Montana v3.6+ uses Class Group VDF instead of hash-chain VDF:

| Property | Hash-Chain (SHAKE256) | Class Group |
|----------|----------------------|-------------|
| Security Type | C (empirical) | B (proven reduction) |
| Verification | O(T) or STARK | O(log T) native |
| Trusted Setup | None | None |
| Quantum | Secure (Grover √T) | Vulnerable (Shor) |
| UTC Model | Not needed | Neutralizes quantum |

**Choice rationale:** Type B security with native O(log T) verification. UTC finality model makes quantum vulnerability irrelevant.

---

## Benchmark Code

Location: `Montana/benchmarks/vdf_benchmark.py`

```bash
# Run benchmark
cd Montana
python3 benchmarks/vdf_benchmark.py
```

---

## Conclusion

1. Montana uses Class Group VDF (Wesolowski 2019) with Type B security.

2. VDF timing is irrelevant — UTC boundaries are the rate limiter.

3. Verification is O(log T) using Wesolowski proof.

4. Quantum computers provide no advantage due to UTC finality model.

---

**Benchmark conducted:** January 2026
**VDF Type:** Class Group (Wesolowski 2019)
