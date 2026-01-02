# Montana STARK (Deprecated)

**Status:** Deprecated as of Montana v3.6

## Deprecation Notice

Montana v3.6+ uses **Class Group VDF (Wesolowski 2019)** instead of hash-chain VDF.

Class Group VDF provides native O(log T) verification through Wesolowski proofs — STARK proofs are no longer needed for VDF verification.

### Why Class Group VDF?

| Property | Hash-Chain + STARK | Class Group VDF |
|----------|-------------------|-----------------|
| Security Type | C (empirical) | B (proven reduction) |
| Verification | O(log T) via STARK | O(log T) native |
| Trusted Setup | None | None |
| Complexity | High (STARK prover) | Lower (group operations) |
| Quantum | Secure (Grover) | Vulnerable (Shor, neutralized by UTC) |

### What Replaced This?

Montana now uses:
- **VDF:** Class Group (Wesolowski 2019) in `montana/core/vdf.py`
- **Verification:** Wesolowski proof (O(log T) group operations)
- **Quantum Protection:** UTC finality model neutralizes Shor's algorithm advantage

## Legacy Code

This crate contains legacy STARK proof implementation for hash-chain VDF.
It is preserved for reference but is not used in Montana v3.6+.

### Original Purpose

STARK proofs enabled O(log T) verification of hash-chain VDF:
1. VDF: `output = H^T(input)` where H = SHAKE256
2. Checkpoints: Intermediate states every N iterations
3. STARK: Prove all H(state[i]) = state[i+1] constraints
4. Verify: Check STARK proof in O(log T)

### Files

```
montana-stark/
├── src/
│   ├── lib.rs       # PyO3 bindings (deprecated)
│   ├── types.rs     # VdfProof types (deprecated)
│   ├── vdf_air.rs   # AIR constraints for SHAKE256 (deprecated)
│   ├── prover.rs    # STARK proof generation (deprecated)
│   └── verifier.rs  # STARK verification (deprecated)
└── benches/
    └── vdf_stark.rs # Benchmarks (deprecated)
```

## Current VDF

For current VDF implementation, see:
- `montana/core/vdf.py` — Class Group VDF with Wesolowski proof
- `Montana/WHITEPAPER.md` §7.2 — VDF specification

## License

MIT
