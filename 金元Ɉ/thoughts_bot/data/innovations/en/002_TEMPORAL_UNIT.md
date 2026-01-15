# 金元Ɉ — Temporal Unit

**Implementation:** `montana/src/types.rs`
**Version:** 1.0

---

## Symbol

**金** — gold (value)
**元** — genesis (origin)
**Ɉ** — time (unit)

---

## Constants from Code

```rust
// types.rs:5-13
pub const GENESIS_TIMESTAMP: u64 = 1735862400;  // 2026-01-03 00:00:00 UTC

pub const TAU1_MINUTES: u64 = 1;      // τ₁ = 1 minute
pub const TAU2_MINUTES: u64 = 10;     // τ₂ = 10 minutes
pub const TAU3_MINUTES: u64 = 20_160; // τ₃ = 14 days
pub const TAU4_MINUTES: u64 = 2_102_400; // τ₄ = 4 years
```

---

## τ Units

| Unit | Value | Seconds | Ɉ |
|------|-------|---------|---|
| τ₁ | 1 minute | 60 | 60 Ɉ |
| τ₂ | 10 minutes | 600 | 600 Ɉ |
| τ₃ | 14 days | 1,209,600 | 1,209,600 Ɉ |
| τ₄ | 4 years | 126,144,000 | 126,144,000 Ɉ |

---

## Beeple Formula (Genesis)

Beeple sale 11.03.2021 established genesis price:

```
$69,300,000 ÷ 5000 days ÷ 86400 sec = $0.1605/sec
```

| Currency | Rate |
|----------|------|
| USD | $0.16 |
| RUB | 12.09₽ |
| AMD | 83.46 dram |
| BTC | 0.00000278 |

**Rates fixed forever.**

---

## Emission

```rust
// types.rs:25-36
pub const REWARD_PER_TAU2: u64 = 3000;
pub const TOTAL_SUPPLY: u64 = 1_260_000_000;
pub const HALVING_INTERVAL: u64 = 210_000;  // ~4 years

pub fn calculate_reward(slice_index: u64) -> u64 {
    let halvings = slice_index / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    REWARD_PER_TAU2 >> halvings
}
```

---

## Principle

```rust
// consensus.rs:13
// lim(evidence → ∞) 1 Ɉ → 1 second
```

Time cannot be forged. 14 days require 14 days.

---

```
Alejandro Montana
January 2026
```
