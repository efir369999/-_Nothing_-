# Adaptive Cooldown

**Implementation:** `montana/src/cooldown.rs`
**Version:** 1.0

---

## Core

Dynamic cooldown for new nodes based on registration median.

```rust
// cooldown.rs:1-2
//! Adaptive cooldown — median-based, per-tier, rate-limited
```

---

## Constants from Code

```rust
// types.rs:16-23
pub const COOLDOWN_MIN_TAU2: u64 = 144;         // 1 day
pub const COOLDOWN_MAX_TAU2: u64 = 25_920;      // 180 days
pub const COOLDOWN_WINDOW_TAU2: u64 = 2_016;    // 14 days (τ₃)
pub const COOLDOWN_DEFAULT_TAU2: u64 = 144;     // Genesis: 1 day
pub const COOLDOWN_SMOOTH_WINDOWS: u64 = 4;     // 56 days
pub const COOLDOWN_MAX_CHANGE_PERCENT: u64 = 20; // ±20% per τ₃
```

---

## Formula

```rust
// cooldown.rs:97-135
// Below median: 1-7 days (linear)
// At median: 7 days (τ₃ / 2)
// Above median: 7-180 days (linear)

let ratio = current_count as f64 / median as f64;

if ratio <= 1.0 {
    // MIN → MID (1 → 7 days)
    COOLDOWN_MIN + ratio * (MID - MIN)
} else {
    // MID → MAX (7 → 180 days)
    MID + (ratio - 1.0) * (MAX - MID)
}
```

---

## Smoothing

```rust
// cooldown.rs:50-74
// 4 τ₃ (56 days) sliding average
fn smoothed_median(&self, current_tau2: u64, tier: u8) -> u64 {
    let mut medians = Vec::new();
    for i in 0..COOLDOWN_SMOOTH_WINDOWS {
        let tau3_idx = current_tau3.saturating_sub(i);
        if let Some(&median) = self.median_history.get(&(tau3_idx, tier)) {
            medians.push(median);
        }
    }
    sum / medians.len()
}
```

---

## Rate Limiting

```rust
// cooldown.rs:77-91
// Maximum ±20% change per τ₃
fn rate_limited_cooldown(&self, raw_cooldown: u64, tier: usize) -> u64 {
    let max_change = (previous * COOLDOWN_MAX_CHANGE_PERCENT) / 100;

    if raw_cooldown > previous {
        raw_cooldown.min(previous + max_change)
    } else {
        raw_cooldown.max(previous - max_change)
    }
}
```

---

## Attack Protection

| Attack | Defense |
|--------|---------|
| Spike manipulation | 56-day smoothing |
| Fast pump | ±20% rate limit |
| Sybil at low load | Minimum 1 day |
| Sybil at spike | Up to 180 days |

---

## Sybil Attack Cost Formula

```
Sybil cost = time × node count
Minimum: 1 day × N
Maximum: 180 days × N
```

---

```
Alejandro Montana
January 2026
```
