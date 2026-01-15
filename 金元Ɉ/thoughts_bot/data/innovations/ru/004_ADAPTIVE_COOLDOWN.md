# Adaptive Cooldown

**Реализация:** `montana/src/cooldown.rs`
**Версия:** 1.0

---

## Суть

Динамический cooldown для новых узлов на основе медианы регистраций.

```rust
// cooldown.rs:1-2
//! Adaptive cooldown — median-based, per-tier, rate-limited
```

---

## Константы из кода

```rust
// types.rs:16-23
pub const COOLDOWN_MIN_TAU2: u64 = 144;         // 1 день
pub const COOLDOWN_MAX_TAU2: u64 = 25_920;      // 180 дней
pub const COOLDOWN_WINDOW_TAU2: u64 = 2_016;    // 14 дней (τ₃)
pub const COOLDOWN_DEFAULT_TAU2: u64 = 144;     // Genesis: 1 день
pub const COOLDOWN_SMOOTH_WINDOWS: u64 = 4;     // 56 дней
pub const COOLDOWN_MAX_CHANGE_PERCENT: u64 = 20; // ±20% per τ₃
```

---

## Формула

```rust
// cooldown.rs:97-135
// Ниже медианы: 1-7 дней (линейно)
// На медиане: 7 дней (τ₃ / 2)
// Выше медианы: 7-180 дней (линейно)

let ratio = current_count as f64 / median as f64;

if ratio <= 1.0 {
    // MIN → MID (1 → 7 дней)
    COOLDOWN_MIN + ratio * (MID - MIN)
} else {
    // MID → MAX (7 → 180 дней)
    MID + (ratio - 1.0) * (MAX - MID)
}
```

---

## Сглаживание (Smoothing)

```rust
// cooldown.rs:50-74
// 4 τ₃ (56 дней) sliding average
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
// Максимум ±20% изменения за τ₃
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

## Защита от атак

| Атака | Защита |
|-------|--------|
| Spike манипуляция | 56-дневное сглаживание |
| Быстрая накачка | ±20% rate limit |
| Sybil при малой нагрузке | Минимум 1 день |
| Sybil при спайке | До 180 дней |

---

## Формула отказоустойчивости

```
Цена Sybil-атаки = время × количество узлов
Минимум: 1 день × N
Максимум: 180 дней × N
```

---

```
Alejandro Montana
Январь 2026
```
