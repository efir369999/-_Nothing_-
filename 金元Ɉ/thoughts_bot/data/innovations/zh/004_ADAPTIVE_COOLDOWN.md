# 自适应冷却

**实现:** `montana/src/cooldown.rs`
**版本:** 1.0

---

## 核心

基于注册中位数的新节点动态冷却期。

```rust
// cooldown.rs:1-2
//! Adaptive cooldown — median-based, per-tier, rate-limited
```

---

## 代码中的常量

```rust
// types.rs:16-23
pub const COOLDOWN_MIN_TAU2: u64 = 144;         // 1天
pub const COOLDOWN_MAX_TAU2: u64 = 25_920;      // 180天
pub const COOLDOWN_WINDOW_TAU2: u64 = 2_016;    // 14天 (τ₃)
pub const COOLDOWN_DEFAULT_TAU2: u64 = 144;     // 创世: 1天
pub const COOLDOWN_SMOOTH_WINDOWS: u64 = 4;     // 56天
pub const COOLDOWN_MAX_CHANGE_PERCENT: u64 = 20; // 每τ₃ ±20%
```

---

## 公式

```rust
// cooldown.rs:97-135
// 低于中位数: 1-7天（线性）
// 在中位数: 7天 (τ₃ / 2)
// 高于中位数: 7-180天（线性）

let ratio = current_count as f64 / median as f64;

if ratio <= 1.0 {
    // MIN → MID (1 → 7天)
    COOLDOWN_MIN + ratio * (MID - MIN)
} else {
    // MID → MAX (7 → 180天)
    MID + (ratio - 1.0) * (MAX - MID)
}
```

---

## 平滑

```rust
// cooldown.rs:50-74
// 4 τ₃ (56天) 滑动平均
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

## 速率限制

```rust
// cooldown.rs:77-91
// 每τ₃最大±20%变化
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

## 攻击防护

| 攻击 | 防御 |
|------|------|
| 峰值操纵 | 56天平滑 |
| 快速拉升 | ±20%速率限制 |
| 低负载时女巫攻击 | 最少1天 |
| 峰值时女巫攻击 | 最多180天 |

---

## 女巫攻击成本公式

```
女巫成本 = 时间 × 节点数量
最小: 1天 × N
最大: 180天 × N
```

---

```
Alejandro Montana
2026年1月
```
