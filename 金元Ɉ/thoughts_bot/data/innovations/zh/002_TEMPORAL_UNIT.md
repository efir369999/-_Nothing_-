# 金元Ɉ — 时间单位

**实现:** `montana/src/types.rs`
**版本:** 1.0

---

## 符号

**金** — 黄金（价值）
**元** — 创世（起源）
**Ɉ** — 时间（单位）

---

## 代码中的常量

```rust
// types.rs:5-13
pub const GENESIS_TIMESTAMP: u64 = 1735862400;  // 2026-01-03 00:00:00 UTC

pub const TAU1_MINUTES: u64 = 1;      // τ₁ = 1分钟
pub const TAU2_MINUTES: u64 = 10;     // τ₂ = 10分钟
pub const TAU3_MINUTES: u64 = 20_160; // τ₃ = 14天
pub const TAU4_MINUTES: u64 = 2_102_400; // τ₄ = 4年
```

---

## τ单位

| 单位 | 值 | 秒 | Ɉ |
|------|-----|-----|---|
| τ₁ | 1分钟 | 60 | 60 Ɉ |
| τ₂ | 10分钟 | 600 | 600 Ɉ |
| τ₃ | 14天 | 1,209,600 | 1,209,600 Ɉ |
| τ₄ | 4年 | 126,144,000 | 126,144,000 Ɉ |

---

## Beeple公式（创世）

2021年3月11日Beeple销售确立了创世价格：

```
$69,300,000 ÷ 5000天 ÷ 86400秒 = $0.1605/秒
```

| 货币 | 汇率 |
|------|------|
| USD | $0.16 |
| RUB | 12.09₽ |
| AMD | 83.46德拉姆 |
| BTC | 0.00000278 |

**汇率永久固定。**

---

## 发行

```rust
// types.rs:25-36
pub const REWARD_PER_TAU2: u64 = 3000;
pub const TOTAL_SUPPLY: u64 = 1_260_000_000;
pub const HALVING_INTERVAL: u64 = 210_000;  // ~4年

pub fn calculate_reward(slice_index: u64) -> u64 {
    let halvings = slice_index / HALVING_INTERVAL;
    if halvings >= 64 {
        return 0;
    }
    REWARD_PER_TAU2 >> halvings
}
```

---

## 原则

```rust
// consensus.rs:13
// lim(evidence → ∞) 1 Ɉ → 1 秒
```

时间无法伪造。14天需要14天。

---

```
Alejandro Montana
2026年1月
```
