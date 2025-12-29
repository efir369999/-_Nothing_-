# The Five Fingers of Adonis

**The only formula for node influence in Proof of Time.**

---

## Overview

Adonis is the unified 5-dimensional scoring system that determines node weight. Like the five fingers of a hand, each dimension plays a specific role — and together they form a complete grip on network consensus.

```
P(i) = Adonis(i) / Σ Adonis(all)
```

Every node's probability of becoming block producer is proportional to its Adonis score.

---

## The Five Fingers

```
🖐️ THE HAND OF ADONIS

👍 THUMB (TIME) ━━━━━━━━━━━━━━━━━━━━━━━━━━━ 50%
│   The opposable finger. Makes the hand work.
│   Without time, the hand cannot grasp anything.
│   Saturates at 180 days. Cannot be bought.
│
☝️ INDEX (INTEGRITY) ━━━━━━━━━━━━━━━━━━━━━━ 20%
│   Points the way. Moral compass.
│   Any violation → 180 days quarantine.
│   Double protection: weight + penalty.
│
🖕 MIDDLE (STORAGE) ━━━━━━━━━━━━━━━━━━━━━━━ 15%
│   Central support. Network backbone.
│   Full nodes store 100% of chain history.
│   The pillar that holds the structure.
│
💍 RING (GEOGRAPHY) ━━━━━━━━━━━━━━━━━━━━━━━ 10%
│   Global commitment. Decentralization promise.
│   Country + city diversity combined.
│   First node from new country → +0.25 bonus.
│   First node from new city → +0.15 bonus.
│
🤙 PINKY (HANDSHAKE) ━━━━━━━━━━━━━━━━━━━━━━  5%
    Elite bonus. Mutual trust between veterans.
    Unlocks only when first 4 fingers are saturated.
    Handshakes require DIFFERENT countries (anti-sybil).
    Saturates at 10 handshakes.
```

---

## Dimension Details

### 👍 THUMB: TIME (50%)

The main factor. This is **Proof of Time** — time cannot be bought, accelerated, or transferred.

```
score = min(uptime_seconds / K_TIME, 1.0)
K_TIME = 15,552,000 seconds (180 days)
```

- Measures continuous uptime
- Saturates at 180 days (newcomer catches veteran)
- Reset on extended downtime
- **The thumb makes the hand opposable** — without it, the hand is useless

### ☝️ INDEX: INTEGRITY (20%)

Points the direction. The moral compass of the network.

```
Positive events:
  BLOCK_PRODUCED:  +0.05
  BLOCK_VALIDATED: +0.02
  TX_RELAYED:      +0.01

Negative events:
  BLOCK_INVALID:   -0.15
  VRF_INVALID:     -0.20
  VDF_INVALID:     -0.25
  EQUIVOCATION:    -1.0 (catastrophic)
  SPAM_DETECTED:   -0.20

Penalties:
  EQUIVOCATION:    180 days quarantine
  VDF_INVALID:     30 days
  VRF_INVALID:     14 days
  SPAM_DETECTED:   7 days
```

**Double protection**: Even if you survive the weight reduction, the quarantine period ensures you can't participate in consensus.

### 🖕 MIDDLE: STORAGE (15%)

The central pillar. Full nodes are the backbone of the network.

```
score = min(stored_blocks / total_blocks / K_STORAGE, 1.0)
K_STORAGE = 1.00 (100%)
```

- Full nodes store complete chain history
- Light nodes get proportionally lower scores
- Encourages data availability and decentralization

### 💍 RING: GEOGRAPHY (10%)

Commitment to global decentralization. **Combined country + city scoring.**

```
Events:
  NEW_COUNTRY: +0.25 (first node from country)
  NEW_CITY:    +0.15 (first node from city)

Score formula:
  country_rarity = 1 / (1 + log10(nodes_in_country))
  country_diversity = min(1.0, total_countries / 50)
  country_score = 0.6 * rarity + 0.4 * diversity

  city_rarity = 1 / (1 + log10(nodes_in_city))
  city_diversity = min(1.0, total_cities / 100)
  city_score = 0.7 * rarity + 0.3 * diversity

  geography_score = 0.6 * country_score + 0.4 * city_score
```

- First node from a new country gets big bonus
- Fewer nodes in your country = higher score
- City hash stored for privacy (cannot reverse-engineer location)
- **The ring finger symbolizes commitment** — commitment to global reach

### 🤙 PINKY: HANDSHAKE (5%)

The elite bonus. Mutual trust between veteran nodes.

```
Requirements for handshake eligibility:
  TIME >= 90% (162+ days of uptime)
  INTEGRITY >= 80%
  STORAGE >= 90%
  GEOGRAPHY > 10% (registered location)

Anti-sybil:
  Both nodes must be in DIFFERENT countries

Score:
  score = min(handshake_count / K_HANDSHAKE, 1.0)
  K_HANDSHAKE = 10 handshakes
```

**The PINKY unlocks only when first 4 fingers are saturated.** Two veterans from different countries shake hands = cryptographic proof of mutual trust.

---

## Handshake Protocol

The handshake is a two-way commitment stored on-chain:

```
1. TX_HANDSHAKE_REQUEST
   - Requester signs: "I vouch for [target_pubkey]"
   - Broadcast to network

2. TX_HANDSHAKE_ACCEPT
   - Target signs: "I accept handshake with [requester_pubkey]"
   - Stored in DAG as permanent record

3. Handshake formed
   - Both nodes get HANDSHAKE_FORMED event
   - HANDSHAKE score updated for both
```

**Breaking handshakes:**
- Automatic: if partner is penalized (equivocation, etc.)
- Automatic: if partner goes offline > 7 days
- Manual: either party can break voluntarily

---

## Privacy Guarantees

Geographic diversity tracking is privacy-preserving:

1. **IP never stored** — only used for geolocation lookup, then discarded
2. **City hash** — `SHA256(country + city)`, not raw location
3. **Country code** — only ISO code (e.g., "US", "DE", "JP")
4. **Cannot reverse** — hash cannot be converted back to city name

---

## What This Architecture Gives Us

| Benefit | How Adonis Delivers |
|---------|---------------------|
| **Sybil Resistance** | TIME (50%) cannot be faked — 180 days is 180 days |
| **Fairness** | Everyone starts at zero, no capital advantage |
| **Decentralization** | GEOGRAPHY (10%) rewards global distribution |
| **Trust Web** | HANDSHAKE (5%) creates cryptographic trust network |
| **Self-Cleaning** | INTEGRITY (20%) + quarantine removes bad actors |
| **Network Effect** | More handshakes = stronger veterans = stable network |

---

## API

```python
from pantheon.adonis import AdonisEngine, ReputationEvent

engine = AdonisEngine()

# Update TIME (THUMB) - call hourly
engine.update_time(pubkey, uptime_seconds)

# Update STORAGE (MIDDLE)
engine.update_storage(pubkey, stored_blocks, total_blocks)

# Record INTEGRITY (INDEX) events
engine.record_event(pubkey, ReputationEvent.BLOCK_PRODUCED, height=1000)
engine.record_event(pubkey, ReputationEvent.EQUIVOCATION, height=1000)  # 180 days penalty

# Register location for GEOGRAPHY (RING)
is_new_country, is_new_city, country_score, city_score = \
    engine.register_node_location(pubkey, "JP", "Tokyo")

# HANDSHAKE (PINKY) - check eligibility
eligible, reason = engine.is_eligible_for_handshake(pubkey)

# Form handshake (both nodes must be eligible + different countries)
success, msg = engine.form_handshake(node_a, node_b, sig_a, sig_b, height)

# Get unified probability
prob = engine.compute_node_probability(
    pubkey,
    uptime_seconds=90 * 86400,
    stored_blocks=1000,
    total_blocks=1000
)

# Get stats
stats = engine.get_stats()
web_stats = engine.get_trust_web_stats()
```

---

## Self-Test

```bash
python -m pantheon.adonis.adonis
```

Output:
```
🖐️ The Five Fingers of Adonis:
   👍 THUMB (TIME): 50% - saturates at 180 days
   ☝️ INDEX (INTEGRITY): 20% - no violations
   🖕 MIDDLE (STORAGE): 15% - saturates at 100%
   💍 RING (GEOGRAPHY): 10% - country + city
   🤙 PINKY (HANDSHAKE): 5% - mutual trust

  THUMB (TIME): 90 days = 0.500
  THUMB (TIME): 200 days (saturated) = 1.000
  MIDDLE (STORAGE): 100% = 1.000
  INDEX (INTEGRITY): 10 blocks = score 0.471
  💍 RING (GEOGRAPHY): JP/Tokyo first node = NEW_COUNTRY + NEW_CITY
  🤙 PINKY (HANDSHAKE) tests:
     Veteran JP eligible: True
     Newbie not eligible: TIME too low
     Handshake JP<->DE formed!
     HANDSHAKE score: 0.10 (1/10)

🖐️ All Five Fingers of Adonis self-tests passed!
```

---

*Named after Adonis — symbolizing the pursuit of perfection through time.*

**🖐️ Five fingers. One hand. Complete grip on consensus.**
