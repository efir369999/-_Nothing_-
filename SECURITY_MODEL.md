# Proof of Time - Security Model

## Overview

This document describes the security model of the Proof of Time (PoT) consensus mechanism, including known vulnerabilities, mitigations, and honest limitations.

**Principle**: Time is the ultimate proof. Unlike capital-based systems (PoS), PoT cannot be purchased or accumulated instantly. However, this creates unique attack vectors that must be addressed.

---

## 1. The "Slow Takeover Attack"

### Description

An attacker gradually accumulates TIME across multiple coordinated nodes over 180+ days. Since TIME is the dominant factor (50% of Adonis Score), a patient attacker could theoretically gain majority influence.

### Attack Vector

```
Day 0:   Attacker deploys 100 nodes across VPN endpoints
Day 90:  Each node reaches 50% TIME saturation
Day 180: All nodes reach 100% TIME saturation
Result:  Attacker controls significant network influence
```

### Mitigations Implemented

#### 1.1 Behavioral Correlation Detection

**File**: `pantheon/adonis/adonis.py` - `ClusterDetector` class

Nodes that act synchronously are detected and penalized:

- **Timing Analysis**: Blocks produced within 100ms of each other are flagged
- **Action Distribution**: Similar action patterns (block/vote/relay ratios) increase correlation
- **Block Height Patterns**: Acting at identical block heights indicates coordination

```python
# Correlation threshold
MAX_CORRELATION_THRESHOLD = 0.7  # 70% similarity = suspicious

# Penalty for correlated nodes
CORRELATION_PENALTY_FACTOR = 0.5  # 50% score reduction
```

#### 1.2 Global Cluster Cap

No cluster (group of correlated nodes) can exceed 33% of total network influence:

```python
MAX_CLUSTER_INFLUENCE = 0.33  # Hard cap at 33%
```

If a cluster's combined weight exceeds this, all members are proportionally reduced.

#### 1.3 Entropy Decay

When network diversity drops below threshold, TIME stops accumulating value:

```python
MIN_NETWORK_ENTROPY = 0.5  # Minimum healthy entropy
ENTROPY_DECAY_RATE = 0.001  # 0.1% decay per hour when unhealthy
```

Entropy is computed from:
- Geographic diversity (40% weight)
- City distribution (25% weight)
- TIME score variance (20% weight)
- Handshake network span (15% weight)

#### 1.4 Handshake Independence Requirement

Handshakes (PINKY finger, 5%) can only form between provably independent nodes:

1. Different countries (mandatory)
2. Low correlation score (< 50%)
3. Not in the same detected cluster

---

## 2. Geographic Verification Vulnerability

### Honest Disclosure

**Geography is the weakest part of the security model.**

Current limitations:
- IP geolocation can be spoofed with VPNs
- Country codes are self-reported or IP-derived
- No cryptographic proof of physical location exists

### Why We Keep It

Geography contributes only 10% (RING finger) and provides:
- Incentive for global distribution
- Additional anti-sybil signal (not foolproof)
- Network resilience metrics

### Future Improvements

Potential solutions being researched:
1. **Latency triangulation**: Verify location through network timing
2. **Trusted hardware attestation**: SGX/TrustZone location proofs
3. **Decentralized oracles**: Multiple independent geolocation sources
4. **Economic incentives**: Penalties for detected location spoofing

---

## 3. Minimum Node Requirements

### Formal vs Practical Security

The protocol can technically run with 3 nodes. However:

| Nodes | Security Level | Notes |
|-------|---------------|-------|
| 3     | MINIMUM       | Trivial coordination, 1 failure = 33% loss |
| 10    | LOW           | Social attacks feasible |
| 50    | MODERATE      | Cluster detection effective |
| 100+  | TARGET        | Recommended for production |

### Implemented Safeguards

```python
MIN_NODES_FOR_CLUSTER_ANALYSIS = 5  # Need enough data for detection
MIN_HANDSHAKE_COUNTRIES = 3         # Handshake network health
```

---

## 4. Attack Resistance Summary

| Attack | Mitigation | Effectiveness |
|--------|------------|---------------|
| Slow Takeover | Correlation detection + cluster cap | HIGH |
| Geographic Sybil | Country requirement + city diversity | MODERATE |
| Flash Attack | VDF time requirements | HIGH |
| Nothing-at-Stake | TIME saturation (180 days) | HIGH |
| Eclipse Attack | Peer diversity + subnet limits | HIGH |
| Timing Attacks | TIMING_VARIANCE_THRESHOLD | MODERATE |

---

## 5. Security Constants

All security constants are defined in `pantheon/adonis/adonis.py`:

```python
# Anti-Cluster Constants
CORRELATION_WINDOW_SECONDS = 86400      # 24-hour analysis window
MAX_CORRELATION_THRESHOLD = 0.7         # 70% = suspicious
CORRELATION_PENALTY_FACTOR = 0.5        # 50% penalty
MAX_CLUSTER_INFLUENCE = 0.33            # 33% cap
MIN_NETWORK_ENTROPY = 0.5               # Minimum healthy entropy
ENTROPY_DECAY_RATE = 0.001              # 0.1% per hour
MIN_NODES_FOR_CLUSTER_ANALYSIS = 5      # Minimum for detection
TIMING_VARIANCE_THRESHOLD = 100         # 100ms = synchronized
MIN_HANDSHAKE_COUNTRIES = 3             # Handshake network health
```

---

## 6. Monitoring & Health

The system provides real-time security metrics:

```python
stats = engine.get_stats()
security = stats['security']

# Cluster detection status
cluster_stats = security['cluster_stats']
# - total_clusters: Number of detected clusters
# - total_nodes_in_clusters: Nodes potentially colluding
# - highest_correlation: Most suspicious correlation found

# Network entropy
entropy_stats = security['entropy_stats']
# - current_entropy: [0, 1] diversity score
# - decay_active: True if TIME is decaying
# - decay_factor: Current decay multiplier

# Overall health
health = security['network_health']
# - overall: [0, 1] health score
# - status: "HEALTHY" / "WARNING" / "CRITICAL"
```

---

## 7. Recommendations for Operators

### For Node Operators

1. **Avoid synchronization**: Don't run nodes with identical timing
2. **Geographic diversity**: Run nodes in different countries if possible
3. **Independent operation**: Maintain separate infrastructure

### For Network Monitors

1. **Watch cluster metrics**: Alert on cluster_count > 0
2. **Monitor entropy**: Alert when entropy < 0.5
3. **Track health status**: Investigate "WARNING" or "CRITICAL"

### For Protocol Development

1. **Regular audits**: Review correlation detection parameters
2. **Threshold tuning**: Adjust based on network size
3. **Geographic improvements**: Implement better location verification

---

## 8. Known Limitations (Honest Disclosure)

1. **Sophisticated attackers**: Random delays can evade timing detection
2. **VPN spoofing**: Cannot cryptographically prove physical location
3. **Small networks**: Cluster detection needs sufficient data (5+ nodes)
4. **Historical attacks**: Past coordination before detection won't be penalized
5. **Collusion outside network**: Off-chain coordination is undetectable

---

## 9. Comparison with PoS

| Aspect | Proof of Stake | Proof of Time |
|--------|---------------|---------------|
| Attack cost | Capital (can be recovered) | Time (irreversible) |
| Flash attacks | Possible with borrowed funds | Impossible (180-day saturation) |
| Wealth concentration | Favors wealthy | Favors patience |
| Nothing-at-stake | Major problem | Mitigated by time investment |
| Recovery from attack | Stake slashing | TIME reset (180 days) |

---

## 10. Future Research

1. **Zero-knowledge location proofs**: Cryptographic proof without revealing exact location
2. **Reputation import**: Cross-chain reputation for new networks
3. **Adaptive thresholds**: ML-based parameter tuning
4. **Hardware attestation**: TEE-based proofs of independent operation

---

## Changelog

- **v1.0** (2024-12): Initial security model with anti-cluster protection
  - Added ClusterDetector
  - Added EntropyMonitor
  - Implemented handshake independence verification
  - Added global cluster cap (33%)

---

*Time is the ultimate proof.*
