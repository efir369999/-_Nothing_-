# Release Rules - Proof of Time Protocol

## Version Numbering

```
MAJOR.MINOR.PATCH
  │     │     └── Bug fixes, security patches
  │     └──────── New features, non-breaking changes
  └────────────── Breaking changes, major rewrites
```

**Current Version: v4.3.0**

---

## Pre-Release Checklist

### 1. Code Analysis
- [ ] Compare all commits since previous version
- [ ] Identify new features, fixes, and breaking changes
- [ ] Verify all tests pass: `python -m pytest tests/ -v`
- [ ] Run security audit: `python tests/test_security_proofs.py`
- [ ] Check for dead code and unused imports

### 2. Module Status (11 Gods)

| Module | Status | Description |
|--------|--------|-------------|
| ADAM | Production | God of Time (7 levels, Bitcoin anchor) |
| PAUL | Production | Network (P2P, Noise Protocol) |
| HADES | Production | Storage (SQLite, DAG) |
| ATHENA | Production | Consensus (DAG ordering, finality) |
| PROMETHEUS | Production | Crypto (VDF, VRF, ECVRF) |
| PLUTUS | Production | Wallet (Argon2id, AES-256-GCM) |
| NYX | Production | Privacy (T0/T1 only) |
| THEMIS | Production | Validation (blocks, transactions) |
| IRIS | Production | RPC Server (JSON-RPC 2.0) |
| APOSTLES | Production | Trust (12 bootstrap nodes) |
| HAL | Production | Humanity (reputation, Sybil, slashing) |

### 3. Documentation
- [ ] Update version in `Montana_vX.X.md`
- [ ] Regenerate `Montana_vX.X.pdf`
- [ ] Update `README.md` if needed
- [ ] Update `PANTHEON.md` if module structure changed

---

## Release Process

### Step 1: Version Bump

```bash
# Create new whitepaper version
cp Montana_v4.2.md Montana_v4.3.md
# Update version inside the file
# Generate PDF
```

### Step 2: Commit Changes

```bash
git add -A
git commit -m "docs: Update whitepaper and README to v4.3"
git push origin main
```

### Step 3: Create Git Tag

```bash
git tag -a v4.3.0 -m "v4.3.0: [RELEASE_TITLE]"
git push origin v4.3.0
```

### Step 4: GitHub Release

```bash
gh release create v4.3.0 \
  --title "v4.3.0: [RELEASE_TITLE]" \
  --notes-file RELEASE_NOTES.md \
  Montana_v4.3.pdf
```

---

## Release Notes Template

```markdown
# v4.3.0: [RELEASE_TITLE]

## Summary
[1-2 sentence overview of this release]

## Breaking Changes
- [List any breaking changes]

## New Features
- [List new features]

## Bug Fixes
- [List bug fixes]

## Security
- [List security improvements]

## Module Changes
- [List module additions/removals/renames]

## Migration Guide
[If breaking changes exist, explain how to migrate]

## Full Changelog
[Link to compare: vX.X.X...vY.Y.Y]
```

---

## v4.3.0 Changelog (from v4.2.0)

### New Modules
- **ADAM** (`pantheon/adam/`) - God of Time
  - Merged from AdamSync + Chronos
  - 7 temporal levels with Bitcoin anchoring
  - VDF fallback to VRF

- **HAL Extensions** (`pantheon/hal/`)
  - `behavioral.py` - Sybil detection, cluster analysis
  - `slashing.py` - SlashingManager moved from ATHENA
  - `reputation.py` - Merged from Adonis

### Renamed Modules
- **HERMES → PAUL** - Peer Authenticated Unified Link
  - Same functionality, new name

### Deleted Modules
- `pantheon/chronos/` - Merged into ADAM
- `pantheon/adonis/` - Merged into HAL
- `pantheon/ananke/` - Empty stub removed
- `pantheon/mnemosyne/` - Empty stub removed

### Deleted Files
- `pantheon/athena/bitcoin_oracle.py` - Duplicate of ADAM
- `pantheon/athena/vdf_fallback.py` - Duplicate of ADAM
- `pantheon/nyx/ristretto.py` - Experimental, removed

### Security Fixes
- Replace `random.randint` with `secrets.randbits` in network.py
- Replace `random.sample` with `secrets.SystemRandom` in pq_crypto.py
- Fix VDF fallback STARK verify (was returning True when unavailable)

### Production Ready
All 11 modules are now production-ready:
- Explicit `__all__` exports (no wildcards)
- Dead imports removed
- ASCII documentation headers
- Type hints throughout

### Stats
```
55 files changed
5,152 insertions(+)
8,840 deletions(-)
```

---

## Audit Checklist

### Security Audit
- [ ] SQL injection: Parameterized queries only
- [ ] Command injection: No user input in shell commands
- [ ] Timing attacks: `hmac.compare_digest` for secrets
- [ ] Random numbers: `secrets` module for crypto
- [ ] Key storage: Argon2id for KDF
- [ ] Network: Noise Protocol XX encryption

### Code Quality
- [ ] No `import *` (wildcard imports)
- [ ] No dead code or unused imports
- [ ] All functions have docstrings
- [ ] Type hints on public APIs
- [ ] Tests for new features

### Test Coverage
- [ ] `test_integration.py` - 48 tests
- [ ] `test_dag.py` - 48 tests
- [ ] `test_fuzz.py` - 27 tests
- [ ] `test_stress.py` - Stress/load tests
- [ ] `test_security_proofs.py` - Security proofs

---

## Version History

| Version | Date | Highlights |
|---------|------|------------|
| v4.3.0 | 2024-12-30 | Module consolidation (ADAM, HAL merge) |
| v4.2.1 | 2024-12-XX | Bitcoin-anchored TIME dimension |
| v4.2.0 | 2024-12-XX | HAL Humanity System |
| v4.0.0 | 2024-12-XX | Montana - Bitcoin Time Oracle |
| v3.1.0 | 2024-12-XX | Security hardening |
