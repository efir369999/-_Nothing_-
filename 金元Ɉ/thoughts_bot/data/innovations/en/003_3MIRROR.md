# 3-Mirror System

**Implementation:** `thoughts_bot/watchdog.py`
**Version:** 1.0

---

## Core

Fault-tolerant network of 5 nodes with automatic failover.

```
1 PRIMARY + 1 BRAIN + 3 MIRRORS = 5 nodes
```

---

## Topology from Code

```python
# watchdog.py:26-39
BRAIN_CHAIN = [
    ("moscow",      "176.124.208.93"),
    ("almaty",      "91.200.148.93"),
    ("spb",         "188.225.58.98"),
    ("novosibirsk", "147.45.147.247"),
]

BOT_CHAIN = [
    ("amsterdam",   "72.56.102.240"),
    ("almaty",      "91.200.148.93"),
    ("spb",         "188.225.58.98"),
    ("novosibirsk", "147.45.147.247"),
]
```

---

## Roles

| Role | Node | IP | Function |
|------|------|----|----------|
| PRIMARY | Amsterdam | 72.56.102.240 | Active bot |
| BRAIN | Moscow | 176.124.208.93 | Controller |
| MIRROR 1 | Almaty | 91.200.148.93 | Standby |
| MIRROR 2 | SPB | 188.225.58.98 | Standby |
| MIRROR 3 | Novosibirsk | 147.45.147.247 | Standby |

---

## Constants

```python
# watchdog.py:41-42
CHECK_INTERVAL = 5   # seconds
SYNC_INTERVAL = 12   # seconds (breathing)
```

---

## Failover Protocol

```python
# watchdog.py:162-172
def am_i_the_brain(my_name: str) -> bool:
    """
    Am I the current brain?
    I'm the brain if all brains BEFORE me in chain are dead.
    """
    for name, ip in BRAIN_CHAIN:
        if name == my_name:
            return True  # Reached myself - I'm the brain
        if is_node_alive(ip):
            return False  # Someone before me is alive
    return False
```

**Reaction time:** < 10 seconds

---

## Breathing Sync

```python
# watchdog.py:140-156
def sync_pull():
    """Inhale: git pull."""
    cmd = f"cd {REPO_PATH} && git pull origin main --rebase"
    ...

def sync_push():
    """Exhale: git push."""
    cmd = f"cd {REPO_PATH} && git push origin main"
    ...
```

Inhale (pull) → Exhale (push) every 12 seconds.

---

## Fault Tolerance Formula

```
4 out of 5 nodes can fail = network alive
Recovery time < 10 seconds
```

---

```
Alejandro Montana
January 2026
```
