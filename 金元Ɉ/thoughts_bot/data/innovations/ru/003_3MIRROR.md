# 3-Mirror System

**Реализация:** `thoughts_bot/watchdog.py`
**Версия:** 1.0

---

## Суть

Отказоустойчивая сеть из 5 узлов с автоматическим failover.

```
1 PRIMARY + 1 BRAIN + 3 MIRRORS = 5 узлов
```

---

## Топология из кода

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

## Роли

| Роль | Узел | IP | Функция |
|------|------|----|---------|
| PRIMARY | Amsterdam | 72.56.102.240 | Активный бот |
| BRAIN | Moscow | 176.124.208.93 | Контроллер |
| MIRROR 1 | Almaty | 91.200.148.93 | Standby |
| MIRROR 2 | SPB | 188.225.58.98 | Standby |
| MIRROR 3 | Novosibirsk | 147.45.147.247 | Standby |

---

## Константы

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

**Время реакции:** < 10 секунд

---

## Дыхание (Breathing Sync)

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

Вдох (pull) → Выдох (push) каждые 12 секунд.

---

## Формула отказоустойчивости

```
4 из 5 узлов могут упасть = сеть жива
Время восстановления < 10 секунд
```

---

```
Alejandro Montana
Январь 2026
```
