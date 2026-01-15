# 三镜系统

**实现:** `thoughts_bot/watchdog.py`
**版本:** 1.0

---

## 核心

具有自动故障转移的5节点容错网络。

```
1 PRIMARY + 1 BRAIN + 3 MIRRORS = 5节点
```

---

## 代码中的拓扑

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

## 角色

| 角色 | 节点 | IP | 功能 |
|------|------|----|------|
| PRIMARY | 阿姆斯特丹 | 72.56.102.240 | 活动机器人 |
| BRAIN | 莫斯科 | 176.124.208.93 | 控制器 |
| MIRROR 1 | 阿拉木图 | 91.200.148.93 | 待命 |
| MIRROR 2 | 圣彼得堡 | 188.225.58.98 | 待命 |
| MIRROR 3 | 新西伯利亚 | 147.45.147.247 | 待命 |

---

## 常量

```python
# watchdog.py:41-42
CHECK_INTERVAL = 5   # 秒
SYNC_INTERVAL = 12   # 秒（呼吸）
```

---

## 故障转移协议

```python
# watchdog.py:162-172
def am_i_the_brain(my_name: str) -> bool:
    """
    我是当前的大脑吗？
    如果链中我之前的所有大脑都死了，我就是大脑。
    """
    for name, ip in BRAIN_CHAIN:
        if name == my_name:
            return True  # 到达自己 - 我是大脑
        if is_node_alive(ip):
            return False  # 我之前有人活着
    return False
```

**反应时间:** < 10秒

---

## 呼吸同步

```python
# watchdog.py:140-156
def sync_pull():
    """吸气: git pull."""
    cmd = f"cd {REPO_PATH} && git pull origin main --rebase"
    ...

def sync_push():
    """呼气: git push."""
    cmd = f"cd {REPO_PATH} && git push origin main"
    ...
```

吸气 (pull) → 呼气 (push) 每12秒。

---

## 容错公式

```
5个节点中4个可以故障 = 网络存活
恢复时间 < 10秒
```

---

```
Alejandro Montana
2026年1月
```
