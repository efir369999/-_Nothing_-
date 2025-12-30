"""
PANTHEON - The Gods of Proof of Time

Each god represents a core protocol component:

| # | God        | Domain      | Module        | Status  |
|---|------------|-------------|---------------|---------|
| 1 | Adam       | Time        | adam/         | Active  |
| 2 | Paul       | Network     | paul/         | Active  |
| 3 | Hades      | Storage     | hades/        | Active  |
| 4 | Athena     | Consensus   | athena/       | Active  |
| 5 | Prometheus | Crypto      | prometheus/   | Active  |
| 6 | Mnemosyne  | Mempool     | mnemosyne/    | Active  |
| 7 | Plutus     | Wallet      | plutus/       | Active  |
| 8 | Nyx        | Privacy     | nyx/          | Active  |
| 9 | Themis     | Validation  | themis/       | Active  |
|10 | Iris       | API/RPC     | iris/         | Active  |
|11 | Ananke     | Governance  | ananke/       | Planned |
|12 | Apostles   | Trust/12    | apostles/     | Active  |
|13 | Hal        | Humanity    | hal/          | Active  |

ADAM = Anchored Deterministic Asynchronous Mesh (God of Time)
HAL = Human Analyse Language (reputation + humanity system)

Usage:
    from pantheon.adam import Adam, AdamLevel
    from pantheon.hal import HalEngine, HumanityTier
    from pantheon.athena import ConsensusCalculator
"""

import sys
from pathlib import Path

_root = str(Path(__file__).parent.parent)
if _root not in sys.path:
    sys.path.insert(0, _root)

GENESIS_TIMESTAMP = 1766966400  # Dec 28, 2025 00:00:00 UTC

GODS = {
    1:  "ADAM",        # Time / VDF / Bitcoin Oracle
    2:  "PAUL",        # Network / P2P (Peer Authenticated Unified Link)
    3:  "HADES",       # Storage / DAG
    4:  "ATHENA",      # Consensus / Leader Selection
    5:  "PROMETHEUS",  # Cryptography
    6:  "MNEMOSYNE",   # Mempool
    7:  "PLUTUS",      # Wallet
    8:  "NYX",         # Privacy
    9:  "THEMIS",      # Validation
    10: "IRIS",        # API / RPC
    11: "ANANKE",      # Governance
    12: "APOSTLES",    # Trust / 12 Apostles
    13: "HAL",         # Humanity / Reputation
}

PROTOCOL_PROMPT = "Proof of Time: Adam proves, Athena selects, Hal trusts."
