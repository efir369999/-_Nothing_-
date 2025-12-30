"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                              ADAM - GOD OF TIME                               ║
║                                                                               ║
║       Chronos is deprecated. Adam is the sole authority for time.            ║
║       All time-related operations MUST go through Adam. No exceptions.        ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                               ║
║  ADAM LEVELS (0-6):                                                           ║
║  ─────────────────                                                            ║
║  0 - NODE_UTC:        Node hardware clock (UTC)                               ║
║  1 - GLOBAL_NTP:      12 national laboratories (NIST, PTB, ВНИИФТРИ, etc.)    ║
║  2 - MEMPOOL_TIME:    Bitcoin mempool observation                             ║
║  3 - BLOCK_TIME:      Bitcoin block confirmation                              ║
║  4 - BITCOIN_ACTIVE:  Normal operation, VDF not needed                        ║
║  5 - VDF_FALLBACK:    Bitcoin down 2 blocks, SHAKE256 VDF active              ║
║  6 - VDF_DEACTIVATE:  Bitcoin returned +20 blocks, VDF shutting down          ║
║                                                                               ║
║  FINALITY STATES:                                                             ║
║  ────────────────                                                             ║
║  PENDING      (0 conf)   - In mempool                                         ║
║  TENTATIVE    (1 conf)   - In block, may reorg                                ║
║  CONFIRMED    (6+ conf)  - Probabilistic finality                             ║
║  IRREVERSIBLE (100+ conf) - Cannot reorg                                      ║
║                                                                               ║
║  VDF FALLBACK (Level 5):                                                      ║
║  ───────────────────────                                                      ║
║  Trigger: Bitcoin missing 2 blocks (~20 min)                                  ║
║  Return:  Bitcoin stable 20 blocks (~3.3 hours)                               ║
║  Monitor: Every 1 second                                                      ║
║  VDF: SHAKE256 finalization every 600 seconds (quantum-resistant)             ║
║  PoH: SHA3-256 chain for instant transaction ordering                         ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""

# VDF classes from Prometheus (for VDF fallback)
from pantheon.prometheus import WesolowskiVDF, VDFProof, VDFCheckpoint

# ============================================================================
# ADAM - THE GOD OF TIME
# ============================================================================

from .adam import (
    # THE MASTER CLASS
    Adam,
    AdamSync,  # Backward compatibility alias

    # LEVELS
    AdamLevel,
    Level0_NodeUTC,
    Level1_NetworkNodes,
    Level2_GlobalNTP,
    Level3_MempoolTime,
    Level4_BlockTime,
    Level56_SystemState,

    # DATA STRUCTURES
    FinalityState,
    LevelState,
    AdamTimestamp,
    Level0State,
    Level1State,
    Level2Result,
    Level3State,
    Level4Block,
    VDFStateTransition,

    # CANONICAL CONSTANTS
    GLOBAL_NTP_SERVERS,
    NTP_SERVER_LIST,
    NTP_MIN_SERVERS,
    MAX_CLOCK_DRIFT_MS,
    MIN_PEER_NODES,
    BITCOIN_BLOCK_TIME,
    CONFIRMATIONS_TENTATIVE,
    CONFIRMATIONS_CONFIRMED,
    CONFIRMATIONS_IRREVERSIBLE,
    VDF_TRIGGER_BLOCKS,
    VDF_TRIGGER_SECONDS,
    VDF_MONITOR_INTERVAL,
    VDF_DEACTIVATION_BLOCKS,
    VDF_DEACTIVATION_HYSTERESIS,
    VDF_FINALIZATION_INTERVAL,
    VDF_CHECKPOINT_INTERVAL,
)

__all__ = [
    # Master class
    'Adam',
    'AdamSync',  # Deprecated alias

    # Levels
    'AdamLevel',
    'Level0_NodeUTC',
    'Level1_NetworkNodes',
    'Level2_GlobalNTP',
    'Level3_MempoolTime',
    'Level4_BlockTime',
    'Level56_SystemState',

    # Data structures
    'FinalityState',
    'LevelState',
    'AdamTimestamp',
    'Level0State',
    'Level1State',
    'Level2Result',
    'Level3State',
    'Level4Block',
    'VDFStateTransition',

    # Constants
    'GLOBAL_NTP_SERVERS',
    'NTP_SERVER_LIST',
    'NTP_MIN_SERVERS',
    'MAX_CLOCK_DRIFT_MS',
    'MIN_PEER_NODES',
    'BITCOIN_BLOCK_TIME',
    'CONFIRMATIONS_TENTATIVE',
    'CONFIRMATIONS_CONFIRMED',
    'CONFIRMATIONS_IRREVERSIBLE',
    'VDF_TRIGGER_BLOCKS',
    'VDF_TRIGGER_SECONDS',
    'VDF_MONITOR_INTERVAL',
    'VDF_DEACTIVATION_BLOCKS',
    'VDF_DEACTIVATION_HYSTERESIS',
    'VDF_FINALIZATION_INTERVAL',
    'VDF_CHECKPOINT_INTERVAL',

    # Legacy (will be deprecated)
    'WesolowskiVDF',
    'VDFProof',
    'VDFCheckpoint',
]
