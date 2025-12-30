"""
Montana v4.2 - Time Oracle (DEPRECATED)

═══════════════════════════════════════════════════════════════════════════════
                              DEPRECATION NOTICE
═══════════════════════════════════════════════════════════════════════════════

This module is DEPRECATED and maintained only for backward compatibility.

USE ADAM INSTEAD:

    from pantheon.chronos import Adam, AdamLevel, FinalityState

    adam = Adam()
    adam.start()

    # Get timestamp
    ts = adam.get_timestamp()

    # Process Bitcoin block
    adam.on_bitcoin_block(height, hash, prev_hash, timestamp)

    # Check finality
    finality = adam.get_finality(height)

Adam provides:
  Level 0: NODE_UTC        - Hardware clock (UTC)
  Level 1: GLOBAL_NTP      - 12 national laboratories
  Level 2: MEMPOOL_TIME    - Bitcoin mempool observation
  Level 3: BLOCK_TIME      - Bitcoin block confirmation
  Level 4: BITCOIN_ACTIVE  - Normal operation
  Level 5: VDF_FALLBACK    - SHAKE256 VDF (quantum-resistant)
  Level 6: VDF_DEACTIVATE  - Transitioning back to Bitcoin

═══════════════════════════════════════════════════════════════════════════════

This wrapper redirects all calls to Adam for compatibility.
"""

import warnings
import logging
from typing import Optional, Tuple, Dict, Any

# Import Adam - THE GOD OF TIME
from pantheon.chronos import (
    Adam, AdamLevel, FinalityState, AdamTimestamp,
    Level4Block, VDF_TRIGGER_SECONDS
)

logger = logging.getLogger("montana.time_oracle")


# ============================================================================
# DEPRECATED WRAPPER
# ============================================================================

class TimeOracleMode:
    """DEPRECATED: Use AdamLevel instead."""
    BITCOIN = AdamLevel.BITCOIN_ACTIVE
    VDF = AdamLevel.VDF_FALLBACK
    HYBRID = AdamLevel.BITCOIN_ACTIVE


class TimeOracle:
    """
    DEPRECATED: Use Adam instead.

    This is a compatibility wrapper that delegates to Adam.
    """

    def __init__(self, vdf_iterations: int = 1000, auto_fallback: bool = True):
        warnings.warn(
            "TimeOracle is deprecated. Use Adam from pantheon.chronos instead.",
            DeprecationWarning,
            stacklevel=2
        )

        # Delegate to Adam
        self._adam = Adam(vdf_iterations=vdf_iterations)
        self.auto_fallback = auto_fallback

        # Legacy compatibility
        self.mode = TimeOracleMode.BITCOIN
        self.sequence = 0

        logger.warning("TimeOracle is DEPRECATED - delegating to Adam")

    def start(self):
        """Start time oracle (delegates to Adam)."""
        self._adam.start()

    def stop(self):
        """Stop time oracle."""
        self._adam.stop()

    @property
    def bitcoin_oracle(self):
        """Legacy access to Bitcoin layer."""
        warnings.warn("bitcoin_oracle is deprecated", DeprecationWarning)
        return self._adam.level3

    @property
    def vdf_fallback(self):
        """Legacy access to VDF layer."""
        warnings.warn("vdf_fallback is deprecated", DeprecationWarning)
        return self._adam.level56

    def switch_to_vdf(self, reason: str = ""):
        """DEPRECATED: Adam handles this automatically."""
        warnings.warn("switch_to_vdf is deprecated", DeprecationWarning)
        self._adam.level56._activate_vdf(reason)

    def switch_to_bitcoin(self, reason: str = ""):
        """DEPRECATED: Adam handles this automatically."""
        warnings.warn("switch_to_bitcoin is deprecated", DeprecationWarning)
        self._adam.level56._deactivate_vdf(reason)

    def get_timestamp(self):
        """Get timestamp (returns AdamTimestamp)."""
        return self._adam.get_timestamp()

    def on_bitcoin_block(
        self,
        height: int,
        block_hash: bytes,
        timestamp: int,
        prev_hash: bytes = b'\x00' * 32
    ):
        """Process Bitcoin block (delegates to Adam)."""
        return self._adam.on_bitcoin_block(
            height=height,
            block_hash=block_hash,
            prev_hash=prev_hash,
            timestamp=timestamp
        )

    def get_montana_time(self):
        """DEPRECATED: Use Adam.get_timestamp() instead."""
        warnings.warn("get_montana_time is deprecated", DeprecationWarning)
        ts = self._adam.get_timestamp()
        return {'btc_height': ts.btc_height, 'utc_time': ts.utc_time}

    def get_time_saturation(self, node_join_height: int) -> float:
        """DEPRECATED: Calculate time saturation."""
        warnings.warn("get_time_saturation is deprecated", DeprecationWarning)
        ts = self._adam.get_timestamp()
        if ts.btc_height is None:
            return 0.0
        HALVING_INTERVAL = 210_000
        current_epoch = ts.btc_height // HALVING_INTERVAL
        node_epoch = node_join_height // HALVING_INTERVAL
        if node_epoch < current_epoch:
            epoch_start = current_epoch * HALVING_INTERVAL
            blocks_this_epoch = ts.btc_height - epoch_start
        else:
            blocks_this_epoch = ts.btc_height - node_join_height
        return min(blocks_this_epoch / HALVING_INTERVAL, 1.0)

    def get_status(self) -> Dict[str, Any]:
        """Get oracle status (delegates to Adam)."""
        adam_status = self._adam.get_status()
        levels = adam_status.get('levels', {})
        return {
            'mode': self._adam.level56.current_level.name,
            'sequence': self._adam.sequence,
            'bitcoin': levels.get('4', levels.get(4, {})),
            'vdf': levels.get('5-6', {}),
            'auto_fallback': self.auto_fallback,
            '_deprecated': True,
            '_use': 'Adam from pantheon.chronos'
        }


# ============================================================================
# SELF-TEST
# ============================================================================

def _self_test():
    """Test deprecated wrapper."""
    import hashlib

    logger.info("Testing TimeOracle (deprecated wrapper)...")

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)

        oracle = TimeOracle(vdf_iterations=50)

        # Simulate blocks
        for i in range(3):
            oracle.on_bitcoin_block(
                height=840000 + i,
                block_hash=hashlib.sha256(f"block_{i}".encode()).digest(),
                timestamp=1700000000 + i * 600
            )

        ts = oracle.get_timestamp()
        assert ts.btc_height == 840002
        logger.info("✓ TimeOracle wrapper works")

    logger.info("TimeOracle wrapper tests passed!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _self_test()
