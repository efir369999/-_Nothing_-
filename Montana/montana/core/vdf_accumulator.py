"""
Ɉ Montana Finality Accumulator v3.4

Layer 2: UTC Finality per MONTANA_TECHNICAL_SPECIFICATION.md §6.

Implements three finality levels through UTC time boundaries:
- Soft:   1 boundary  (1 minute)  - Block included in checkpoint
- Medium: 2 boundaries (2 minutes) - High certainty
- Hard:   3 boundaries (3 minutes) - Maximum security

Sequential hash chain proves participation within a time window, not computation speed.
Hardware advantage eliminated — fast hardware waits for UTC boundary.

TERMINOLOGY NOTE:
Montana uses a "sequential hash chain" (SHAKE256^T), not a classical VDF
in the Boneh et al. (2018) sense. The "VDF" terminology is retained in
class/function names for API compatibility.

Security: Type C (empirical) — no iteration shortcut known for SHAKE256.
"""

from __future__ import annotations
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from enum import IntEnum

from montana.constants import (
    VDF_CHECKPOINT_TIME_SEC,
    FINALITY_SOFT_CHECKPOINTS,
    FINALITY_MEDIUM_CHECKPOINTS,
    FINALITY_HARD_CHECKPOINTS,
    VDF_BASE_ITERATIONS,
    TIME_TOLERANCE_SEC,
    FINALITY_INTERVAL_SEC,
)
from montana.core.types import Hash
from montana.core.vdf import VDFOutput, VDFProof, SHAKE256VDF, get_vdf

logger = logging.getLogger(__name__)


class FinalityLevel(IntEnum):
    """
    Finality levels per §6.2.

    Each level represents accumulated VDF checkpoints providing
    increasing confidence in temporal ordering.
    """
    NONE = 0      # No finality (pending)
    SOFT = 1      # 1 checkpoint (~2.5s)
    MEDIUM = 2    # 100 checkpoints (~4min)
    HARD = 3      # 1000 checkpoints (~40min)


@dataclass
class FinalityThresholds:
    """Checkpoint thresholds for each finality level."""
    soft: int = FINALITY_SOFT_CHECKPOINTS      # 1
    medium: int = FINALITY_MEDIUM_CHECKPOINTS  # 100
    hard: int = FINALITY_HARD_CHECKPOINTS      # 1000


@dataclass
class AccumulatedState:
    """
    Accumulated VDF state for a block or transaction.

    Tracks the accumulation of VDF checkpoints to determine
    current finality level.
    """
    block_hash: Hash                           # Block this state belongs to
    initial_vdf_output: Hash                   # VDF output at block creation
    accumulated_checkpoints: int = 0           # Total accumulated checkpoints
    last_checkpoint_time: float = 0.0          # Timestamp of last checkpoint
    proofs: List[VDFProof] = field(default_factory=list)  # Accumulated proofs

    @property
    def finality_level(self) -> FinalityLevel:
        """Determine current finality level from accumulated checkpoints."""
        if self.accumulated_checkpoints >= FINALITY_HARD_CHECKPOINTS:
            return FinalityLevel.HARD
        elif self.accumulated_checkpoints >= FINALITY_MEDIUM_CHECKPOINTS:
            return FinalityLevel.MEDIUM
        elif self.accumulated_checkpoints >= FINALITY_SOFT_CHECKPOINTS:
            return FinalityLevel.SOFT
        return FinalityLevel.NONE

    @property
    def estimated_time_to_hard(self) -> float:
        """Estimate seconds until hard finality."""
        remaining = FINALITY_HARD_CHECKPOINTS - self.accumulated_checkpoints
        if remaining <= 0:
            return 0.0
        return remaining * VDF_CHECKPOINT_TIME_SEC

    def add_checkpoint(self, proof: VDFProof) -> FinalityLevel:
        """
        Add a VDF checkpoint and return new finality level.

        Args:
            proof: VDF proof for this checkpoint

        Returns:
            Current finality level after adding checkpoint
        """
        self.accumulated_checkpoints += 1
        self.last_checkpoint_time = time.time()
        self.proofs.append(proof)
        return self.finality_level


class VDFAccumulator:
    """
    VDF checkpoint accumulator for finality per §6.

    Manages the accumulation of VDF checkpoints across blocks,
    computing finality levels and chain selection.
    """

    def __init__(
        self,
        thresholds: Optional[FinalityThresholds] = None,
        vdf: Optional[SHAKE256VDF] = None,
    ):
        """
        Initialize accumulator.

        Args:
            thresholds: Custom finality thresholds
            vdf: VDF instance to use (defaults to global)
        """
        self.thresholds = thresholds or FinalityThresholds()
        self.vdf = vdf or get_vdf()

        # State tracking per block
        self._states: Dict[Hash, AccumulatedState] = {}

        # Current chain tip
        self._chain_tip: Optional[Hash] = None

    def register_block(self, block_hash: Hash, vdf_output: Hash) -> AccumulatedState:
        """
        Register a new block for finality tracking.

        Args:
            block_hash: Hash of the block
            vdf_output: VDF output included in block

        Returns:
            New AccumulatedState for the block
        """
        if block_hash in self._states:
            return self._states[block_hash]

        state = AccumulatedState(
            block_hash=block_hash,
            initial_vdf_output=vdf_output,
            last_checkpoint_time=time.time(),
        )
        self._states[block_hash] = state

        logger.debug(f"Registered block {block_hash.hex()[:16]} for finality tracking")
        return state

    def add_checkpoint(self, block_hash: Hash, proof: VDFProof) -> Optional[FinalityLevel]:
        """
        Add a VDF checkpoint to a block's finality.

        Args:
            block_hash: Block to add checkpoint to
            proof: VDF proof for this checkpoint

        Returns:
            New finality level, or None if block not found
        """
        state = self._states.get(block_hash)
        if state is None:
            logger.warning(f"Block {block_hash.hex()[:16]} not registered")
            return None

        # Verify proof chains from previous state
        if state.proofs:
            last_proof = state.proofs[-1]
            if proof.input_hash != last_proof.output_hash:
                logger.warning("VDF proof doesn't chain from previous output")
                return None
        else:
            if proof.input_hash != state.initial_vdf_output:
                logger.warning("VDF proof doesn't chain from block VDF output")
                return None

        # Verify the proof itself
        if not self.vdf.verify_proof(proof):
            logger.warning("VDF proof verification failed")
            return None

        # Add checkpoint
        old_level = state.finality_level
        new_level = state.add_checkpoint(proof)

        if new_level != old_level:
            logger.info(
                f"Block {block_hash.hex()[:16]} reached {new_level.name} finality "
                f"({state.accumulated_checkpoints} checkpoints)"
            )

        return new_level

    def get_finality(self, block_hash: Hash) -> FinalityLevel:
        """Get current finality level for a block."""
        state = self._states.get(block_hash)
        if state is None:
            return FinalityLevel.NONE
        return state.finality_level

    def get_state(self, block_hash: Hash) -> Optional[AccumulatedState]:
        """Get accumulated state for a block."""
        return self._states.get(block_hash)

    def compare_finality(self, hash_a: Hash, hash_b: Hash) -> int:
        """
        Compare finality between two blocks.

        Returns:
            1 if A has more finality, -1 if B has more, 0 if equal
        """
        level_a = self.get_finality(hash_a)
        level_b = self.get_finality(hash_b)

        if level_a > level_b:
            return 1
        elif level_b > level_a:
            return -1

        # Same level - compare checkpoint counts
        state_a = self._states.get(hash_a)
        state_b = self._states.get(hash_b)

        if state_a and state_b:
            if state_a.accumulated_checkpoints > state_b.accumulated_checkpoints:
                return 1
            elif state_b.accumulated_checkpoints > state_a.accumulated_checkpoints:
                return -1

        return 0

    def select_chain_tip(self, candidates: List[Hash]) -> Optional[Hash]:
        """
        Select chain tip from candidates based on accumulated finality.

        This implements the fork choice rule per §6.3:
        "The chain with the most accumulated VDF work is canonical."

        Args:
            candidates: List of candidate block hashes

        Returns:
            Hash of the block with most accumulated finality
        """
        if not candidates:
            return None

        best = candidates[0]
        for candidate in candidates[1:]:
            if self.compare_finality(candidate, best) > 0:
                best = candidate

        self._chain_tip = best
        return best

    def prune_old_states(self, keep_hashes: set[Hash]) -> int:
        """
        Remove states for blocks not in keep_hashes.

        Args:
            keep_hashes: Set of block hashes to keep

        Returns:
            Number of states pruned
        """
        to_remove = [h for h in self._states if h not in keep_hashes]
        for h in to_remove:
            del self._states[h]
        return len(to_remove)

    @property
    def chain_tip(self) -> Optional[Hash]:
        """Current chain tip based on finality."""
        return self._chain_tip

    def get_finality_stats(self) -> Dict[str, int]:
        """Get statistics about tracked blocks by finality level."""
        stats = {level.name: 0 for level in FinalityLevel}
        for state in self._states.values():
            stats[state.finality_level.name] += 1
        return stats


# Global accumulator instance
_accumulator: Optional[VDFAccumulator] = None


def get_accumulator() -> VDFAccumulator:
    """Get or create global VDF accumulator."""
    global _accumulator
    if _accumulator is None:
        _accumulator = VDFAccumulator()
    return _accumulator


def get_finality_time(level: FinalityLevel) -> float:
    """
    Get expected time to reach finality level (UTC model).

    Args:
        level: Target finality level

    Returns:
        Expected time in seconds
    """
    # UTC finality: 1 boundary = 1 minute
    boundaries = {
        FinalityLevel.NONE: 0,
        FinalityLevel.SOFT: 1,      # 1 minute
        FinalityLevel.MEDIUM: 2,    # 2 minutes
        FinalityLevel.HARD: 3,      # 3 minutes
    }
    return boundaries.get(level, 0) * FINALITY_INTERVAL_SEC


# ==============================================================================
# UTC FINALITY CHECKPOINT (v3.4)
# ==============================================================================

@dataclass
class FinalityCheckpoint:
    """
    Finality checkpoint at UTC boundary per §6.6.

    Created every FINALITY_INTERVAL_SEC (1 minute) at UTC boundaries.
    Contains all blocks and heartbeats from the time window.
    """
    boundary_timestamp_ms: int      # UTC boundary (e.g., 00:10:00.000)
    blocks_merkle_root: bytes       # 32 bytes - Merkle root of blocks in window
    vdf_proofs_root: bytes          # 32 bytes - Merkle root of VDF proofs
    participants_count: int         # Number of participating nodes (heartbeats)
    previous_checkpoint_hash: bytes # 32 bytes - Hash of previous checkpoint

    def checkpoint_hash(self) -> bytes:
        """Compute SHA3-256 hash of checkpoint."""
        from montana.crypto.hash import sha3_256
        data = (
            self.boundary_timestamp_ms.to_bytes(8, 'big') +
            self.blocks_merkle_root +
            self.vdf_proofs_root +
            self.participants_count.to_bytes(4, 'big') +
            self.previous_checkpoint_hash
        )
        return sha3_256(data)


def resolve_checkpoint_conflict(
    checkpoint_a: FinalityCheckpoint,
    checkpoint_b: FinalityCheckpoint
) -> FinalityCheckpoint:
    """
    Resolve conflicting checkpoints at the same UTC boundary.

    Fork choice rule per §6.9:
    1. More participants (heartbeats) wins
    2. Tie: lower checkpoint hash (deterministic)

    Args:
        checkpoint_a: First checkpoint
        checkpoint_b: Second checkpoint

    Returns:
        Canonical checkpoint
    """
    # Must be same UTC boundary
    if checkpoint_a.boundary_timestamp_ms != checkpoint_b.boundary_timestamp_ms:
        raise ValueError("Checkpoints must be at same UTC boundary")

    # Primary: more participants
    if checkpoint_a.participants_count != checkpoint_b.participants_count:
        return max(checkpoint_a, checkpoint_b,
                   key=lambda c: c.participants_count)

    # Tiebreaker: lexicographically smaller hash
    return min(checkpoint_a, checkpoint_b,
               key=lambda c: c.checkpoint_hash())


def get_utc_finality_level(block_timestamp_ms: int, current_time_ms: int) -> FinalityLevel:
    """
    Determine finality level based on UTC boundaries passed.

    Args:
        block_timestamp_ms: When block was created
        current_time_ms: Current UTC time

    Returns:
        Current finality level
    """
    # Calculate which boundary the block belongs to
    boundary_ms = FINALITY_INTERVAL_SEC * 1000
    block_boundary = (block_timestamp_ms // boundary_ms) * boundary_ms
    current_boundary = (current_time_ms // boundary_ms) * boundary_ms

    # Count boundaries passed
    boundaries_passed = (current_boundary - block_boundary) // boundary_ms

    if boundaries_passed >= 3:
        return FinalityLevel.HARD
    elif boundaries_passed >= 2:
        return FinalityLevel.MEDIUM
    elif boundaries_passed >= 1:
        return FinalityLevel.SOFT
    return FinalityLevel.NONE


def is_within_time_tolerance(timestamp_ms: int, reference_ms: int) -> bool:
    """
    Check if timestamp is within ±TIME_TOLERANCE_SEC of reference.

    Args:
        timestamp_ms: Timestamp to check
        reference_ms: Reference time (usually local UTC)

    Returns:
        True if within tolerance
    """
    tolerance_ms = TIME_TOLERANCE_SEC * 1000
    return abs(timestamp_ms - reference_ms) <= tolerance_ms


def get_next_boundary_ms(current_time_ms: int) -> int:
    """
    Get the next UTC finality boundary timestamp.

    Args:
        current_time_ms: Current UTC time in milliseconds

    Returns:
        Next boundary timestamp in milliseconds
    """
    boundary_ms = FINALITY_INTERVAL_SEC * 1000
    return ((current_time_ms // boundary_ms) + 1) * boundary_ms


def get_current_boundary_ms(current_time_ms: int) -> int:
    """
    Get the current UTC finality boundary timestamp.

    Args:
        current_time_ms: Current UTC time in milliseconds

    Returns:
        Current boundary timestamp in milliseconds
    """
    boundary_ms = FINALITY_INTERVAL_SEC * 1000
    return (current_time_ms // boundary_ms) * boundary_ms
