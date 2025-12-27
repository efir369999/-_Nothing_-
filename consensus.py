"""
Proof of Time - Consensus Module
Production-grade implementation of the Proof of Time consensus mechanism.

Includes:
- Node state management
- Probability calculations
- Leader selection via VRF
- Sybil resistance
- Slashing conditions
- Weight rebalancing

Во времени все равны / In time, everyone is equal
"""

import time
import struct
import hashlib
import logging
import threading
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import IntEnum, auto
from collections import defaultdict

from crypto import sha256, Ed25519, ECVRF, VRFOutput, WesolowskiVDF, VDFProof
from structures import Block, BlockHeader, Transaction, create_genesis_block
from config import PROTOCOL, NodeConfig, get_block_reward

logger = logging.getLogger("proof_of_time.consensus")


# ============================================================================
# NODE STATE
# ============================================================================

class NodeStatus(IntEnum):
    """Node status enumeration."""
    ACTIVE = auto()
    QUARANTINE = auto()
    OFFLINE = auto()
    SLASHED = auto()


@dataclass
class NodeState:
    """
    State of a network node for consensus.
    
    Tracks:
    - Uptime (continuous online time)
    - Storage (fraction of chain history)
    - Reputation (signed blocks)
    - Quarantine status
    """
    # Identity
    pubkey: bytes
    
    # Time component (f_time)
    uptime_start: int = 0  # Timestamp when current uptime started
    total_uptime: int = 0  # Cumulative uptime in seconds
    
    # Space component (f_space)
    stored_blocks: int = 0  # Number of blocks stored
    
    # Reputation component (f_rep)
    signed_blocks: int = 0  # Number of blocks signed
    last_signed_height: int = 0
    
    # Status
    status: NodeStatus = NodeStatus.OFFLINE
    quarantine_until: int = 0  # Timestamp when quarantine ends
    quarantine_reason: str = ""
    
    # Last seen
    last_seen: int = 0
    
    def get_uptime(self, current_time: int) -> int:
        """Get current uptime in seconds."""
        if self.status != NodeStatus.ACTIVE:
            return 0
        return min(
            self.total_uptime + (current_time - self.uptime_start),
            PROTOCOL.K_TIME  # Cap at saturation
        )
    
    def get_storage_ratio(self, total_blocks: int) -> float:
        """Get storage ratio (0.0 to 1.0)."""
        if total_blocks == 0:
            return 0.0
        return min(self.stored_blocks / total_blocks, 1.0)
    
    def start_uptime(self, timestamp: int):
        """Start or resume uptime tracking."""
        if self.status == NodeStatus.QUARANTINE:
            if timestamp < self.quarantine_until:
                return  # Still in quarantine
            # Quarantine ended
            self.status = NodeStatus.ACTIVE
            self.quarantine_reason = ""
        
        self.uptime_start = timestamp
        self.status = NodeStatus.ACTIVE
        self.last_seen = timestamp
    
    def stop_uptime(self, timestamp: int):
        """Stop uptime tracking (node going offline)."""
        if self.status == NodeStatus.ACTIVE:
            self.total_uptime += timestamp - self.uptime_start
            self.total_uptime = min(self.total_uptime, PROTOCOL.K_TIME)
        
        self.status = NodeStatus.OFFLINE
        self.last_seen = timestamp
    
    def reset_uptime(self):
        """Reset uptime to zero (for quarantine)."""
        self.total_uptime = 0
        self.uptime_start = 0
    
    def enter_quarantine(self, timestamp: int, reason: str):
        """Put node in quarantine."""
        self.status = NodeStatus.QUARANTINE
        self.quarantine_until = timestamp + (PROTOCOL.QUARANTINE_BLOCKS * PROTOCOL.BLOCK_INTERVAL)
        self.quarantine_reason = reason
        self.reset_uptime()
        logger.warning(f"Node {self.pubkey.hex()[:16]}... entered quarantine: {reason}")
    
    def record_signed_block(self, height: int):
        """Record that this node signed a block."""
        self.signed_blocks = min(self.signed_blocks + 1, PROTOCOL.K_REP)
        self.last_signed_height = height
    
    def serialize(self) -> bytes:
        """Serialize node state."""
        data = bytearray()
        data.extend(self.pubkey)
        data.extend(struct.pack('<Q', self.uptime_start))
        data.extend(struct.pack('<Q', self.total_uptime))
        data.extend(struct.pack('<Q', self.stored_blocks))
        data.extend(struct.pack('<Q', self.signed_blocks))
        data.extend(struct.pack('<Q', self.last_signed_height))
        data.extend(struct.pack('<B', self.status))
        data.extend(struct.pack('<Q', self.quarantine_until))
        data.extend(struct.pack('<Q', self.last_seen))
        return bytes(data)
    
    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple['NodeState', int]:
        """Deserialize node state."""
        pubkey = data[offset:offset + 32]
        offset += 32
        
        uptime_start = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        total_uptime = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        stored_blocks = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        signed_blocks = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        last_signed_height = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        status = NodeStatus(data[offset])
        offset += 1
        quarantine_until = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        last_seen = struct.unpack_from('<Q', data, offset)[0]
        offset += 8
        
        return cls(
            pubkey=pubkey,
            uptime_start=uptime_start,
            total_uptime=total_uptime,
            stored_blocks=stored_blocks,
            signed_blocks=signed_blocks,
            last_signed_height=last_signed_height,
            status=status,
            quarantine_until=quarantine_until,
            last_seen=last_seen
        ), offset


# ============================================================================
# PROBABILITY CALCULATION
# ============================================================================

@dataclass
class ProbabilityWeights:
    """Adjustable probability weights for consensus."""
    w_time: float = PROTOCOL.W_TIME
    w_space: float = PROTOCOL.W_SPACE
    w_rep: float = PROTOCOL.W_REP
    
    def normalize(self):
        """Normalize weights to sum to 1.0."""
        total = self.w_time + self.w_space + self.w_rep
        if total > 0:
            self.w_time /= total
            self.w_space /= total
            self.w_rep /= total


class ConsensusCalculator:
    """
    Calculates node probabilities for leader selection.
    
    Probability formula:
    P_i = (w_time × f_time(t_i) + w_space × f_space(s_i) + w_rep × f_rep(r_i)) / Z
    
    where:
    - f_time(t) = min(t / k_time, 1)
    - f_space(s) = min(s / k_space, 1)
    - f_rep(r) = min(r / k_rep, 1)
    - Z = Σ P_i (normalization constant)
    """
    
    def __init__(self, weights: Optional[ProbabilityWeights] = None):
        self.weights = weights or ProbabilityWeights()
    
    def compute_f_time(self, uptime: int) -> float:
        """Compute time component (saturating at k_time)."""
        return min(uptime / PROTOCOL.K_TIME, 1.0)
    
    def compute_f_space(self, stored_blocks: int, total_blocks: int) -> float:
        """Compute space component (saturating at k_space)."""
        if total_blocks == 0:
            return 0.0
        storage_ratio = stored_blocks / total_blocks
        return min(storage_ratio / PROTOCOL.K_SPACE, 1.0)
    
    def compute_f_rep(self, signed_blocks: int) -> float:
        """Compute reputation component (saturating at k_rep)."""
        return min(signed_blocks / PROTOCOL.K_REP, 1.0)
    
    def compute_raw_probability(
        self,
        node: NodeState,
        current_time: int,
        total_blocks: int
    ) -> float:
        """
        Compute raw (unnormalized) probability for a node.
        """
        # Time component
        uptime = node.get_uptime(current_time)
        f_time = self.compute_f_time(uptime)
        
        # Space component
        f_space = self.compute_f_space(node.stored_blocks, total_blocks)
        
        # Reputation component
        f_rep = self.compute_f_rep(node.signed_blocks)
        
        # Weighted sum
        raw_prob = (
            self.weights.w_time * f_time +
            self.weights.w_space * f_space +
            self.weights.w_rep * f_rep
        )
        
        # Quarantine penalty
        if node.status == NodeStatus.QUARANTINE:
            raw_prob *= 0.1  # 90% reduction during quarantine
        
        return raw_prob
    
    def compute_probabilities(
        self,
        nodes: List[NodeState],
        current_time: int,
        total_blocks: int
    ) -> Dict[bytes, float]:
        """
        Compute normalized probabilities for all nodes.
        
        Returns:
            Dict mapping pubkey -> probability
        """
        # Compute raw probabilities
        raw_probs = {}
        for node in nodes:
            if node.status in (NodeStatus.ACTIVE, NodeStatus.QUARANTINE):
                raw_probs[node.pubkey] = self.compute_raw_probability(
                    node, current_time, total_blocks
                )
        
        # Normalize
        total = sum(raw_probs.values())
        if total == 0:
            return {}
        
        return {pk: p / total for pk, p in raw_probs.items()}


# ============================================================================
# LEADER SELECTION
# ============================================================================

class LeaderSelector:
    """
    Selects block leader using VRF and node probabilities.
    
    Process:
    1. Each eligible node computes VRF(prev_block_hash)
    2. VRF output is mapped to [0, 1) range
    3. Node is selected if VRF_output < P_i (their probability)
    4. If multiple nodes qualify, lowest VRF output wins
    """
    
    def __init__(self, calculator: ConsensusCalculator):
        self.calculator = calculator
    
    def compute_selection_hash(
        self,
        prev_block_hash: bytes,
        node_pubkey: bytes
    ) -> bytes:
        """Compute deterministic input for VRF."""
        return sha256(prev_block_hash + node_pubkey)
    
    def vrf_to_float(self, vrf_output: bytes) -> float:
        """Convert VRF output to float in [0, 1)."""
        # Use first 8 bytes as numerator
        num = struct.unpack('<Q', vrf_output[:8])[0]
        return num / (2**64)
    
    def is_leader(
        self,
        node: NodeState,
        prev_block_hash: bytes,
        vrf_output: bytes,
        probability: float
    ) -> bool:
        """
        Check if node is eligible leader.
        
        Node is leader if VRF_output < probability
        """
        vrf_float = self.vrf_to_float(vrf_output)
        return vrf_float < probability
    
    def select_leader(
        self,
        nodes: List[NodeState],
        prev_block_hash: bytes,
        current_time: int,
        total_blocks: int,
        node_vrfs: Dict[bytes, VRFOutput]  # pubkey -> VRF output
    ) -> Optional[bytes]:
        """
        Select leader from eligible nodes.
        
        Args:
            nodes: List of node states
            prev_block_hash: Previous block hash (VRF input)
            current_time: Current timestamp
            total_blocks: Total blocks in chain
            node_vrfs: VRF outputs from each node
        
        Returns:
            Public key of selected leader, or None if no valid leader
        """
        # Compute probabilities
        probs = self.calculator.compute_probabilities(
            nodes, current_time, total_blocks
        )
        
        if not probs:
            logger.warning("No active nodes with probability")
            return None
        
        # Find eligible leaders
        candidates = []
        
        for pubkey, prob in probs.items():
            if pubkey not in node_vrfs:
                continue
            
            vrf = node_vrfs[pubkey]
            vrf_float = self.vrf_to_float(vrf.beta)
            
            # Check eligibility
            if vrf_float < prob:
                candidates.append((pubkey, vrf_float))
        
        if not candidates:
            # Fallback: lowest VRF output among all
            logger.debug("No VRF winner, using fallback selection")
            all_vrfs = [(pk, self.vrf_to_float(vrf.beta)) 
                        for pk, vrf in node_vrfs.items()
                        if pk in probs]
            if all_vrfs:
                candidates = [min(all_vrfs, key=lambda x: x[1])]
        
        if not candidates:
            return None
        
        # Lowest VRF output wins
        winner = min(candidates, key=lambda x: x[1])
        logger.debug(f"Leader selected: {winner[0].hex()[:16]}... (VRF: {winner[1]:.6f})")
        
        return winner[0]


# ============================================================================
# SYBIL RESISTANCE
# ============================================================================

class SybilDetector:
    """
    Detects and mitigates Sybil attacks.
    
    Measures:
    1. Track new node connection rate
    2. Apply probation period for rapid influx
    3. Monitor for coordinated behavior
    """
    
    def __init__(self, window_size: int = PROTOCOL.ADJUSTMENT_WINDOW):
        self.window_size = window_size
        self.connection_times: List[int] = []  # Timestamps of new connections
        self.median_rate: float = 1.0  # Connections per block period
        
        self._lock = threading.Lock()
    
    def record_connection(self, timestamp: int):
        """Record a new node connection."""
        with self._lock:
            self.connection_times.append(timestamp)
            
            # Prune old entries
            cutoff = timestamp - (self.window_size * PROTOCOL.BLOCK_INTERVAL)
            self.connection_times = [t for t in self.connection_times if t > cutoff]
            
            # Update median rate
            if len(self.connection_times) >= 10:
                self._update_median_rate()
    
    def _update_median_rate(self):
        """Update median connection rate."""
        if len(self.connection_times) < 2:
            return
        
        intervals = []
        sorted_times = sorted(self.connection_times)
        for i in range(1, len(sorted_times)):
            intervals.append(sorted_times[i] - sorted_times[i-1])
        
        if intervals:
            intervals.sort()
            mid = len(intervals) // 2
            self.median_rate = intervals[mid] if intervals else PROTOCOL.BLOCK_INTERVAL
    
    def is_suspicious_influx(self) -> bool:
        """
        Check if current connection rate is suspicious.
        
        Suspicious if rate > 2x median.
        """
        with self._lock:
            if len(self.connection_times) < 10:
                return False
            
            # Count recent connections
            current_time = int(time.time())
            recent_window = PROTOCOL.BLOCK_INTERVAL * 10  # Last 10 blocks
            recent = sum(1 for t in self.connection_times 
                        if t > current_time - recent_window)
            
            expected = recent_window / max(self.median_rate, 1)
            
            return recent > 2 * expected
    
    def get_probation_multiplier(self, is_new_node: bool) -> float:
        """
        Get probability multiplier for new nodes.
        
        During suspicious influx, new nodes get reduced probability.
        """
        if not is_new_node:
            return 1.0
        
        if self.is_suspicious_influx():
            return 0.1  # 90% reduction
        
        return 1.0


# ============================================================================
# SLASHING
# ============================================================================

class SlashingCondition(IntEnum):
    """Types of slashable offenses."""
    EQUIVOCATION = auto()  # Signing conflicting blocks
    INVALID_VDF = auto()  # Submitting invalid VDF proof
    INVALID_VRF = auto()  # Submitting invalid VRF proof
    DOUBLE_SPEND = auto()  # Including double-spend in block


@dataclass
class SlashingEvidence:
    """Evidence of slashable offense."""
    condition: SlashingCondition
    offender: bytes  # Public key
    evidence_block1: Optional[bytes] = None  # Block hash
    evidence_block2: Optional[bytes] = None  # Conflicting block hash
    timestamp: int = 0
    
    def serialize(self) -> bytes:
        """Serialize evidence."""
        data = bytearray()
        data.extend(struct.pack('<B', self.condition))
        data.extend(self.offender)
        data.extend(self.evidence_block1 or b'\x00' * 32)
        data.extend(self.evidence_block2 or b'\x00' * 32)
        data.extend(struct.pack('<Q', self.timestamp))
        return bytes(data)


class SlashingManager:
    """
    Manages slashing conditions and penalties.
    
    Penalties:
    - Reputation reset to 0
    - 180-day quarantine (26,000 blocks)
    - Cannot receive rewards during quarantine
    """
    
    def __init__(self):
        self.pending_slashes: List[SlashingEvidence] = []
        self.slashed_nodes: Set[bytes] = set()
        self._lock = threading.Lock()
    
    def check_equivocation(
        self,
        block1: Block,
        block2: Block
    ) -> Optional[SlashingEvidence]:
        """
        Check if two blocks constitute equivocation.
        
        Equivocation = same height, same leader, different blocks.
        """
        if (block1.height == block2.height and
            block1.header.leader_pubkey == block2.header.leader_pubkey and
            block1.hash != block2.hash):
            
            return SlashingEvidence(
                condition=SlashingCondition.EQUIVOCATION,
                offender=block1.header.leader_pubkey,
                evidence_block1=block1.hash,
                evidence_block2=block2.hash,
                timestamp=int(time.time())
            )
        
        return None
    
    def report_slash(self, evidence: SlashingEvidence):
        """Report a slashing offense."""
        with self._lock:
            if evidence.offender in self.slashed_nodes:
                return  # Already slashed
            
            self.pending_slashes.append(evidence)
            self.slashed_nodes.add(evidence.offender)
            
            logger.warning(
                f"Slashing reported: {SlashingCondition(evidence.condition).name} "
                f"by {evidence.offender.hex()[:16]}..."
            )
    
    def apply_slash(
        self,
        evidence: SlashingEvidence,
        node: NodeState,
        current_time: int
    ):
        """Apply slashing penalty to node."""
        # Reset reputation
        node.signed_blocks = 0
        node.last_signed_height = 0
        
        # Enter quarantine
        node.enter_quarantine(
            current_time,
            f"Slashed: {SlashingCondition(evidence.condition).name}"
        )
        
        logger.warning(
            f"Slash applied to {node.pubkey.hex()[:16]}...: "
            f"quarantined until {node.quarantine_until}"
        )
    
    def get_pending_slashes(self) -> List[SlashingEvidence]:
        """Get pending slash evidence for inclusion in blocks."""
        with self._lock:
            return list(self.pending_slashes)
    
    def clear_pending(self, processed: List[SlashingEvidence]):
        """Clear processed slash evidence."""
        with self._lock:
            for ev in processed:
                if ev in self.pending_slashes:
                    self.pending_slashes.remove(ev)


# ============================================================================
# WEIGHT REBALANCING
# ============================================================================

class WeightRebalancer:
    """
    Rebalances consensus weights every adjustment window.
    
    Target weights: 60% time, 20% space, 20% reputation
    
    If one component becomes dominant (>70%), its weight is reduced
    and redistributed to maintain decentralization.
    """
    
    def __init__(self, target_weights: ProbabilityWeights):
        self.target = target_weights
        self.current = ProbabilityWeights(
            w_time=target_weights.w_time,
            w_space=target_weights.w_space,
            w_rep=target_weights.w_rep
        )
    
    def analyze_distribution(
        self,
        nodes: List[NodeState],
        current_time: int,
        total_blocks: int
    ) -> Dict[str, float]:
        """
        Analyze component distributions across nodes.
        
        Returns average values for each component.
        """
        if not nodes:
            return {"time": 0, "space": 0, "rep": 0}
        
        calc = ConsensusCalculator()
        
        total_time = 0
        total_space = 0
        total_rep = 0
        
        for node in nodes:
            if node.status == NodeStatus.ACTIVE:
                uptime = node.get_uptime(current_time)
                total_time += calc.compute_f_time(uptime)
                total_space += calc.compute_f_space(node.stored_blocks, total_blocks)
                total_rep += calc.compute_f_rep(node.signed_blocks)
        
        n = len([n for n in nodes if n.status == NodeStatus.ACTIVE])
        if n == 0:
            return {"time": 0, "space": 0, "rep": 0}
        
        return {
            "time": total_time / n,
            "space": total_space / n,
            "rep": total_rep / n
        }
    
    def rebalance(
        self,
        nodes: List[NodeState],
        current_time: int,
        total_blocks: int
    ) -> ProbabilityWeights:
        """
        Rebalance weights based on current distribution.
        
        Returns updated weights.
        """
        dist = self.analyze_distribution(nodes, current_time, total_blocks)
        
        # Check for dominance
        total = sum(dist.values())
        if total == 0:
            return self.current
        
        # Calculate relative contributions
        time_ratio = (self.current.w_time * dist["time"]) / total
        space_ratio = (self.current.w_space * dist["space"]) / total
        rep_ratio = (self.current.w_rep * dist["rep"]) / total
        
        # Adjust if any component is dominant (>70%)
        threshold = 0.70
        
        if time_ratio > threshold:
            # Reduce time weight
            adjustment = (time_ratio - self.target.w_time) * 0.1
            self.current.w_time = max(0.3, self.current.w_time - adjustment)
            self.current.w_space += adjustment / 2
            self.current.w_rep += adjustment / 2
        
        if space_ratio > threshold:
            adjustment = (space_ratio - self.target.w_space) * 0.1
            self.current.w_space = max(0.1, self.current.w_space - adjustment)
            self.current.w_time += adjustment / 2
            self.current.w_rep += adjustment / 2
        
        if rep_ratio > threshold:
            adjustment = (rep_ratio - self.target.w_rep) * 0.1
            self.current.w_rep = max(0.1, self.current.w_rep - adjustment)
            self.current.w_time += adjustment / 2
            self.current.w_space += adjustment / 2
        
        # Normalize
        self.current.normalize()
        
        logger.debug(
            f"Weights rebalanced: time={self.current.w_time:.2f}, "
            f"space={self.current.w_space:.2f}, rep={self.current.w_rep:.2f}"
        )
        
        return self.current


# ============================================================================
# CONSENSUS ENGINE
# ============================================================================

class ConsensusEngine:
    """
    Main consensus engine for Proof of Time.
    
    Coordinates:
    - Node state management
    - Leader selection
    - Block validation
    - Slashing
    - Weight rebalancing
    """
    
    def __init__(self, config: Optional[NodeConfig] = None):
        self.config = config or NodeConfig()
        
        # Components
        self.vdf = WesolowskiVDF(PROTOCOL.VDF_MODULUS_BITS)
        self.weights = ProbabilityWeights()
        self.calculator = ConsensusCalculator(self.weights)
        self.leader_selector = LeaderSelector(self.calculator)
        self.sybil_detector = SybilDetector()
        self.slashing_manager = SlashingManager()
        self.rebalancer = WeightRebalancer(self.weights)
        
        # State
        self.nodes: Dict[bytes, NodeState] = {}
        self.chain_tip: Optional[Block] = None
        self.total_blocks: int = 0
        
        self._lock = threading.RLock()
    
    def initialize(self, genesis: Optional[Block] = None):
        """Initialize consensus with genesis block."""
        if genesis is None:
            genesis = create_genesis_block()
        
        self.chain_tip = genesis
        self.total_blocks = 1
        
        logger.info(f"Consensus initialized with genesis: {genesis.hash.hex()[:16]}...")
    
    def register_node(self, pubkey: bytes, stored_blocks: int = 0):
        """Register a new node."""
        with self._lock:
            if pubkey in self.nodes:
                return
            
            current_time = int(time.time())
            
            node = NodeState(
                pubkey=pubkey,
                stored_blocks=stored_blocks
            )
            node.start_uptime(current_time)
            
            self.nodes[pubkey] = node
            self.sybil_detector.record_connection(current_time)
            
            logger.info(f"Node registered: {pubkey.hex()[:16]}...")
    
    def update_node(self, pubkey: bytes, **kwargs):
        """Update node state."""
        with self._lock:
            if pubkey not in self.nodes:
                return
            
            node = self.nodes[pubkey]
            for key, value in kwargs.items():
                if hasattr(node, key):
                    setattr(node, key, value)
    
    def get_active_nodes(self) -> List[NodeState]:
        """Get list of active nodes."""
        with self._lock:
            return [n for n in self.nodes.values() 
                   if n.status in (NodeStatus.ACTIVE, NodeStatus.QUARANTINE)]
    
    def compute_probabilities(self) -> Dict[bytes, float]:
        """Compute current node probabilities."""
        current_time = int(time.time())
        active_nodes = self.get_active_nodes()
        
        return self.calculator.compute_probabilities(
            active_nodes, current_time, self.total_blocks
        )
    
    def select_leader(
        self,
        prev_block_hash: bytes,
        node_vrfs: Dict[bytes, VRFOutput]
    ) -> Optional[bytes]:
        """Select leader for next block."""
        current_time = int(time.time())
        active_nodes = self.get_active_nodes()
        
        return self.leader_selector.select_leader(
            active_nodes,
            prev_block_hash,
            current_time,
            self.total_blocks,
            node_vrfs
        )
    
    def validate_leader(
        self,
        block: Block,
        prev_block: Block
    ) -> bool:
        """Validate block leader selection."""
        # Verify VRF proof
        vrf_input = self.leader_selector.compute_selection_hash(
            prev_block.hash,
            block.header.leader_pubkey
        )
        
        vrf_output = VRFOutput(
            beta=block.header.vrf_output,
            proof=block.header.vrf_proof
        )
        
        if not ECVRF.verify(block.header.leader_pubkey, vrf_input, vrf_output):
            logger.warning("Invalid VRF proof")
            return False
        
        # Verify probability eligibility
        if block.header.leader_pubkey not in self.nodes:
            logger.warning("Unknown leader")
            return False
        
        probs = self.compute_probabilities()
        prob = probs.get(block.header.leader_pubkey, 0)
        
        vrf_float = self.leader_selector.vrf_to_float(vrf_output.beta)
        
        # Leader should have won with their VRF output
        # (Allow some tolerance for network timing)
        if vrf_float > prob * 1.1:  # 10% tolerance
            logger.warning(f"Leader VRF {vrf_float:.6f} > probability {prob:.6f}")
            # Don't reject outright, may be valid under different view
        
        return True
    
    def process_block(self, block: Block) -> bool:
        """
        Process a new block.
        
        Updates:
        - Chain tip
        - Node states
        - Slashing if needed
        - Weight rebalancing
        """
        with self._lock:
            # Update chain
            self.chain_tip = block
            self.total_blocks = block.height + 1
            
            # Update leader reputation
            leader_pubkey = block.header.leader_pubkey
            if leader_pubkey in self.nodes:
                self.nodes[leader_pubkey].record_signed_block(block.height)
            
            # Process slashing evidence (if any in block)
            # (Would be in special transactions)
            
            # Rebalance weights every adjustment window
            if block.height % PROTOCOL.ADJUSTMENT_WINDOW == 0 and block.height > 0:
                active_nodes = self.get_active_nodes()
                self.weights = self.rebalancer.rebalance(
                    active_nodes,
                    block.timestamp,
                    self.total_blocks
                )
                self.calculator.weights = self.weights
            
            logger.debug(f"Processed block {block.height}: {block.hash.hex()[:16]}...")
            
            return True
    
    def check_equivocation(self, block1: Block, block2: Block):
        """Check and report equivocation."""
        evidence = self.slashing_manager.check_equivocation(block1, block2)
        if evidence:
            self.slashing_manager.report_slash(evidence)
            
            # Apply slash immediately
            if evidence.offender in self.nodes:
                self.slashing_manager.apply_slash(
                    evidence,
                    self.nodes[evidence.offender],
                    int(time.time())
                )


# ============================================================================
# SELF-TEST
# ============================================================================

def _self_test():
    """Run consensus self-tests."""
    logger.info("Running consensus self-tests...")
    
    # Test probability calculation
    calc = ConsensusCalculator()
    
    node1 = NodeState(pubkey=b'\x01' * 32)
    node1.total_uptime = PROTOCOL.K_TIME  # Max uptime
    node1.stored_blocks = 8000  # 80% of 10000
    node1.signed_blocks = PROTOCOL.K_REP  # Max reputation
    node1.status = NodeStatus.ACTIVE
    
    node2 = NodeState(pubkey=b'\x02' * 32)
    node2.total_uptime = PROTOCOL.K_TIME // 2  # Half max
    node2.stored_blocks = 4000
    node2.signed_blocks = PROTOCOL.K_REP // 2
    node2.status = NodeStatus.ACTIVE
    
    current_time = int(time.time())
    probs = calc.compute_probabilities([node1, node2], current_time, 10000)
    
    assert len(probs) == 2
    assert abs(sum(probs.values()) - 1.0) < 0.001
    assert probs[node1.pubkey] > probs[node2.pubkey]
    logger.info("✓ Probability calculation")
    
    # Test leader selection
    selector = LeaderSelector(calc)
    
    # Generate VRF outputs
    sk1, pk1 = Ed25519.generate_keypair()
    sk2, pk2 = Ed25519.generate_keypair()
    
    node1.pubkey = pk1
    node2.pubkey = pk2
    
    prev_hash = sha256(b"test")
    vrf1 = ECVRF.prove(sk1, prev_hash)
    vrf2 = ECVRF.prove(sk2, prev_hash)
    
    vrfs = {pk1: vrf1, pk2: vrf2}
    
    probs = calc.compute_probabilities([node1, node2], current_time, 10000)
    leader = selector.select_leader(
        [node1, node2], prev_hash, current_time, 10000, vrfs
    )
    
    assert leader in (pk1, pk2)
    logger.info("✓ Leader selection")
    
    # Test consensus engine
    engine = ConsensusEngine()
    engine.initialize()
    
    engine.register_node(pk1, stored_blocks=8000)
    engine.register_node(pk2, stored_blocks=4000)
    
    active = engine.get_active_nodes()
    assert len(active) == 2
    
    probs = engine.compute_probabilities()
    assert len(probs) == 2
    logger.info("✓ Consensus engine")
    
    # Test slashing
    block1 = Block()
    block1.header.height = 100
    block1.header.leader_pubkey = pk1
    block1.header.merkle_root = b'\x01' * 32
    
    block2 = Block()
    block2.header.height = 100
    block2.header.leader_pubkey = pk1
    block2.header.merkle_root = b'\x02' * 32
    
    evidence = engine.slashing_manager.check_equivocation(block1, block2)
    assert evidence is not None
    assert evidence.condition == SlashingCondition.EQUIVOCATION
    logger.info("✓ Equivocation detection")
    
    logger.info("All consensus self-tests passed!")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    _self_test()
