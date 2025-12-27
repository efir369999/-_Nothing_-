"""
Proof of Time - Configuration Module
Production-grade configuration with validation and environment support.

Во времени все равны / In time, everyone is equal
"""

import os
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum, auto
import json
import logging

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================

def setup_logging(level: str = "INFO", log_file: Optional[str] = None) -> logging.Logger:
    """Configure production logging with rotation support."""
    logger = logging.getLogger("proof_of_time")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    
    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        from logging.handlers import RotatingFileHandler
        file_handler = RotatingFileHandler(
            log_file, maxBytes=50*1024*1024, backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


# ============================================================================
# PROTOCOL CONSTANTS (IMMUTABLE)
# ============================================================================

class ProtocolConstants:
    """Immutable protocol constants - changing these breaks consensus."""
    
    # Block timing
    BLOCK_INTERVAL: int = 600  # 10 minutes in seconds
    HALVING_INTERVAL: int = 210_000  # Blocks per halving epoch
    MAX_BLOCKS: int = 6_930_000  # Total blocks (33 halvings)
    
    # Rewards (in seconds)
    INITIAL_REWARD: int = 3000  # 50 minutes
    MIN_FEE: int = 1  # 1 second minimum
    
    # Total supply
    TOTAL_SUPPLY: int = 1_260_000_000  # 21 million minutes in seconds
    
    # Consensus weights
    W_TIME: float = 0.60
    W_SPACE: float = 0.20
    W_REP: float = 0.20
    
    # Saturation thresholds
    K_TIME: int = 15_552_000  # 180 days in seconds
    K_SPACE: float = 0.80  # 80% of chain history
    K_REP: int = 2016  # Signed blocks for max reputation
    
    # Network
    MIN_NODES: int = 3
    ADJUSTMENT_WINDOW: int = 2016  # Blocks for difficulty adjustment
    QUARANTINE_BLOCKS: int = 26_000  # ~180 days penalty
    
    # Privacy
    RING_SIZE: int = 16  # Ring signature anonymity set
    
    # Cryptographic parameters
    VDF_MODULUS_BITS: int = 2048
    HASH_SIZE: int = 32  # SHA-256 output
    SIGNATURE_SIZE: int = 64  # Ed25519 signature
    PUBLIC_KEY_SIZE: int = 32  # Ed25519 public key
    
    # Protocol versioning
    PROTOCOL_VERSION: int = 1
    MAGIC_BYTES: bytes = b'\xf9\xbe\xb4\xd9'
    
    # Genesis timestamp (2025-12-25 00:00:00 UTC)
    GENESIS_TIMESTAMP: int = 1735084800


class NetworkType(IntEnum):
    """Network type enumeration."""
    MAINNET = auto()
    TESTNET = auto()
    REGTEST = auto()


# ============================================================================
# RUNTIME CONFIGURATION
# ============================================================================

@dataclass
class NetworkConfig:
    """Network-specific configuration."""
    network_type: NetworkType = NetworkType.MAINNET
    default_port: int = 8333
    max_peers: int = 125
    connection_timeout: int = 30
    handshake_timeout: int = 10
    ping_interval: int = 120
    max_message_size: int = 32 * 1024 * 1024  # 32 MB
    
    # DNS seeds for peer discovery
    dns_seeds: list = field(default_factory=lambda: [
        "seed1.proofoftime.network",
        "seed2.proofoftime.network",
        "seed3.proofoftime.network",
    ])
    
    def __post_init__(self):
        if self.network_type == NetworkType.TESTNET:
            self.default_port = 18333
        elif self.network_type == NetworkType.REGTEST:
            self.default_port = 18444


@dataclass
class VDFConfig:
    """VDF computation configuration."""
    # Base iterations (will be calibrated dynamically if auto_calibrate=True)
    iterations: int = 3_000_000  # ~1 minute on typical CPU

    # Modulus configuration
    modulus_bits: int = 2048

    # Performance options
    parallel_verify: bool = True
    cache_proofs: bool = True

    # Dynamic calibration
    auto_calibrate: bool = True  # Calibrate on startup
    calibration_sample: int = 10_000  # Iterations for calibration

    # Timing targets (seconds) - used when auto_calibrate=True
    target_compute_time: float = 60.0  # Target 1 minute for block production
    min_compute_time: float = 30.0  # Minimum acceptable
    max_compute_time: float = 120.0  # Maximum acceptable

    # Checkpointing
    checkpoint_enabled: bool = True
    checkpoint_interval: int = 100_000  # Save state every N iterations
    checkpoint_dir: str = "vdf_checkpoints"

    def get_iterations_for_time(self, target_seconds: float, ips: float) -> int:
        """Calculate iterations needed for target time given iterations/sec."""
        return max(1000, int(ips * target_seconds))


@dataclass
class StorageConfig:
    """Database and storage configuration."""
    db_path: str = "blockchain.db"
    blocks_dir: str = "blocks"
    chainstate_dir: str = "chainstate"
    
    # Performance
    cache_size_mb: int = 512
    write_buffer_mb: int = 64
    max_open_files: int = 1000
    
    # Pruning (optional)
    prune_enabled: bool = False
    prune_target_mb: int = 10_000


@dataclass
class MempoolConfig:
    """Transaction mempool configuration."""
    max_size_mb: int = 300
    max_tx_count: int = 50_000
    min_fee_rate: int = 1  # Seconds per KB
    expiry_hours: int = 336  # 2 weeks
    
    # Replace-by-fee
    rbf_enabled: bool = True
    rbf_min_increment: float = 1.1  # 10% fee increase


@dataclass 
class NodeConfig:
    """Complete node configuration."""
    # Sub-configurations
    network: NetworkConfig = field(default_factory=NetworkConfig)
    vdf: VDFConfig = field(default_factory=VDFConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    mempool: MempoolConfig = field(default_factory=MempoolConfig)
    
    # Node identity
    data_dir: str = "~/.proofoftime"
    node_name: str = "PoT-Node"
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[str] = None
    
    # Features
    enable_mining: bool = True
    enable_wallet: bool = True
    enable_rpc: bool = True
    rpc_port: int = 8332
    rpc_bind: str = "127.0.0.1"
    
    @classmethod
    def from_file(cls, path: str) -> 'NodeConfig':
        """Load configuration from JSON file."""
        with open(path, 'r') as f:
            data = json.load(f)
        return cls._from_dict(data)
    
    @classmethod
    def from_env(cls) -> 'NodeConfig':
        """Load configuration from environment variables."""
        config = cls()
        
        # Override from environment
        if os.getenv("POT_DATA_DIR"):
            config.data_dir = os.getenv("POT_DATA_DIR")
        if os.getenv("POT_NETWORK"):
            config.network.network_type = NetworkType[os.getenv("POT_NETWORK").upper()]
        if os.getenv("POT_LOG_LEVEL"):
            config.log_level = os.getenv("POT_LOG_LEVEL")
        if os.getenv("POT_PORT"):
            config.network.default_port = int(os.getenv("POT_PORT"))
        if os.getenv("POT_RPC_PORT"):
            config.rpc_port = int(os.getenv("POT_RPC_PORT"))
        if os.getenv("POT_MAX_PEERS"):
            config.network.max_peers = int(os.getenv("POT_MAX_PEERS"))
            
        return config
    
    @classmethod
    def _from_dict(cls, data: dict) -> 'NodeConfig':
        """Create config from dictionary."""
        config = cls()
        
        for key, value in data.items():
            if hasattr(config, key):
                if isinstance(value, dict):
                    sub_config = getattr(config, key)
                    for sub_key, sub_value in value.items():
                        if hasattr(sub_config, sub_key):
                            setattr(sub_config, sub_key, sub_value)
                else:
                    setattr(config, key, value)
        
        return config
    
    def to_dict(self) -> dict:
        """Export configuration to dictionary."""
        from dataclasses import asdict
        return asdict(self)
    
    def save(self, path: str):
        """Save configuration to JSON file."""
        with open(path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2, default=str)
    
    def validate(self) -> bool:
        """Validate configuration values."""
        errors = []
        
        if self.network.max_peers < 1:
            errors.append("max_peers must be >= 1")
        if self.vdf.iterations < 1000:
            errors.append("VDF iterations must be >= 1000")
        if self.storage.cache_size_mb < 64:
            errors.append("cache_size_mb must be >= 64")
        if self.mempool.max_size_mb < 10:
            errors.append("mempool max_size_mb must be >= 10")
            
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")
        
        return True


# ============================================================================
# GLOBAL INSTANCES
# ============================================================================

# Default configuration (can be overridden)
DEFAULT_CONFIG = NodeConfig()

# Protocol constants (immutable)
PROTOCOL = ProtocolConstants()


def get_block_reward(height: int) -> int:
    """
    Calculate block reward at given height with halving.
    
    Args:
        height: Block height
        
    Returns:
        Reward in seconds (time tokens)
    """
    halvings = height // PROTOCOL.HALVING_INTERVAL
    if halvings >= 33:
        return 0
    return PROTOCOL.INITIAL_REWARD >> halvings


def get_halving_epoch(height: int) -> int:
    """Get halving epoch number for block height."""
    return height // PROTOCOL.HALVING_INTERVAL + 1


def blocks_until_halving(height: int) -> int:
    """Calculate blocks remaining until next halving."""
    return PROTOCOL.HALVING_INTERVAL - (height % PROTOCOL.HALVING_INTERVAL)


def estimate_total_supply_at_height(height: int) -> int:
    """Estimate total supply emitted by given height."""
    if height <= 0:
        return 0
    
    total = 0
    remaining = height
    reward = PROTOCOL.INITIAL_REWARD
    
    while remaining > 0 and reward > 0:
        blocks_in_epoch = min(remaining, PROTOCOL.HALVING_INTERVAL)
        total += blocks_in_epoch * reward
        remaining -= blocks_in_epoch
        reward >>= 1
    
    return total
