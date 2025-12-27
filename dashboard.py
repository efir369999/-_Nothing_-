#!/usr/bin/env python3
"""
Proof of Time - Network Dashboard
Real-time monitoring of node and network metrics.

Usage:
    python dashboard.py              # One-time display
    python dashboard.py --live       # Live updating (every 5s)
    python dashboard.py --json       # JSON output for integrations
"""

import os
import sys
import time
import json
import argparse
import platform
import threading
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

# Colors for terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    END = '\033[0m'

def colorize(text: str, color: str) -> str:
    """Add color to text if terminal supports it."""
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.END}"
    return text

def format_bytes(size: int) -> str:
    """Format bytes to human readable."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"

def format_duration(seconds: int) -> str:
    """Format seconds to human readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    elif seconds < 86400:
        hours = seconds // 3600
        mins = (seconds % 3600) // 60
        return f"{hours}h {mins}m"
    else:
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        return f"{days}d {hours}h"

def get_system_metrics() -> Dict[str, Any]:
    """Get system resource metrics."""
    metrics = {
        'platform': platform.system(),
        'python_version': platform.python_version(),
    }

    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_SELF)
        metrics['memory_mb'] = usage.ru_maxrss / 1024  # Convert to MB on Linux
        if platform.system() == 'Darwin':
            metrics['memory_mb'] = usage.ru_maxrss / (1024 * 1024)  # macOS uses bytes
    except:
        metrics['memory_mb'] = 0

    return metrics

def get_node_metrics(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Get node metrics from running node or database."""
    metrics = {
        'status': 'unknown',
        'chain_height': 0,
        'genesis_hash': '',
        'peers_connected': 0,
        'peers_known': 0,
        'mempool_size': 0,
        'mempool_bytes': 0,
        'uptime_seconds': 0,
        'sync_state': 'unknown',
        'vdf_iterations': 0,
        'blocks_today': 0,
        'tx_today': 0,
    }

    try:
        # Try to load from database
        from database import BlockchainDB
        from config import StorageConfig

        data_dir = '/var/lib/proofoftime'
        if config_path and os.path.exists(config_path):
            with open(config_path) as f:
                cfg = json.load(f)
                data_dir = cfg.get('data_dir', data_dir)

        db_path = os.path.join(data_dir, 'blockchain.db')
        if os.path.exists(db_path):
            db = BlockchainDB(StorageConfig(db_path=db_path))

            # Get chain state
            state = db.get_chain_state()
            if state:
                metrics['chain_height'] = state.get('tip_height', 0)
                tip_hash = state.get('tip_hash', b'')
                if tip_hash:
                    metrics['tip_hash'] = tip_hash.hex()[:16] + '...'
                metrics['total_supply'] = state.get('total_supply', 0)
                metrics['difficulty'] = state.get('difficulty', 0)

            # Get genesis
            genesis = db.get_block_by_height(0)
            if genesis:
                metrics['genesis_hash'] = genesis.hash.hex()[:16] + '...'

            # Get latest block time
            latest = db.get_latest_block()
            if latest:
                metrics['last_block_time'] = latest.timestamp
                metrics['last_block_age'] = int(time.time()) - latest.timestamp

            db.close()
            metrics['status'] = 'database_ok'
    except Exception as e:
        metrics['error'] = str(e)

    # Check if node process is running
    try:
        import subprocess
        result = subprocess.run(
            ['pgrep', '-f', 'node.py.*--run'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            metrics['status'] = 'running'
            metrics['pid'] = result.stdout.strip().split('\n')[0]
    except:
        pass

    # Check systemd service
    try:
        import subprocess
        result = subprocess.run(
            ['systemctl', 'is-active', 'proofoftime'],
            capture_output=True, text=True
        )
        if result.stdout.strip() == 'active':
            metrics['status'] = 'running (systemd)'
            metrics['service'] = 'active'
    except:
        pass

    return metrics

def get_network_metrics() -> Dict[str, Any]:
    """Get network-level metrics."""
    metrics = {
        'p2p_port': 8333,
        'rpc_port': 8332,
        'listening': False,
        'external_ip': 'unknown',
    }

    # Check if P2P port is listening
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('127.0.0.1', 8333))
        metrics['listening'] = (result == 0)
        sock.close()
    except:
        pass

    return metrics

def get_consensus_metrics() -> Dict[str, Any]:
    """Get consensus-related metrics."""
    metrics = {
        'vdf_type': 'Wesolowski RSA-2048',
        'vrf_type': 'ECVRF Ed25519 (RFC 9381)',
        'dag_type': 'PHANTOM-PoT',
        'block_time_target': '10 min',
        'finality_threshold': 0.99,
    }

    try:
        from config import PROTOCOL
        metrics['block_time_target'] = f"{PROTOCOL.get('BLOCK_TIME', 600) // 60} min"
        metrics['max_block_size'] = PROTOCOL.get('MAX_BLOCK_SIZE', 2_000_000)
        metrics['initial_reward'] = PROTOCOL.get('INITIAL_BLOCK_REWARD', 100)
    except:
        pass

    return metrics

def get_privacy_metrics() -> Dict[str, Any]:
    """Get privacy-related metrics."""
    return {
        'privacy_model': 'Tiered (T0-T3)',
        'ring_sig': 'LSAG (Linkable SAG)',
        'range_proofs': 'Bulletproofs',
        'stealth_addresses': 'Ed25519 DHKE',
        'tiers': {
            'T0': 'Public (transparent)',
            'T1': 'Stealth addresses',
            'T2': 'Confidential (CT)',
            'T3': 'Full privacy (Ring + CT)',
        }
    }

def print_dashboard(live: bool = False):
    """Print the dashboard to terminal."""

    # Gather all metrics
    system = get_system_metrics()
    node = get_node_metrics('/etc/proofoftime.json')
    network = get_network_metrics()
    consensus = get_consensus_metrics()
    privacy = get_privacy_metrics()

    # Clear screen for live mode
    if live:
        os.system('clear' if os.name != 'nt' else 'cls')

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Header
    print()
    print(colorize("╔══════════════════════════════════════════════════════════════════╗", Colors.GREEN))
    print(colorize("║           PROOF OF TIME - NETWORK DASHBOARD                      ║", Colors.GREEN))
    print(colorize("║           Во времени все равны / In time, everyone is equal      ║", Colors.GREEN))
    print(colorize("╚══════════════════════════════════════════════════════════════════╝", Colors.GREEN))
    print(f"  {colorize('Updated:', Colors.DIM)} {now}")
    print()

    # Node Status
    print(colorize("┌─ NODE STATUS ─────────────────────────────────────────────────────┐", Colors.CYAN))

    status_color = Colors.GREEN if 'running' in node.get('status', '') else Colors.RED
    print(f"  Status:        {colorize(node.get('status', 'unknown').upper(), status_color)}")

    if node.get('pid'):
        print(f"  PID:           {node['pid']}")

    print(f"  Chain Height:  {colorize(str(node.get('chain_height', 0)), Colors.YELLOW)}")

    if node.get('genesis_hash'):
        print(f"  Genesis:       {node['genesis_hash']}")

    if node.get('tip_hash'):
        print(f"  Tip Hash:      {node['tip_hash']}")

    if node.get('last_block_age'):
        age = format_duration(node['last_block_age'])
        print(f"  Last Block:    {age} ago")

    if node.get('total_supply'):
        supply = node['total_supply'] / 1e8  # Convert from base units
        print(f"  Total Supply:  {supply:,.2f} TIME")

    print()

    # Network Status
    print(colorize("┌─ NETWORK ──────────────────────────────────────────────────────────┐", Colors.CYAN))

    listen_status = colorize("LISTENING", Colors.GREEN) if network['listening'] else colorize("NOT LISTENING", Colors.RED)
    print(f"  P2P Port:      {network['p2p_port']} ({listen_status})")
    print(f"  RPC Port:      {network['rpc_port']} (localhost only)")
    print(f"  Peers:         {node.get('peers_connected', 0)} connected / {node.get('peers_known', 0)} known")
    print()

    # Consensus
    print(colorize("┌─ CONSENSUS ────────────────────────────────────────────────────────┐", Colors.CYAN))
    print(f"  VDF:           {consensus['vdf_type']}")
    print(f"  VRF:           {consensus['vrf_type']}")
    print(f"  DAG:           {consensus['dag_type']}")
    print(f"  Block Time:    {consensus['block_time_target']}")
    print(f"  Finality:      {consensus['finality_threshold'] * 100:.0f}% threshold")
    print()

    # Privacy
    print(colorize("┌─ PRIVACY ──────────────────────────────────────────────────────────┐", Colors.CYAN))
    print(f"  Model:         {privacy['privacy_model']}")
    print(f"  Ring Sigs:     {privacy['ring_sig']}")
    print(f"  Range Proofs:  {privacy['range_proofs']}")
    print(f"  Stealth:       {privacy['stealth_addresses']}")
    print()
    print(f"  {colorize('Privacy Tiers:', Colors.BOLD)}")
    for tier, desc in privacy['tiers'].items():
        print(f"    {colorize(tier, Colors.YELLOW)}: {desc}")
    print()

    # System
    print(colorize("┌─ SYSTEM ───────────────────────────────────────────────────────────┐", Colors.CYAN))
    print(f"  Platform:      {system['platform']}")
    print(f"  Python:        {system['python_version']}")
    if system.get('memory_mb'):
        print(f"  Memory:        {system['memory_mb']:.1f} MB")
    print()

    # Commands
    print(colorize("┌─ COMMANDS ─────────────────────────────────────────────────────────┐", Colors.CYAN))
    print(f"  {colorize('pot-status', Colors.YELLOW)}   - Check systemd service status")
    print(f"  {colorize('pot-log', Colors.YELLOW)}      - View live logs")
    print(f"  {colorize('pot-restart', Colors.YELLOW)}  - Restart node")
    print(f"  {colorize('pot-cli', Colors.YELLOW)}      - RPC commands")
    print()

    if live:
        print(colorize("  Press Ctrl+C to exit live mode", Colors.DIM))

def output_json():
    """Output all metrics as JSON."""
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'system': get_system_metrics(),
        'node': get_node_metrics('/etc/proofoftime.json'),
        'network': get_network_metrics(),
        'consensus': get_consensus_metrics(),
        'privacy': get_privacy_metrics(),
    }
    print(json.dumps(metrics, indent=2, default=str))

def main():
    parser = argparse.ArgumentParser(description='Proof of Time Network Dashboard')
    parser.add_argument('--live', '-l', action='store_true', help='Live updating mode')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    parser.add_argument('--interval', '-i', type=int, default=5, help='Update interval (seconds)')
    args = parser.parse_args()

    if args.json:
        output_json()
        return

    if args.live:
        try:
            while True:
                print_dashboard(live=True)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nExiting dashboard...")
    else:
        print_dashboard(live=False)

if __name__ == '__main__':
    main()
