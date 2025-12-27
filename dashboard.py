#!/usr/bin/env python3
"""
Proof of Time - Real-time Node Dashboard
Minimal display of critical network metrics.
"""

import os
import sys
import time
import json
import socket
from datetime import datetime

# Colors
G = '\033[92m'  # Green
Y = '\033[93m'  # Yellow
R = '\033[91m'  # Red
C = '\033[96m'  # Cyan
B = '\033[1m'   # Bold
D = '\033[2m'   # Dim
N = '\033[0m'   # Reset

def c(text, color):
    """Colorize text."""
    return f"{color}{text}{N}" if sys.stdout.isatty() else str(text)

def get_metrics():
    """Get critical metrics from node."""
    m = {
        'height': 0,
        'nodes': 0,
        'block_time': 600,  # Target: 10 min
        'last_block_age': 0,
        'time_to_block': 0,
        'status': 'offline',
        'mempool': 0,
        'tps': 0.0,
    }

    # Try RPC call to running node
    try:
        import urllib.request
        req = urllib.request.Request(
            'http://127.0.0.1:8332/',
            data=json.dumps({"method": "getinfo"}).encode(),
            headers={'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            data = json.loads(resp.read())
            if 'result' in data:
                r = data['result']
                m['height'] = r.get('height', 0)
                m['nodes'] = r.get('peers', 0)
                m['mempool'] = r.get('mempool_size', 0)
                m['status'] = 'online'
    except:
        pass

    # Try database directly
    try:
        from database import BlockchainDB
        from config import StorageConfig

        db_path = '/var/lib/proofoftime/blockchain.db'
        if os.path.exists(db_path):
            db = BlockchainDB(StorageConfig(db_path=db_path))

            state = db.get_chain_state()
            if state:
                m['height'] = state.get('tip_height', 0)

            latest = db.get_latest_block()
            if latest:
                m['last_block_age'] = int(time.time()) - latest.timestamp
                m['time_to_block'] = max(0, 600 - m['last_block_age'])

            db.close()
            if m['status'] == 'offline':
                m['status'] = 'synced'
    except:
        pass

    # Check if node process running
    try:
        import subprocess
        result = subprocess.run(['pgrep', '-f', 'node.py.*--run'],
                              capture_output=True, timeout=1)
        if result.returncode == 0 and m['status'] == 'offline':
            m['status'] = 'running'
    except:
        pass

    return m

def format_time(seconds):
    """Format seconds to MM:SS or HH:MM:SS."""
    if seconds < 0:
        return "--:--"
    if seconds < 3600:
        return f"{seconds // 60:02d}:{seconds % 60:02d}"
    return f"{seconds // 3600}:{(seconds % 3600) // 60:02d}:{seconds % 60:02d}"

def render(m):
    """Render dashboard."""
    now = datetime.now().strftime('%H:%M:%S')

    # Status color
    if m['status'] == 'online':
        status = c('ONLINE', G)
    elif m['status'] in ('running', 'synced'):
        status = c(m['status'].upper(), Y)
    else:
        status = c('OFFLINE', R)

    # Time to block color
    ttb = m['time_to_block']
    if ttb > 300:
        ttb_color = G
    elif ttb > 60:
        ttb_color = Y
    else:
        ttb_color = R

    print()
    print(c("  PROOF OF TIME", G) + c(" │ ", D) + c("Time is the ultimate proof", D))
    print(c("  ─────────────────────────────────────────", D))
    print()
    print(f"  {c('STATUS', C)}      {status}")
    print()
    print(f"  {c('HEIGHT', C)}      {c(m['height'], B)}")
    print(f"  {c('NODES', C)}       {m['nodes']}")
    print(f"  {c('MEMPOOL', C)}     {m['mempool']} tx")
    print()
    print(f"  {c('NEXT BLOCK', C)}  {c(format_time(ttb), ttb_color)}")
    print(f"  {c('LAST BLOCK', C)}  {format_time(m['last_block_age'])} ago")
    print()
    print(c(f"  ─────────────────────────────────────────", D))
    print(c(f"  Updated: {now}  │  Ctrl+C to exit", D))

def clear():
    """Clear screen."""
    os.system('clear' if os.name != 'nt' else 'cls')

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', '-l', action='store_true', help='Live mode')
    parser.add_argument('--json', '-j', action='store_true', help='JSON output')
    parser.add_argument('--interval', '-i', type=int, default=1, help='Update interval')
    args = parser.parse_args()

    if args.json:
        print(json.dumps(get_metrics(), indent=2))
        return

    if args.live:
        try:
            while True:
                clear()
                render(get_metrics())
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\n")
    else:
        render(get_metrics())
        print()

if __name__ == '__main__':
    main()
