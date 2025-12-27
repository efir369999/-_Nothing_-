#!/bin/bash
# Proof of Time - Production Install Script
# https://github.com/afgrouptime/proofoftime
#
# Usage: curl -sSL https://raw.githubusercontent.com/afgrouptime/proofoftime/main/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[PoT]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check root
if [[ $EUID -eq 0 ]]; then
    error "Do not run as root. Script will use sudo when needed."
fi

log "Installing Proof of Time node..."

# Detect OS
if [[ -f /etc/debian_version ]]; then
    PKG_MANAGER="apt"
    PKG_INSTALL="sudo apt install -y"
    sudo apt update
elif [[ -f /etc/redhat-release ]]; then
    PKG_MANAGER="yum"
    PKG_INSTALL="sudo yum install -y"
else
    error "Unsupported OS. Use Debian/Ubuntu or RHEL/CentOS."
fi

# Install dependencies
log "Installing system dependencies..."
if [[ "$PKG_MANAGER" == "apt" ]]; then
    $PKG_INSTALL python3 python3-pip python3-venv libsodium-dev git curl
else
    $PKG_INSTALL python3 python3-pip libsodium-devel git curl
fi

# Create directories
POT_HOME="/opt/proofoftime"
POT_DATA="/var/lib/proofoftime"
POT_LOG="/var/log/proofoftime"
POT_USER="pot"

log "Creating user and directories..."
sudo useradd -r -s /bin/false $POT_USER 2>/dev/null || true
sudo mkdir -p $POT_HOME $POT_DATA $POT_LOG
sudo chown -R $POT_USER:$POT_USER $POT_DATA $POT_LOG

# Clone repository
log "Downloading Proof of Time..."
if [[ -d "$POT_HOME/.git" ]]; then
    cd $POT_HOME && sudo git pull
else
    sudo rm -rf $POT_HOME
    sudo git clone https://github.com/afgrouptime/proofoftime.git $POT_HOME
fi
sudo chown -R $POT_USER:$POT_USER $POT_HOME

# Setup Python environment
log "Setting up Python environment..."
cd $POT_HOME
sudo -u $POT_USER python3 -m venv venv
sudo -u $POT_USER ./venv/bin/pip install --upgrade pip
sudo -u $POT_USER ./venv/bin/pip install -r requirements.txt

# Verify installation
log "Verifying installation..."
sudo -u $POT_USER ./venv/bin/python -c "
from crypto import WesolowskiVDF
from consensus import ConsensusEngine
from privacy import LSAG
print('All modules loaded successfully')
" || error "Module verification failed"

# Create config
log "Creating configuration..."
sudo tee /etc/proofoftime.json > /dev/null << 'EOF'
{
    "data_dir": "/var/lib/proofoftime",
    "log_dir": "/var/log/proofoftime",
    "p2p_port": 8333,
    "rpc_port": 8332,
    "rpc_bind": "127.0.0.1",
    "log_level": "INFO",
    "max_peers": 125,
    "dns_seeds": []
}
EOF
sudo chown $POT_USER:$POT_USER /etc/proofoftime.json

# Create systemd service
log "Creating systemd service..."
sudo tee /etc/systemd/system/proofoftime.service > /dev/null << EOF
[Unit]
Description=Proof of Time Node
Documentation=https://github.com/afgrouptime/proofoftime
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$POT_USER
Group=$POT_USER
WorkingDirectory=$POT_HOME
ExecStart=$POT_HOME/venv/bin/python node.py --config /etc/proofoftime.json
Restart=always
RestartSec=10
TimeoutStopSec=60

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$POT_DATA $POT_LOG

# Resource limits
LimitNOFILE=65535
MemoryMax=4G

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
sudo systemctl daemon-reload

# Create helper commands
log "Creating helper commands..."
sudo tee /usr/local/bin/pot-cli > /dev/null << 'EOF'
#!/bin/bash
curl -s -X POST -H "Content-Type: application/json" \
    -d "{\"method\": \"$1\", \"params\": [${@:2}]}" \
    http://127.0.0.1:8332/
EOF
sudo chmod +x /usr/local/bin/pot-cli

sudo tee /usr/local/bin/pot-log > /dev/null << 'EOF'
#!/bin/bash
journalctl -u proofoftime -f
EOF
sudo chmod +x /usr/local/bin/pot-log

# Firewall
log "Configuring firewall..."
if command -v ufw &> /dev/null; then
    sudo ufw allow 8333/tcp comment "Proof of Time P2P" 2>/dev/null || true
elif command -v firewall-cmd &> /dev/null; then
    sudo firewall-cmd --permanent --add-port=8333/tcp 2>/dev/null || true
    sudo firewall-cmd --reload 2>/dev/null || true
fi

# Print summary
echo ""
log "Installation complete!"
echo ""
echo "Commands:"
echo "  sudo systemctl start proofoftime   # Start node"
echo "  sudo systemctl enable proofoftime  # Enable on boot"
echo "  pot-log                             # View logs"
echo "  pot-cli getinfo                     # RPC call"
echo ""
echo "Config: /etc/proofoftime.json"
echo "Data:   $POT_DATA"
echo "Logs:   $POT_LOG"
echo ""
warn "Run 'sudo systemctl start proofoftime' to start the node"
