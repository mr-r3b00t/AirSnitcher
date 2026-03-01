#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# AirSnitch – Kali Linux Installer
# ──────────────────────────────────────────────────────────────────────────────
# Installs AirSnitch + web control panel on Kali Linux (bare-metal / laptop).
#
#   - Clones and builds airsnitch from source
#   - Installs all wireless dependencies
#   - Sets up a web UI on port 8080 for browser-based control
#   - Direct USB wireless adapter access (no Docker, no VMs)
#
# Usage:  chmod +x install.sh && sudo ./install.sh
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/airsnitch"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${AIRSNITCH_PORT:-8080}"

# ── Helpers ──────────────────────────────────────────────────────────────────

info()    { echo -e "${BLUE}[*]${NC} $*"; }
success() { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[-]${NC} $*"; exit 1; }

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "    _    _      ____        _ _       _     "
    echo "   / \  (_)_ __/ ___| _ __ (_) |_ ___| |__  "
    echo "  / _ \ | | '__\___ \| '_ \| | __/ __| '_ \ "
    echo " / ___ \| | |   ___) | | | | | || (__| | | |"
    echo "/_/   \_\_|_|  |____/|_| |_|_|\__\___|_| |_|"
    echo ""
    echo -e "${NC}${BOLD}  Wi-Fi Client Isolation Testing Toolkit${NC}"
    echo -e "  Kali Linux Installer"
    echo ""
}

# ── Root check ───────────────────────────────────────────────────────────────

check_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script must be run as root. Use: sudo ./install.sh"
    fi
}

# ── System dependencies ─────────────────────────────────────────────────────

install_deps() {
    info "Updating package lists..."
    apt-get update -qq

    info "Installing system dependencies..."
    apt-get install -y -qq \
        build-essential \
        git \
        python3 \
        python3-pip \
        python3-venv \
        libnl-3-dev \
        libnl-genl-3-dev \
        libnl-route-3-dev \
        libssl-dev \
        libdbus-1-dev \
        pkg-config \
        aircrack-ng \
        dnsmasq \
        tcpreplay \
        macchanger \
        iw \
        wireless-tools \
        wpasupplicant \
        net-tools \
        iputils-ping \
        iproute2 \
        tcpdump \
        usbutils \
        pciutils \
        kmod \
        rfkill \
        tmux \
        curl \
        wget \
        > /dev/null 2>&1

    success "System dependencies installed"
}

# ── Clone & build airsnitch ──────────────────────────────────────────────────

install_airsnitch() {
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "AirSnitch repo already exists at ${INSTALL_DIR}, pulling latest..."
        cd "${INSTALL_DIR}"
        git pull --quiet || true
    else
        info "Cloning AirSnitch..."
        rm -rf "${INSTALL_DIR}"
        git clone https://github.com/vanhoefm/airsnitch.git "${INSTALL_DIR}"
    fi

    cd "${INSTALL_DIR}"
    git submodule update --init --recursive

    info "Building AirSnitch (setup.sh)..."
    chmod +x setup.sh
    ./setup.sh || true

    # Build the research tool specifically
    cd "${INSTALL_DIR}/airsnitch/research"
    if [[ -f build.sh ]]; then
        chmod +x build.sh
        info "Building modified wpa_supplicant..."
        ./build.sh || true
    fi

    # Set up Python venv for the research tool
    if [[ -f pysetup.sh ]]; then
        chmod +x pysetup.sh
        info "Setting up Python environment..."
        ./pysetup.sh || true
    fi

    # Ensure venv exists
    if [[ ! -d "venv" ]]; then
        python3 -m venv venv
        . venv/bin/activate
        pip install --upgrade pip --quiet
        [[ -f requirements.txt ]] && pip install -r requirements.txt --quiet
    fi

    success "AirSnitch built at ${INSTALL_DIR}/airsnitch/research/"
}

# ── Install web control panel ────────────────────────────────────────────────

install_web() {
    info "Installing web control panel..."

    # Copy web files into the install dir
    mkdir -p "${INSTALL_DIR}/web/templates" "${INSTALL_DIR}/web/static/css" "${INSTALL_DIR}/web/static/js"
    cp "${SCRIPT_DIR}/web/server.py"                "${INSTALL_DIR}/web/"
    cp "${SCRIPT_DIR}/web/requirements.txt"         "${INSTALL_DIR}/web/"
    cp "${SCRIPT_DIR}/web/templates/index.html"     "${INSTALL_DIR}/web/templates/"
    cp "${SCRIPT_DIR}/web/static/css/style.css"     "${INSTALL_DIR}/web/static/css/"
    cp "${SCRIPT_DIR}/web/static/js/app.js"         "${INSTALL_DIR}/web/static/js/"

    # Config dir
    mkdir -p "${INSTALL_DIR}/configs"
    if [[ -f "${SCRIPT_DIR}/config/client.conf.example" ]]; then
        cp "${SCRIPT_DIR}/config/client.conf.example" "${INSTALL_DIR}/configs/"
    fi
    if [[ ! -f "${INSTALL_DIR}/configs/client.conf" ]]; then
        cp "${INSTALL_DIR}/configs/client.conf.example" "${INSTALL_DIR}/configs/client.conf" 2>/dev/null || true
    fi

    # Web venv
    if [[ ! -d "${INSTALL_DIR}/web/.venv" ]]; then
        python3 -m venv "${INSTALL_DIR}/web/.venv"
    fi
    "${INSTALL_DIR}/web/.venv/bin/pip" install --quiet --upgrade pip
    "${INSTALL_DIR}/web/.venv/bin/pip" install --quiet -r "${INSTALL_DIR}/web/requirements.txt"

    success "Web control panel installed"
}

# ── Create systemd service + launcher ────────────────────────────────────────

install_service() {
    info "Creating launcher scripts..."

    # Start script
    cat > "${INSTALL_DIR}/start.sh" << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
PORT="${AIRSNITCH_PORT:-8080}"

# Kill NetworkManager on the wifi interface to avoid interference
# (only if user confirms — NM can be re-enabled after testing)
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo "[!] NetworkManager is running. It may interfere with wireless testing."
    echo "    To disable: sudo systemctl stop NetworkManager"
fi

echo ""
echo "  AirSnitch Control Panel"
echo "  http://localhost:${PORT}"
echo "  Press Ctrl+C to stop."
echo ""

exec /opt/airsnitch/web/.venv/bin/python3 /opt/airsnitch/web/server.py
EOF
    chmod +x "${INSTALL_DIR}/start.sh"

    # Stop script
    cat > "${INSTALL_DIR}/stop.sh" << 'EOF'
#!/usr/bin/env bash
pkill -f "airsnitch.*server.py" 2>/dev/null || true
echo "[+] AirSnitch web UI stopped."
EOF
    chmod +x "${INSTALL_DIR}/stop.sh"

    # Symlink for convenience
    ln -sf "${INSTALL_DIR}/start.sh" /usr/local/bin/airsnitch-web
    ln -sf "${INSTALL_DIR}/stop.sh"  /usr/local/bin/airsnitch-stop

    # Systemd service (optional — user can enable if they want auto-start)
    cat > /etc/systemd/system/airsnitch-web.service << EOF
[Unit]
Description=AirSnitch Web Control Panel
After=network.target

[Service]
Type=simple
ExecStart=/opt/airsnitch/web/.venv/bin/python3 /opt/airsnitch/web/server.py
WorkingDirectory=/opt/airsnitch
Restart=on-failure
Environment=AIRSNITCH_PORT=${PORT}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload

    success "Launcher scripts created"
    info "Commands: airsnitch-web (start) | airsnitch-stop (stop)"
    info "Optional: sudo systemctl enable airsnitch-web  (auto-start on boot)"
}

# ── Main ─────────────────────────────────────────────────────────────────────

main() {
    banner
    check_root
    install_deps
    install_airsnitch
    install_web
    install_service

    # Detect wireless interfaces right now
    echo ""
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}${BOLD}  AirSnitch installation complete!${NC}"
    echo -e "${GREEN}${BOLD}══════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "  ${BOLD}Start the web UI:${NC}"
    echo -e "    ${CYAN}sudo airsnitch-web${NC}"
    echo -e "    Then open ${CYAN}http://localhost:${PORT}${NC}"
    echo ""
    echo -e "  ${BOLD}Or run directly:${NC}"
    echo -e "    ${CYAN}cd /opt/airsnitch/airsnitch/research${NC}"
    echo -e "    ${CYAN}source venv/bin/activate${NC}"
    echo -e "    ${CYAN}sudo ./airsnitch.py wlan0 --check-gtk-shared wlan1${NC}"
    echo ""

    echo -e "  ${BOLD}Wireless interfaces detected:${NC}"
    iw dev 2>/dev/null | grep -E "Interface" | while read -r line; do
        echo -e "    ${CYAN}${line}${NC}"
    done
    if ! iw dev 2>/dev/null | grep -q "Interface"; then
        echo -e "    ${YELLOW}(none — plug in your USB adapter)${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Configuration:${NC}"
    echo "    Edit ${CYAN}/opt/airsnitch/configs/client.conf${NC}"
    echo "    with your target network credentials."
    echo ""
}

main "$@"
