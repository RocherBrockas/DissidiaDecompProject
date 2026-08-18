#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# PSPDEV is kept outside the repository.
PSPDEV="${PSPDEV:-$HOME/pspdev}"

VENV_DIR="$PROJECT_ROOT/.venv"

echo
echo "============================================================"
echo " Dissidia 012 - Development Environment"
echo "============================================================"
echo

# ------------------------------------------------------------
# Check OS
# ------------------------------------------------------------

if grep -qi microsoft /proc/version 2>/dev/null; then
    echo "[INFO] WSL detected."
else
    echo "[INFO] Native Linux detected."
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "[ERROR] Debian/Ubuntu is required."
    exit 1
fi

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------

echo
echo "[1/5] Installing system dependencies..."

sudo apt-get update

sudo apt-get install -y \
    build-essential \
    autoconf \
    automake \
    bison \
    flex \
    gettext \
    texinfo \
    cmake \
    patch \
    git \
    wget \
    curl \
    unzip \
    p7zip-full \
    python3 \
    python3-venv \
    python3-pip \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libreadline-dev \
    libarchive-dev \
    libusb-1.0-0-dev \
    libtool \
    pkg-config

echo "[OK] System dependencies installed."

# ------------------------------------------------------------
# PSPDEV
# ------------------------------------------------------------

echo
echo "[2/5] Checking PSPDEV..."

if [ ! -x "$PSPDEV/bin/psp-gcc" ]; then

    echo
    echo "PSPDEV is not installed."
    echo "Installing PSPDEV into:"
    echo
    echo "    $PSPDEV"
    echo

    PSPDEV="$PSPDEV" bash -c '
        git clone https://github.com/pspdev/pspdev.git /tmp/pspdev-bootstrap
        cd /tmp/pspdev-bootstrap

        export PSPDEV="'"$PSPDEV"'"

        sudo mkdir -p "$PSPDEV"
        sudo chown -R "$USER:$USER" "$PSPDEV"

        ./build-all.sh
    '

    rm -rf /tmp/pspdev-bootstrap
fi

if [ ! -x "$PSPDEV/bin/psp-gcc" ]; then
    echo
    echo "[ERROR] PSPDEV installation failed."
    exit 1
fi

echo "[OK] PSPDEV found."

# ------------------------------------------------------------
# Environment
# ------------------------------------------------------------

export PSPDEV
export PATH="$PSPDEV/bin:$PATH"

# ------------------------------------------------------------
# Python environment
# ------------------------------------------------------------

echo
echo "[3/5] Preparing Python environment..."

if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"

python -m pip install --upgrade pip setuptools wheel

echo "[OK] Python environment ready."

# ------------------------------------------------------------
# Python tools
# ------------------------------------------------------------

echo
echo "[4/5] Installing disassembly tools..."

python -m pip install --upgrade \
    spimdisasm \
    'splat64[mips]'

echo "[OK] Disassembly tools installed."

# ------------------------------------------------------------
# Validation
# ------------------------------------------------------------

echo
echo "[5/5] Verifying tools..."

echo
echo "PSPDEV:"
echo "  $PSPDEV"

echo
echo "psp-gcc:"
psp-gcc --version | head -n 1

echo
echo "psp-objdump:"
psp-objdump --version | head -n 1

echo
echo "Python:"
python --version

echo
echo "spimdisasm:"
spimdisasm --version 2>/dev/null || true

echo
echo "PSPSDK:"
if [ -d "$PSPDEV/psp/sdk" ]; then
    echo "  OK"
else
    echo "  WARNING: $PSPDEV/psp/sdk not found"
fi

echo
echo "============================================================"
echo " Environment ready."
echo "============================================================"