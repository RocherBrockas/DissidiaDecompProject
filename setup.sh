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
# Sudo authentication
# ------------------------------------------------------------

echo
echo "============================================================"
echo " Checking administrator access"
echo "============================================================"
echo

if ! command -v sudo >/dev/null 2>&1; then
    echo "[ERROR] sudo is not installed."
    echo "[ERROR] Please install sudo before continuing."
    exit 1
fi

echo "[INFO] Administrator privileges are required to install"
echo "       system dependencies."
echo

echo "[INFO] Please enter your WSL/Linux password when prompted."
echo

if ! sudo -v; then
    echo
    echo "[ERROR] sudo authentication failed."
    echo "[ERROR] The setup cannot continue without administrator privileges."
    exit 1
fi

echo
echo "[OK] Administrator access confirmed."

# ------------------------------------------------------------
# System dependencies
# ------------------------------------------------------------

echo
echo "[1/5] Installing system dependencies..."
echo

echo "============================================================"
echo " Updating APT package lists"
echo "============================================================"
echo

echo "[APT] Updating package lists..."
sudo apt-get update \
    -o Acquire::Retries=3 \
    -o APT::Update::Progress-Fancy="1"

STATUS=$?

if [ $STATUS -ne 0 ]; then
    echo "[ERROR] apt-get update failed with exit code $STATUS"
    exit $STATUS
fi

echo "[APT] Package lists updated successfully."

echo
echo "[OK] APT package lists updated."
echo

echo "============================================================"
echo " Installing required packages"
echo "============================================================"
echo

if ! sudo apt-get install -y \
    build-essential \
    autoconf \
    automake \
    bison \
    flex \
    gettext \
    texinfo \
    cmake \
    meson \
    ninja-build \
    patch \
    git \
    wget \
    curl \
    unzip \
    p7zip-full \
    python3 \
    python3-venv \
    python3-pip \
    gpg \
    libgpgme-dev \
    openssl \
    libssl-dev \
    libgmp-dev \
    libmpfr-dev \
    libmpc-dev \
    libreadline-dev \
    libarchive-dev \
    libusb-1.0-0-dev \
    libtool \
    pkg-config
then
    echo
    echo "[ERROR] Failed to install system dependencies."
    exit 1
fi

if [ $? -ne 0 ]; then
    echo
    echo "[ERROR] Package installation failed."
    exit 1
fi

echo
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

	PSPDEV="$PSPDEV" PATH="$PSPDEV/bin:$PATH" bash -c '
		set -e

		BOOTSTRAP_DIR="/tmp/pspdev-bootstrap"

		echo "[PSPDEV] Cloning PSPDEV..."
		rm -rf "$BOOTSTRAP_DIR"
		git clone https://github.com/pspdev/pspdev.git "$BOOTSTRAP_DIR"

		cd "$BOOTSTRAP_DIR"

		export PSPDEV="'"$PSPDEV"'"
		export PATH="$PSPDEV/bin:$PATH"

		echo
		echo "[PSPDEV] Installation directory:"
		echo "         $PSPDEV"
		echo
		echo "[PSPDEV] PATH:"
		echo "         $PATH"
		echo

		sudo mkdir -p "$PSPDEV"
		sudo chown -R "$USER:$USER" "$PSPDEV"

		echo "[PSPDEV] Running dependency check..."
		./depends/check-dependencies.sh

		echo
		echo "[PSPDEV] Building PSPDEV..."
		echo

		./build-all.sh
	'

    # Only remove the bootstrap directory after a successful build.
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

PSPDEV="${PSPDEV:-$HOME/pspdev}"
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