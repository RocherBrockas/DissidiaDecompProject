#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ISO_SOURCE="${1:-}"

ISO_DIR="$PROJECT_ROOT/PlaceYourIsoHere"
ISO_DEST="$ISO_DIR/ULUS10566.iso"
ISO_EXTRACT="$ISO_DIR/Extracted_Iso"

DECRYPTED_EBOOT="$ISO_EXTRACT/PSP_GAME/SYSDIR/ULUS10566_EBOOT.elf"
DECRYPTED_LIBFONT="$ISO_EXTRACT/PSP_GAME/USRDIR/DATA/MODULE/libfont.elf"

VENV="$PROJECT_ROOT/.venv"

error()
{
    echo
    echo "[ERROR] $1"
    echo
    exit 1
}

ok()
{
    echo "[OK] $1"
}

# ============================================================
# Arguments
# ============================================================

if [ "$#" -ne 1 ]; then

    echo
    echo "Usage:"
    echo
    echo "  ./bootstrap.sh /path/to/ULUS10566.iso"
    echo
    echo "Windows / WSL example:"
    echo
    echo "  ./bootstrap.sh /mnt/c/Users/User/Downloads/ULUS10566.iso"
    echo

    exit 1
fi

if [ ! -f "$ISO_SOURCE" ]; then
    error "ISO not found: $ISO_SOURCE"
fi

# ============================================================
# Setup environment
# ============================================================

echo
echo "============================================================"
echo " Dissidia 012 Decompilation Bootstrap"
echo "============================================================"
echo

echo "[1/8] Preparing development environment..."

"$PROJECT_ROOT/setup.sh"

source "$VENV/bin/activate"

export PSPDEV="${PSPDEV:-$HOME/pspdev}"
export PATH="$PSPDEV/bin:$PATH"

ok "Development environment ready."

# ============================================================
# Directories
# ============================================================

echo
echo "[2/8] Creating project directories..."

mkdir -p "$ISO_DIR"
mkdir -p "$ISO_EXTRACT"
mkdir -p "$PROJECT_ROOT/Extract"
mkdir -p "$PROJECT_ROOT/DisasmResult"

ok "Directories created."

# ============================================================
# ISO
# ============================================================

echo
echo "[3/8] Copying ISO..."

if [ "$ISO_SOURCE" != "$ISO_DEST" ]; then
    cp "$ISO_SOURCE" "$ISO_DEST"
fi

ok "ISO copied."

# ============================================================
# Extract ISO
# ============================================================

echo
echo "[4/8] Extracting ISO..."

if [ ! -f "$ISO_EXTRACT/PSP_GAME/PARAM.SFO" ]; then

    rm -rf "$ISO_EXTRACT"
    mkdir -p "$ISO_EXTRACT"

    7z x "$ISO_DEST" \
        "-o$ISO_EXTRACT" \
        -y >/dev/null
fi

if [ ! -f "$ISO_EXTRACT/PSP_GAME/PARAM.SFO" ]; then
    error "ISO extraction failed."
fi

ok "ISO extracted."

# ============================================================
# Validate game
# ============================================================

echo
echo "[5/8] Validating game..."

EBOOT="$ISO_EXTRACT/PSP_GAME/SYSDIR/EBOOT.BIN"

if [ ! -f "$EBOOT" ]; then
    error "EBOOT.BIN not found."
fi

if [ ! -d "$ISO_EXTRACT/PSP_GAME/USRDIR/DATA" ]; then
    error "Game DATA directory not found."
fi

ok "ULUS10566 game structure detected."

# ============================================================
# PPSSPP
# ============================================================

echo
echo "[6/8] Checking PPSSPP decrypted files..."
echo

if [ ! -f "$DECRYPTED_EBOOT" ]; then

    echo "The decrypted EBOOT has not been found."
    echo
    echo "On Windows:"
    echo
    echo "  1. Launch PPSSPP."
    echo "  2. Open Developer Tools."
    echo "  3. Enable:"
    echo
    echo "       Dump decrypted EBOOT.BIN on game boot"
    echo
    echo "  4. Launch ULUS10566."
    echo "  5. Close PPSSPP."
    echo
    echo "Expected file:"
    echo
    echo "  $DECRYPTED_EBOOT"
    echo

    read -r -p "Press ENTER when the decrypted EBOOT is available..."

fi

if [ ! -f "$DECRYPTED_EBOOT" ]; then
    error "Decrypted EBOOT not found."
fi

ok "Decrypted EBOOT found."

# ------------------------------------------------------------
# libfont
# ------------------------------------------------------------

if [ ! -f "$DECRYPTED_LIBFONT" ]; then

    echo
    echo "The decrypted libfont has not been found."
    echo
    echo "Expected:"
    echo
    echo "  $DECRYPTED_LIBFONT"
    echo
    echo "Please dump the PRX using PPSSPP and place it there."
    echo

    read -r -p "Press ENTER when libfont.elf is available..."

fi

if [ ! -f "$DECRYPTED_LIBFONT" ]; then
    error "Decrypted libfont not found."
fi

ok "Decrypted libfont found."

# ============================================================
# package.bin
# ============================================================

echo
echo "[7/8] Extracting package.bin..."

python3 \
    "$PROJECT_ROOT/Tools/PackageBinExtract/ExtractPackageBin.py"

ok "package.bin extracted."

# ============================================================
# Disassembly
# ============================================================

echo
echo "[8/8] Running initial disassembly..."

make disasmOVL

ok "Initial disassembly complete."

# ============================================================
# Done
# ============================================================

echo
echo "============================================================"
echo " Bootstrap complete!"
echo "============================================================"
echo
echo "The project is ready."
echo
echo "Useful commands:"
echo
echo "    make"
echo "    make package"
echo "    make disasmOVL"
echo "    make clean"
echo