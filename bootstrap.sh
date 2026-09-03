#!/usr/bin/env bash

set -euo pipefail

# ============================================================
# Bootstrap entrypoint
#
# Can be launched from:
#   - WSL
#   - Native Linux
#   - Git Bash / MSYS2 on Windows
#
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ============================================================
# Helpers
# ============================================================

error()
{
    echo
    echo "[ERROR] $1"
    echo
    exit 1
}

info()
{
    echo "[INFO] $1"
}

ok()
{
    echo "[OK] $1"
}

# ============================================================
# Detect execution environment
# ============================================================

is_wsl()
{
    grep -qi microsoft /proc/version 2>/dev/null
}

is_msys()
{
    case "${OSTYPE:-}" in
        msys*)
            return 0
            ;;
        cygwin*)
            return 0
            ;;
        win32*)
            return 0
            ;;
    esac

    return 1
}

# ============================================================
# Windows / Git Bash
# ============================================================

if is_msys; then

    echo
    echo "============================================================"
    echo " Windows environment detected"
    echo "============================================================"
    echo

    # --------------------------------------------------------
    # Check WSL
    # --------------------------------------------------------

    if ! command -v wsl.exe >/dev/null 2>&1; then
        error "WSL was not found.

Please install WSL first.

For example from PowerShell:

    wsl --install -d Ubuntu
"
    fi

    # --------------------------------------------------------
    # Get Windows path of project
    # --------------------------------------------------------

    WINDOWS_PROJECT_DIR="$(cd "$SCRIPT_DIR" && pwd -W)"

    info "Windows project directory:"
    echo "       $WINDOWS_PROJECT_DIR"

    # --------------------------------------------------------
    # Convert project path to WSL path
    # --------------------------------------------------------

    WSL_PROJECT_DIR="$(wsl.exe wslpath -a "$WINDOWS_PROJECT_DIR" | tr -d '\r')"

    if [ -z "$WSL_PROJECT_DIR" ]; then
        error "Could not convert project path to WSL path."
    fi

    info "WSL project directory:"
    echo "       $WSL_PROJECT_DIR"

    # --------------------------------------------------------
    # Convert ISO argument
    # --------------------------------------------------------

    if [ "$#" -ne 1 ]; then

        echo
        echo "Usage:"
        echo
        echo "    ./bootstrap.sh /path/to/ULUS10566.iso"
        echo
        exit 1

    fi

    WINDOWS_ISO_PATH="$(cd "$(dirname "$1")" && pwd -W)/$(basename "$1")"

    if [ ! -f "$WINDOWS_ISO_PATH" ]; then
        error "ISO not found:

    $WINDOWS_ISO_PATH
"
    fi

    WSL_ISO_PATH="$(wsl.exe wslpath -a "$WINDOWS_ISO_PATH" | tr -d '\r')"

    info "ISO:"
    echo "       $WSL_ISO_PATH"

    echo
    echo "Launching bootstrap inside WSL..."
    echo

    # --------------------------------------------------------
    # Execute bootstrap inside WSL
    # --------------------------------------------------------

    wsl.exe bash -lc "
        cd '$WSL_PROJECT_DIR'
        chmod +x ./bootstrap.sh ./setup.sh
        ./bootstrap.sh '$WSL_ISO_PATH'
    "

    exit $?
fi

# ============================================================
# WSL / Linux
# ============================================================

if is_wsl; then
    info "WSL detected."
else
    info "Native Linux detected."
fi

# ============================================================
# Arguments
# ============================================================

if [ "$#" -ne 1 ]; then

    echo
    echo "Usage:"
    echo
    echo "    ./bootstrap.sh /path/to/ULUS10566.iso"
    echo

    exit 1
fi

ISO_SOURCE="$1"

# ============================================================
# Validate Linux environment
# ============================================================

if ! command -v apt-get >/dev/null 2>&1; then

    error "Debian/Ubuntu is required.

This script is running in a Linux environment, but apt-get
was not found.

If you are on Windows, make sure WSL Ubuntu is installed.
"

fi

# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT="$SCRIPT_DIR"

ISO_DIR="$PROJECT_ROOT/PlaceYourIsoHere"
ISO_DEST="$ISO_DIR/ULUS10566.iso"
ISO_EXTRACT="$ISO_DIR/Extracted_Iso"

DECRYPTED_EBOOT="$ISO_EXTRACT/PSP_GAME/SYSDIR/ULUS10566_EBOOT.elf"

DECRYPTED_LIBFONT="$ISO_EXTRACT/PSP_GAME/USRDIR/DATA/MODULE/libfont.elf"

VENV="$PROJECT_ROOT/.venv"

# ============================================================
# Main bootstrap
# ============================================================

echo
echo "============================================================"
echo " Dissidia 012 Decompilation Bootstrap"
echo "============================================================"
echo

# ------------------------------------------------------------
# 1. Setup
# ------------------------------------------------------------

echo "[1/8] Preparing development environment..."

"$PROJECT_ROOT/setup.sh"

source "$VENV/bin/activate"

export PSPDEV="${PSPDEV:-$HOME/pspdev}"
export PATH="$PSPDEV/bin:$PATH"

ok "Development environment ready."

# ------------------------------------------------------------
# 2. Directories
# ------------------------------------------------------------

echo
echo "[2/8] Creating project directories..."

mkdir -p "$ISO_DIR"
mkdir -p "$ISO_EXTRACT"
mkdir -p "$PROJECT_ROOT/Extract"
mkdir -p "$PROJECT_ROOT/DisasmResult"

ok "Directories created."

# ------------------------------------------------------------
# 3. Copy ISO
# ------------------------------------------------------------

echo
echo "[3/8] Copying ISO..."

if [ "$(realpath "$ISO_SOURCE")" != "$(realpath "$ISO_DEST" 2>/dev/null || true)" ]; then
    cp "$ISO_SOURCE" "$ISO_DEST"
fi

ok "ISO copied."

# ------------------------------------------------------------
# 4. Extract ISO
# ------------------------------------------------------------

echo
echo "[4/8] Extracting ISO..."

NEED_EXTRACTION=true

if [ -f "$ISO_EXTRACT/PSP_GAME/PARAM.SFO" ]; then

    echo
    echo "An extracted ISO environment was already found at:"
    echo "    $ISO_EXTRACT"
    echo
    echo "Options:"
    echo "    [s] Skip extraction and keep existing files"
    echo "    [c] Clean extracted folder and re-extract"
    echo

    read -r -p "Choice [s/c] (default: s): " EXTRACT_CHOICE

    case "${EXTRACT_CHOICE:-s}" in
        c|C)
            info "Cleaning existing extracted files..."
            rm -rf "$ISO_EXTRACT"
            mkdir -p "$ISO_EXTRACT"
            ;;
        s|S|*)
            info "Skipping ISO extraction."
            NEED_EXTRACTION=false
            ;;
    esac

fi

if [ "$NEED_EXTRACTION" = true ]; then

    info "Extracting ISO contents..."

    7z x \
        "$ISO_DEST" \
        "-o$ISO_EXTRACT" \
        -y

fi

if [ ! -f "$ISO_EXTRACT/PSP_GAME/PARAM.SFO" ]; then
    error "ISO extraction failed."
fi

ok "ISO extracted."

# ------------------------------------------------------------
# 5. Validate game
# ------------------------------------------------------------

echo
echo "[5/8] Validating game..."

EBOOT="$ISO_EXTRACT/PSP_GAME/SYSDIR/EBOOT.BIN"

if [ ! -f "$EBOOT" ]; then
    error "EBOOT.BIN was not found."
fi

if [ ! -d "$ISO_EXTRACT/PSP_GAME/USRDIR/DATA" ]; then
    error "PSP_GAME/USRDIR/DATA was not found."
fi

ok "Game structure detected."

# ------------------------------------------------------------
# 6. PPSSPP
# ------------------------------------------------------------

echo
echo "[6/8] Checking PPSSPP decrypted files..."
echo

if [ ! -f "$DECRYPTED_EBOOT" ]; then

    echo "The decrypted EBOOT has not been found."
    echo
    echo "Please launch PPSSPP on Windows and generate the"
    echo "decrypted EBOOT using Developer Tools."
    echo
    echo "Expected:"
    echo
    echo "    $DECRYPTED_EBOOT"
    echo

    read -r -p "Press ENTER when the file is ready..."

fi

if [ ! -f "$DECRYPTED_EBOOT" ]; then
    error "Decrypted EBOOT not found."
fi

ok "Decrypted EBOOT found."

# ------------------------------------------------------------
# Modules (libfont & libsuppreacc)
# ------------------------------------------------------------

MODULES=("libfont" "libsuppreacc")

for MODULE in "${MODULES[@]}"; do
    PRX_SRC="$ISO_EXTRACT/PSP_GAME/USRDIR/DATA/MODULE/${MODULE}.prx"
    ELF_DEST="$ISO_EXTRACT/PSP_GAME/USRDIR/DATA/MODULE/${MODULE}.elf"
    ALT_PRX="$ISO_EXTRACT/PSP_GAME/USRDIR/DATA/MODULE/ULUS10566_$(echo "$MODULE" | tr '[:lower:]' '[:upper:]').PRX"

    if [ ! -f "$ELF_DEST" ] && [ -f "$ALT_PRX" ]; then
        info "Found alternate file $(basename "$ALT_PRX"), using it as ${MODULE}.elf..."
        cp "$ALT_PRX" "$ELF_DEST"
    fi

    if [ ! -f "$ELF_DEST" ] && [ "$MODULE" = "libsuppreacc" ] && [ -f "$PRX_SRC" ]; then
        info "libsuppreacc is unencrypted, converting directly to elf..."
        cp "$PRX_SRC" "$ELF_DEST"
    fi

    if [ ! -f "$ELF_DEST" ] && [ -f "$PRX_SRC" ]; then
        info "Attempting to decrypt ${MODULE}.prx..."
        
        if command -v prxdecompress >/dev/null 2>&1; then
            prxdecompress "$PRX_SRC" "$ELF_DEST" 2>/dev/null || true
        elif command -v prxdec >/dev/null 2>&1; then
            prxdec "$PRX_SRC" "$ELF_DEST" 2>/dev/null || true
        elif command -v pspdecrypt >/dev/null 2>&1; then
            pspdecrypt -o "$ELF_DEST" "$PRX_SRC" 2>/dev/null || true
        fi
    fi

    # 4. Validation finale
    if [ ! -f "$ELF_DEST" ]; then
        echo
        echo "The decrypted ${MODULE}.elf has not been found."
        echo
        echo "Expected:"
        echo "    $ELF_DEST"
        echo
        echo "Press ENTER once ${MODULE}.elf is ready, or type 's' to skip..."
        echo

        read -r -p "Choice [Enter/s]: " MODULE_CHOICE

        if [ "$MODULE_CHOICE" = "s" ] || [ "$MODULE_CHOICE" = "S" ]; then
            info "Skipping ${MODULE} check."
        elif [ ! -f "$ELF_DEST" ]; then
            error "Decrypted ${MODULE} not found."
        else
            ok "Decrypted ${MODULE} found."
        fi
    else
        ok "Decrypted ${MODULE} found."
    fi
done

# ------------------------------------------------------------
# 7. package.bin
# ------------------------------------------------------------

echo
echo "[7/8] Extracting package.bin..."

NEED_PACKAGE_EXTRACT=true
EXTRACTED_PKG_DIR="$PROJECT_ROOT/Extract"

if [ -d "$EXTRACTED_PKG_DIR" ] && [ "$(ls -A "$EXTRACTED_PKG_DIR" 2>/dev/null)" ]; then

    echo
    echo "Extracted package files were already found at:"
    echo "    $EXTRACTED_PKG_DIR"
    echo
    echo "Options:"
    echo "    [s] Skip package.bin extraction and keep existing files"
    echo "    [c] Clean extracted folder and re-extract"
    echo

    read -r -p "Choice [s/c] (default: s): " PKG_CHOICE

    case "${PKG_CHOICE:-s}" in
        c|C)
            info "Cleaning existing extracted package files..."
            rm -rf "$EXTRACTED_PKG_DIR"
            mkdir -p "$EXTRACTED_PKG_DIR"
            ;;
        s|S|*)
            info "Skipping package.bin extraction."
            NEED_PACKAGE_EXTRACT=false
            ;;
    esac

fi

if [ "$NEED_PACKAGE_EXTRACT" = true ]; then

    info "Extracting package.bin..."

    python3 \
        "$PROJECT_ROOT/Tools/PackageBinExtract/ExtractPackageBin.py"

fi

ok "package.bin extracted."

# ------------------------------------------------------------
# 8. Initial disassembly
# ------------------------------------------------------------

echo
echo "[8/8] Running initial disassembly..."

RUN_DISASM=true
DISASM_DIR="$PROJECT_ROOT/DisasmResult"

if [ -d "$DISASM_DIR" ] && [ "$(ls -A "$DISASM_DIR" 2>/dev/null)" ]; then

    echo
    echo "Disassembly results were already found at:"
    echo "    $DISASM_DIR"
    echo
    echo "Options:"
    echo "    [s] Skip disassembly and keep existing files"
    echo "    [c] Clean disassembly folder and re-disassemble"
    echo

    read -r -p "Choice [s/c] (default: s): " DISASM_CHOICE

    case "${DISASM_CHOICE:-s}" in
        c|C)
            info "Cleaning existing disassembly results..."
            rm -rf "$DISASM_DIR"
            mkdir -p "$DISASM_DIR"
            ;;
        s|S|*)
            info "Skipping disassembly."
            RUN_DISASM=false
            ;;
    esac

fi

if [ "$RUN_DISASM" = true ]; then

    info "Running disassembly..."

    make disasmOVL

fi

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