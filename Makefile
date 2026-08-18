# ============================================================
# Dissidia 012 Decompilation Makefile
# ============================================================

SHELL := /bin/bash

PROJECT_ROOT := $(CURDIR)

# ============================================================
# PSPDEV
# ============================================================

PSPDEV ?= $(HOME)/pspdev

PSPSDK := $(PSPDEV)/psp/sdk

export PSPDEV
export PATH := $(PSPDEV)/bin:$(PATH)

CC      := $(PSPDEV)/bin/psp-gcc
OBJDUMP := $(PSPDEV)/bin/psp-objdump

CFLAGS  := -O2 -G0 -Wall -I$(PSPSDK)/include
LDFLAGS := -L$(PSPSDK)/lib

# ============================================================
# Python tools
# ============================================================

VENV := $(PROJECT_ROOT)/.venv/bin

SPIMDISASM := $(VENV)/spimdisasm

# ============================================================
# Game
# ============================================================

ISO_ROOT := $(PROJECT_ROOT)/PlaceYourIsoHere/Extracted_Iso

EBOOT := $(ISO_ROOT)/PSP_GAME/SYSDIR/ULUS10566_EBOOT.elf

LIBFONT := $(ISO_ROOT)/PSP_GAME/USRDIR/DATA/MODULE/libfont.elf

# ============================================================
# Output
# ============================================================

DISASM_ROOT := $(PROJECT_ROOT)/DisasmResult

# ============================================================
# Default
# ============================================================

.PHONY: all

all:
	@echo
	@echo "Dissidia 012 Decompilation Project"
	@echo
	@echo "Available targets:"
	@echo
	@echo "  make package"
	@echo "  make disasmOVL"
	@echo "  make check"
	@echo "  make clean"
	@echo

# ============================================================
# C compilation
# ============================================================

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.asm: %.o
	$(OBJDUMP) -d $< > $@

# ============================================================
# Validation
# ============================================================

.PHONY: check

check:
	@test -x "$(CC)" || \
		{ echo "ERROR: psp-gcc not found."; exit 1; }

	@test -x "$(OBJDUMP)" || \
		{ echo "ERROR: psp-objdump not found."; exit 1; }

	@test -x "$(SPIMDISASM)" || \
		{ echo "ERROR: spimdisasm not found."; exit 1; }

	@test -f "$(EBOOT)" || \
		{ echo "ERROR: decrypted EBOOT not found:"; echo "  $(EBOOT)"; exit 1; }

	@test -f "$(LIBFONT)" || \
		{ echo "ERROR: decrypted libfont not found:"; echo "  $(LIBFONT)"; exit 1; }

	@echo "Environment OK."

# ============================================================
# package.bin
# ============================================================

.PHONY: package

package:
	python3 ./Tools/PackageBinExtract/ExtractPackageBin.py

# ============================================================
# Disassembly
# ============================================================

.PHONY: disasmOVL

disasmOVL: check

	@mkdir -p "$(DISASM_ROOT)/OVL_BATTLE_ELF"
	@mkdir -p "$(DISASM_ROOT)/OVL_MENU_ELF"
	@mkdir -p "$(DISASM_ROOT)/OVL_EXTRA_ELF"
	@mkdir -p "$(DISASM_ROOT)/MODULE"

	@echo
	@echo "Disassembling OVL_BATTLE_APP..."
	$(SPIMDISASM) elfObjDisasm \
		"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_BATTLE_APP.ELF" \
		"$(DISASM_ROOT)/OVL_BATTLE_ELF/"

	@echo
	@echo "Disassembling OVL_MENU_APP..."
	$(SPIMDISASM) elfObjDisasm \
		"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_MENU_APP.ELF" \
		"$(DISASM_ROOT)/OVL_MENU_ELF/"

	@echo
	@echo "Disassembling OVL_EXTRA_APP..."
	$(SPIMDISASM) elfObjDisasm \
		"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_EXTRA_APP.ELF" \
		"$(DISASM_ROOT)/OVL_EXTRA_ELF/"

	@echo
	@echo "Disassembling EBOOT..."
	$(SPIMDISASM) elfObjDisasm \
		"$(EBOOT)" \
		"$(DISASM_ROOT)/"

	@echo
	@echo "Disassembling LIBSUPPREACC..."
	$(SPIMDISASM) elfObjDisasm \
		"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/MODULE/LIBSUPPREACC.PRX" \
		"$(DISASM_ROOT)/MODULE/"

	@echo
	@echo "Disassembling libfont..."
	$(SPIMDISASM) elfObjDisasm \
		"$(LIBFONT)" \
		"$(DISASM_ROOT)/MODULE/"

	@echo
	@echo "Disassembly complete."

# ============================================================
# Clean
# ============================================================

.PHONY: clean

clean:
	rm -f *.o *.asm