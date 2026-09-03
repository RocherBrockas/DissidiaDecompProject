# ============================================================
# Dissidia 012 Decompilation Makefile
# ============================================================

SHELL := /bin/bash

PROJECT_ROOT := $(CURDIR)

# ============================================================
# PSPDEV & Tools
# ============================================================

PSPDEV ?= $(HOME)/pspdev
PSPSDK := $(PSPDEV)/psp/sdk

export PSPDEV
export PATH := $(PSPDEV)/bin:$(PATH)

CC      := $(PSPDEV)/bin/psp-gcc
AS      := $(PSPDEV)/bin/psp-as
LD      := $(PSPDEV)/bin/psp-gcc
OBJDUMP := $(PSPDEV)/bin/psp-objdump

CFLAGS  := -O2 -G0 -Wall -I$(PSPSDK)/include
ASFLAGS := -march=allegrex -mabi=eabi -mgp32 -EL
LDFLAGS := -L$(PSPSDK)/lib

# ============================================================
# Python & Decomp Tools
# ============================================================

VENV := $(PROJECT_ROOT)/.venv/bin
SPIMDISASM := $(VENV)/spimdisasm

# ============================================================
# Directories & Files
# ============================================================

ISO_ROOT     := $(PROJECT_ROOT)/PlaceYourIsoHere/Extracted_Iso
EBOOT        := $(ISO_ROOT)/PSP_GAME/SYSDIR/ULUS10566_EBOOT.elf
LIBFONT      := $(ISO_ROOT)/PSP_GAME/USRDIR/DATA/MODULE/libfont.elf

DISASM_ROOT  := $(PROJECT_ROOT)/DisasmResult
BUILD_DIR    := $(PROJECT_ROOT)/build
ASM_DIR      := $(PROJECT_ROOT)/asm
ISO_OUT      := $(PROJECT_ROOT)/Dissidia012_Rebuilt.iso

# Collect ASM sources if they exist
ASM_SRCS     := $(shell find $(ASM_DIR) -type f -name "*.s" 2>/dev/null)
OBJ_FILES    := $(patsubst $(ASM_DIR)/%.s, $(BUILD_DIR)/%.o, $(ASM_SRCS))

# ============================================================
# Default Target
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
	@echo "  make build_eboot"
	@echo "  make iso"
	@echo "  make clean"
	@echo

# ============================================================
# C / ASM compilation
# ============================================================

$(BUILD_DIR)/%.o: $(ASM_DIR)/%.s
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

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

	@if [ ! -f "$(LIBFONT)" ]; then \
		echo "WARNING: decrypted libfont not found ($(LIBFONT)). Skipping its verification."; \
	fi

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

	@if [ -f "$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_BATTLE_APP.ELF" ]; then \
		echo ""; \
		echo "Disassembling OVL_BATTLE_APP..."; \
		$(SPIMDISASM) elfObjDisasm \
			"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_BATTLE_APP.ELF" \
			"$(DISASM_ROOT)/OVL_BATTLE_ELF/"; \
	fi

	@if [ -f "$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_MENU_APP.ELF" ]; then \
		echo ""; \
		echo "Disassembling OVL_MENU_APP..."; \
		$(SPIMDISASM) elfObjDisasm \
			"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_MENU_APP.ELF" \
			"$(DISASM_ROOT)/OVL_MENU_ELF/"; \
	fi

	@if [ -f "$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_EXTRA_APP.ELF" ]; then \
		echo ""; \
		echo "Disassembling OVL_EXTRA_APP..."; \
		$(SPIMDISASM) elfObjDisasm \
			"$(ISO_ROOT)/PSP_GAME/USRDIR/DATA/OVL_EXTRA_APP.ELF" \
			"$(DISASM_ROOT)/OVL_EXTRA_ELF/"; \
	fi

	@echo ""
	@echo "Disassembling EBOOT..."
	@$(SPIMDISASM) elfObjDisasm \
		"$(EBOOT)" \
		"$(DISASM_ROOT)/"

	@echo ""
	@SUPPREACC_FILE=$$(ls $(ISO_ROOT)/PSP_GAME/USRDIR/DATA/MODULE/*suppreacc* 2>/dev/null | head -n 1); \
	if [ -f "$$SUPPREACC_FILE" ]; then \
		if head -c 4 "$$SUPPREACC_FILE" | grep -q "ELF"; then \
			echo "Disassembling LIBSUPPREACC..."; \
			$(SPIMDISASM) elfObjDisasm "$$SUPPREACC_FILE" "$(DISASM_ROOT)/MODULE/"; \
		else \
			echo "Skipping LIBSUPPREACC (Not a valid decrypted ELF)."; \
		fi; \
	fi

	@echo ""
	@if [ -f "$(LIBFONT)" ]; then \
		if head -c 4 "$(LIBFONT)" | grep -q "ELF"; then \
			echo "Disassembling libfont..."; \
			$(SPIMDISASM) elfObjDisasm "$(LIBFONT)" "$(DISASM_ROOT)/MODULE/"; \
		else \
			echo "Skipping libfont (Not a valid decrypted ELF file)."; \
		fi; \
	else \
		echo "Skipping libfont (file not found)."; \
	fi

	@echo ""
	@echo "Disassembly complete."

# ============================================================
# ELF Re-compilation
# ============================================================

.PHONY: build_eboot

build_eboot:
	@mkdir -p "$(BUILD_DIR)"
	@if [ -n "$(OBJ_FILES)" ]; then \
		echo "Linking reassembled objects..."; \
		$(LD) $(OBJ_FILES) -specs=$(PSPSDK)/lib/prxspecs -Wl,-q -nostartfiles -o "$(BUILD_DIR)/ULUS10566_EBOOT.elf"; \
	elif [ -f "$(EBOOT)" ]; then \
		echo "No ASM sources found in asm/. Using base decrypted EBOOT.elf..."; \
		cp "$(EBOOT)" "$(BUILD_DIR)/ULUS10566_EBOOT.elf"; \
	else \
		echo "ERROR: No decrypted EBOOT found to build."; exit 1; \
	fi

# ============================================================
# Generation ISO
# ============================================================

.PHONY: iso

iso: build_eboot
	@if command -v mkisofs >/dev/null 2>&1 || command -v genisoimage >/dev/null 2>&1; then \
		ISO_CMD=$$(command -v mkisofs || command -v genisoimage); \
		echo "Copying EBOOT to ISO structure..."; \
		cp "$(BUILD_DIR)/ULUS10566_EBOOT.elf" "$(ISO_ROOT)/PSP_GAME/SYSDIR/EBOOT.BIN"; \
		echo "Building ISO image..."; \
		$$ISO_CMD -sysid "PSP" \
			-A "PSP GAME" \
			-V "DISSIDIA012" \
			-iso-level 4 \
			-o "$(ISO_OUT)" \
			"$(ISO_ROOT)"; \
		echo "ISO successfully generated: $(ISO_OUT)"; \
	else \
		echo "ERROR: Neither mkisofs nor genisoimage is installed. Run 'sudo apt install genisoimage'."; \
		exit 1; \
	fi

# ============================================================
# Clean
# ============================================================

.PHONY: clean

clean:
	rm -rf $(BUILD_DIR) *.o *.asm