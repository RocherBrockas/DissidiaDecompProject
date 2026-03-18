# Makefile
PSPDEV ?= /c/pspdev
PSPSDK = $(PSPDEV)/psp/sdk

CC      = psp-gcc
CFLAGS  = -O2 -G0 -Wall -I$(PSPSDK)/include
LDFLAGS = -L$(PSPSDK)/lib

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Désassemble pour comparer avec Ghidra
%.asm: %.o
	psp-objdump -d $< > $@

disasm-install:
	sudo apt-get install python3-pip
	python3 -m pip install -U spimdisasm
	python3 -m pip install -U splat64[mips]

disasmOVL: disasm-install
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_BATTLE_APP.ELF ./DisasmResult/OVL_BATTLE_ELF/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_MENU_APP.ELF ./DisasmResult/OVL_MENU_ELF/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_EXTRA_APP.ELF ./DisasmResult/OVL_EXTRA_ELF/

clean:
	rm -f *.o *.asm