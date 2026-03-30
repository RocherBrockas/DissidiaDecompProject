# Makefile
PSPDEV ?= /c/pspdev
PSPSDK = $(PSPDEV)/psp/sdk

CC      = psp-gcc
CFLAGS  = -O2 -G0 -Wall -I$(PSPSDK)/include
LDFLAGS = -L$(PSPSDK)/lib

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Disasm rule
# Place your Iso in PlaceYourIsoHere and extract it with the dissidia modding suite in ./PlaceYourIsoHere/Extracted_Iso
%.asm: %.o
	psp-objdump -d $< > $@

disasm-install:
	sudo apt-get install python3-pip
	python3 -m pip install -U spimdisasm
	python3 -m pip install -U splat64[mips]

#Launch PPSSPP once and use developper tools to dump ISO and PRX files, you should dump decrypted Eboot.elf and Libfont.prx, place them near their crypted equivalent
disasmOVL: disasm-install
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_BATTLE_APP.ELF ./DisasmResult/OVL_BATTLE_ELF/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_MENU_APP.ELF ./DisasmResult/OVL_MENU_ELF/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/PSP_GAME/USRDIR/DATA/OVL_EXTRA_APP.ELF ./DisasmResult/OVL_EXTRA_ELF/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/SYSDIR/ULUS10566_EBOOT.elf ./DisasmResult/
	spimdisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/USRDIR/DATA/MODULE/LIBSUPPREAC.PRX ./DisasmResult/MODULE
	spindisasm elfObjDisasm ./PlaceYourIsoHere/Extracted_Iso/USRDIR/DATA/MODULE/ULUS10566_LIBFONT.PRX ./DisasmResult/MODULE


clean:
	rm -f *.o *.asm