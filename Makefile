# Makefile
PSPDEV ?= /c/pspdev
PSPSDK = $(PSPDEV)/psp/sdk

CC      = psp-gcc
CFLAGS  = -O2 -G0 -Wall -I$(PSPSDK)/include
LDFLAGS = -L$(PSPSDK)/lib

# Pour l'instant on compile juste en .o pour vérifier l'ASM
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Désassemble pour comparer avec Ghidra
%.asm: %.o
	psp-objdump -d $< > $@

clean:
	rm -f *.o *.asm