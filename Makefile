ifeq ($(PS5_PAYLOAD_SDK),)
$(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS := -Wall -lkernel_sys -lSceRegMgr

ELF := testpayload.elf
KILLSHELL := killshell.elf
REGDUMP := regdump.elf
SYSREGDUMP := sysregdump.elf
KEYSCAN := keyscan.elf
SHELLSCAN := shellscan.elf
DEEPSCAN := deepscan.elf
DIPSWPATCH := dipswpatch.elf
PANELSCAN := panelscan.elf
DEVKITACT := devkitact.elf

all: $(ELF) $(KILLSHELL) $(REGDUMP) $(SYSREGDUMP) $(KEYSCAN) $(SHELLSCAN) $(DEEPSCAN) $(DIPSWPATCH) $(PANELSCAN) $(DEVKITACT)

$(ELF): main.c
	$(CC) $(CFLAGS) $^ -o $@

$(KILLSHELL): killshell.c
	$(CC) -Wall -lkernel_sys $^ -o $@

$(REGDUMP): regdump.c
	$(CC) -Wall -lkernel_sys -lSceRegMgr $^ -o $@

$(SYSREGDUMP): sysregdump.c
	$(CC) -Wall -lkernel_sys $^ -o $@

$(KEYSCAN): keyscan.c
	$(CC) -Wall -lkernel_sys -lSceRegMgr $^ -o $@

$(SHELLSCAN): shellscan.c
	$(CC) -Wall -lkernel_sys $^ -o $@

$(DEEPSCAN): deepscan.c
	$(CC) -Wall -lkernel_sys -lSceRegMgr $^ -o $@

$(DIPSWPATCH): dipswpatch.c
	$(CC) -Wall -lkernel_sys -lSceRegMgr $^ -o $@

$(PANELSCAN): panelscan.c
	$(CC) -Wall -lkernel_sys $^ -o $@

$(DEVKITACT): devkitact.c
	$(CC) -Wall -lkernel_sys -lSceRegMgr $^ -o $@

clean:
	rm -f $(ELF) $(KILLSHELL) $(REGDUMP) $(SYSREGDUMP) $(KEYSCAN) $(SHELLSCAN) $(DEEPSCAN) $(DIPSWPATCH) $(PANELSCAN) $(DEVKITACT)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
