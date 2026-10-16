ifeq ($(PS5_PAYLOAD_SDK),)
$(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

CFLAGS := -Wall -lkernel_sys -lSceRegMgr

ELF := testpayload.elf
KILLSHELL := killshell.elf

all: $(ELF) $(KILLSHELL)

$(ELF): main.c
	$(CC) $(CFLAGS) $^ -o $@

$(KILLSHELL): killshell.c
	$(CC) -Wall -lkernel_sys $^ -o $@

clean:
	rm -f $(ELF) $(KILLSHELL)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
