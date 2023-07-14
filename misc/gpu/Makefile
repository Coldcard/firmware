# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Makefile for Q1's GPU co-processor.
#
# Targets:
#	all - make everything, look for dafu.elf inparticular
#	clean - delete intermediates
#	clobber - delete all build products
#

# Toolchain
TOOLCHAIN = arm-none-eabi-
CC = $(TOOLCHAIN)gcc
OBJDUMP = $(TOOLCHAIN)objdump
OBJCOPY = $(TOOLCHAIN)objcopy
NM = $(TOOLCHAIN)nm
SIZE = $(TOOLCHAIN)size

# Basename of all targets
TARGET_NAME = gpu

# Source files, listed here as the object files they will become.
OBJS += startup.o
OBJS += main.o version.o
OBJS += stm32c0xx_hal.o system_stm32c0xx.o interrupts.o

# Have to have copies of these because the DMA and interrupt stuff
# needs to be commented-out.
#OBJS += stm32l4xx_hal_gpio.o stm32l4xx_hal_spi.o
#OBJS += stm32l4xx_hal_rcc.o stm32l4xx_hal_rcc_ex.o

# Where we will end up in the memory map (at start of flash)
GPU_FLASH_BASE = 0x08000000
GPU_FLASH_SIZE = 0x4000
GPU_FLASH_LAST = 0x08004000

# Use all of 6k of SRAM...
GPU_SRAM_BASE = 0x20000000
GPU_SRAM_SIZE = 0x00001800

# Compiler flags.
CFLAGS = -I. -Wall --std=gnu99 -Os -g3 \
			-mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=soft -mtune=cortex-m0 \
			-ffunction-sections -fdata-sections \
			-mcpu=cortex-m0 -DMCU_SERIES_C0 -DSTM32C011xx 
#-DUSE_HAL_DRIVER

# Pass in the locations of stuff
CFLAGS += -D GPU_FLASH_BASE=$(GPU_FLASH_BASE) -D GPU_FLASH_SIZE=$(GPU_FLASH_SIZE)
CFLAGS += -D GPU_SRAM_BASE=$(GPU_SRAM_BASE) -D GPU_SRAM_SIZE=$(GPU_SRAM_SIZE) 

# Header file search path
INC_PATHS = external/cmsis_device_c0/Include \
			external/stm32c0xx_hal_driver/Inc \
			../../external/micropython/lib/cmsis/inc

CFLAGS += $(foreach INC,$(INC_PATHS),-I$(INC))

# Specialized linker-script here. Not the standard one!
#
LINKER_SCRIPT = link-script.ld
LDFLAGS += -Wl,-T$(LINKER_SCRIPT)

#LDFLAGS += -flto -Wl,--gc-sections --specs=nano.specs
LDFLAGS += -fpic -Wl,--gc-sections --specs=nano.specs
LDFLAGS += -Wl,--defsym,GPU_FLASH_BASE=$(GPU_FLASH_BASE)
LDFLAGS += -Wl,--defsym,GPU_FLASH_SIZE=$(GPU_FLASH_SIZE)
LDFLAGS += -Wl,--defsym,GPU_SRAM_BASE=$(GPU_SRAM_BASE)
LDFLAGS += -Wl,--defsym,GPU_SRAM_SIZE=$(GPU_SRAM_SIZE)
LDFLAGS += -Wl,-Map=$(TARGET_NAME).map

ASFLAGS += -Wa,--defsym,GPU_FLASH_BASE=$(GPU_FLASH_BASE) -Wa,--defsym,GPU_FLASH_SIZE=$(GPU_FLASH_SIZE)
ASFLAGS += -Wa,--defsym,GPU_SRAM_BASE=$(GPU_SRAM_BASE) -Wa,--defsym,GPU_SRAM_SIZE=$(GPU_SRAM_SIZE)


TARGET_ELF = $(TARGET_NAME).elf
TARGETS = $(TARGET_NAME).lss $(TARGET_NAME).bin $(TARGET_NAME).sym

all: $(TARGETS)

# recompile on any Makefile change, because with a small project like this...
$(OBJS): Makefile
$(TARGETS): $(TARGET_ELF) Makefile

# link step
$(TARGET_ELF): $(OBJS) $(LINKER_SCRIPT) Makefile
	$(CC) $(CFLAGS) -o $(TARGET_ELF) $(LDFLAGS) $(OBJS)
	$(SIZE) -Ax $@

# detailed listing, very handy
%.lss: $(TARGET_ELF)
	$(OBJDUMP) -h -S $< > $@

# symbol dump, meh
%.sym: $(TARGET_ELF)
	$(NM) -n $< > $@

# raw binary, forced to right size, pad w/ 0xff
%.bin: $(TARGET_ELF)
	$(OBJCOPY) -O binary --pad-to $(GPU_FLASH_LAST) --gap-fill 0xff $< $@.tmp
	dd bs=$(shell printf "%d" $(GPU_FLASH_SIZE)) count=1 if=$@.tmp of=$@

# assumes openocd running from current directory
up:
	echo 'flash write_image $(TARGET_ELF)' | nc localhost 4444

# make a 'release' build
release: code-committed clean all capture
release: CFLAGS += -DRELEASE=1 -Werror

.PHONY: code-committed
code-committed:
	@echo ""
	@echo "Are all changes commited already?"
	git diff --stat --exit-code .
	@echo '... yes'

# these files are what we capture and store for each release.
DELIVERABLES = $(TARGET_NAME).bin $(TARGET_NAME).lss

checksums.txt: $(DELIVERABLES)
	shasum -a 256 $(DELIVERABLES) > $@

# Track released versions
.PHONY: capture
capture: version.txt version-full.txt $(DELIVERABLES) checksums.txt
	V=`cat version.txt` && cat checksums.txt > releases/$$V.txt && cat version-full.txt >> releases/$$V.txt && mkdir -p releases/$$V; cp $(DELIVERABLES) releases/$$V
	@echo
	@echo "      Version: " `cat version.txt`
	@echo
	V=`cat version.txt` && git tag -am "Mk4 Bootloader version $$V" "mk4-bootloader-"$$V
	git add -f releases/*/bootloader.* releases/*.txt

# Pull out the version string from binary object (already linked in) and 
# construct a text file (version.txt) with those contents
version.txt version-full.txt: version.o Makefile
	$(OBJCOPY) -O binary -j .rodata.version_string version.o version-tmp.txt
	cat version-tmp.txt | sed -e 's/ .*//' | sed -e 's/ .*//' > version.txt
	cat version-tmp.txt | tr '\0' '\n' > version-full.txt
	@echo
	@echo "Version string: " `cat version-full.txt`
	@echo
	$(RM) version-tmp.txt

# nice version numbers.
BUILD_TIME = $(shell date '+%Y%m%d.%H%M%S')
BRANCH = $(shell git rev-parse --abbrev-ref HEAD)
SHA_VERSION = $(shell git rev-parse --short HEAD)
GIT_HASH = "$(BRANCH)@$(SHA_VERSION)"
version.o: CFLAGS += -DBUILD_TIME='"$(BUILD_TIME)"' -DGIT_HASH='$(GIT_HASH)'
version.o: Makefile version.h

clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(TARGETS)

debug:
	arm-none-eabi-gdb bootloader.elf -x gogo.gdb

xxx:
	@echo CFLAGS = $(CFLAGS)
	@echo 
	@echo OBJS = $(OBJS)

tags:
	ctags -f .tags *.[ch] -R $(INC_PATHS)

# EOF
