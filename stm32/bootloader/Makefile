#
# "Bootloader" Makefile
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

PYTHON_DFU = python ../../external/micropython/tools/dfu.py
PYTHON_PYDFU = python ../../external/micropython/tools/pydfu.py

# Basename of all targets
TARGET_NAME = bootloader

# Source files. Important: Add them also to link-script.ld to control placement.
OBJS += startup.o assets/screens.o
OBJS += enable.o dispatch.o verify.o oled.o clocks.o storage.o constant_time.o rng.o ae.o
OBJS += delay.o gpio.o pins.o version.o sflash.o
OBJS += stm32l4xx_hal_firewall.o stm32l4xx_hal_gpio.o stm32l4xx_hal_spi.o
OBJS += stm32l4xx_hal_rcc.o stm32l4xx_hal_rcc_ex.o
OBJS += sha256.o micro-ecc/uECC.o

#OBJS = $(addsuffix .o, $(basename $(C_SRCS) $(ASM_SRCS)))

# Turn off some suprious warnings
micro-ecc/uECC.o: c_flags += -Wno-undef -Wno-redundant-decls

# Headers for chip stuff (assumes STM32L476 chip)
STM32LIB_PATH = ../../external/micropython/lib

# Where we will end up in the memory map (at start of flash)
BL_FLASH_BASE = 0x08000000
BL_FLASH_SIZE = 0x7800
BL_FLASH_LAST = 0x08007800

# Top 8k of SRAM2 is reserved for us.
# We wipe whole thing before and after using it. 
# - highest 1k page set for write-protect (but not secret)
BL_SRAM_BASE = 0x10006000
BL_SRAM_SIZE = 0x00001c00

# Final 2k bytes reserved for data (not code)
# - must be page-aligned, contains pairing secret
BL_NVROM_BASE = 0x08007800
BL_NVROM_SIZE = 0x800

# Compiler flags.
CFLAGS = -I. -Wall --std=gnu99 -Os -g3 \
			-mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mtune=cortex-m4 \
			-ffunction-sections -fdata-sections \
			-mcpu=cortex-m4 -DMCU_SERIES_L4 -DSTM32L475xx

# -flto -fdata-sections -ffunction-sections -funsigned-char -funsigned-bitfields 

# Pass in the locations of stuff
CFLAGS += -D BL_FLASH_BASE=$(BL_FLASH_BASE) -D BL_FLASH_SIZE=$(BL_FLASH_SIZE)
CFLAGS += -D BL_NVROM_BASE=$(BL_NVROM_BASE) -D BL_NVROM_SIZE=$(BL_NVROM_SIZE)
CFLAGS += -D BL_SRAM_BASE=$(BL_SRAM_BASE) -D BL_SRAM_SIZE=$(BL_SRAM_SIZE) 

# Header file search path
INC_PATHS = $(STM32LIB_PATH)/stm32lib/CMSIS/STM32L4xx/Include \
			$(STM32LIB_PATH)/stm32lib/STM32L4xx_HAL_Driver/Inc \
			$(STM32LIB_PATH)/cmsis/inc

CFLAGS += $(foreach INC,$(INC_PATHS),-I$(INC))

# Specialized linker-script here. Not the standard one!
#
LINKER_SCRIPT = link-script.ld

LDFLAGS += -flto -Wl,--gc-sections --specs=nano.specs -Wl,-T$(LINKER_SCRIPT)
LDFLAGS += -nostartfiles
LDFLAGS += -Wl,--defsym,BL_FLASH_BASE=$(BL_FLASH_BASE)
LDFLAGS += -Wl,--defsym,BL_FLASH_SIZE=$(BL_FLASH_SIZE)
LDFLAGS += -Wl,--defsym,BL_NVROM_BASE=$(BL_NVROM_BASE)
LDFLAGS += -Wl,--defsym,BL_NVROM_SIZE=$(BL_NVROM_SIZE)
LDFLAGS += -Wl,--defsym,BL_SRAM_BASE=$(BL_SRAM_BASE)
LDFLAGS += -Wl,--defsym,BL_SRAM_SIZE=$(BL_SRAM_SIZE)
LDFLAGS += -Wl,-Map=$(TARGET_NAME).map

ASFLAGS += -Wa,--defsym,BL_FLASH_BASE=$(BL_FLASH_BASE) -Wa,--defsym,BL_FLASH_SIZE=$(BL_FLASH_SIZE)
ASFLAGS += -Wa,--defsym,BL_SRAM_BASE=$(BL_SRAM_BASE) -Wa,--defsym,BL_SRAM_SIZE=$(BL_SRAM_SIZE)


TARGET_ELF = $(TARGET_NAME).elf
TARGETS = $(TARGET_NAME).lss $(TARGET_NAME).bin $(TARGET_NAME).sym $(TARGET_NAME).dfu
TARGETS += sigheader.py

all: $(TARGETS)

# recompile on any change, because with a small project like this...
$(OBJS): Makefile

$(TARGETS): $(TARGET_ELF) Makefile

sigheader.py: sigheader.h mk-sigheader.py
	python3 mk-sigheader.py

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
	$(OBJCOPY) -O binary --pad-to $(BL_FLASH_LAST) --gap-fill 0xff $< $@.tmp
	dd bs=30720 count=1 if=$@.tmp of=$@

# dfu packaged file
%.dfu: %.bin
	$(PYTHON_DFU) -b $(BL_FLASH_BASE):$< $@

assets/screens.c: assets/Makefile assets/*.png assets/convert.py
	(cd assets; $(MAKE))


# some hard to generate bits...
ae.o: ae_config.h

ae_config.h: keylayout.py secel_config.py
	python3 ./keylayout.py

dfu-slow: $(TARGET_NAME).dfu
	dfu-util -d 0483:df11 -a 0 -D $<

dfu: $(TARGET_NAME).dfu
	$(PYTHON_PYDFU) -u $<

dfu2:
	$(PYTHON_PYDFU) -u $(TARGET_NAME).dfu

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
DELIVERABLES = $(TARGET_NAME).dfu $(TARGET_NAME).bin $(TARGET_NAME).lss

checksums.txt: $(DELIVERABLES)
	shasum -a 256 $(DELIVERABLES) > $@

# Track released versions
.PHONY: capture
capture: version.txt version-full.txt $(DELIVERABLES) checksums.txt
	V=`cat version.txt` && cat checksums.txt > releases/$$V.txt && cat version-full.txt >> releases/$$V.txt && mkdir -p releases/$$V; cp $(DELIVERABLES) releases/$$V
	@echo
	@echo "      Version: " `cat version.txt`
	@echo
	V=`cat version.txt` && git tag -am "Bootloader version $$V" "bootloader-"$$V
	git add -f releases/*/bootloader.*

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
version.o: Makefile


clean:
	$(RM) $(OBJS)

clobber: clean
	$(RM) $(TARGETS)

debug:
	@echo CFLAGS = $(CFLAGS)
	@echo 
	@echo OBJS = $(OBJS)

tags:
	ctags -f .tags *.[ch] -R $(INC_PATHS) $(STM32LIB_PATH)/stm32lib/STM32L4xx_HAL_Driver/*/*.[ch] \
