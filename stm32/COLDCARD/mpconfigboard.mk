# Comparable ../B_L475E_IOT01A

MCU_SERIES = l4
CMSIS_MCU = STM32L475xx
AF_FILE = boards/stm32l476_af.csv
LD_FILES = boards/$(BOARD)/layout.ld boards/common_ifs.ld
OPENOCD_CONFIG = boards/openocd_stm32l4.cfg

# see py/mpconfig.h which uses this var if set
#INC += -DMP_CONFIGFILE=\"boards/$(BOARD)/ckcc-port.h\"

# need the CDC inf file to be built before this file
initfs.c: $(GEN_CDCINF_HEADER)

# NgU and uQR libraries
NGU_NEEDS_CIFRA = 1
USER_C_MODULES = boards/$(BOARD)/c-modules

# the bulk of the COLDCARD-specific code
# - do not want contents of stm32/boards/manifest.py
FROZEN_MANIFEST = \
					boards/$(BOARD)/shared/manifest.py \
					boards/$(BOARD)/shared/manifest_mk3.py

# This will relocate things up by 32k=0x8000
# see also ./layout.ld
CFLAGS_MOD += -DVECT_TAB_OFFSET=0x8000
TEXT0_ADDR = 0x08008000
TEXT1_ADDR = 0x0800C000

# don't want any of these: soft_spi, soft_qspi, dht
#DRIVERS_SRC_C -= drivers/bus/softspi.c \
#	drivers/bus/softqspi.c drivers/memory/spiflash.c \
#	drivers/dht/dht.c

# Approximately all the source code files?
ALL_SRC = $(SRC_LIB) $(SRC_LIBM) $(EXTMOD_SRC_C) $(DRIVERS_SRC_C) \
			 $(SRC_HAL) $(SRC_USBDEV) $(SRC_MOD)
ALL_SRC += $(addprefix ports/stm32/, $(SRC_C))
ALL_SRC += py/*.[ch]

# XXX: this barely works, ignore errors
tags:
	echo $(ALL_SRC)
	(cd $(TOP)/../..; pwd; ctags -R -f .tags $(addprefix external/micropython/, $(ALL_SRC)) \
				external/micropython/lib/stm32lib/STM32L4xx_HAL_Driver/*/*.[ch] \
				external/micropython/lib/stm32lib/CMSIS/STM32L4xx/Include/stm32l475xx.h \
				external/micropython/lib/cmsis/inc/core_cm4.h \
				external/micropython/ports/stm32/*.[ch] \
				external/micropython/ports/stm32/*/*.[ch] \
				external/micropython/ports/stm32/usbdev/{core,class}/{src,inc}/*.[ch] \
				external/libngu/ngu/*.[ch])
	sed -i .tmp '/dynruntime./d' $(TOP)/../../.tags


checksum:
	$(OBJCOPY) -O binary -j .isr_vector -j .text -j .data \
						--pad-to 0x080e0000 --gap-fill 0xff \
						$(BUILD)/firmware.elf $(BUILD)/firmware-complete.bin
	shasum -a 256 $(BUILD)/firmware-complete.bin

# This costs about 241,136 of flash! Not clear on what I gain.
# It enables -O0 instead of -Os!! Very bad.
#DEBUG = 1

# we always want debug symbols, since they get stripped anyway
COPT += -g

# bugfix IIRC
build-COLDCARD/boards/COLDCARD/modckcc.o: COPT = -O0 -DNDEBUG

files:
	# SRC_C: $(SRC_C)
	@echo
	# SRC_HAL: $(SRC_HAL)
	@echo
	# CFLAGS: $(CFLAGS)
	@echo
	# FROZEN_MANIFEST: $(FROZEN_MANIFEST)
