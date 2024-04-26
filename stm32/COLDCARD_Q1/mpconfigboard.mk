# Config for our board.
#
MCU_SERIES = l4
CMSIS_MCU = STM32L4S5xx
AF_FILE = boards/$(BOARD)/stm32l4s5_af.csv
LD_FILES = boards/$(BOARD)/layout.ld boards/common_ifs.ld
OPENOCD_CONFIG = boards/openocd_stm32l4.cfg

# MicroPython settings
MICROPY_VFS_LFS2 = 1
MICROPY_VFS_FAT = 1

# see py/mpconfig.h which uses this var if set
CFLAGS_EXTRA += -DMP_CONFIGFILE=\"boards/$(BOARD)/ckcc-port.h\"
CFLAGS_EXTRA += -DCOLDCARD_DEBUG=$(DEBUG_BUILD)

# NgU and uQR libraries
NGU_NEEDS_CIFRA = 1
USER_C_MODULES = boards/$(BOARD)/c-modules

# the bulk of the COLDCARD-specific code
# - do not want contents of stm32/boards/manifest.py
FROZEN_MANIFEST =  \
					boards/$(BOARD)/shared/manifest.py \
					boards/$(BOARD)/shared/manifest_q1.py

# This will relocate things up by 128k=0x2_0000
# see also ./layout.ld
CFLAGS_MOD += -DVECT_TAB_OFFSET=0x20000
TEXT0_ADDR = 0x08020000
TEXT1_ADDR = 0x08024000

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
build-COLDCARD_Q1/boards/COLDCARD_Q1/modckcc.o: COPT = -O0 -DNDEBUG

# pickiness
build-COLDCARD_Q1/dma.o: COPT=-Werror=unused-const-variable=0
build-COLDCARD_Q1/boards/COLDCARD_Q1/psramdisk.o: COPT=-Werror=unused-const-variable=0

# bugfix: remove unwanted setup code called from ports/stm32/resethandler.s
build-COLDCARD_Q1/lib/stm32lib/CMSIS/STM32L4xx/Source/Templates/system_stm32l4xx.o: \
	CFLAGS += -DSystemInit=SystemInit_OMIT

# bugfix: replace keyboard interrupt handling
build-COLDCARD_Q1/lib/utils/interrupt_char.o: \
	CFLAGS += -Dmp_hal_set_interrupt_char=mp_hal_set_interrupt_char_OMIT

# bugfix: leave my LED's alone
build-COLDCARD_Q1/flashbdev.o: CFLAGS += -Dled_state=led_state_OMIT
build-COLDCARD_Q1/spibdev.o: CFLAGS += -Dled_state=led_state_OMIT
build-COLDCARD_Q1/factoryreset.o: CFLAGS += -Dled_state=led_state_OMIT
build-COLDCARD_Q1/boardctrl.o: CFLAGS += -Dled_state=led_state_OMIT


files:
	# SRC_C: $(SRC_C)
	@echo
	# SRC_HAL: $(SRC_HAL)
	@echo
	# CFLAGS: $(CFLAGS)
	@echo
	# FROZEN_MANIFEST: $(FROZEN_MANIFEST)
