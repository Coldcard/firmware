# Comparable ../B_L475E_IOT01A

MCU_SERIES = l4
CMSIS_MCU = STM32L475xx
AF_FILE = boards/stm32l476_af.csv
LD_FILES = boards/$(BOARD)/layout.ld boards/common_ifs.ld

# see py/mpconfig.h which uses this var if set
INC += -DMP_CONFIGFILE=\"boards/$(BOARD)/ckcc-port.h\"

# need the CDC inf file to be built before this file
initfs.c: $(GEN_CDCINF_HEADER)

# crypto code
CFLAGS_MOD += -Iboards/$(BOARD)/modcryptocurrency
CFLAGS_MOD += -Iboards/$(BOARD)/crypto
SRC_MOD += $(addprefix boards/$(BOARD)/crypto/,\
				bignum.c ecdsa.c curves.c secp256k1.c nist256p1.c \
				rand.c hmac.c pbkdf2.c \
				bip32.c bip39.c base58.c base32.c segwit_addr.c \
				address.c script.c \
				ripemd160.c sha2.c sha3.c hasher.c \
				blake256.c blake2b.c blake2s.c \
				aes/aescrypt.c aes/aeskey.c aes/aestab.c aes/aes_modes.c \
				ed25519-donna/curve25519-donna-32bit.c \
				ed25519-donna/curve25519-donna-helpers.c \
				ed25519-donna/modm-donna-32bit.c \
				ed25519-donna/ed25519-donna-basepoint-table.c \
				ed25519-donna/ed25519-donna-32bit-tables.c \
				ed25519-donna/ed25519-donna-impl-base.c \
				ed25519-donna/ed25519.c \
				ed25519-donna/curve25519-donna-scalarmult-base.c \
				ed25519-donna/ed25519-keccak.c \
				ed25519-donna/ed25519-sha3.c \
				chacha20poly1305/chacha20poly1305.c \
				chacha20poly1305/chacha_merged.c \
				chacha20poly1305/poly1305-donna.c \
				chacha20poly1305/rfc7539.c )
SRC_MOD += ../../external/mpy-qr/moduqr.c

# settings that apply only to crypto C-lang code
build-COLDCARD/boards/COLDCARD/crypto/%.o: CFLAGS_MOD += \
	-DUSE_BIP39_CACHE=0 -DBIP32_CACHE_SIZE=0 -DUSE_BIP32_CACHE=0 -DBIP32_CACHE_MAXDEPTH=0 \
	-DRAND_PLATFORM_INDEPENDENT=1 -DUSE_BIP39_GENERATE=0 -DUSE_BIP32_25519_CURVES=0


# This will relocate things up by 32k=0x8000
# see also ./layout.ld
CFLAGS_MOD += -DVECT_TAB_OFFSET=0x8000
TEXT0_ADDR = 0x08008000
TEXT1_ADDR = 0x0800C000

#don't want any of these: soft_spi, soft_qspi, dht
DRIVERS_SRC_C-=\
	drivers/bus/softspi.c \
	drivers/bus/softqspi.c \
	drivers/memory/spiflash.c \
	drivers/dht/dht.c
# Approximately all the source code files?
ALL_SRC = $(SRC_LIB) $(SRC_LIBM) $(EXTMOD_SRC_C) $(DRIVERS_SRC_C) \
			 $(SRC_HAL) $(SRC_USBDEV) $(SRC_MOD)
ALL_SRC += $(addprefix ports/stm32/, $(SRC_C))
ALL_SRC += py/*.[ch]


FROZEN_MPY_DIR = boards/$(BOARD)/frozen-modules

# XXX: this barely works
tags:
	echo $(ALL_SRC)
	cd $(TOP)/../..; pwd; ctags -R -f .tags $(addprefix external/micropython/, $(ALL_SRC)) \
				external/micropython/lib/stm32lib/STM32L4xx_HAL_Driver/*/*.[ch] \
				external/micropython/lib/stm32lib/CMSIS/STM32L4xx/Include/stm32l475xx.h \
				external/micropython/lib/cmsis/inc/core_cm4.h \
				external/micropython/ports/stm32/*.[ch] \
				external/micropython/ports/stm32/*/*.[ch] \
				external/micropython/ports/stm32/usbdev/class \
				external/crypto


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

build-COLDCARD/boards/COLDCARD/modckcc.o: COPT = -O0 -DNDEBUG

files:
	# SRC_C: $(SRC_C)
	@echo
	# SRC_HAL: $(SRC_HAL)
	@echo
	# CFLAGS: $(CFLAGS)
