#
# Pure ASM version of AES-256 for CTR mode only
#

ifeq ($(BOARD), COLDCARD)

SRC_USERMOD += $(USERMOD_DIR)/aes_256_ctr.o
SRC_USERMOD += $(USERMOD_DIR)/module.c

endif

