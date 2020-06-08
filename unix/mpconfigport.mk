# COLDCARD specific changes

# Get my variations into the build
# - C modules (extmod) that I need
# - exclude code that isn't needed (SSL, for example)

# Enable/disable modules and 3rd-party libs to be included in interpreter

# Build 32-bit binaries on a 64-bit host
MICROPY_FORCE_32BIT = 0

# This variable can take the following values:
#  0 - no readline, just simple stdin input
#  1 - use MicroPython version of readline
MICROPY_USE_READLINE = 1

# btree module using Berkeley DB 1.xx
MICROPY_PY_BTREE = 1

# _thread module using pthreads
MICROPY_PY_THREAD = 1

# Subset of CPython termios module
MICROPY_PY_TERMIOS = 1

# Subset of CPython socket module
MICROPY_PY_SOCKET = 1

# ffi module requires libffi (libffi-dev Debian package)
MICROPY_PY_FFI = 1

# not wanted
MICROPY_PY_USSL = 0
MICROPY_SSL_AXTLS = 0
MICROPY_SSL_MBEDTLS = 0
MICROPY_PY_JNI = 0

# Avoid using system libraries, use copies bundled with MicroPython
# as submodules (currently affects only libffi).
MICROPY_STANDALONE = 0

INC += -I$(CC_UNIX_TOP) 
CFLAGS_EXTRA = -DMP_CONFIGFILE="\"mpconfigport_coldcard.h\""

# crypto code
T_CRYPTO_DIR = $(TOP)/../crypto
CFLAGS_MOD += -I$(TOP)/../modcryptocurrency
CFLAGS_MOD += -DMICROPY_PY_TREZORCRYPTO=1 -I$(T_CRYPTO_DIR)
VPATH = $(TOP)/..
SRC_MOD += $(addprefix modcryptocurrency/, crc.c modtcc.c) $(TOP)/unix/unix_random.c
SRC_MOD += $(addprefix crypto/,\
	bignum.c ecdsa.c curves.c \
	secp256k1.c nist256p1.c \
	rand.c \
	hmac.c \
	bip32.c \
	bip39.c \
	pbkdf2.c \
	base58.c base32.c segwit_addr.c \
    address.c \
    script.c \
    ripemd160.c \
    sha2.c \
    sha3.c \
    hasher.c \
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
    blake256.c \
    blake2b.c blake2s.c \
	chacha20poly1305/chacha20poly1305.c \
	chacha20poly1305/chacha_merged.c \
	chacha20poly1305/poly1305-donna.c \
	chacha20poly1305/rfc7539.c )
SRC_MOD += ../external/mpy-qr/moduqr.c



# settings that apply only to crypto C-lang code
build/crypto/%.o: CFLAGS_MOD += \
	-DUSE_BIP39_CACHE=0 -DUSE_BIP39_GENERATE=0 \
	-DBIP32_CACHE_SIZE=0 -DUSE_BIP32_CACHE=0 -DBIP32_CACHE_MAXDEPTH=0 \
	-DRAND_PLATFORM_INDEPENDENT=1 

