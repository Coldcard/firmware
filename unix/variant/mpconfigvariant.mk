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

# NGU library
FROZEN_MANIFEST += $(CC_TOP)/unix/variant/manifest.py
NGU_NEEDS_CIFRA = 1

USER_C_MODULES = $(CC_TOP)/external/c-modules

# target binary
PROG = coldcard-mpy
