# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Use this to build the simulator.
#
#
MPY_TOP = ../external/micropython
PORT_TOP = $(MPY_TOP)/ports/unix
V=0

CC_TOP := $(realpath ..)

MAKE_ARGS = -j 4 VARIANT=coldcard-mpy VARIANT_DIR=$(PWD)/variant CC_TOP=$(CC_TOP) DEBUG=1

#		FROZEN_MANIFEST=$(PWD)/variant/manifest.py \
#		NGU_NEEDS_CIFRA=1 USER_C_MODULES=$(LIB_NGU) NGU_TOP_DIR=$(LIB_NGU)

# Which micropython patch this host needs, if any. Override to use another, ie.
# on Ubuntu 24.04:   make mpy-patch MPY_PATCH=ubuntu24_mpy.patch
MPY_PATCH_Darwin = macos-mpy.patch
MPY_PATCH = $(MPY_PATCH_$(shell uname -s))

all: mpy-patch
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS)

clean:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) clean

tags: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) tags

# Keep the micropython patch applied. It only ever lives in that submodule's working
# tree, so `git submodule update`, a checkout, or a clean silently reverts it and the
# next build dies hundreds of lines deep in py/ on -Werror warnings that look like real
# bugs. Re-asserting it before each build is cheap; applying it twice is a no-op.
mpy-patch:
ifneq ($(MPY_PATCH),)
	@cd $(MPY_TOP) && \
	  if git apply --reverse --check $(CC_TOP)/$(MPY_PATCH) 2>/dev/null; then \
	    true; \
	  elif git apply $(CC_TOP)/$(MPY_PATCH); then \
	    echo "applied $(MPY_PATCH)"; \
	  else \
	    echo "ERROR: cannot apply $(MPY_PATCH); micropython tree is not in a state I understand."; \
	    echo "       'cd $(MPY_TOP) && git checkout .' then retry, if you have no work there."; \
	    exit 1; \
	  fi
endif

# Make a vanilla copy of micropython (unix) for use with upip and comparsion purposes
tools: mpy-patch
	# axtls, not deplibs: deplibs also builds the bundled libffi, which is
	# unused here (MICROPY_STANDALONE=0 links the system libffi via pkg-config)
	# and whose aarch64 sysv.S no longer assembles under recent clang.
	cd $(PORT_TOP) && $(MAKE) clean axtls all
	cp $(PORT_TOP)/micropython ./micropython
	cd $(PORT_TOP) && $(MAKE) clean

setup:
	-ln -s $(PORT_TOP) l-port
	-ln -s $(MPY_TOP) l-mpy
	-ln -s $(PORT_TOP)/coldcard-mpy coldcard-mpy
	cd $(PORT_TOP) ; git submodule update --init
	$(MAKE) tools
	@echo Setup DONE

ngu-setup:
	cd ../external/libngu/libs/cifra; git submodule update --init .
	cd ../external/libngu/libs/secp256k1; git submodule update --init .
	cd ../external/libngu; make min-one-time
