# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Use this to build the simulator.
#
# BUG: sometimes gets caught in a depenancy loop, where it's remaking Q strings.
# - workaround: "make clean && make tool" ... just a make clean isn't enough
#
MPY_TOP = ../external/micropython
PORT_TOP = $(MPY_TOP)/ports/unix
CC_UNIX_TOP = $(PWD)
V=0

# bugfix for my Mac at least
export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig

MAKE_ARGS = -j 4 FROZEN_MPY_DIR=$(PWD)/frozen-modules MPCONFIGPORT_MK=$(PWD)/mpconfigport.mk CC_UNIX_TOP=$(CC_UNIX_TOP) PROG=coldcard-mpy V=$(V) DEBUG=1

all:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS)

clean:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) clean

up: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy-stlink

dfu: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy

tags: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) tags

# Make a vanilla copy of micropython (unix) for use with upip and comparsions purposes
tools:
	cd $(PORT_TOP) && $(MAKE) clean deplibs all
	cp $(PORT_TOP)/micropython ./micropython
	cd $(PORT_TOP) && $(MAKE) clean

setup:
	-ln -s $(PORT_TOP) l-port
	-ln -s $(MPY_TOP) l-mpy
	-ln -s $(PORT_TOP)/coldcard-mpy coldcard-mpy
	cd $(PORT_TOP) ; git submodule update --init
	$(MAKE) tools
	@echo Setup DONE

