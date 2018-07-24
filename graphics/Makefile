# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.

all: graphics.py
	
SOURCES = $(wildcard *.txt) $(wildcard *.png)

graphics.py: Makefile $(SOURCES) build.py
	./build.py $(SOURCES)

up: all
	(cd ../shared; make up)
