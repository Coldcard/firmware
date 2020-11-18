# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.

all: graphics.py
	
SOURCES = $(wildcard *.txt) $(wildcard *.png)

graphics.py: Makefile $(SOURCES) build.py
	./build.py $(SOURCES)

up: all
	(cd ../shared; make up)
