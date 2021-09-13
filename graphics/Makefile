# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.

all: graphics.py
	
SOURCES = $(filter-out mk4_%, $(wildcard *.txt) $(wildcard *.png))
MK4_SOURCES = $(wildcard mk4_*.txt) $(wildcard mk4_*.png)

graphics.py: Makefile $(SOURCES) build.py
	./build.py graphics.py $(SOURCES)
	./build.py graphics_mk4.py $(MK4_SOURCES)

up: all
	(cd ../shared; make up)
