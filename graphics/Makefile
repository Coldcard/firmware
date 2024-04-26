# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.

all: graphics_mk4.py graphics_q1.py
	
MK4_SOURCES = $(wildcard mono/*.txt) $(wildcard mono/*.png)
Q1_SOURCES = colour/*.???

graphics_mk4.py: Makefile $(MK4_SOURCES) build.py
	./build.py graphics_mk4.py $(MK4_SOURCES)

graphics_q1.py: Makefile $(Q1_SOURCES) compress.py
	./compress.py graphics_q1.py $(Q1_SOURCES)

up: all
	(cd ../shared; make up)

