# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#

all:
	pytest .

cont:
	pytest . --ff

tags:
	ctags --python-kinds=-i -f .tags *.py */*.py

.PHONY: all cont tags
