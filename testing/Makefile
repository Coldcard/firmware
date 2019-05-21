

all:
	pytest .

cont:
	pytest . --ff

tags:
	ctags --python-kinds=-i -f .tags *.py */*.py

.PHONY: all cont tags
