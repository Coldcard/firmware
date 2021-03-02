
all:
	@echo no default

build:
	docker build -t coldcard-build .

shell:
	docker run -it coldcard-build sh

	
copy:
	(cd .. ; git archive --format tar HEAD) | \
		docker run -i coldcard-build tar x -C /work -f -
	(cd .. ; git archive -o docker/snapshot.tar HEAD)
