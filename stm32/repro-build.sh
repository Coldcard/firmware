#!/bin/sh
#
# Executes inside the docker container... but works on your files here!
#
set -ex

TARGETS="firmware-signed.bin firmware-signed.dfu production.bin dev.dfu"

BYPRODUCTS="check-fw.bin check-bootrom.bin repro-got.txt repro-want.txt"

cd /work/src/stm32

if ! touch repro-build.sh ; then
    # If we seem to be on a R/O filesystem:
    # - create a writable overlay on top of read-only source tree
    #   from <https://stackoverflow.com/a/54465442>
    # - copy certain files (build products) back to /work/built

    mkdir /tmp/overlay
    mount -t tmpfs tmpfs /tmp/overlay
    mkdir -p /tmp/overlay/upper /tmp/overlay/work /work/tmp
    mount -t overlay overlay -o lowerdir=/work/src,upperdir=/tmp/overlay/upper,workdir=/tmp/overlay/work /work/tmp

    cd /work/tmp/stm32
fi

# need signit.py in path
cd ../cli
python -m pip install -r requirements.txt
python -m pip install --editable .
cd ../stm32

make setup
#make clean
make all
make $TARGETS

if [ $PWD == '/work/tmp/stm32' ]; then
    # Copy back build products.
    rsync -av --ignore-missing-args $TARGETS $BYPRODUCTS /work/built
fi

make check-repro
