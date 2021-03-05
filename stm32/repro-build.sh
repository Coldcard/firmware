#!/bin/sh
#
# NOTE: Executes inside the docker container.
# - assumes /work/src is a git checkout
# - copy certain files (build products) back to /work/built
#
set -ex

TARGETS="firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf"

BYPRODUCTS="check-fw.bin check-bootrom.bin repro-got.txt repro-want.txt"

cd /work/src/stm32

#if ! touch repro-build.sh ; then
if false ; then
    # If we seem to be on a R/O filesystem:
    # - create a writable overlay on top of read-only source tree
    #   from <https://stackoverflow.com/a/54465442>

    mkdir /tmp/overlay
    mount -t tmpfs tmpfs /tmp/overlay
    mkdir -p /tmp/overlay/upper /tmp/overlay/work /work/tmp
    mount -t overlay overlay -o lowerdir=/work/src,upperdir=/tmp/overlay/upper,workdir=/tmp/overlay/work /work/tmp

    cd /work/tmp/stm32
fi

if ! touch repro-build.sh ; then
    # If we seem to be on a R/O filesystem:
    # - do a local checkout of HEAD, build from that
    mkdir /tmp/checkout
    mount -t tmpfs tmpfs /tmp/checkout
    cd /tmp/checkout
    git clone /work/src/.git firmware
    cd firmware/external
    git submodule update --init
    cd ../stm32
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

if [ $PWD != '/work/src/stm32' ]; then
    # Copy back build products.
    rsync -av --ignore-missing-args $TARGETS /work/built
fi

set +e
make check-repro

set +ex
if [ $PWD != '/work/src/stm32' ]; then
    # Copy back byproducts
    rsync -a --ignore-missing-args $BYPRODUCTS /work/built
fi
