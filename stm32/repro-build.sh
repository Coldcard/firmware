#!/bin/sh
#
# NOTE: Executes inside the docker container.
# - assumes /work/src is a git checkout
# - will copy certain files (build products) back to /work/built
#
set -ex

# arguments
VERSION_STRING=$1
MK_NUM=$2

TARGETS="firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf"

BYPRODUCTS="check-fw.bin check-bootrom.bin repro-got.txt repro-want.txt file_time.c"

cd /work/src/stm32

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
    rsync --ignore-missing-args -av /work/src/releases/20*.dfu ../releases
fi

# need signit.py in path
cd ../cli
python -m pip install -r requirements.txt
python -m pip install --editable .
cd ../stm32

cd ../releases
if [ -f *-v$VERSION_STRING-mk$MK_NUM-coldcard.dfu ]; then
    echo "Using existing binary in ../releases, not downloading."
else
    # fetch a copy of the required binary
    PUBLISHED_BIN=`grep v$VERSION_STRING-mk$MK_NUM-coldcard.dfu signatures.txt | dd bs=66 skip=1`
    if [ -z "$PUBLISHED_BIN" ]; then
        # may indicate first attempt to build this release
        echo "Cannot determine release date / full file name."
    else
        wget -S https://coldcardwallet.com/downloads/$PUBLISHED_BIN
    fi
fi
cd ../stm32

make setup
make DEBUG_BUILD=0 all
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
