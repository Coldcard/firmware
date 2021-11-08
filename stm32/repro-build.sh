#!/bin/sh
#
# NOTE: Executes inside the docker container.
# - assumes $WORK_SRC is a git checkout
# - will copy certain files (build products) back to $WORK_BUILT
#
set -ex

TARGETS="firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf"

BYPRODUCTS="check-fw.bin check-bootrom.bin repro-got.txt repro-want.txt COLDCARD/file_time.c"

VERSION_STRING=$1
WORK_SRC=${2:-'/work/src'}
WORK_BUILT=${3:-'/work/built'}

cd $WORK_SRC/stm32

if ! touch repro-build.sh ; then
    # If we seem to be on a R/O filesystem:
    # - do a local checkout of HEAD, build from that
    mkdir /tmp/checkout
    mount -t tmpfs tmpfs /tmp/checkout
    cd /tmp/checkout
    git clone $WORK_SRC/.git firmware
    cd firmware/external
    git submodule update --init
    cd ../stm32
    rsync --ignore-missing-args -av $WORK_SRC/releases/*.dfu ../releases
fi

# need signit.py in path
cd ../cli
python -m pip install -r requirements.txt
python -m pip install --editable .
cd ../stm32

cd ../releases
if [ -f *-v$VERSION_STRING-coldcard.dfu ]; then
    echo "Using existing binary in ../releases, not downloading."
else
    # fetch a copy of the required binary
    PUBLISHED_BIN=`grep $VERSION_STRING signatures.txt | dd bs=66 skip=1`
    if [ -z "$PUBLISHED_BIN" ]; then
        echo "Cannot determine release date / full file name. Stop."
        exit 1
    fi
    wget -S https://coldcard.com/downloads/$PUBLISHED_BIN
fi
cd ../stm32

make setup
make all
make $TARGETS

if [ $PWD != '$WORK_SRC/stm32' ]; then
    # Copy back build products.
    rsync -av --ignore-missing-args $TARGETS $WORK_BUILT
fi

set +e
make check-repro
CR_EXITCODE=$?

set +ex
if [ $PWD != '$WORK_SRC/stm32' ]; then
    # Copy back byproducts
    rsync -a --ignore-missing-args $BYPRODUCTS $WORK_BUILT
fi

if [ $CR_EXITCODE -ne 0 ]; then
    echo "FAILURE."
    echo "Exit code $CR_EXITCODE from 'make check-repro'"
    exit 1
fi
