#!/bin/sh
#
# NOTE: Executes inside the docker container.
# - assumes /work/src is a git checkout
# - will copy certain files (build products) back to /work/built
#
set -ex

# arguments, all required
VERSION_STRING=$1
HW_MODEL=$2
PARENT_MKFILE=$3

VENV_PATH="/tmp/ENV"

MAKE="make -f $PARENT_MKFILE"

TARGETS="firmware-signed.bin firmware-signed.dfu production.bin dev.dfu firmware.lss firmware.elf"

BYPRODUCTS="check-fw.bin check-bootrom.bin repro-got.txt repro-want.txt file_time.c"

cd /work/src/stm32

if ! touch repro-build.sh ; then
    # If we seem to be on a R/O filesystem:
    # - do a local checkout of HEAD, build from that
    mkdir /tmp/checkout
    cd /tmp/checkout
    git clone /work/src/.git firmware
    cd firmware/external
    git submodule update --init
    cd ../stm32
    rsync --ignore-missing-args -av /work/src/releases/20*.dfu ../releases
fi

# need signit.py in path
cd ../cli
python -m venv $VENV_PATH
. $VENV_PATH/bin/activate
python -m pip install -r requirements.txt
python -m pip install --editable .
cd ../stm32

cd ../releases
if [ -f *-v$VERSION_STRING-$HW_MODEL-coldcard.dfu ]; then
    echo "Using existing binary in ../releases, not downloading."
    PUBLISHED_BIN=`realpath *-v$VERSION_STRING-$HW_MODEL-coldcard.dfu`
else
    # fetch a copy of the required binary
    PUBLISHED_BIN=`grep -F v$VERSION_STRING-$HW_MODEL-coldcard.dfu signatures.txt | dd bs=66 skip=1`
    if [ -z "$PUBLISHED_BIN" ]; then
        # may indicate first attempt to build this release
        echo "Cannot determine release date / full file name."
    else
        wget -S https://coldcard.com/downloads/$PUBLISHED_BIN
        PUBLISHED_BIN=`realpath "$PUBLISHED_BIN"`
    fi
fi
cd ../stm32

if [ -z "$SOURCE_DATE_EPOCH" ] && [ -n "$PUBLISHED_BIN" ]; then
    DT=$(basename $PUBLISHED_BIN | cut -d "-" -f1,2,3)
    export SOURCE_DATE_EPOCH=$(python -c 'import datetime, sys; sys.stdout.write(str(int(datetime.datetime.strptime(sys.argv[1], "%Y-%m-%dT%H%M").timestamp())))' "$DT")
fi

$MAKE setup
$MAKE DEBUG_BUILD=0 all
$MAKE $TARGETS

if [ $PWD != '/work/src/stm32' ]; then
    # Copy back build products.
    rsync -av --ignore-missing-args $TARGETS /work/built
fi

set +e
$MAKE "PUBLISHED_BIN=$PUBLISHED_BIN" check-repro

set +ex
if [ $PWD != '/work/src/stm32' ]; then
    # Copy back byproducts
    rsync -a --ignore-missing-args $BYPRODUCTS /work/built
fi
