# Coldcard Wallet

Coldcard is an Affordable, Ultra-secure & Verifiable Hardware Wallet for Bitcoin.
Get yours at [Coldcard.com](http://coldcard.com)

[Follow @COLDCARDwallet on Twitter](https://twitter.com/coldcardwallet) to keep up
with the latest updates and security alerts.

![coldcard logo](https://coldcard.com/static/images/coldcard-logo-nav.png)

![Mk4 coldcard picture front](https://coldcard.com/static/images/mk4.png)

## Reproducible Builds

To have confidence this source code tree is the same as the binary on your device,
you can rebuild it from source and get **exactly the same bytes**. This process
has been automated using Docker. Steps are as follows:

1. Install [Docker](https://www.docker.com) and start it.
2. Install [make (GNUMake)](https://www.gnu.org/software/make/) if you don't already have it.
3. Checkout the code, and start the process.

    ```shell
    git clone https://github.com/Coldcard/firmware.git
    cd firmware/stm32
    make repro
    ```

4. At the end of the process a clear confirmation message is shown, or the differences.
5. Build products can be found `firmware/stm32/built`.

## Check-out and Setup

**NOTE** This is the `master` branch and covers the latest hardware (Mk4).
See branch `v4-legacy` for firmware which supports only Mk3/Mk2 and earlier.

Do a checkout, recursively to get all the submodules:

```shell
git clone --recursive https://github.com/Coldcard/firmware.git
```

Already checked-out and getting git errors? Do this:

```shell
git fetch
git reset --hard origin/master
```

Alternatively, to get the latest release, you checkout a tagged branch:

```shell
git clone https://github.com/Coldcard/firmware.git
cd firmware
git checkout $(git describe --match "20*" --abbrev=0)
git submodule update --init --recursive
```

Do not use a path with any spaces in it. The Makefiles do not handle
that well, and we're not planning to fix it.

Keep in mind that python requirements may change between versions,
so at the top level, do this command:

```shell
pip install -r requirements.txt
```

### macOS

[Python 3.5 or higher](https://www.python.org) and [Homebrew](https://brew.sh) is required.

If working on an ARM-based MacOS system, you may want to create a
new shell with `arch -x86_64 bash` before starting, or continuing
to work on this source tree.

#### Setup and run the desktop simulator

You'll probably need to install at least these packages:

```shell
brew install sdl2 xterm swig
brew install --cask xquartz gcc-arm-embedded
```

Used to be these were needed as well:

```shell
brew tap PX4/px4
brew search px4/px4/gcc-arm-none-eabi
```

Then install the newest version, currently 83:

```shell
brew install px4/px4/gcc-arm-none-eabi-83
```

You may need to `brew upgrade gcc-arm-embedded` because we need 10.2 or higher.

Then:

```shell
brew install automake autogen virtualenv
virtualenv -p python3 ENV
source ENV/bin/activate (or source ENV/bin/activate.csh based on shell preference)
pip install -U pip
pip install -r requirements.txt
# apply micropython patch
pushd external/micropython
git apply ../../macos-mpy.patch
popd
make -C external/micropython/mpy-cross
cd unix; make setup && make ngu-setup && make && ./simulator.py
```

You may need to reboot to avoid a `DISPLAY is not set` error.

The next time you want to run the simulator, you can simply do

```shell
source ENV/bin/activate && cd unix && ./simulator.py
```

#### Building the firmware

- `cd ../cli; pip install --editable .`
- `cd ../stm32; make setup && make; make firmware-signed.dfu`
- The resulting file, `firmware-signed.dfu` can be loaded directly onto a Coldcard, using this
  command (already installed based on above)
- `ckcc upgrade firmware-signed.dfu`

Which looks like this:

```shell
[ENV] [firmware/stm32 42] ckcc upgrade firmware-signed.dfu  
675328 bytes (start @ 293) to send from 'firmware-signed.dfu'
Uploading  [##########--------------------------]   29%  0d 00:01:04
```

#### Big Sur Issues

`defaults write org.python.python ApplePersistenceIgnoreState NO` will suppress a warning about `Python[22580:10101559] ApplePersistenceIgnoreState: Existing state will not be touched. New state will be written to...`

See <https://bugs.python.org/issue32909>

### Linux

All steps you need to install and run the Coldcard simulator on Ubuntu 20.04:


```shell
# Install (system) requirements, tools and libraries
apt install build-essential git python3 python3-pip libudev-dev gcc-arm-none-eabi libffi-dev xterm swig libpcsclite-dev python-is-python3 autoconf libtool python3-venv

# Get sources, this takes a long time (because of external libraries), then open
git clone --recursive https://github.com/Coldcard/firmware.git
cd firmware

# Apply address patch
git apply unix/linux_addr.patch 

# Create Python virtual environment and activate it
python3 -m venv ENV  # or virtualenv -p python3 ENV
source ENV/bin/activate

# Install dependencies
pip install -U pip setuptools
pip install -r requirements.txt #general requirements
pip install pysdl2-dll # Ubuntu needs this dependency

# Build the Coldcard simulator
cd unix
pushd ../external/micropython/mpy-cross/
make  # mpy-cross
popd
make setup
make ngu-setup
make

# Run the simulator in the active virtualenv
./simulator.py

# Later, if you want to run it (after a reboot). This assumes you extracted the git repo in ~ (home)
cd ~/firmware
source ENV/bin/activate
cd unix
./simulator.py
```

Also make sure that you have your python3 symlinked to python.

## Code Organization

Top-level dirs:

`shared`

- shared code between desktop test version and real-deal
- expected to be largely in python, and higher-level
- new code found only on the Mk4 will be listed in `manifest_mk4.py` code exclusive
  to earlier hardware is in `manifest_mk3.py`

`unix`

- unix (macOS) version for testing/rapid dev
- this is a simulator for the product

`testing`

- test cases and associated data

`stm32`

- embedded binaries (and building), for actual product hardware
- final target is a binary file for loading onto hardware

`external`

- code from other projects, ie. the dreaded submodules

`graphics`

- images which ship as part of the final product (icons)

`stm32/bootloader`

- 32k of factory-set code that you cannot change (Mk3)
- however, you can inspect what code is on your coldcard and compare to this.

`stm32/mk4-bootloader`

- 128k of factory-set code that you cannot change for Mk4
- however, you can inspect what code is on your coldcard and compare to this.

`hardware`

- schematic and bill of materials for the Coldcard

`unix/work/...`

- `/MicroSD/*` files on "simulated" microSD card

- `/VirtDisk/*` simulated emulated virtual Disk files.

- `/settings/*.aes` persistent settings for Simulator

## Support

Found a bug? Email: support@coinkite.com
