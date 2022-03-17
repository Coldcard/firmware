# Coldcard Wallet

Coldcard is a Cheap, Ultra-secure & Verifiable Hardware Wallet for Bitcoin.
Get yours at [Coldcard.com](http://coldcard.com)

[Follow @COLDCARDwallet on Twitter](https://twitter.com/coldcardwallet) to keep up
with the latest updates and security alerts. 

![coldcard logo](https://coldcard.com/static/images/coldcard-logo-nav.png)

![coldcard picture front](https://coldcard.com/static/images/coldcard-front.png)
![coldcard picture back](https://coldcard.com/static/images/coldcard-back.png)

## Reproducible Builds

To have confidence this source code tree is the same as the binary on your device,
you can rebuild it from source and get **exactly the same bytes**. This process
has been automated using Docker. Steps are as follows:

1. Install Docker and start it.
2. Install [make (GNUMake)](https://www.gnu.org/software/make/) if you don't already have it.
3. Checkout the code, and start the process.

    git clone https://github.com/Coldcard/firmware.git
    
    cd firmware/stm32
    
    make repro

4. At the end of the process a clear confirmation message is shown, or the differences.
5. Build products can be found `firmware/stm32/built`.

## Check-out and Setup

Do a checkout, recursively to get all the submodules:

    git clone --recursive https://github.com/Coldcard/firmware.git

Already checked-out and getting git errors? Do this:

    git fetch
    git reset --hard origin/master

Then:

- `cd firmware`
- `git submodule update --init` _(if needed?)_
- `brew install automake autogen virtualenv`
- `virtualenv -p python3 ENV` (Python > 3.5 is required)
- `source ENV/bin/activate` (or `source ENV/bin/activate.csh` based on shell preference)
- `pip install -r requirements.txt`

Setup and Run the Desktop-based Coldcard simulator:

- `cd unix; make setup && make && ./simulator.py`

Building the firmware:

- `cd ../cli; pip install --editable .`
- `cd ../stm32; make setup && make; make firmware-signed.dfu`
- The resulting file, `firmware-signed.dfu` can be loaded directly onto a Coldcard, using this
  command (already installed based on above)
- `ckcc upgrade firmware-signed.dfu`

Which looks like this:

    [ENV] [firmware/stm32 42] ckcc upgrade firmware-signed.dfu
    675328 bytes (start @ 293) to send from 'firmware-signed.dfu'
    Uploading  [##########--------------------------]   29%  0d 00:01:04


### MacOS

You'll probably need to install at least these packages:

    brew install --cask xquartz
    brew install sdl2 xterm
    brew install --cask gcc-arm-embedded

Used to be these were needed as well:

    brew tap PX4/px4
    brew search px4
    brew install px4/px4/gcc-arm-none-eabi-80 (latest gcc-arm-none-eabi-XX, currently 80)

You may need to reboot to avoid a `DISPLAY is not set` error.

### Linux

You'll need to install these (Ubuntu 20.04):

    apt install build-essential git python3 python3-pip libudev-dev gcc-arm-none-eabi

Install and run simulator on Ubuntu 20.04
```shell
git clone --recursive https://github.com/Coldcard/firmware.git
cd firmware
# apply address patch
git apply unix/unix_addr.patch
# apply libngu patch
pushd external/libngu
git apply ../libngu.patch
popd
# create virtualenv and activate it
python3 -m venv ENV  # or virtualenv -p python3 ENV
source ENV/bin/activate
# install dependencies
pip install -U pip setuptools
pip install -r requirements.txt
# build simulator
cd unix
pushd ../external/micropython/mpy-cross/
make  # mpy-cross
popd
make setup
make ngu-setup
make
# below line runs the simulator
./simulator.py
```

## Code Organization

Top-level dirs:

`shared`

- shared code between desktop test version and real-deal
- expected to be largely in python, and higher-level

`unix`

- unix (MacOS) version for testing/rapid dev
- this is a simulator for the product

`testing`

- test cases and associated data


`stm32`

- embedded micro version, for actual product
- final target is a binary file for loading onto hardware

`external`

- code from other projects, ie. the dreaded submodules

`stm32/bootloader`

- 32k of factory-set code that you cannot change
- however, you can inspect what code is on your coldcard and compare to this.

`hardware`

- schematic and bill of materials for the Coldcard

`unix/work/MicroSD`

- files on "simulated" microSD card 


## Support

Found a bug? Email: support@coinkite.com
