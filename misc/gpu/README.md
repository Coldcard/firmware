# GPU on Q1

The name is a joke. It's not a GPU, just a very simple and cheap micro that can
animate a progress bar. And that's all we want it to do.

It is field upgradable, but we will remove that and start locking it down in 
production once it's features are stable.


## Hardware

It's a STM32C011F4:

- 16k bytes of Flash
- 6k bytes of RAM
- 4-48Mhz
- 18 GPIO
- 20 pins
- a newer part, so some challenges there

Of the two TagConnect spots, the GPU is the inboard one; other is for main micro.

## OpenOCD

Version 0.12.0 of OpenOCD, the latest release as of this writing, does not yet support this chip.

You'll need to compile from ST Micro's fork of OpenOCD. In particular we need
this diff:
<https://github.com/STMicroelectronics/OpenOCD/commit/21c81a2b2edf5402afbba8c22feaeda6f626554e>

I am using brew's install of normal 0.12.0 for config files, and
a compiled version named `openocd-stm`, so my command line is:

    openocd-stm -s /usr/local/Cellar/open-ocd/0.12.0/share/openocd/scripts -f openocd-gpu.cfg

Useful commands:

    flash erase_sector 0 0 last

Set EMPTY bit, so goes into BL:

    > mdw 0x40022000
    0x40022000: 00040600 
    > mmw 0x40022000 0x10000 0
    > mdw 0x40022000          
    0x40022000: 00050600 



## In-Circuit Programming

- AN4221 describes the protocol used to load the flash
- timing is sensitive, but more important is where the i2c start/stops fall:

## First Time Boot

- on a fresh device, there is an `EMPTY` bit set on power-up (only) if flash looks empty
- this causes bootmode to happen, regardless of subsequent flash contents, resets, and `BOOT0` line
- so must clear bit 16 of `FLASH_ACR` after loading image: @ `0x40022000`
- also, main micro has control over `BOOT0` (PE2) which stop main flash from running too
- and the reset line on E6
- we use this flag to get into boot mode from working code

## Getting BOOT0 to work

- default config in flash bit (option bytes) is to 
- see `FLASH_OPTR` bit: `nBOOT_SEL` (bit 24) needs to be zero, default is one
- `NRST_MODE` should be 0b01 (input only) not default (0b11 = bidirectional)
- register `FLASH_OPTR` at 0x40022020 => found as 0xfffffeaa
- loads from 0x1FFF7800 at power up
- TODO XXX still need this!

## AN4221 / Bootloader Bugs

- command 0x00 - 'get' ... returns 19 bytes, but says v1.1 of protocol; clearly v1.2
- command 0x02 - 'getid' ... returns 1 byte, but math wrong on length part of response
- command 0x01 - 'getversion' ... return 1 byte, and doesn't include length prefix byte
- memory read only works from flash, some parts of SRAM... not IO registers
- undocumented need for N-1 as length in read/write commands
- flash writes need to be 256-aligned, or else they do nothing and don't fail

## Resource Sharing

- SPI bus to the display is shared by the GPU and main micro.
- Main micro configures its pins as pull-up, open-drain outputs (there is no input except TEAR).
- GPU does the same, but no pull-ups (so open drain).
- Later turns out we need push-pull I/O to get the SPI speeds involved (rise times too slow
  with built-in resistors)

## Other References

- Ideas, not code: <https://github.com/rogerclarkmelbourne/Arduino_STM32/blob/341cd894516f747f14108de5da593dad99900ae0/tools/macosx/src/stm32flash_serial/src/stm32.c>





