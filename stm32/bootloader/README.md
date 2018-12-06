# Coldcard Bootloader

We have a bootloader. It does the usual code signature checking, but also offers
some security features used during runtime. Part of this is keeping some bytes
secret in the long term. It can never be field upgraded, and yet plays an
important part in that process.

# Firewalled Code/Data

This code is linked separately from other executables, and resides in its own
reserved area at the start of flash memory. That area is protected from readback
using chip features: "Proprietary Code Read-Out Protection (PCROP)" aka. firewall.

A very limited amount of security-sensitive code resides here. It
protects your currency, but only indirectly. It's more about making
your key storage per-system unique.

# Notes

- the most helpful file here is `bootloader.lss` which is generated in build process

- using OpenOCD is prefered for lower level code like this (not GDB)

- `stm32l4x.cpu arm disassemble 0x000008 10 thumb` is very helpful

- you can power cycle the board (to enter/exit DFU) and OpenOCD keeps working

- for consistent reading of state, do this:
    - power cycle
    - "reset"
    - "halt"

- wipe chip with:
    - ``stm32l4x mass_erase 0`` in openocd monitor to bulk-erase whole chip

- To clear flash with write protect on... FLASH regs at 0x40022000 base
    FLASH->CR = 0x40022014
    FLASH->WRP1AR = 0x4002202c

    # have DFU active. doesn't work from running
    halt
    # expect 0x40000000, if it's 0xc0000000, can't work; reboot w/ DFU pressed, to fix
    mdw 0x40022014
    # ignore warning about "power cycle" from this:
    stm32l4x unlock 0
    # expect 0 from this:
    mdw 0x40022014
    # disable all write-protect (bank 1, A region)
    mww 0x4002202c 0xff00ffff
    mww 0x40022030 0xff00ffff
    # commit change
    mww 0x40022014 0x20000
    # read back in OB (expect ff00ffff NOT ff0fff00)
    mdw 0x1FFF7818
    # launch changes? (causes weird reset)
    mww 0x40022014 0x8000000

- "stm32l4x.cpu mdb" is nice hexdump, much better than regular mdb

# Credits

- <https://github.com/B-Con/crypto-algorithms> for sha256 code.

# Reset Vector + Callgate Hacking

- using OpenOCD monitor talking to real chip
- using OpenOCD disassembler
- working in RAM @ 0x10000000
- need to encode the reset vector (into boot loader) and also be a valid sequence of thumb insts
- best if it doesn't mangle R1-R4,LR so they can be used for callgate API
- I require: 08000 xxxx where
        - LSB of x is one (thumb mode),
        - and (x) is less than 0x7800
        - preferably x is small

    mwh 0x10000000 0x00b1
    mwh 0x10000002 0x0800
    stm32l4x.cpu arm disassemble 0x10000000 2 thumb

    0x10000000  0x00b1      LSLS    r1, r6, #0x02
    0x10000002  0x0800      LSRS    r0, r0, #0x20

- "LSRS    r0, r0, #0x20" will be unavoidable

- here's a nice sequence:
    0x10000000  0x007f      LSLS    r7, r7, #0x01
    0x10000002  0x0800      LSRS    r0, r0, #0x20

- however, it's a no-go because once the firewall is activated, the
    reset vector can't work: it doesn't do the callgate right. It may
    be fetching the reset vector and/or the stack ptr before dying but
    it's hard to tell. Also tried jumping to the callgate (0x05) as the
    reset vector but that didn't work either.

- lesson learned: we must keep the bootloader readonly and block flash writes
  because other wise the DFU can/will (partially) erase the 0x100 or so non-firewalled
  bytes. Of course the datasheet says that too, and states level 2 write protection
  is needed.


# Reading 'pairing secret'

This is a useful command, but only works on non-production units:

    dfu-util -d 0483:df11 -a 0 -s 0x08007800:256 -U pairing.bin


# Resources

- [Useful asm directives and more](https://community.arm.com/processors/b/blog/posts/useful-assembler-directives-and-macros-for-the-gnu-assembler)

# Todo List

- measure OLED reset and CS pulse lengths, and SPI clk during boot w/ internal RC oscilator
- HAL code for SPI should be removed and replaced with a few one-liners
- GPIO code maybe removed as well?


# NOTES

- for 0123783355b2ab9dee:
- 2dcc34b2c3531a5d60153647413318502499448aa365d8424178a3c3133e638c

