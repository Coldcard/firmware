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

- If you're having trouble getting the debugger to started / link up right, try in DFU mode.

- You must always wipe flash when you change the 508/608 because no code to erase the
  pairing secret and can't rewrite flash.

    halt
    stm32l4x unlock 0
    stm32l4x mass_erase 0

# Credits

- <https://github.com/B-Con/crypto-algorithms> for sha256 code.

# Reading 'pairing secret'

This is a useful command, but only works on non-production units:

    dfu-util -d 0483:df11 -a 0 -s 0x08007800:256 -U pairing.bin


# Resources

- [Useful asm directives and more](https://community.arm.com/processors/b/blog/posts/useful-assembler-directives-and-macros-for-the-gnu-assembler)

# Todo List

- measure OLED reset and CS pulse lengths, and SPI clk during boot w/ internal RC oscilator
- HAL code for SPI should be removed and replaced with a few one-liners
- GPIO code maybe removed as well?


