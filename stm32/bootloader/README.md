# Coldcard Bootloader - Mk3 and Mk4

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

- using OpenOCD is preferred for lower level code like this (not GDB)

- `stm32l4x.cpu arm disassemble 0x000008 10 thumb` is very helpful

- you can power cycle the board (to enter/exit DFU) and OpenOCD keeps working

- for consistent reading of state, do this:
    - power cycle
    - "reset"
    - "halt"

- wipe chip with:
    - ``stm32l4x mass_erase 0`` in openocd monitor to bulk-erase whole chip

- To clear flash with write protect on... FLASH regs at 0x40022000 base
    # XXX this process no longer works?
    FLASH->CR = 0x40022014
    FLASH->WRP1AR = 0x4002202c

    # this works on Mk4: with less weird errors/warnings.
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

- newer approach, with later OpenOCD versions:

    # boot into DFU, gain control
    halt
    stm32l4x option_write 0 0x2c 0xff00ffff 0xffffffff
    stm32l4x option_load 0
    # (system resets, might run)
    # check it worked
    stm32l4x option_read 0 0x2c
    # says: Option Register: <0x4002202c> = 0xff00ffff


- "stm32l4x.cpu mdb" is nice hexdump, much better than regular mdb

- If you're having trouble getting the debugger to started / link up right, try in DFU mode.

- You must always wipe flash when you change the 508/608 because no code to erase the
  pairing secret and can't rewrite flash.

    halt
    stm32l4x unlock 0
    stm32l4x mass_erase 0

# Reading 'pairing secret'

This is a useful command, but only works on non-production units:

Mk1-3:

    dfu-util -d 0483:df11 -a 0 -s 0x08007800:256 -U pairing.bin

Mk4 & Q1:

    dfu-util -d 0483:df11 -a 0 -s 0x0801c000:16384 -U pairing.bin

- but that file is misleading, because all the unused mcu key slots are un-programmed-cells (ones)
- will hit assert on new MCU key attempt if you just write that back
- trim and write only actual non-ones content

# Wiping Secrets

Mk4:
    flash erase_address 0x801c000 0x4000


# Resources

- [Useful asm directives and more](https://community.arm.com/processors/b/blog/posts/useful-assembler-directives-and-macros-for-the-gnu-assembler)

# Todo List

- measure OLED reset and CS pulse lengths, and SPI clk during boot w/ internal RC oscilator
- HAL code for SPI should be removed and replaced with a few one-liners
- GPIO code may be removed as well?


## Bootloader upgrade 3.0.? to 3.0.2

- mk3 only
- capture pairing data:

    dfu-util -d 0483:df11 -a 0 -s 0x0801c000:8192 -U pairing.bin

- do the above unlock write-protect process, but don't erase any flash
    - would only be required if "bag" operation done

- then upload old pairing data

    dfu-util -d 0483:df11 -a 0 -s 0x0801c000:8192 -D pairing.bin

- unit will boot w/ no seed

- for cleanest result, wipe last flash page:

    flash erase_address 0x0801e000 0x2000

## Bootloader upgrade 3.0.? to 3.1.?

- clear main PIN before install, or else you won't be able to get back in!


## Re-do Bag Number

- cannot write ones, and then change flash cells; have to remain unprogrammed

    dfu-util -d 0483:df11 -a 0 -s 0x0801c000:8192 -U pairing.bin

- want 0..0x50 then 0x70 

    dd if=pairing.bin of=p1.bin bs=80 count=1
    dd if=pairing.bin of=p2.bin bs=112 skip=1

- two burns:
    => DFU does not work, each run erases other part of page
    => same with "program" cmd in openocd
    => these work tho:

    flash erase_address 0x801c000 0x2000
    flash write_image mk4-bootloader/p1.bin 0x0801c000
    flash write_image mk4-bootloader/p2.bin 0x0801c070


