# Coldcard Memory Map

## Background

The microprocess on the Coldcard is the STM32L476R?. It comes with
one megabyte of flash, and 128k of SRAM. All types of memory share
the same 32-bit address space.

The bootloader code runs first, and enables specific hardware
firewall features, which cover various parts of the address space.
The firewall will reset the chip when inappropriate access are made,
so for example, you cannot see any of the flash used by the boot loader.

If you want to verify the contents of the boot loader, you can give
it a 32-bit nonce and it will provide a SHA256 of itself with that
nonce as a prefix. That hash covers `0x0800 0000` to `0x0800 7800`.
Flash above `0x0800 8000` can be examined directly from python programs.

## Memory Layout

| Start         | Size      | Notes
|---------------|-----------|--------------------------
| 0x0800 0000   | 0x7800    | Mapped at zero briefly at boot time. Code. see `stm32/bootloader`
| 0x0800 7800   | 0x0800    | Sensitive "pairing secret" flash page (2k)
| 0x0800 8000   | 16k       | Interrupt handlers, file header (Micropython and Coldcard code)
| 0x0800 c000   | 848k      | Main flash area for Micropython / Coldcard C code.
| 0x080e 0000   | 128k      | Internal FAT filesystem (the "patch" area, for custom python)
| 0x1000 0000   | 0x6000    | SRAM2 area used by micropython code: disk caches, large byte arrays
| 0x1000 6000   | 0x1c00    | SRAM2 area used by boot loader
| 0x1000 7c00   | 0x0400    | Read-only. "Root seed" (once per bootup nonce), copy of firmware sig
| 0x2000 0000   | 96k       | SRAM1: heap and working SRAM for micropython


## Security Measures

- On entry the bootloader always wipes it's entire working SRAM2 area. You may change 
  it, or even use it for very temporary storage, but it will be destroyed once the callgate
  into the bootloader is accessed.
- All of SRAM1 and SRAM2 is cleared on boot up, and when the "secure logout" feature is used.
- DFU firmware updates can only affect areas at and above 0x08008000. Upgrade process will
  crash (harmlessly) if you give a DFU file which changes another area.
- If you manage to erase the entire chip's flash (not clear that's possible), then you will
  lose the pairing secret (0x0800 7800) and be unable to communicate with the secure element.
- The boot up verification process does a double-SHA256 over all of flash (including the pairing
  secret area) and also a few registers that are loaded from flash cells.
  See `verify.c` in `stm32/bootloader`.


