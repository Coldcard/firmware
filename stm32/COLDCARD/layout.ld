/* based on ../stm32l476xg.ld
/*
    GNU linker script for STM32L476XG
*/

/* Specify the memory areas */
MEMORY
{
    FLASH (rx)      : ORIGIN = 0x08008000, LENGTH = 112K

    /* NOTE: first 32k reserved for bootloader and firewalled code */
    FLASH_ISR (rx)  : ORIGIN = 0x08008000, LENGTH = 16K
    FLASH_TEXT (rx) : ORIGIN = 0x0800c000, LENGTH = 848K
    FLASH_FS (r)    : ORIGIN = 0x080e0000, LENGTH = 128K

    RAM (xrw)       : ORIGIN = 0x20000000, LENGTH = 96K

    /* SRAM2 is 32k of SRAM used for:
        - filesyste cache (2k at zero)
        - top 8k reserved for bootloader/call gate
        - manually-allocated for some runtime python stuff (see sram2.py) from bottom
        - remainder is the stack, growing down from 0x10006000
    */
    FS_CACHE(xrw)   : ORIGIN = 0x10000000, LENGTH = 2K
    SRAM2 (xrw)     : ORIGIN = 0x10000800, LENGTH = 22K
}

ENTRY(Reset_Handler)

/* produce a link error if there is not this amount of RAM for these sections */
_minimum_stack_size = 0;        /* now in SRAM2, so no need to reserve any space here */
_minimum_heap_size = 16K;

/* Define the top end of the stack.  The stack is full descending so begins just
   above last byte of RAM.  Note that EABI requires the stack to be 8-byte
   aligned for a call. */
_estack = ORIGIN(SRAM2) + LENGTH(SRAM2);

/* RAM extents for the garbage collector */
_ram_start = ORIGIN(RAM);
_ram_end = ORIGIN(RAM) + LENGTH(RAM);
_heap_start = _ebss; /* heap starts just after statically allocated memory */
_heap_end = _ram_end; /* reserving nothing for stack, it's in SRAM2 */

_flash_fs_start = ORIGIN(FLASH_FS);
_flash_fs_end   = ORIGIN(FLASH_FS) + LENGTH(FLASH_FS);

_ram_fs_cache_start = ORIGIN(FS_CACHE);
_ram_fs_cache_end = ORIGIN(FS_CACHE) + LENGTH(FS_CACHE);
