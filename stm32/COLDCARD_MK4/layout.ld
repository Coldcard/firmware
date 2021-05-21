/* based on ../stm32l476xg.ld
/*
    GNU linker script for Mk4 running on STM32L4s5
*/

/* Specify the memory areas */
MEMORY
{
    FLASH (rx)      : ORIGIN = 0x08010000, LENGTH = 112K

    /* NOTE: first 16k of flash reserved for bootloader and firewalled code */
    FLASH_ISR (rx)  : ORIGIN = 0x08010000, LENGTH = 16K
    FLASH_TEXT (rx) : ORIGIN = 0x08014000, LENGTH = 848K
    FLASH_FS (r)    : ORIGIN = 0x080e8000, LENGTH = 128K

    /* SRAM1,2, and 3 are continuous, first 0x2000 reserved for bootloader */
    RAM (xrw)       : ORIGIN = 0x20002000, LENGTH =  0x9e000   
}

ENTRY(Reset_Handler)

/* produce a link error if there is not this amount of RAM for these sections */
_minimum_stack_size = 2K;
_minimum_heap_size = 16K;

/* Define the stack.  The stack is full descending so begins just above last byte of RAM,
   or bottom of FS cache..  Note that EABI requires the stack to be 8-byte aligned for a call. */

/* RAM extents for the garbage collector */
_ram_start = ORIGIN(RAM);
_ram_end = ORIGIN(RAM) + LENGTH(RAM);

_ram_fs_cache_end = _ram_end;
_ram_fs_cache_start = _ram_fs_cache_end - 2K; /* fs cache = 2K */

_estack = _ram_fs_cache_start - _estack_reserve;
_sstack = _estack - 16K; /* stack = 16K */

_heap_start = _ebss; /* heap starts just after statically allocated memory */
_heap_end = _sstack; /* bss + heap, tunable by adjusting stack size */

_flash_fs_start = ORIGIN(FLASH_FS);
_flash_fs_end   = ORIGIN(FLASH_FS) + LENGTH(FLASH_FS);
