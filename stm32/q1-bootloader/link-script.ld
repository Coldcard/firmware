/**
 *
 * a specialized linker script: 
 *  - limits itself to just part of the device
 *  - assumes only a small amount of ram is available.
 *  - reference: <https://sourceware.org/binutils/docs/ld/>
 *  - spaces actually matter in expressions in this file
 *
 */

OUTPUT_FORMAT("elf32-littlearm", "elf32-littlearm", "elf32-littlearm")
OUTPUT_ARCH(arm)
SEARCH_DIR(.)

/* Memory Spaces Definitions */
MEMORY
{
  rom    (rx)  : ORIGIN = BL_FLASH_BASE, LENGTH = BL_FLASH_SIZE
  ram    (rwx) : ORIGIN = BL_SRAM_BASE, LENGTH = BL_SRAM_SIZE
}

/* The stack size used by the bootloader. */
STACK_SIZE = DEFINED(STACK_SIZE) ? STACK_SIZE : DEFINED(__stack_size__) ? __stack_size__ : 0x800;

/* Section Definitions */
SECTIONS
{
    .text :
    {
        . = ALIGN(4);
        _sfixed = .;
        KEEP(*(.entry_code))
        KEEP(*(.outside_fw))
        firewall.o(.text*)
        stm32l4xx_hal_firewall.o(.text*)

        . = ALIGN(256);
        _firewall_start = .;

        KEEP(*(.firewall_code))
        dispatch.o(.text*)
        main.o(.text*)
        lcd.o(.text*)
        stm32l4xx_hal_gpio.o(.text*)
        stm32l4xx_hal_spi.o(.text*)

        /* important: this pulls in library (libgcc) stuff here */
        KEEP(*(.text .text.* .gnu.linkonce.t.*))
        *(.rodata .rodata* .gnu.linkonce.r.*)

/*
        *(.glue_7t) *(.glue_7)
        *(.ARM.extab* .gnu.linkonce.armextab.*)
*/

        . = ALIGN(4);
        _efixed = .;            /* End of text section */

    } > rom

    /* .ARM.exidx is sorted, so has to go in its own output section.  */
    PROVIDE_HIDDEN (__exidx_start = .);
    .ARM.exidx :
    {
      *(.ARM.exidx* .gnu.linkonce.armexidx.*)
    } > rom
    PROVIDE_HIDDEN (__exidx_end = .);

    . = ALIGN(4);
    _etext = .;

    .relocate : AT (_etext)
    {
        . = ALIGN(4);
        _srelocate = .;
        *(.ramfunc .ramfunc.*);
        _check_ro_hack = .;
        *(.data .data.*);
        . = ALIGN(4);
        _erelocate = .;

    } > ram

/*
    .text : {
        . = (BL_FLASH_SIZE - BL_NVROM_SIZE);

        KEEP(*(.pairing_secret))
    } > rom
*/

    /* Some very manual linking! I've tried doing it right, and couldn't get it to work well */
    addr_rom_secrets = BL_NVROM_BASE;
    addr_mcu_keys = BL_NVROM_BASE + 0x2000;

	/* if you initialize a global var to some non-zero value, then that data ends up
		in .relocate as read-only data and used briefly at startup (when copied to RAM).
		We don't want to support that, so we're checking here that hasn't happened. */
	ASSERT(_check_ro_hack == _erelocate, 
				"Sorry, no initialized data support! Set to zero or remove.")

    /* ensure binary fits */
    ASSERT(_erelocate - BL_SRAM_BASE + _etext <= BL_FLASH_BASE + BL_FLASH_SIZE,
                "Binary is too big to fit!!!")

    /* .bss section which is used for uninitialized data */
    .bss (NOLOAD) :
    {
        . = ALIGN(4);
        _sbss = . ;
        _szero = .;
        *(.bss .bss.*)
        *(COMMON)
        . = ALIGN(4);
        _ebss = . ;
        _ezero = .;
    } > ram

    /* stack section */
    .stack (NOLOAD):
    {
        . = ALIGN(8);
        _sstack = .;
        . = . + STACK_SIZE;
        . = ALIGN(8);
        _estack = .;
    } > ram

    . = ALIGN(4);
    _end = . ;
}
