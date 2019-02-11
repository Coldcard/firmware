// starting value for the top of our stack.
#define OUR_STACK      (BL_SRAM_BASE+BL_SRAM_SIZE)

    .thumb
    .syntax unified

    .text
    .section .entry_code

    .global     reset_entry
    .global     vector_table
    .global     firewall_starts
    .global     bootloader_info
    .global     my_version_code

    // NOTE: Little attempt to support anything but reset vector here.
    //
vector_table:
    .word       OUR_STACK               // initial stack value: near top of SRAM2
    .word       reset_entry             // verify: must be odd, to indicate Thumb mode
    .word       NMI_Handler             // placeholder / debug aid
    .word       HardFault_Handler
    .word       MemManage_Handler
    .word       BusFault_Handler
    .word       UsageFault_Handler


    // Debug aids: just die but in a way a debugger can maybe see why.

    .type       NMI_Handler, %function 
NMI_Handler:
    bkpt        1

    .type       HardFault_Handler, %function 
HardFault_Handler:
    bkpt        2

    .type       MemManage_Handler, %function 
MemManage_Handler:
    bkpt        3

    .type       BusFault_Handler, %function 
BusFault_Handler:
    bkpt        4

    .type       UsageFault_Handler, %function 
UsageFault_Handler:
    bkpt        5

    b           .

    // NOTES: 
    // - fixed at 0x8000040
    // - these ptrs are used by Micropython code
bootloader_info:
    .align      6

    .word       callgate_entry0         // start of callgate (expect 08000x05)
my_version_code:
    .word       0x100                   // callgate protcol version, in BDC, unused
    .word       0                       // reserved words
    .word       0
    .word       0
    .word       0


    .align      4
    .ascii      "(c) Copyright 2018-2019 by Coinkite Inc. \n"
    .ascii      " \n"
    .ascii      "This space for rent! Just 2BTC/year. \n"
    .ascii      " \n"

    //
    // Remainder is flexible for location
    //

    .align      2
    .type       reset_entry, %function       // critical to have this, marks thumb entry pt
reset_entry:

    // do the critical one-time setup of firewall
    bl      firewall_setup

    // init some other things, maybe the screen
    mov     r0, -1
    mov     r1, 0
    mov     r2, 0
    mov     r3, 0
    bl      callgate_entry0

    // get a ptr to real code
    // load R1 with 0x08008000 value: start of firmware's area
    movw    r1, (0x08008000 >> 12)
    lsl     r1, 12

    // set stack pointer to their preference
    ldr     r0, [r1]
    mov     sp, r0

    // Read reset vector, and jump to it.
    mov     r0, 1           // set reset_mode arg: 1=normal?
    ldr     lr, [r1, 4]
    bx      lr


    //
    // Firewalled region starts here, must be 0x100 aligned.
    //
    .section .firewall_code
    .align      8
firewall_starts:
    .word       0x0f193a11                      // my elite-speak is terrible
    .type       callgate_entry0, %function      // critical to have this, marks thumb entry pt
callgate_entry0:

    // Wipe our sram completely
    // CONCERN: damages r9, r10
    movw        r9, BL_SRAM_BASE & 0xffff
    movt        r9, BL_SRAM_BASE >> 16
    mov         r10, BL_SRAM_SIZE
    add         r10, r9, r10

wipe_loop1:
    str         r10, [r9], +4                   // will write 0x10008000
    cmp         r9, r10
    bne         wipe_loop1

    // switch to our own stack (but save caller's stack ptr)
    mov         r10, sp
    mov         sp, r9

    push        {r10, lr}
    // do the real work
dispatcher:                                     // just for debuger view
    bl          firewall_dispatch

    pop         {r10, lr}
    mov         sp, r10

    // clear our sram completely
    movw        r9, BL_SRAM_BASE & 0xffff
    movt        r9, BL_SRAM_BASE >> 16
    mov         r10, BL_SRAM_SIZE
    add         r10, r9, r10

wipe_loop2:
    str         r0, [r9], +4
    cmp         r9, r10
    bne         wipe_loop2

    bx          lr

    .end
