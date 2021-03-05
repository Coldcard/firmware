#exec-file l-port/build-COLDCARD/firmware.elf
exec-file built/firmware.elf
#add-symbol-file l-port/build-COLDCARD/firmware.elf 0x8000000
add-symbol-file bootloader/bootloader.elf 0x8000000

# hex for all numbers
set output-radix 16

# kill X repeats N times, which interfer w/ cut-n-paste into python of dumps
set print repeats 128

# Use ST-Link (st-utils)
#target extended-remote :4242

# Connect to the OpenOCD gdb server (needs to be already connected)
#   
#   openocd -f openocd_stm32l4x6.cfg
#
target extended-remote :3333

# NOTE: other types of reset don't work (OpenOCD)
define reset
mon reset init
end

# Complete chip wipe, even DFU area?
# TODO: see README for sequence, but needs timing gaps, etc.
define CHIP_WIPE
mon halt
mon stm32l4x unlock 0
mon reset halt
mon halt
mon stm32l4x mass_erase 0
end
