add-symbol-file gpu.elf 0x08000000

# hex for all numbers
set output-radix 16

# kill X repeats N times, which interfere w/ cut-n-paste into python of dumps
set print repeats 128

# Use ST-Link (st-utils)
#target extended-remote :4242

# Connect to the OpenOCD gdb server (needs to be already running & connected)
target extended-remote :3333

define reset
mon reset init
end

define wipe_chip
mon flash erase_sector 0 0 last
mon reset halt
end
