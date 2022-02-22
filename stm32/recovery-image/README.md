
## Recovery Disk Image

Mk4 bootloader is smart enough to read an SD card. You will only
be able to trigger the SD card loading code, if it was powered down
during the upgrade process. At that point, the intended firmware
image has been lost because it it held in PSRAM only during the
flash writing process.

The bootloader will only install an image of exactly the same version
as was being installed when interrupted. This is done by verifying
the checksum vs. a value held in SE1 by the pin-holder.

This directory holds data and code to build a special SD-card disk
image will all possible releases. The goal is a single file that
can be used restore a Mk4 Coldcard of any (intended) version.
