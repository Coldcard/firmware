
## Recovery Disk Image

The Mk4 bootloader is smart enough to read an SD card. However, you
will only be able to trigger the SD card loading code, if the system
is powered-down during the upgrade process. At that point, the
intended (new) firmware image has been lost because it is held in
PSRAM (volatile memory) during the flash writing process.

The bootloader will only install an image of exactly the same version
as was being installed when interrupted. This is done by verifying
the checksum vs. a value set in SE1 by the pin-holder. This prevents
side-loading or up/downgrade attacks.

This directory holds data and code to build a special SD-card disk
image with all possible releases. The goal is a single disk image that
can be used restore a Mk4 Coldcard of any (intended) version.
