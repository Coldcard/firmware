
# Firmware Upgrade and Recovery Process

_This document applies only to the Mk4. Earlier COLDCARDs did not use this approach._

On the COLDCARD, we have done away with the slow external SPI flash
(serial flash) chip entirely (used in Mk1-Mk3). In it's place we
use a much faster and huge 64 Mbit PSRAM chip (quad SPI RAM chip:
ESP-PSRAM64H).

This chip is volatile and forgets its contents at power down.

For working space of PSBT files during signing, that's okay but it
can be a problem during firmware upgrades. This document explains
how we've solved the risks of firmware upgrades and possible bricking
that can happen with power fails at just the wrong time.

## Firmware Upgrade Process

Steps:

- firmware image (DFU file) is copied onto the COLDCARD, either by USB or SDCard
- the proposed firmware image (up to about 1.5Mbytes) is stored in PSRAM
- the user approves the upgrade, and they must process the main PIN code to do that.
- firmware image is checked for correct signature from factory (nothing proceeds if
  not signed by a legit key)
- a checksum is calculated over the new firmware, and the current contents of
  flash, including the bootloader code, its secrets, unique identity bits
  (for the main chip). We call this the "world checksum".
- before anything else happens, we update the main secure element (608B) with
  the world checksum, and during boot, knowledge of the world checksum is required
  to light the green genuine light.
- the light stays green at this point, and the system could still boot the old firmware
- flash erasing and writing of the new firmware starts
- this takes about 15 seconds because flash is relatively slow
- once that is done, the system resets, and the normal bootup sequence will
  re-verify the flash for its signature
- the green light will be active because the world checksum was already written earlier
  
## Recovery Cases

When the system boots up, it always checks the firmware's signature. If it's
corrupt or missing, then we attempt a few different recovery stpes.

### PSRAM Holds New Firmware

If the system resets before the flash is erased and programmed completely, we
still have enough information in the PSRAM to start over. If main firmware
is corrupt, then we look in PSRAM for an image that we might have been
burning when we got interrupted. A full signature check is done (so any bitrot
will be detected). 

Importantly, the firmware we find in PSRAM at this point must also reconstruct
the right "world checksum" as is already stored in the 608. If it does not,
then we do not use the contents of the PSRAM and continue with other options.

We need this policy because the PSRAM is an external chip, and an attacker
might try this:

1) Corrupt the main firmware slightly. Perhaps by shining a UV-C light source
   at the bare die. Only one bit flip is required. This is done only to trigger
   recovery mode.

2) Replace the PSRAM contents with a special firmware image. (It would need
   to factory signed, but perhaps it has some feature they want to abuse or
   something.)

3) Power up the COLDCARD, and it would try to restore the firmware image in PSRAM. 

Because of the world checksum, only the intended firmware can be
restored, not any other version. There is no way to for the attacker
to change the other parts of the firmware based just corrupting a few
bits using UV-C.

### Recovering from Power Fails

The most likely way to make the upgrade fail is a power failure
during the 15-second period while the firmware is copied from PSRAM
to main flash. The PSRAM will forget it's contents, and the COLDCARD
no longer has a complete copy of firmware anywhere.

Most products would be a "brick" at this point, and the docs would
warn against power fails during upgrade.  However, the COLCARD can read
SD Cards to load replacement firmware. The card does not need to
be specially prepared, but we recommend erasing it, formating with
FAT32 and then copying just the firmware onto the card.

If the main firmware is corrupt or missing, and the PSRAM does not
hold a suitable firmware upgrade, then the screen will show "Insert Card".
Once a card is inserted, a search is made for a suitable firmware file.

All DFU files will be considered, but you must provide the firmware
file that you were attempting to upgrade to during the power failure,
because the "world checksum" is calculated for each image found on
the card. You will not be able to substitue a newer version of firmware.
Of course, firmware factory signatures are checked as well.


## Key Entry Sequence

We do **not** provide a key sequence to enter recovery mode. This
would be a nice to have to recover from major bugs in the main firmware,
but our security model does not allow it: Since the recovery methods
will only replace the bits you used to have with the exact same
bits you had previously, there is no need to "recover" if the
firmware is already there.

Attackers would not need a sequence, since they can gitch the clock
or use UV-C light on the bare die to change bits.


## Reality of Flipping Bits in Flash

It's not actually possible to flip a few flash bits because this
chip has ECC for all flash cells. It will auto-correct single-bit
errors, and for double-bit errors it stops execution completely.
So good luck attackers, have a nice day!

