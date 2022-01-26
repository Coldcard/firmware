# Developers on Coldcard

Yes, external developers can modify COLDCARD and make their own versions!

## Approaches

### Hard Core

- build a new image, all the way to a DFU file (see `../stm32/Makefile`)
- sign with non-production key, provided in github tree (key zero)
- install your DFU file using existing upgrade methods (microSD, usb upload, VirtDisk)
- you can replace any part of the python code, and even the mpy interpreter itself
- you cannot change the bootrom, and it still runs first
- since your code is not signed by a factory key, a warning and forced delay always occurs:

![custom warning screen](dev-custom.png)

- in versions before the Mk4, if you had the green light set, via blessing the custom firmware,
  this delay/warning could be avoided, but that is no longer the case.
- you can distrubute your DFU file to the world, but everyone who runs it will see above warning
- remember the main PIN has to be set and provided correctly before new firmware can be installed
- your COLDCARD will be bricked if your code crashes before it gets running "enough" that you
  can upload a corrected version. Bugs in the boot & login sequence are fatal in that sense.

### Medium Core

- Develop your changes using the Simulator (see `../unix`)
- Submit a PR (pull request) explaining your new feature or fix.
- Coinkite team will review for security and other code-quality issues
- your PR could get merged into the next Coinkite firmware release for all to use.

### Soft Core

- Send an email to support asking for your improvements to be implemented.
- Await reply patiently.

## Corrupt Flash

If the red/green light is red, this means some part of flash was
changed without the secure checkum inside SE1 being first updated.
The upgrade process does this correctly in Mk4, and there is no
point time the checksum is wrong, so there should be no way to see this
screen:

![warning screen](dev-warning.png)

But it will be shown if the COLDCARD finds its flash checksum does
not match the checksum held in SE1, secured by the main PIN. This
can be false positive, but in Mk4 we've worked hard to avoid those cases.

A checksum error on the firmware itself (the main code) will always
fail with a "corrupt firmware" (lemon) icon. The broken firmware is not
started, but it's possible to recover the COLDCARD using a firmware from
an SD Card.

You cannot load *new* code via the SD Card firmware recovery mode.
It requires the new firmware (based on whatever is found on SD Card)
to have a checksum that already matches the value found in SE1.
This means only the signed firmware that was attempting to be
installed during the power-fail can be loaded, and not new code you
may have written.


## Shortcuts and Accerations

- You can access a micropython REPL if you are willing to break your case
  and attach to the test points along right edge of board, marked: G=Gnd, R=Rx, T=Tx.
  It's a serial port with 3.3v TTL signals running
  at 115,200 bps. Enter the REPL by pressing `^C` after enabling the REPL in
  Advanced > Danger Zone > I Am Developer. > Serial REPL

- To skip the prompts for the PIN, assuming correct PIN is '12-12'... run this code
  in the REPL:

```python
from nvstore import SettingsObject
s=SettingsObject()
s.set('_skip_pin', '12-12')
s.save()
```

