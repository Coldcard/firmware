# Developers on Coldcard

Yes, external developers can modify Coldcard... We've saved 128k of flash just for you!

## Approaches

### Hard Core

- build a new image, all the way to a DFU file (see `../stm32/Makefile`)
- sign with non-production key, provided in github tree
- install your DFU file using existing upgrade methods (microSD, usb upload)
- you can replace any part of the python code, and even the mpy interpreter itself
- you cannot change the bootrom, and it still runs first
- your code will not be signed by the factory key, so warning and delay, is shown:
  ![dev-warning screen](dev-warning.png)
- to get green light, the user (who knows the main PIN) must do the "bless" operation
- you can distrubute your DFU file to the world
- you can take factory-fresh Coldcards, destroy the tamper-evident bag, and load your
  firmware onto them before shipping to your customers.


### Medium Core

- install any published dev version (or build your own, see above)
- enable the virtual disk feature:
    Advanced > Danger Zone > I Am Developer. > Enable USB Disk
- REPL and mass-storage emulation will now be active
    - or you can just enable the REPL, and connect there and experiment first
- expect to find helpful file: `/Volumes/COLDCARD/README.txt`
- write code and save into `.../COLDCARD/lib`
    - any same-named file will replace built-in stock module
    - `lib/boot2.py` and `lib/main2.py` are loaded if they exist during boot sequence
    - the only python you cannot override is `main.py`
- RAM limits complexity of the override you can do (but freezing your micropython helps)
- you cannot change the bootrom, and it still runs first
- changes to the virtual disk cause the light to go red, you'll need to bless after
  each change you make.
- distribute your version by capturing an image of your working virtual disk drive,
  and then putting just that into a DFU file (128k)
    - users will have to have a similar dev version of main firmware, but
      you would probably give it to them, as separate DFU file.
    - both files could be put into a single DFU, but that's not supported by
      MicroSD upgrade method

### Soft Core

- Send an email to support asking for your altcoin to be supported. Await reply patiently.


## Shortcuts and Accerations

- You can enable USB, or USB disk emulation, automatically at the end of `boot2.py`. 
  Mount the emulated disk, and create this file, as `/Volumes/COLDCARD/lib/boot2.py`

```python
# start the REPL very early
import uasyncio.core as asyncio
from usb import enable_usb

loop = asyncio.get_event_loop()
enable_usb(loop, True)
```

- To skip the prompts for the PIN, assuming correct PIN is '12-12'... add this code
  to `boot2.py` or run once when the system hasn't yet logged in.

```python
from main import settings
settings.set('_skip_pin', '12-12')
```

- For max crash-change-rerun speed, enable the mass storage all the
  time, and work directly in `/COLDCARD/lib` files. After making a
  change, you just need to do a warm reboot (^D in REPL, 'warm reset'
  on menus). At that point, `main.py` runs, and your code will be
  used again. The USB doesn't disconnect, and the drive will still
  be mounted, ready for more changes.

## Limitations

- You cannot enable mass storage, virtual comm port (VCP = REPL access) and also HID
  for the Coldcard protocol at the same time. Pick any two.

- `.py` files in `/lib` will be interpreted at runtime. This is slow, and bytecode
  takes large amounts of RAM. Some files in the normal code are too big to even
  fit in RAM. The solution is to freeze your code before copying onto Coldcard. See the
  `stm32/Makefile` target `up` which does a build (freezing all the files, using
  `mpy-cross`) and then rsyncs the changed `.mpy` files into place. You'll want to do
  this on a smaller scale, and probably only for the files you are working on.


