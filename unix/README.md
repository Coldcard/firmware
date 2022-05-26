# Coldcard Desktop Simulator

## One Time Setup

    make setup
    make ngu-setup

## Usage

    make && ./simulator.py


## Other Startup Flags

The default is to boot up, skip the tedious PIN entry step, and start as a functional
wallet (on testnet, always with the same seed). But there are other options:

- `-w` => like a factory-fresh unit; no PIN, no secrets
- `-l` => PIN is set (12-12) but no secret yet
- `-2` => enable a secondary wallet, with pin 33-33 and no secret
- `-q` => boot and drop into REPL; does nothing else, no setup
- `-f -w` => boot like a unit that hasn't left factory yet
- `-p` => pretend we don't know the seed words (xprv import) and so menus are different
- `--ms` => define a 2-of-4 multisig wallet, and start off in multisig wallet menu; cosigners are
            "Me", "Myself", "And I" and empty string. BIP45 path.
        - add `--p2wsh` or `--wrap` for the other two address types
- `-s` => go to the MicroSD menu at startup
- `--mk2` => emulate mark2 hardware (older micro, etc), default is current-gen (mark4)
- `--mk3` => emulate mark3 hardware
- `--mk4` => emulate mark4 hardware
- `-g` => don't skip login sequence
- `--addr` => go to the address explorer at startup
- `--xw` => go to the wallet export submenu
- `--paper` => go to the Paper Wallet menu at startup
- `--xfp F0012345` => pretend like the XFP of secret is F0012345: useful for debug of PSBT files
- `--mainnet` => start on mainnet instead of testnet
- `--seed "art art ... food"` => set the seed phrase to 24 words provided
- `--metal` => use USB attached Coldcard for bootrom and SE features
- `--metal --sflash` => copy SPI flash contents at boot time from real device (no writeback)
- `--nick Name` => set the pre-login nickname for the Coldcard so it will be shown
- `--delay X` => set the "login countdown" value to X minutes, also force login
- `--set key=val` => preset the setting 'key' to be 'val' 
- `--msg` => jump to message signing from SD card menu item
- `--hsm` => enable existing HSM policy
- `--users` => preset a few users: "totp", "hotp" and "pw"
- `--user-mgmt` => go to the User Management menu inside settings
- `--pin 123456-123456` => set PIN code to indicated value
- `--deriv` => go to the Derive Entropy menu inside settings, also loads XPRV from BIP
- `--secret 01abababab...` => directly set contents of SE secret, see SecretStash.encode()
- `--eject` => pretend no (simulated) SD Card is inserted
- `--eff` => (mk4) wipe setttings at startup, use simulator defaults
- `--seq 1234yx34` => after start, enter those keypresses to get you to some submenu

See `variant/sim_settings.py` for the details of settings-related options.

## Requirements

- uses good olde `xterm` for console input and output
- this directory has additional `requirements.txt` (a superset of other requirements of the project)
- run "brew install sdl2" before/after doing python requirements
- run "make setup" then "make"
- then "./simulator.py"

# MacOS building

- Follow instructions on <https://github.com/micropython/micropython>
- probably: `brew install libffi` if not already present
- to get `pkg-config libffi` to output useful things, need this:

    setenv PKG_CONFIG_PATH /usr/local/opt/libffi/lib/pkgconfig

- but that's in the Makefile now

# Other OS

- linux supported (only tested on debian based Ubuntu 20.04), please check main README.md
- no Windows


