# Temporary Seeds


[_(new in v5.0.7, requires Mk4)_](upgrade.md)


Temporary seed (renamed in `5.2.0` from Ephemeral seed) is a temporary secret completely separate 
from the master seed, typically held in **COLDCARD<sup>&reg;</sup>** RAM and 
not persisted between reboots in the Secure Element.
Temporary seeds *completely* defeat the design
of Coldcard's security model, based on secure elements.
Enable the `Seed Vault` feature to store these secrets longer-term.
Read more about `Seed Vault` feature below.


!!! warning "Make sure you know what you're doing!"

    This feature is intended for those one-off signings, like recovering
    a lost seed from some other system or importing some seed as a
    balance check. We do not recommend handing unencrypted seed material
    on a regular basis!


## Usage

* if temporary seed is already in use, first home menu option `[<xfp>]` is visible with fingerprint of temporary master secret
* go to `Advanced/Tools > Temporary Seed`

* temporary seed words can be Generated with TRNG
    - `Advanced/Tools > Temporary Seed > Generate Words`

* temporary seed words can be imported
    - `Advanced/Tools > Temporary Seed > Import Words`

* importing extended private keys
    - `Advanced/Tools > Temporary Seed > Import XPRV`
    - `Advanced/Tools > Temporary Seed > Tapsigner Backup`

* temporary seed can be activated from BIP-85 derived secrets - go to `Advanced/Tools > Derive Seed B85` and pick types of secret. Keep in mind that only word based and xprv based secrets can be used as temporary seed.
    - `12 words`
    - `18 words`
    - `24 words`
    - `XPRV (BIP-32)`
    - pick derivation `Index` in next prompt, or just press OK for index 0
    - Press (2) in next prompt to activate derived secret as a temporary seed

* temporary seed can be activated from Duress Wallet
    - go to `Settings -> Login Settings -> Trick Pins`
    - add new Duress Wallet trick pin and save it
    - choose newly created trick pin in trick pins menu and use `Activate Wallet` option

* temporary seed can be obtained from `SeedXOR`
    - go to `Advanced/Tools -> Danger Zone -> Seed Functions -> SeedXOR`
    - pick `Restore Seed XOR` option and provide all XOR parts
    - Press (2) to activate restored seed as temporary seed

* BIP-39 passphrase is from version `5.2.0` handled internally as temporary seed


Ability to generate and use **Temporary seed** is available on Coldcard when:

1. no PIN chosen and no secret chosen (newly unpacked Coldcard)
2. PIN set up but no secret chosen yet
3. with both PIN and secret already picked


# Restore Master

[_(new in v5.2.0, requires Mk4)_](upgrade.md)

From version `5.2.0` users no longer need to reboot COLDCARD to return
to their "master seed" (one stored in SE2). Once COLDCARD has temporary
seed active, first item in home menu is `[xfp]` and is a clone of `Ready To Sign`.
Last item in home menu is `Restore Master`.

`Restore Master` offers two options. First, if user presses OK, COLDCARD wipes temporary seed settings
and switches back to master seed and its settings.
If user presses (1) temporary seed settings are preserved for later use and COLDCARD only switches
back to master seed and its settings.

If current temporary seed is also saved in Seed Vault, option to wipe settings is not available.
Seed Vault entries can only be deleted in Seed Vault menu.


# Seed Vault

[_(new in v5.2.0, requires Mk4)_](upgrade.md)

Seed Vault adds the ability to store multiple temporary secrets into encrypted settings for simple
recall and later use (AES-256-CTR encrypted with your master seed's key).
Users can capture and hold master secret from any temporary seed source, including: TRNG, Dice Rolls,
SeedXOR, TAPSIGNER backups, BIP-85 derived values, BIP-39 passphrase wallets.

## Enable Seed Vault

Enable this functionality in `Advanced/Tools -> Danger Zone -> Seed Vault -> Enable`.
Once seed vault is enabled new menu item is visible in home menu `Seed Vault`.
To disable Seed Vault user needs to remove all entries from Seed Vault first.


## Add Seed to Vault

After `Seed Vault` is enabled, users will see a new prompt, after
creation of temporary seed, asking whether to save this temporary
seed to Seed Vault. Press (1) to save or any other key to ignore.

If option to save was chosen, confirmation prompt is shown - `Saved to seed vault.`


## Seed Vault menu

* if Seed Vault is empty `(none saved yet)` is the first menu item followed by shortcut to `Temporary Seed` menu.
* if not empty, saved seeds are listed in menu as `[xfp]`
* if current active temporary seed is stored in Seed Vault - it has checkmark next to it
* if temporary seed is active - last menu item of Seed Vault menu is `Restore Master`

## Seed Vault entry submenu

1. by default `[xfp]` but can be renamed to allow user labeling and leads to additional information about the seed
2. `Use This Seed` allows to switch to the saved temporary seed. If it is already active `In Use` is shown instead.
3. `Rename` allows to change 1. menu item to something personalized to user (limited to 40 characters)
4. `Delete` allows to remove temporary seed from Seed Vault and optionally to completely wipe its settings.
