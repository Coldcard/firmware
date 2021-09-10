## 4.1.4 - Sep ??, 2021

- Enhancement: if an XFP of zero is seen in a PSBT file, assume that should be replaced by
  our current XFP value and try to sign the input (same for change outputs and change-fraud
  checks).  This makes building a workable PSBT file easier and could be used to preserve
  privacy of XFP value itself. A warning is shown when this happens.

## 4.1.3 - Sep 2, 2021

- Enhancement: support "importdescriptors" command in Bitcoin Core 0.21 so that
  a descriptor-based wallet is created. PSBT files are then supported natively by
  Core, and the resulting desktop wallet can be used for spending (ie. create PSBT
  via GUI) and also watching. Translation: Easy air-gap PSBT operation with Bitcoin Core!
- Enhancement: remove "m/0/0" derivations from public.txt and address explorer,
  since that path is obsolete and not used by any major wallets now. We can still
  sign PSBT files with that path, but it's an unnecessary risk to show derived
  addresses for a type of wallet that doesn't exist anymore.
- Enhancement: if PSBT input sections don't contain the key path information we need,
  show a more specific error message.
- Bugfix: a PSBT which provided the wrong pubkey (based on UTXO being spent) was not
  flagged as invalid, but instead we proceeded to do nothing. Now says "pubkey vs. address wrong".
- Bugfix: if asked to serialize a partially-signed transaction, we did. Now fails properly.
- Bugfix: if multiple copies of the same BIP-39 passphrase were saved to a card, the menu
  would not display correctly and you might not be able to select your saved value.

## 4.1.2 - July 28, 2021

- Enhancement: Shows QR code with BIP-85 derived entropy value if you press (3) while
  value shown on-screen. Thanks to [@opennoms](https://twitter.com/openoms) for idea.
  Works with 12/18/24-words, XPRV, privatekey and even hex cases.
- Enhancement: Offer to show QR in other places:
    - Coldcard's main XPUB, in Advanced > View Identity
    - Seed words, during picking process (before the quiz)
    - Stored seed words: Advanced > Danger Zone > Seed Functions > View Seed Words
    - TXID of just-signed transaction (64 hex digits)
    - Encryption password for the system backup file (12 words) 
- Enhancement: We now grind a nonce so that our signatures are always 71 bytes or shorter.
  This may save a byte in transaction size, and makes our signatures identical to those
  produced by Bitcoin Core, improving anonymity on-chain. Thanks to
  [@craigraw](https://twitter.com/craigraw) for detecting this.
- Bugfix: On a blank Coldcard, after importing a seed phrase using the
  [Seed XOR feature](https://seedxor.com/), the main menu was not updated to show
  system is "Ready To Sign".
- Bugfix: Red caution light could happen (a false positive) if a specific sequence of
  firmware upgrades and reboots occurred in the right order. Issue could only occur once
  during lifetime of any particular Coldcard.

## 4.1.1 - April 30, 2021

- Bugfix/Enhancement: [Unchained Capital](https://unchained-capital.com/)
  was using the P2SH (BIP-45) value we exported in our multisig
  wallet file (removed in 4.1.0). So we've restored that, added
  BIP-45 path to our generic JSON export (if account number is zero),
  and added a dedicated menu item: Advanced > MicroSD > Export > Unchained Capital

## 4.1.0 - April 29, 2021

- New feature: Seed XOR -- split your secret BIP-39 seed into 2 (or 3 or 4) new seed phrases
    - any combination of found seed word phrases is a fully working wallet (great for duress)
    - still 24 words, and can be encoded onto a SEEDPLATE
    - all parts are required to be known to get back to original
      seed phrase (**not** M of N, always N of N),
    - your existing seed can be split by Coldcard (one already in use)
    - you can do the math on paper, and it's possible to split/combine without the Coldcard
    - see [docs/seed-xor.md](docs/seed-xor.md) for more, and the paper tools you need
      are available at <https://github.com/Coldcard/wordlist-paper>
- Enhancement: Add support for BIP-48 derivations when exporting generic JSON (including
  the accounts number) under Advanced > MicroSD Card > Export Wallet > Generic JSON.
  These are targeted towards multisig wallets, such as
  [Sparrow](https://sparrowwallet.com/docs/coldcard-wallet.html)
- Enhancement: Ask for account number when creating Multisig Wallets via air-gapped
  Coldcards. Use account zero for compatibility with previous versions. No need to
  use same account number on each participating Coldcard, but we recommend that. Creating
  new P2SH (BIP-45) type air-gapped wallets has been removed since it cannot support
  multiple accounts.
- Enhancement: Show new firmware version number and date before installing firmware update.
- Bugfix: Could not clear PIN codes, including the duress PIN, so was not possible to wipe
  the main secret, if a duress PIN had been set. 999999-999999 works again now.
- Bugfix: Deleting a multisig wallet that was identical to another wallet, except
  for different address type, would lead to an error.
- Bugfix: Standardize on BIP-nn in place of BIPnn in source code, messages and docs.

## 4.0.2 - April 7, 2021

- New feature: "Countdown and Brick" (Mk3 only)
    - set a special PIN code, and when used, the Coldcard is immediately bricked while a 
    normal-looking countdown for login is shown (default 1 hour). As an alternative to
    bricking, you can make it consume all but the final PIN attempt.
- Enhancements to "Login Countdown" feature:
    - turning off the Coldcard will not clear the countdown, it continues on next power-up.
    - login countdown time delays are more accurate now.
    - Important: for the first login when firmware runs (immediately after upgrade),
      the login countdown delay, if you had previously enabled it, will **not** be
      enforced. However, the setting is then migrated to a new spot and takes effect going
      forward without any action needed.
- Enhancement: Settings > Display Units: Select how to show Bitcoin amounts when displayed
  on-screen. Choices are _BTC_ (default), _mBTC_ (millibit), _bits_ (aka uBTC),
  and _sats_ (an integer).
- Enhancement: Settings > Disable USB: New setting to disable USB port if your plan
  is air-gap only. Default remains USB port enabled.
- Bugfix: Formatting of larger SD Cards works again (FAT32 support).
- Bugfix: Reject transactions whose outputs are greater than inputs.
- Downgrades to v3 no longer supported.

## 4.0.1 - March 29, 2021

- Fixes security issue in v4.0.0. (3.x.x Unaffected)
- Known issue: formatting of SD Card does not work and leads to a crash.

## 4.0.0 - March 17, 2021

- Major internal changes.
    - now using [Bitcoin Core's "libsecp256k1"](https://github.com/bitcoin-core/secp256k1)
      for all EC crypto operations
    - super fast pure-assembly AES256-CTR code makes USB communications faster
    - newly optimized SHA256 and SHA256(SHA256) code
    - all crypto and BIP39 related code replaced
    - huge thanks to [@switck](https://twitter.com/switck) for the new library!
- Enhancement: During seed phrase import, after 23 words provided, Coldcard will
  calculate the correct checksum and show the valid choices for the last word (there
  will be 8 typically). This means you can pick seed words by drawing from a hat.
- New feature: Secure Device Cloning. Using a MicroSD card, copy your Coldcard's secrets
  and settings to a blank Coldcard. Very quick and easy, uses public key encryption
  (Diffie-Hellman key exchange) and AES-256-CBC for the transfer.
- Bugfix: CSV of addresses explorer export via Address Explorer, when account number
  was used, did not reflect the (non-zero) account number.
- Enhancement: Reproducible builds! Checkout code, "cd stm32; make repro" should do it all.
- Enhancement: Paper wallet feature restored as it was previously. Same cautions apply.
- Enhancement: Inside encrypted backup files (7z), the cleartext filename is no longer
  fixed as `ckcc-backup.txt`. Instead it's a random word and number. Improves plausible
  deniability when backup files discovered.
- Enhancement: Show a progress bar during slow parts of the login process.
- Enhancement: Long menus, like the seed-word picking system, now wrap around from top/bottom, so
  you can get to Z by going up from A.
- Limitation: Mk2 (older hardware, with less memory) may struggle with some of the new
  features, but can still run this firmware release... so you can clone it to your new Mk3!
- HSM/CKBunker mode changes:
    - IMPORTANT: users with passwords will have to be reconstructed as hash algo has changed 
    - when unlocking HSM mode from "boot to HSM mode" (using secret PIN immediately after bootup)
      the HSM policy is no longer removed automatically. 
    - time limit to escape "boot to HSM" mode has doubled from 30 seconds to 1 minute.
- Remaining GPL code has been removed, so license is now MIT+CC on everything.

## 3.2.2 - Jan 14, 2021

- Major Address Explorer enhancements! Thanks go to [@switck](https://twitter.com/switck)
  for this major feature bump.
    - View sub-accounts as exported, just enter the account number.
    - Multisig wallet support! (Caveat: addresses are for verification purposes
      and never for direct use as deposit, so they are partially redacted)
    - Enter any custom derivation path, by entering numbers directly; for gurus.
    - Warning screen can be suppressed after reading first time (press 6)
    - Export of addresses now named "addresses.csv" not ".txt"
- Bugfix: Disable a few more path derivation checks for "Skip Checks" for
  multisig compatibility. Handles error shown when working
  with previously-imported Specter multisig wallets (ie. `multisig.py: 891`).
- Bugfix: Generic wallet export (JSON) name for BIP49 wallets changed
  from "p2wpkh-p2sh" to "p2sh-p2wpkh". Thanks [@craigraw](https://twitter.com/craigraw)

## 3.2.1 - Jan 8, 2021

- Major Multisig improvements! If you are using multisig features, please backup
  your Coldcard before upgrade, just in case (but shouldn't be a problem).
    - Tracks derivation path for each co-signer and no longer assumes
      they all use a shared derivation path. Blocks multiple instances of same XFP in the
      wallet (not supported anymore, bad idea). Various displays updated to reflect
      derivation path change.  Text file import: "Derivation:" line can be repeated,
      applies to all following xpubs.
    - Show Ypub/Zpub formated values from SLIP-132 when viewing details of wallet.
    - Standardize on "p2sh-p2wsh" nomenclature, rather than "p2wsh-p2sh", thanks
      to [@humanumbrella](https://github.com/humanumbrella). For airgaped multisig wallet 
      creation, you must use same firmware verison on all Coldcards or this change can
      make trouble.
    - Address type (p2sh-p2wsh, p2sh, p2wsh) is captured from MS wallets created
      by PSBT file import.
    - Can now store multiple wallets involving same set of XFP values, if they
      have differing subkey paths and/or address formats.
    - New mode which disables certain multisig checks to assist bug compatibility.
- Enhancement: Add support for signing Payjoin PSBT files based on
  [BIP-78](https://github.com/bitcoin/bips/blob/master/bip-0078.mediawiki). 
- Enhancement: Promoted the address explorer to the main menu. It's useful! 
  (credit to @matt_odell)
- Bugfix: zero-length BIP39 passphrase, when saved, would cause a crash when
  restore attempted. We recommend longer passphrases, but fixed the issue.
- Enhancement: Move the "blockchain" setting deeper into the "Danger Zone" and add
  warning screen. This mitigates a concern raised by @benma (Marko Bencun) where
  an attacker could socially-engineer you to sign a transaction on Testnet, which
  corresponds to real UTXO being stolen. Only developers should be using Testnet.
- Bugfix: Display of amounts could be incorrect by a few sats in final digits.
- Bugfix: Incorrect digest method picked when P2SH-P2WSH incorrectly identified as plain P2SH.
- Bugfix: Better error reporting when importing bogus multisig wallet files.
- Enhancement: Files created on MicroSD will have date and time determined by the version
  of firmware that made them. Downstream systems might use this to know when the Coldcard
  should be upgraded, or which firmware version created the data. Idea from
  [@sancoder](https://twitter.com/sancoder)
- Enhancement: Show version of secure element, under Advanced > Upgrade > Show Version.
- Enhancement: Improve 'None of the keys involved...' message to show XFP value actually
  found inside PSBT file.
- Enhancement: "Invalid PSBT" errors are shown with more information now.
- Paper Wallet features temporarily removed to free space; will return in future version.
- License changed from GPL to MIT+CC on files for which the GPL doesn't apply.



*See History.md for older entries*
