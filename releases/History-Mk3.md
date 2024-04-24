*See ChangeLog.md for more recent changes, these are historic versions*

## 4.1.9 - Jun 26, 2023

- Bugfix: QR codes could not be rendered in 4.1.8 release due to a regression.

## 4.1.8 - Jun 19, 2023

- Bugfix: "Validating..." screen would be shown twice in some cases. Improves signing performance.
- Bugfix: Reproducible builds corrected.

## 4.1.7 - Nov 15, 2022

- Bugfix: Upgrades to 4.1.6 version using SD Card did not work due to an obscure alignment
  bug. USB upgrade did work. A workaround to this issue has been added for this release.

## 4.1.6 - Oct 5, 2022

- Bugfix: order of multisig wallet registration does NOT matter in PSBT signing
- Bugfix: allow unknown scripts in HSM mode
- Enhancement: `OP_RETURN` is now a known script and is displayed in ascii if possible

## 4.1.5 - May 4, 2022

- Enhancement: Support P2TR outputs (pay to Taproot) in PSBT files. Allows
  on-screen verification of P2TR destination addresses (`bc1p..`) so you can send
  your BTC to them. Does **not** support signing, so you cannot operate a Taproot
  wallet with Mk3 COLDCARD as the signing device.
- Bugfix: Yikes error shown during BIP-85 menu operation.
- Enhancement: Rename "Derive Entropy" to "Derive Seed B85" to match Mk4 menus

## 4.1.4 - Apr 26, 2022

- Enhancement: if an XFP of zero is seen in a PSBT file, assume that should be replaced by
  our current XFP value and try to sign the input (same for change outputs and change-fraud
  checks).  This makes building a workable PSBT file easier and could be used to preserve
  privacy of XFP value itself. A warning is shown when this happens.
- Enhancement: "Advanced > Export XPUB" provides direct way to show XPUB (or ZPUB/YPUB) for
  BIP-84 / BIP-44 / BIP-49 standard derivations, as a QR. Also can show XFP and master XPUB.
- Bugfix: Updated domain name from `coldcardwallet.com` to `coldcard.com` in docs and few
  on-screen messages.
- Bugfix: allow sending to scripts that we cannot parse, with a warning, to support
  `OP_RETURN` and other outputs we don't understand well (yet).

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



## 3.1.9 - Aug 6, 2020

- Enhancement: Very minor change so that login feels more responsive.
- Bugfix: Small bug in production selftest. No other changes.

## 3.1.8 - Aug 4, 2020

- Enhancement: Optimized and improved drawing speed on screen, and responsiveness of keypad 
  entry. You'll see some slight changes to login screen (centered now) and massive drawing
  performance improvements system-wide. Laggy and unresponsive keypad is no more!
- New feature: New setting, "Delete PSBTs", will blank and securely erase input PSBT files
  when they are no longer needed. Also renames signed transaction to be `(txid).txn` (in hex)
- Enhancement: The current XFP (xpub fingerprint) is shown on the "Ready To Sign" screen,
  if you have entered an BIP39 Passphrase.
- Enhancement: File names from SD Card are now shown in sorted order.
- Enhancement: Can show the SHA256(file contents) for any file on SD Card. Use
  Advanced > MicroSD > List Files and pick your file. Thanks to B.O. for this idea.
- Enhancement: Enable full BIP-85 support on older Mk2 hardware (derived entropy feature).
- Enhancement: Minor text changes based on feedback from customers.
- Enhancement: Two assertions promoted to text error messags related to bad PSBT files.

## 3.1.7 - Jul 3, 2020

- Bugfix: support use of new security bags with longer serial numbers.

## 3.1.6 - Jun 14, 2020

- Bugfix of the bugfix: Clear up assertion error that occured with some specific sizes of
  transactions.

## 3.1.5 - Jun 13, 2020

- Bugfix: Signing PSBT with finalization, from MicroSD card did not work. Error about
  "HexWriter" was shown. Fixed!

## 3.1.4 - Jun 12, 2020

- Enhancement: Detect, report and block the recently reported type of attack
  against BIP-143 (replay of segwit inputs) with an error message. No changes
  needed to your input PBST files. Will show errors similar to:
  "Input#0: Expected 15 but PSBT claims 5.00001 BTC"
- Enhancement: When the Coldcard is finalizing the transaction, we show the TXID (hex
  transaction ID) of the transaction on the screen. 
- Enhancement: Export deterministically-derived entropy in the form of
  seed phrases (BIP39), XPRV, private key (WIF), or hex digits using new BIP-85 standard.
  Useful for seeding other wallets from your Coldcard, so you don't need to backup
  "yet another" seed phrase. Derived values (all types) can be easly recreated from
  Coldcard later, or the backup of the Coldcard. Does not expose the Coldcard's master
  secret, should new wallet be compromised.
- Bugfix: When scrambled keypad used with the login delay feature, the PIN-entry sequence
  was not scrambled after the forced delay was complete. Thanks to an anon customer
  for reporting this.
- Bugfix: Scrambled keypad didn't change between PIN prefix and suffix.
- Enhancement: QR Code rendering improved. Should be more readable in more cases. Faster.
- Enhancement: View percent consumed of the settings flash space (just for debug)
- Enhancement: New command to clear the UTXO history, in rare case of false positive.

## 3.1.3 - Apr 30, 2020

- Enhancement: Save your BIP39 passphrases, encrypted, onto a specific SDCard, if desired.
  Passphrases are encrypted with AES-256 (CTR mode) using a key derived from the master
  secret and hash of the serial number of the SDCard. You cannot copy the file to
  another card. To use this feature, press (1) after you've successfully entered your
  passphrase. 'Restore Saved' menu item will appear at top of passphrase-entry menu,
  if correctly-encrypted file is detected.
- Enhancement: Export a generic JSON skeleton file, not aligned with any particular
  desktop/mobile wallet, but useful for any such integrations. Includes XPUB (and
  associated data) needed for P2PKH, P2WPKH (segwit) and P2WPKH-P2SH wallets, which
  conform to BIP44, BIP84, and BIP49 respectively.
  Thanks to [@craigraw](https://twitter.com/craigraw) the idea.
- Enhancement: when signing a text file from MicroSD card, if you specify a derivation
  path that starts with `m/84'/...` indicating that you are following BIP84 for
  segwit addresses, the resulting signature will be formatted as P2WPKH in Bech32.
- Minor code cleanups and optimizations.


## 3.1.2 - Feb 27, 2020

- Bugfix: exporting non-zero account numbers didn't work


## 3.1.1 - Feb 26, 2020

- Enhancement: New setting to enable a scrambled numeric keypad during PIN login.
- Enhancement: Press 4 when viewing a payment address (triggered by USB command) to
  see the QR code on-screen (Mk3 only).
- Enhancement: Can enter non-zero account numbers when exporting wallet files for Electrum
  and Bitcoin Core. This makes importing seeds from other systems easier and safer.
- Enhancement: Dims the display when entering HSM Mode.
- Bugfix: Trust PSBT setting (for multisig wallets) was being ignored. Thanks to @CasaHODL
  for reporting this.
- Bugfix: XPUB values volunteered in the global section of a PSBT for single-signer files would
  cause errors (but ok in multisig). Coldcard will now handle this, although it doesn't need them.

## 3.1.0 - Feb 20, 2020

- HSM (Hardware Security Module) mode: give Coldcard spending rules, including whitelisted
  addresses, velocity limits, subsets of authorizing users ... and Coldcard can sign with
  no human present. Requires companion software to setup (ckbunker or ckcc-protocol),
  and disabled by default, with multi-step on-screen confirmation required to enable. Mk3 only.
- Enhancement: New "user management" menu. Advanced > User Management shows a menu
  with usernames, some details and a 'delete user' command. USB commands must be used to
  create user accounts and they are only used to authenticate txn approvals in HSM mode.
- Enhancement: PSBT transaction can be "visualized" over USB, meaning you can view what
  the Coldcard will show on the screen during approval process, as text, downloaded over USB.
  That text can be signed (always with root key) to prove authenticity.
- Enhancement: Sending large PSBT files, and firmware upgrades over USB should be a little faster.
- IMPORTANT: This release is NOT COMPATIBLE with Mk1 hardware. It will brick Mk1 Coldcards.

## 3.0.6 - Dec 19, 2019

- Security Bugfix: Fixed a multisig PSBT-tampering issue, that could allow a MitM to
  steal funds. Please upgrade ASAP.
- Enhancement: Sign a text file from MicroSD. Input file must have extension .TXT and
  contain a single line of text. Signing key subpath can also provided on the second line.
- Enhancement: Now shows the change outputs of the transaction during signing
  process. This additional data can be ignored, but it is useful for those who
  wish to verify all parts of the new transaction.
- Enhancement: PSBT files on MicroSD can now be provided in base64 or hex encodings. Resulting
  (signed) PSBT will be written in same encoding as the input PSBT.
- Bugfix: crashed on entry into the Address Explorer (some users, sometimes).
- Bugfix: add blank line between addresses shown if sending to multiple destinations.
- Bugfix: multisig outputs were not checked to see if they are change (would have been
  shown as regular outputs), if the PSBT did not have XPUB data in globals section.
- NOTE: This is the final version to support Mk1 hardware.

## 3.0.5 - Nov 25, 2019

- Address explorer can show QR code for any address (Mk3 only). Press 4 to view. Once
  shown, press 1 to invert image, and 5/8 for next address. Succesfull scanning requires
  the best phone camera, and some patience, due to limited screen size.
- Export a command file for Bitcoin Core to create an air-gapped, watch-only wallet.
  Requires v0.18 or higher of Bitcoin Core.
  [docs/bitcoin-core-usage.md](./docs/bitcoin-core-usage.md) has been updated.
  Thanks to [@Sjors](https://github.com/Sjors) for creating this new feature!
- Paper Wallets! Creates random private key, unrelated to your seed words, and
  saves deposit address and private key (WIF format) into a text file on MicroSD. If you
  have a Mk3, it will also add a QR code inside the text file, and if you provide a 
  special PDF-like template file (example in ../docs/paperwallet.pdf) then it will superimpose
  the QR codes into the template, and save the resulting ready-to-print PDF to MicroSD.
  CAUTION: Paper wallets carry MANY RISKS and should only be used for SMALL AMOUNTS.
- Adds a "Format Card" command for erasing MicroSD contents and reformating (FAT32).
- Bugfix: Idle-timeout setting should only take effect after the login countdown.
  Thanks to [@aoeui21](https://twitter.com/aoeui21) for reporting this.

## 3.0.4 - Nov 13, 2019

- Bugfix: encrypted backup files larger than 2000 bytes could fail to verify (but restored okay),
  and this can happen now with larger multisig setups involving many co-signers.

## 3.0.3 - Nov 6, 2019

- Add "Login Countdown" feature: once enabled, you must enter you PIN correctly,
  and then wait out a forced delay (of minutes/hours/days) while a count down
  is shown on-screen. Then enter your PIN correctly, a second time, to get in. You must
  provide continuous power to the Coldcard during this entire period!
  Go to Settings > "Login Countdown" for the time intervals to pick from. Thanks
  to [@JurrienSaelens](https://twitter.com/jurriensaelens) for this feature suggestion.
- Nickname feature: Enter a short text name for your personal Coldcard. It's displayed
  at startup time before PIN is entered. Try it out in Settings > "Set Nickname"
- Bugfix: Adding a second signature (multisig) onto a PSBT already signed by
  a different Coldcard could fail with "psbt.py:351" error.

## 3.0.2 - Nov 1, 2019

- New command in Danger Zone menu to view the seed words on-screen, so you can make
  another on-paper backup as needed.
- Robustness: Analyse paths used for change outputs and show a warning if they
  are not similar in structure to the inputs of that same transaction.
  These are imperfect heuristics and if you receive a false positive, or are doing
  weird things that don't suit the rules below, please send an example PSBT to
  support and we'll see if we can handle it better:
    - same derivation path length
    - shared pattern of hardened/not path components
    - 2nd-last position is one or zero (change/not change convention)
    - last position within 200 units of highest value observed on inputs
- Robustness: Improve checking on key path derivations when we encounter them as text.
    - accept 10h and 10p as if they are 10' (alternative syntax)
    - define a max depth (12) for all derivations
    - thanks to [@TheCharlatan](https://twitter.com/the_charlatan_)
- Security Improvement: during secure logout, wipe entire contents of serial flash,
  which might contain PSBT, signed or unsigned (for more privacy, deniability)

## 3.0.1 - Oct 10, 2019

- MARK3 SUPPORT!
    - Adds support for Mark 3 hardware: larger CPU and better secure element (608)
    - Many invisible changes inside the secure element (ATECC608A).
    - Mark3 will brick itself after 13 incorrect PIN codes, so lots of warning are shown.
- Contains all the features of 2.1.6 and still works on Mk1 and Mk2 hardware
- Visual changes to login process (rounded boxes, different prompts, more warnings)
- New USB command to report if Bitcoin versus Testnet setting is in effect.

## 2.1.6 - Oct 8, 2019

- NEW: "Address Explorer": view receive addresses on the screen of the Coldcard, so you can
  be certain your funds are going to the right place. Can also write first 250 addresses onto
  the SDCard in a simple text (CSV) format. Special thanks go to
  [@hodlwave](https://github.com/hodlwave) for creating this feature.
- Bugfix: Improve error message shown when depth of XPUB of multisig cosigner conflicts with path
  details provided in PSBT or USB 'show address' command.
- Bugfix: When we don't know derivation paths for a multisig wallet, or when all do not share
  a common path-prefix, don't show anything.

## 2.1.5 - Sep 17, 2019

- Bugfix: Changes to redeem vs. witness script content in PSBTs. Affects multisig change outputs,
  primarily.
- Bugfix: Import of multisig wallet from xpubs in PSBT could fail if attempted from SD Card.
- Bugfix: Improved message shown if import of multsig wallet was refused during PSBT signing.

## 2.1.4 - Sep 11, 2019

- Bugfix: For multisig change outputs, many cases were incorrected flagged as fraudulent.

## 2.1.3 - Sep 6, 2019

- Visual change: unknown components of multsig co-signer derivation paths used to be
  shown as `m/?/?/0/1` but will now be shown as `m/_/_/0/1`. The blank indicates better
  that we can't prove what is in that spot, not that we don't know what value is claimed.
- Bugfix: Some backup files would hit an error during restore (random, less than 6%). Those
  existing backup files will be read correctly by this new version of firmware.
- Bugfix: P2SH-P2WPKH change outputs incorrectly flagged as fraudulent (regression from v1.1.0)
- Bugfix: Wanted redeem script, but should be witness script for P2WSH change outputs.

## 2.1.2 - Aug 2, 2019

- Add extra warning screen added about forgetting your PIN.
- Remove warning screen about Testnet vs Mainnet.
- Bugfix: Change for XFP endian display introduced in 2.0.0 didn't actually correct
  endian display and it was still showing values in LE32. Correctly corrected now.
    - now showing both values in "Advanced > View Identity screen".
    - some matching changes to ckcc-protocol (CLI tool)
    - when making multisig wallets in airgap mode, you must use latest firmware on all the units
- Bugfix: Error messages would sometimes disappear off the screen quickly. Now they stay up
  until OK pressed. Text of certain messages also improved.
- Bugfix: Show a nicer message when given a PSBT with corrupted UTXO values.
- Bugfix: Block access to multisig menu when no seed phrase yet defined.
- Bugfix: Any command on multisig menu that used the MicroSD card would crash, if
  card was not present.
- Bugfix: When offline multisig signing sometimes tried to finalize PSBT, but we can't.
- Bugfix: For multi-pass-multisig signing, handle filenames better (end in -part, not -signed).


## 2.1.1 - July 3, 2019

- New feature: Create seed words from D6 dice rolls:
    - under "Import Existing > Dice Rolls"
    - just keep pressing 1 - 6 as you roll. At least 99 rolls are required for 256-bit security
    - seed is sha256(over all rolls, as ascii string)
    - normal seed words are shown so you can write those down instead of the rolls
    - can also "mix in" dice rolls: after Coldcard picks the seed words and shows them,
      press 4 and you can then do some dice rolls (as many or as few as desired) and get a
      new set of words, which adds those rolls as additional entropy.
- Wasabi wallet support: remove extra info from skeleton file, change XFP endian, add version field.

## 2.1.0 - June 26, 2019

- Major release with Multisig support!
    - New menu under: Settings > Multisig Wallets
    - Lists all imported M-of-N wallets already setup
    - Export, import for air-gapped creation
    - Related settings and more
    - Electrum support is in the works.
- Broad change: extended public key finger (XFP) values used to be shown in the
  wrong endian (byte swapped), and prefixed with `0x` to indicate they were a number.
  In fact, they are a byte string and should be shown in network order. Everywhere
  you might be used to seeing your XFP value has been switched, so `0x0f056943`
  becomes `4369050F` (all caps, no `0x` prefix). Affected areas include:
    - BIP39 password confirmation screen
    - Advanced > View Identity screen
    - Electrum skeleton wallet export (label of wallet)
    - Dump public data file (text in file header)
    - `xfp` command in ckcc CLI helper (can show opposite endian, if needed)
- Export skeleton wallets for Wasabi Wallet <https://wasabiwallet.io/> to support air-gapped use.
- Summary file (public.txt) has been reworked to include more XPUB values and a warning about
  using addresses your blockchain-monitoring wallet might not be ready for.
- When BIP39 passphrase is given over USB, and approved, the new XFP is shown on-screen for reference.


## 2.0.4 - May 13, 2019

- Bugfix: Clearing duress PIN would lead to a error screen.
- Bugfix: Advanced > "Lock Down Seed" command didn't work correctly.
- Bugfix: Importing seed words manually didn't work on second try (thanks @duck1123)

## 2.0.3 - Apr 25, 2019

- Transaction signing speed improved by about 3X.
- Will warn if miner's fee is over 5% of txn amount (was 1% before). Hard limit remains 10% (configurable, can be disabled completely).
- Robustness: Tighten stack-depth checking, increase heap size, shuffle some memory.
- Bugfix: Transactions with more than 10 outputs were not summarized correctly.
- Bugfix: Consolidating transactions that move UTXO within same wallet are shown better.
- Bugfix: Better recovery from too-complex transaction errors.
- "Don't forget your PIN" warning message is more bold now.

## 2.0.2 - Apr 9, 2019

- Page up/down on long text displays with 7/9 keys
- Public summary file now includes extended master key fingerprint near top of file.
- Bugfix: signing larger transactions could fail due to lack of memory

## 2.0.1 - Apr 4, 2019

- BIP39 Passphrase support: enter up to 100 characters to create
    new wallets  from your existing seed words. Each is a completely
    independent wallet to Electrum and PSBT files, so please make note
    of the extended master fingerprint (eight hex digits).
- Support for Mark2 hardware, with membrane keypad replacing touch interface.
- Adds activity light during MicroSD card read/write (Mk2 only)
- New command: "Lock down seed" which converts BIP39 seed words and passphrase into the
    master xprv and saves that as new wallet secret. Locks in the passphrase, deletes seed words.
- New bootrom, version 1.2.1 with Mk2 hardware support and improved one-wire bus MitM defences.
- Bugfix: extra keypress occurs during certain interactions involving key repeat.
- 2.0.0 vs 2.0.1 bugfix: underscore/space indicator shown on Settings > Idle Timeout menu

## 1.1.1 - Dec 2018

- Rename menu item "Change PIN code" => "PIN Options"
- Trivial bugfix in unused codepath (`get_duress_secret` hits assertion).


## 1.1.0 - Nov 2018

- Allow setting max network fee to a number of possible levels, or disable it (was
  previously fixed to 10%). Thanks to @crwatkins for this suggestion.

- Touch improvements: two new setting, which are between the old 'Least Sensitive'
  and 'Most Sensitive' settings. New menu text.

- Touch sensitivity preference is applied before login, so PIN entry is easier.

- Although we do not use the `bech32_decode()` function recently found to have
  an buffer overflow bug, we've included the fix into our fork of the affected
  library. This change, and the original bug, does not affect the Coldcard firmware
  in any way.

- Correctly include witness data in transactions when signing based on witness
  UTXO data (thanks to @SomberNight)

- Bugfix: Fix divide-by-zero if transaction sends zero amount out (only possible if 
  network fee equals 100% of inputs).

## 1.0.2 - Sep 2018

- Add support for [SLIP-132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
    - yprv/zprv keys can now be imported
    - public.txt file includes both SLIP-132 and BIP-32 values where needed (segwit cases)
    - test cases added to match

- Can create Electrum skeleton wallet for Segwit Native and Segwit P2SH now.
    - caveat: the plugin is not ready yet for P2SH/Segwit, but Segwit native is fine

- Improvements in 'public.txt' output:
    - add SLIP-132 values where we can
    - correct names when used for Litecoin

- Improvements to backup and restore
    - can now restore cleartext backups (for devs only!)
    - fix "Unable to open ... /sd/backup.7z" error


## 1.0.1 - Sep 2018

- Touch sensitivity improvements: now less sensitive (by default) and a new setting can
  change that back to fast and sensitive, or select low sensitivity for noisy environments or
  personal preference.

- Remove respin feature (press 2) when showing seed words, and add confirm step
  to Cancel press. This misfeature was causing grief due to accidents during the
  high-stress seed word process.

- Improvement: show better what's happening during PIN attempt forced delay.

- Bugfix: possible lockup after entering an incorrect PIN code

- Bugfix: 'warm reset' inside Debug Functions didn't work properly.


## 1.0.0r2 - Aug 2018

- Initial release to public
