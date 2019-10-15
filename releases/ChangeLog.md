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
