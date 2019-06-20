## 2.1.RC0 - June 5, 2019

*2.1.RC0 is for testing purposes only. Please use multisig features only on testnet.*

- Major release with Multisig support!
    - New menu under: Settings > Multisig Wallets
    - Lists all imported M-of-N wallets already setup
    - Export, import for air-gapped creation
    - Related settings and more
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
- Further documentation and Electrum support are in the works.

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
