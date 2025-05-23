# COLDCARD Message Signing 

COLDCARD can sign messages send to it via USB with the help of `ckcc` utility, 
sign messages provided via specially crafted file on SD card or Vdisk, 
and Mk4 can also sign messages sent to COLDCARD via NFC.

Signature format follows [BIP-0137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) specification.
COLDCARD Mk3 and COLDCARD Mk4 up to version `5.1.0` used compressed P2PKH header byte for all script types.
From Mk4 `5.1.0` correct header byte is used for corresponding script type.

### Verification

From COLDCARD Mk4 version `5.1.0` users can verify signed messages directly on the device.
If signature file is on SD card or Virtual disk `Advanced/Tools -> File Management -> Verify Sig File`. In case
signature file is detached signature of signed export (or any other file), COLDCARD can check if digest of file 
specified in the message matches contents of file. This requires file signed to be  available on SD card or Vdisk.
File size limit for signature files is approximately 10KB.
If signature file is imported via NFC `Advance/Tools -> NFC Tools -> Verify Sig File`.
To cross-verify COLDCARD verification use https://www.verifybitcoinmessage.com/ as it supports multiple script types.
Bitcoin core can only verify P2PKH.

## Signed Exports

From Mk4 version `5.1.0` most of SD card and Virtual disk exports are accompanied by detached signature file.
If exported file name is `addresses.csv` signature file name will be `addresses.sig`.

### Message construction and signature file format

1. contents of the exported file are hashed with single SHA256 hash
2. `msg = hash from step 1. + two spaces + exported filename (basename)`
3. msg from step 2. is hashed again with Bitcoin msg hash `"Bitcoin Signed Message:" + ser_compact_size(len(msg)) + msg`
4. detached signature file format:
```text
-----BEGIN BITCOIN SIGNED MESSAGE-----
f1591bfb04a89f723e1f14eb01a6b2f6f507eb0967d0a5d7822b329b98018ae4  coldcard-export.json
-----BEGIN BITCOIN SIGNATURE-----
mtHSVByP9EYZmB26jASDdPVm19gvpecb5R
IFOvGVJrm31S0j+F4dVfQ5kbRKWKcmhmXIn/Lw8iIgaCG5QNZswjrN4X673R7jTZo1kvLmiD4hlIrbuLh/HqDuk=
-----END BITCOIN SIGNATURE-----
```

### What is signed

### What Is Signed

1. **Single sig address explorer exports:** Signed by the key corresponding to the first (0th) address on the exported list.
2. **Specific single sig exports:** Signed by the key corresponding to the external address at index zero of chosen application specific derivation `m/<app_deriv>h/<coin_type>'h/<account>h/0/0`.
    * Bitcoin Core
    * Electrum Wallet
    * Wasabi Wallet
    * Samourai Postmix
    * Samourai Premix
    * Descriptor
3. **Generic single sig exports:** Signed by key that corresponds to first (0th) external address at derivation `m/44h/<coin_type>h/<account>h/0/0`.
    * Lily Wallet
    * Generic JSON
    * Dump Summary
4. **BIP85 derived entropy exports:** Signed by path that corresponds to specific BIP85 application.
5. **Paper wallet exports:** Signed by key and address exported as paper wallet itself.
6. **Multisig exports:** public keys are encoded as P2PKH address for all multisg signature exports
    * Multisig wallet descriptor: signed by the key corresponding to the first external address of own enrolled extended key `my_key/0/0`
    * Generic XPUBs export: signed by the key corresponding to the first external address of own standard P2WSH derivation `m/48h/<coin_type>h/<account>h/2h/0/0`
    * Multisig address explorer export: Signed by own key at the same derivation as first (0th) row on exported list. `my_key/<change>/<start_index>`

### What is NOT signed

Multisig exports and generic multisig xpub exports are not signed. It is not clear at this point
whether to sign these exports with some generic single signature key (i.e. `m/44'/<coin_type>'/0'/0/0`)
or with our portion (leg) of script. In both cases script type (address format) would not match as multisignature
message signing is not standardized.

1. **Multisig exports**
2. **Generic multisig exports**