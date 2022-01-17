## 5.0.0 - Nov ??, 2021

Mk4 - New hardware

- (mk3&4) Performance improved: some internal objects cached to reduce delays when
  accessing master secret. Helps address explorer, many USB commands and signing.
- Enhancement: Power-down during the login countdown now resets the time delay to force 
  attacker (or yourself) to start over with full delay time.
- Enhancement: if an XFP of zero is seen in a PSBT file, assume that should be replaced by
  our current XFP value and try to sign the input (same for change outputs and change-fraud
  checks). This makes building a workable PSBT file easier and could be used to preserve
  privacy of XFP value itself. A warning is shown when this happens.
- Enhancement: "Advanced > Export XPUB" provides direct way to show XPUB (or ZPUB/YPUB) for
  BIP-84 / BIP-44 / BIP-49 standard derivations, as a QR. Also can show XFP and master XPUB.
Mk4 changes
- PSBT files up to 2 megabytes now supported
