# Change Log

This lists the new changes that have not yet been published in a normal release.

**In an attempt to avoid constant rebasing, please leave a blank line around
your addition and anything else already in this file.**

# Shared Improvements - Both Mk and Q

- Change: Restrict the Codex32 checksum calculator to MS1 shares and warn that
  completing a checksum locks in transcription errors.


# Mk Specific Changes

## 5.6.? - 2026-10-??

- Bugfix: Fix awkwardly wrapped share labels when displaying Codex32 QR codes on Mk4 and Mk5.

- Bugfix: Shorten the Shamir Split share-count prompt on Mk4/Mk5 to fit the screen.

- Bugfix: HSM `min_pct_self_transfer` and `EQ_NUM_OWN_INS_OUTS` rules counted
  outputs as ours based on host-supplied PSBT key-path metadata, so a foreign
  output with forged derivation info could satisfy self-transfer requirements.
  Only outputs verified as change are counted now. Thanks to Swaplane for the report.



# Q Specific Changes

## 1.5.?Q - 2026-10-??

- tbd

