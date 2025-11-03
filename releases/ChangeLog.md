# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

# Shared Improvements - Both Mk4 and Q

- Enhancement: Address format guessing changed away from using PSBT XPUB's derivation paths.
  Now based on witness/redeem script of first PSBT input instead.
- Enhancement: Show master XFP of backup secret and ask user for confirmation before loading backup.
- Enhancement: Show firmware version added to hobbled Advanced/Tools menu.
- Bugfix: Exiting text input of Custom Backup Password caused yikes.
- Bugfix: Temporary seeds in SSSP mode were not able to update block height.

# Mk4 Specific Changes

## 5.4.5 - 2025-11-03

- None.


# Q Specific Changes

## 1.3.5Q - 2025-11-03

- Enhancement: Show backup filename at the top of the screen during backup password entry.



# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk4.md`](History-Mk4.md)
- [`History-Mk3.md`](History-Mk3.md)

