# Change Log

This lists the changes in the most recent firmware, for each hardware platform.

## 2026-07-31 Hotfix Versions: 5.6.0 & 1.5.0Q

**Urgent hotfix to correct a limited entropy bug**

Please regenerate seeds only with this version of the firmware and any
later updates from today onwards.

**Mk3 users must regenerate any seeds** made on version 4.0.1 or
later as their entropy is critically low at just ~40 bits.  We are
not planning to update Mk3 firmware at this time, so please use
newer hardware or add a BIP-39 passphrase as a stopgap.

On **Mk4, Mk5 and Q entropy** may be as low as ~72 bits. This is
well below our target of 128 bits.

Follow the steps listed in 
[our blog announcement](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
to be safe, and please be careful not to cut corners or rush this process.

# Release History

- [`History-Q.md`](History-Q.md)
- [`History-Mk.md` (Mk4 and Mk5)](History-Mk.md)
- [`History-Mk3.md`](History-Mk3.md)

