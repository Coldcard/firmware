# Coldcard Internal Documentation

These docs are meant for you hackers out there... but also for anyone who
wants to understand why it's safe to put your moneys into Coldcard.

- [`security-model.md`](security-model.md) The COLDCARD Mk4/Mk5/Q security model.
- [`pin-entry.md`](pin-entry.md) Huge and detailed discussion of PIN codes and the security element that holds the secrets.
- [`secure-elements.md`](secure-elements.md) How the dual secure elements work together.
- [`dev-access.md`](dev-access.md) How developers can modify Coldcard to extend it.
- [`memory-map.md`](memory-map.md) Memory map highlights
- [`notes-on-repro.md`](notes-on-repro.md) Detailed breakdown of the reproducible build process.
- [`upgrade-recovery.md`](upgrade-recovery.md) Firmware upgrade and recovery process.
- [`backup-files.md`](backup-files.md) Some details of our encrypted backup files.
- [`temporary-seeds.md`](temporary-seeds.md) Temporary (ephemeral) seeds and the Seed Vault.
- [`seed-xor.md`](seed-xor.md) More about _Seed XOR_ feature, including fully worked Seed XOR example, and useful XOR lookup chart.
- [`key-teleport.md`](key-teleport.md) Key Teleport: encrypted transfer of seeds and secrets between Q devices.
- [`spending-policy.md`](spending-policy.md) Spending policy: autonomous signing with configurable limits.
- [`microsd-2fa.md`](microsd-2fa.md) Using a MicroSD card as a second factor for login.
- [`web2fa.md`](web2fa.md) Web 2FA authentication.
- [`bip85-passwords.md`](bip85-passwords.md) Deriving deterministic passwords via BIP-85.
- [`msg-signing.md`](msg-signing.md) COLDCARD message signing.
- [`proof-of-reserves-bip-322.md`](proof-of-reserves-bip-322.md) BIP-322 generic signed message format and proof of reserves.
- [`generic-wallet-export.md`](generic-wallet-export.md) Generic JSON wallet export file format.
- [`bip-21-extensions.md`](bip-21-extensions.md) Coldcard's BIP-21 URI extensions, including multisig ownership address check.
- [`nfc-coldcard.md`](nfc-coldcard.md) NFC support on Coldcard Mk4 and Q.
- [`nfc-pushtx.md`](nfc-pushtx.md) NFC Push Transaction: broadcast a signed transaction via your phone.
- [`usb-batteries.md`](usb-batteries.md) Using USB battery packs with Coldcard.
- [`electrum-usage.md`](electrum-usage.md) Importing seed words into Electrum for funds usage (and other tips).
- [`bitcoin-core-usage.md`](bitcoin-core-usage.md) How to use with Bitcoin Core.
- [`bitcoin-core2of2desc.md`](bitcoin-core2of2desc.md) Airgapped 2-of-2 multisig with Bitcoin Core using descriptors.
- [`limitations.md`](limitations.md) Documented limitations, policy choices, and TODO items.
- [`paperwallet.pdf`](paperwallet.pdf) Example paper wallet template file.
- [`menu-tree.txt`](menu-tree.txt) Dump of the menu system. Incomplete, may be out of date.

