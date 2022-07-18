# BIP-85 Passwords

This feature derives a deterministic password according from your seed,
according to [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
(with the recent changes 
[proposed here](https://github.com/scgbckbone/bips/blob/passwords/bip-0085.mediawiki)).
Generated passwords can be sent as keystrokes via USB to the host computer,
effectively using Coldcard as specialized password manager.

In addition to deriving up to 10,000 distinct secure passwords, the Coldcard Mk4
can also type them into a computer by emulating a USB keyboard, and simulating the
keystrokes needed to type the password.

#### Requirements

* Coldcard Mk4 with version 5.0.5 or newer
* USB-C with data link (won't work with power only cable from Coinkite)

## Type Passwords over USB

1. To enable "Type Passwords" feature, connect your Coldcard to host PC with USB cable (check requirements) and go to Settings -> Keyboard EMU -> Enable.
2. Go back to top menu and "Type Passwords" option will be shown below "Address Explorer".
3. When it is time to enter a secret password, select "Type Passwords" from the main menu. After 
an information screen, the USB emulation will be switch to keyboard emulation
and `Switching...` shown on the screen.
4. Choose "Password index" (BIP-85 index) and press OK to generate that password.
5. It takes a moment to generate the password, and then you can scroll down to check BIP-85 path used and double-check password to be typed.
6. To send keystrokes, place mouse at required password prompt and press OK. This will send desired keystrokes plus hit enter at the end.
6. You are back at step 4, and can continue to generate passwords or you can press X
to exit. Exiting from "Type Passwords" will cause Coldcard to turn off keyboard emulation and enable normal USB mode if it was enabled before. Otherwise, USB stays disabled.

## View BIP-85 passwords

1. Go to Advanced/Tools -> Derive Seed B85 -> Passwords
2. Choose "Password/Index number" (BIP-85 index) and press OK to generate password.
3. Screen shows generated password, path, and entropy from which password was derived
4. A few different options are available at this point:
   1. press 1 to save password backup file on MicroSD card (cleartext!)
   2. press 2 to send keystrokes (this will first of all enable keyboard emulation, then send keystrokes + enter, and finally disables keyboard emulation)
   3. press 3 to view password as QR code
   4. press 4 to send over NFC (only appears when NFC is enabled)

## Keyboard language settings

Emulated Keystrokes are mapped to specific characters based on your host PC keyboard
language settings. For Coldcard to be able to type the correct BIP-85
password your host computer MUST use language settings that
corresponds to a [QWERTY](https://simple.wikipedia.org/wiki/QWERTY) key layout.

Passwords generated and shown on Coldcard will always be correct
with respect to BIP-85. However, when sending keystrokes, for example
on German keyboard, what was typed will not match the text that was
generated and shown on Coldcard's screen.

For example, if the correct password is `zYLoepugzdVJvdL56ogNV` but when used
with German keyboard language settings, what will be typed is
`yZLoepugydVJvdL56ogNV`. You can see that German keyboard is not
QWERTY, but it is QUERTZ (y and z are swapped).

Even with "non-standard" keyboard language settings, Coldcard always
sends exact same keystrokes for specific password index and it is
deterministic, as long the keyboard language setting do not change.
However, BIP-85 won't be respected in this case.

## Coldcard Specifics

Check [BIP-85](https://github.com/scgbckbone/bips/blob/passwords/bip-0085.mediawiki)
for complete specification of the new addition to BIP-85.

Coldcard does not allow you to specify password length - we always
use length of **21**. Passwords of this length generated according
to BIP will have approximately 126 bits of entropy. This is on par
with bitcoin security model and therefore all passwords the Coldcard
will generate are considered very strong.

## Examples

Using below seed, path and index, we generate passwords shown in the table:

```shell
wife shiver author away frog air rough vanish fantasy frozen noodle athlete pioneer citizen symptom firm much faith extend rare axis garment kiwi clarify
```

| Index | Path                       | Password |
|-------|----------------------------|----------|
| 0     | m/83696968'/707764'/21'/0' |  BSdrypS+J4Wr1q8DWjbFE |
| 1     | m/83696968'/707764'/21'/1' |  TkDX7d9fnX9FZ9QEpjFDB |
| 2     | m/83696968'/707764'/21'/2' |  cvfdmoZL3BcIpJ7G+Rb8k |
| 3     | m/83696968'/707764'/21'/3' |  wsCALdN+GgbSOGyGE9aRN |
| 4     | m/83696968'/707764'/21'/4' |  HfYbWx7gVmUmb2Bw4o4QD |
| 5     | m/83696968'/707764'/21'/5' |  vLOf9WPO5QiPbOTEbz/yJ |
| 6     | m/83696968'/707764'/21'/6' |  1oSUs7Cy3fnpdh/fAS7EK |
| 7     | m/83696968'/707764'/21'/7' |  seh9WN6mlvPPB5jdVz3xN |
| 8     | m/83696968'/707764'/21'/8' |  U4RD0R0A0RjpHOFtwnv9k |


## Incompatible Applications

Although the Coldcard is emulating a keyboard at the lowest possible level,
for some reason occasionally high-level applications have
trouble with our high-speed typing.

- KeePass2 2.45 (under Ubuntu). Capital/lowercase letters may be incorrectly typed. Use KeePassXC instead.


