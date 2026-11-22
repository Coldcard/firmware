# BIP-85 Passwords

This feature derives a deterministic password from your seed,
according to [BIP-85 PWD BASE64](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#pwd-base64).
Generated passwords can be sent as keystrokes via USB to the host computer,
effectively using Coldcard as specialized password manager.

In addition to deriving up to 10,000 distinct secure passwords, the Coldcard
can also type them into a computer by emulating a USB keyboard, and simulating the
keystrokes needed to type the password.

#### Requirements

* Coldcard Mk4 or Mk5 (firmware 5.0.5 or newer), or any Q
* USB-C with data link (won't work with power only cable from Coinkite)

## Type Passwords over USB

1. To enable "Type Passwords" feature, connect your Coldcard to host PC with USB cable (check requirements) and go to Settings -> Keyboard EMU -> Enable.
2. Go back to top menu and "Type Passwords" option will be shown below "Address Explorer".
3. Select "Type Passwords" from the main menu. USB switches to keyboard emulation and `Switching...` is shown on screen. 
4. Choose a password length from 21 to 86 characters (default 21).
5. Choose "Password index" (BIP-85 index).
6. It takes a moment to generate the password, and then you can scroll down to check BIP-85 path used and double-check password to be typed.
7. To send keystrokes, place mouse at required password prompt and press OK. This will send desired keystrokes plus hit enter at the end.
8. You are back at step 4 and can continue to generate passwords.

Cancel the length prompt to exit "Type Passwords". This turns off keyboard emulation and enables normal USB mode if it was enabled before. Otherwise, USB stays disabled.

## View BIP-85 passwords

1. Go to Advanced/Tools -> Derive Seed B85 -> Passwords
2. Choose a password length from 21 to 86 characters (default 21 → ~126 bits) 
3. Choose "Password/Index number" (BIP-85 index).
4. Screen shows generated password, path, and entropy from which password was derived
5. A few different options are available at this point (on Mk; on Q the NFC and
   QR buttons are used instead of (3)/(4)):
   1. press (1) to save password backup file on MicroSD card (cleartext!)
   2. press (2) to save to Virtual Disk (only when available)
   3. press (3) to send over NFC (only appears when NFC is enabled)
   4. press (4) to view password as QR code
   5. press (6) to send keystrokes over USB (this enables keyboard emulation, sends keystrokes + enter, then disables keyboard emulation)

## Keyboard language settings

Emulated Keystrokes are mapped to specific characters based on your host PC keyboard
language settings. For Coldcard to be able to type the correct BIP-85
password your host computer MUST use language settings that
corresponds to a [QWERTY](https://simple.wikipedia.org/wiki/QWERTY) key layout,
including number row directly above QWERTY:

```
1 2 3 4 5 6 7 8 9 0 - =
 Q W E R T Y U I O P [ ] \
  A S D F G H J K L ; '
   Z X C V B N M , . /
```

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

Check [BIP-85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki#pwd-base64)
for the complete specification.

Coldcard supports password lengths from **21 to 86** characters, including
the BIP-85 picker in Secure Notes on Q. The default remains **21**, preserving
existing passwords with approximately 126 bits of entropy.

Length is part of the derivation path: changing it produces a different password,
not a longer or shorter version of the same password. Record both the length and
index to reproduce a password using the same source wallet (including any BIP-39
passphrase). The path shown on screen and in file exports includes both values.

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


