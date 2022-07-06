# BIP-85 Passwords

#### Requirements:
* Coldcard Mk4 with version 5.0.5 or newer
* USB-C with data link (won't work with power only cable from Coinkite)

This feature derives a deterministic password according [BIP-85](https://github.com/scgbckbone/bips/blob/passwords/bip-0085.mediawiki), from the seed. \
Generated passwords can be sent as keystrokes via USB to the host computer,
effectively using Coldcard as password manager.

## Type Passwords

1. to enable "Type Passwords" feature, connect your Coldcard to host PC with USB cable (check requirements) and go to Settings -> Keyboard EMU -> Enable.
2. go back to top menu and "Type Passwords" option is right below "Address Explorer".
At this point no USB protocol switching happened (can check with `dmesg` ) and Coldcard is still usable in normal USB mode.
3. after you enter "Type Passwords" and press OK in description of the feature, USB
protocol is changed to emulate keyboard ( `Switching...` shown on the screen).
4. choose "Password number" (BIP-85 index) and press OK to generate password
5. at this point password is generated and you can scroll down to check BIP-85 path and password.
To send keystrokes, place mouse at required password prompt and press OK. This will send desired keystrokes plus hit enter at the end.
6. you're back at step 4. nd can continue to generate passwords or you can press X
to exit. Exit from "Type Passwords" will cause Coldcard to turn off keyboard emulation and enable normal USB mode if it was enabled before. Otherwise USB stays disabled.
7. to disable "Type Passwords" feature go to Settings -> Keyboard EMU -> Default Off.
After return to top menu "Type Passwords" is not available.

## Backup BIP-85 passwords
1. go to Advanced/Tools -> Derive Seed B85 -> Passwords
2. choose "Password/Index number" (BIP-85 index) and press OK to generate password
3. screen is showing generated password, path, and entropy from which password was derived
4. few different options available at this point:
   1. press 1 to save password backup file on MicroSD card
   2. press 2 to send keystrokes (this will first of all enable keyboard emulation, then send keystrokes + enter, and finally disables keyboard emulation)
   3. press 3 to view password as QR code
   4. press 4 to send over NFC (only appears when NFC is enabled)

## Keyboard language settings
Keys are mapped to specific characters based on your host PC keyboard language settings.
For Coldcard to be able to type correct BIP-85 passwords you MUST use language that fulfil below requirements:
1. has to be `qwerty`

Passwords generated and shown on Coldcard will always be BIP-85 correct. However
if you send keystrokes, for example on german keyboard, what was typed will not match what was generated on Coldcard.

For example, correct password is `dKLoepugzdVJvdL56ogNV` but with german or slovak keyboard language settings
what will be typed is `dKLoepugydVJvdL56ogNV`. You can see that german keyboard is not qwerty (y instead of z).

Even with "exotic" keyboard language settings will Coldcard always send exact same keystrokes (for exact same language settings).
Yet BIP-85 won't be respected.

It is considered best practice to always adjust your keyboard language settings to meet requirements. For instance English US or English UK.