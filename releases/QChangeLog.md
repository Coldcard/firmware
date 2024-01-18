# Q Unique Features / Improvements

## Features
- Secure Notes & Passwords: stash text and/or passwords in your Q. 
- Scan Any QR: and the Q will figure something useful to do with it.
- Press QR or NFC key in many contexts and useful things happen (may not be documented)


## Little Things
- whitens TRNG source for seed generation with double sha256 instead of single


## Secure Notes & Passwords
- store notes (freeform text) and/or passwords
- "note" has a title and freform text
- "password" has title, username, website, and notes.
- QR: can paste into note from QR
- NFC: shares text of note (or password) if NFC is pressed
- detects Google Auth app export QR and provides title
- detects OTP 2FA (RFC ?) QR code and provides nice title
