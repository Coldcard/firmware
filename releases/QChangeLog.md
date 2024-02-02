# Q Unique Features / Improvements

## Features

- Secure Notes & Passwords: stash text and/or passwords in your Q. 
- Scan Any QR: and the Q will figure something useful to do with it.
- Press QR or NFC key in many contexts and useful things happen (may not be documented)
- QR icon in corner: can paste into text field from QR


## Little Things

- whitens TRNG source for seed generation with double sha256 instead of single


## Secure Notes & Passwords

- store notes (freeform text) and/or passwords
- "note" has a title and freform text
- "password" has title, username, website, and notes.
- detects Google Auth app export QR and provides title
- detects OTP 2FA (RFC ?) QR code and provides nice title
- detects URL in QR, and uses domain name as title
