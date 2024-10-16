# Web 2FA Authentication

How to support [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238)
TOTP (Time based One Time Password) 2FA check, on our little embedded
device without a clock?

Solution: Store the preshared secret in the Colcard, and send that
securely to a trusted webserver which knows the time and can do a
fancy UX. The backend accepts the numeric code and reveals a secret
that can be used back on the Coldcard to authorize an action.

## History / Background

The HSM feature uses HOTP tokens, which do not require a backend,
but are not as robust as time-based tokens.

For now Web2FA is only being used as part of CCC spending policy (opt in),
but we may find other uses for it.

## How It Works

- Web backend has a ECC keypair, with pubkey known to CC firmware releases.
- Usual 2fa base32 secret is picked by CC and stored in CC (so that server is stateless)
- CC creates URL encrypted to the pubkey of server, containing args: 
  - shared secret 
  - the good nonce (16 bytes, or only 8 decimal digits for Mk4) to be provided back
    on successful auth
  - flag if Q model, so can provide a QR to be scanned in that case (rather than digits)
  - some text label for what's being approved [presented to user so they can pick
    correct 2fa shared secret]
  - above is all encrypted in the URL.
- user is sent to that encrypted URL using NFC tap on the Coldcard
- user arrives at server:
  - shown label [which also indicates the server can be trusted, since only it could decrypt it]
  - prompt for 6 digits from authenticator app
  - does [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) 2FA check 
- checks using current time and the shared secret provided by CC, fails if wrong.
  - time based failure: offer retry (they typed too slow / minor clock drift)
  - can offer to retry, but also do some rate limiting (only one attempt per 30-sec period)
  - server will store very recent responses so attacker cannot get two codes
    in any 30sec period (ie. blocks immediate reuse of same URL)
- if Q, show a QR code to be scanned, with the full nonce
- for non-Q system, a 8-digit decimal value is given: user has to enter that into the Coldcard
- web site shows instructions about what to do next on product.

## From Coldcard PoV

- makes complex encrypted URL, waits for number back (or QR)
- it's either the nonce from the URL, or fail
- if the good nonce, then we know the server knows our shared secret and we
  are trusting it actually verify the 2FA token.

## Encryption - Simple ECDH

- CC picks a secp256k1 keypair, generates compressed pubkey
- multiplies that by server's known public key, sha256(that coordinate) is the session key
- apply AES-256-CTR over URL contents (ascii text)
- prepend 33 bytes of pubkey, and base64url encode the result

## Trust Issues

- 2FA enrol happens on the CC, which picks the shared secret and shows QR for mobile
  app setup. Same TRNG process as picking a seed.
- Server knows the shared secret, but only during operation, and we won't store it [sorry,
  gotta trust us on that, but no help to us to store it].
- Only we can run the server, because the private key is company-secret.
- MiTM and network snoopers get nothing because HTTPS is used and only your browser
  can see the nonce, and only after you've given the right digits.

## URL Format 

    https://coldcard.com/2fa?ss={shared_secret}&q={is_q}&g={nonce}&nm={label_text}

- `shared_secret`: 16 chars of Base32-encoded pre-shared secret
- `is_q`: flag indicating use of QR to provide nonce back to user
- `nonce`: text string that is either 8 digits for Mk4, or hex digits for QR
- `nm`: human readable label for the transaction/purpose

Server will accept plaintext arguments as above, but normally everything
after the question mark is encrypted.

