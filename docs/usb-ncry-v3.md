# USB ncry v3

`ncry` is the USB command that starts encrypted communication between a
host client and a COLDCARD. Earlier versions used ECDH to create an AES-CTR
session stream. Version 3 keeps the same general setup flow, but changes the
encrypted message format so each message is authenticated and each direction
uses independent keys.

## What v3 Does

During setup, the host sends an ephemeral public key and requests
`USB_NCRY_V3`. The device replies with its own ephemeral public key, master
fingerprint, and master xpub information. Both sides use ECDH to compute the
same session key.

For v3, that session key is not used directly as one shared CTR stream. Instead
the implementation runs it through an HMAC-SHA256 KDF and derives separate keys
for:

- host to device encryption
- host to device message authentication
- device to host encryption
- device to host message authentication

The KDF binds the output keys to the v3 protocol label, the requested version,
and both ephemeral public keys:

```
transcript = SHA256("ccncry3" || version || host_pubkey || dev_pubkey)
prk = HMAC-SHA256(key=transcript, message=session_key)
okm = HKDF-Expand(prk, "ccncry3", 128)
```

Here `version` is the little-endian 32-bit `USB_NCRY_V3` value, and the public
keys are the 64-byte uncompressed x/y values carried by `ncry`. The same short
COLDCARD ncry v3 label is used for both the transcript hash and HKDF-Expand
context.

The 128-byte KDF output is split into four 32-byte keys, in the same order as
the list above. Encrypted messages then use this wire format:

```
ciphertext = AES-256-CTR(plaintext)        # counter-0 stream, per direction
tag        = HMAC-SHA256(key=mac_key, message=
                 direction || LE32(sequence) || LE32(length) || ciphertext)[0:16]
wire       = ciphertext || tag
```

The direction value is different for host-to-device and device-to-host traffic.
The authentication tag is the first 16 bytes of the HMAC-SHA256 result. The
sequence number is an unsigned little-endian 32-bit value. It starts at zero
for each direction and increments after each valid message. Sequence number
`0xffffffff` may be used once; the next message in that direction must fail
instead of wrapping to zero.

## Fixed Test Vector

The following values are normative and are independently checked by the
firmware and `ckcc-protocol` test suites:

```text
session_key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
host_pubkey = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
              202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f
device_pubkey = 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f
                606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f
transcript = a5209d34d0dd4dc037e973145f388686e03a78c8e9db20e353a86022b19b1dce
prk = ebf7de0dac1c1bd46a4290865e2fc49b9bdeb85cc66e5d73525c5f97602ab338
h2d_enc = 4ae5bbe99e5565f58383634c28916469c6f9777392c5fc4d16e1a4ccffce51d4
h2d_mac = 8641e0d7e0e9d7610cd33bc6c6025dd772faaad259bb6492ea59362ab7e284df
d2h_enc = 176e6002488acf16c63646f483d7965c78b41159863e77710fd069a3c7b4ab32
d2h_mac = 07bdfcd21c34b50241509b146675a5f06d385242dbaf4d0060e2ccfee819706e

request plaintext = 70696e676e6372792d76332d766563746f72
request wire = 4d90a086a4411368708106e3b6ae321fef9d
               5fc1cfedaf2be32b1cdb55ce62b48029
response plaintext = 62696e796e6372792d76332d766563746f72
response wire = 026d1b5205e4686f3682acab956ac2690efe
                f79887d299df4e655f887a112a7081d5
```

Both wire examples use sequence number zero. The request direction is
`C2D\0`; the response direction is `D2C\0`.

## Security Properties

ncry v3 improves the USB encrypted channel in three broad areas:

- Confidentiality: passive observers cannot read encrypted command or response
  contents, and host-to-device and device-to-host traffic do not reuse the same
  CTR stream.
- Message integrity: tampered ciphertext is rejected before it is decrypted,
  and CTR bit-flipping attacks are blocked by the message authentication tag.
- Session ordering: same-session replay or reordering is rejected by the
  sequence number, and cross-direction reflection is rejected by the direction
  value in the MAC.

After v3 setup, all future USB commands in that session are expected to be
encrypted. Like v2, v3 is a bound USB mode: the device rejects a second `ncry`
setup attempt for that USB handler.

## What v3 Does Not Do

ncry v3 does not authenticate the COLDCARD endpoint by itself. The ECDH public
keys in the `ncry` setup are ephemeral and unsigned. An active attacker in the
middle can establish one encrypted session with the host and another encrypted
session with the device.

In that attack, v3 still protects each individual encrypted session from
passive reading, tampering, replay, and reflection. It does not prove that the
host is talking directly to the intended COLDCARD. Endpoint authentication is
provided by the separate `mitm` command.

v3 also does not provide downgrade negotiation or recovery from a
desynchronized stream. Any authentication or framing failure is terminal: the
firmware stops processing USB commands for that session, and the client rejects
further use of the connection. Reboot the Coldcard and reconnect.

## Using v3 With MITM Check

For sensitive clients, the recommended flow is:

1. Open one `ColdcardDevice` connection with `ncry_ver=USB_NCRY_V3`.
2. Immediately run `check_mitm(expected_xpub=trusted_xpub)`.
3. Only continue with sensitive commands if the MITM check passes.
4. If the MITM check or any v3 authentication check fails, close the session and
   require a fresh connection.

Example:

```python
from ckcc.client import ColdcardDevice
from ckcc.constants import USB_NCRY_V3
from ckcc.protocol import CCProtocolPacker

trusted_xpub = "xpub..."

dev = ColdcardDevice(ncry_ver=USB_NCRY_V3)
try:
    dev.check_mitm(expected_xpub=trusted_xpub)

    # Run sensitive commands only after the endpoint check passes.
    xpub = dev.send_recv(CCProtocolPacker.get_xpub("m"), timeout=None)
finally:
    dev.close()
```

The `expected_xpub` value should come from a trusted source, such as a previous
trusted pairing, user verification, or another authenticated channel. If a
client uses only the xpub returned by the same first-contact USB session, an
active attacker could substitute its own identity and pass the check against
that substituted value. The MITM check is strongest when the host already knows
which COLDCARD it expects.

The MITM command works by asking the COLDCARD to sign the current session key
with its master key. The host verifies that signature against the trusted xpub.
Because an active MITM creates a different session key on each side, it cannot
forward the real device's signature and make it verify for the host's separate
session.

## Operational Notes

Client support is implemented in ckcc-protocol source version `1.6.0`.
Firmware support is unreleased and planned for the next standard Mk4/Mk5 and
Q firmware releases.

Use v3 only when both the client and firmware are known to support it. The
default client encryption version remains `USB_NCRY_V1` for compatibility, so a
client must explicitly opt in to v3.

The ncry version is selected by the host in the initial `ncry` command. There
is no in-protocol version negotiation or downgrade path. If firmware does not
support `USB_NCRY_V3`, it rejects the setup request and the client must close
that attempt.

Use one client-side request/response flow at a time. Do not pipeline or
interleave commands in a v3 session. The sequence numbers and CTR streams are
stateful per direction, so the next command should be sent only after the
previous response has been received and authenticated.
