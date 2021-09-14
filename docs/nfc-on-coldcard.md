# NFC and Coldcard Mk4

(Applies to Coldcard Mk4 only)

## Standards Background

NFC is a layer of protocols on top of ISO standards for short-range
radio communications.

Unfortunately, both ISO and NFC Forum bodies are so poor they must
sell their standards. Membership starts at a few thousand dollars,
or you must buy each PDF for a few hundred dollars. Every single
thing is behind a paywall.

This policy does not allow us to link to reference standards. Instead
we have to hand-wave about our interpretation of their standards
documents.

In our opinion, this policy is not in the public interest and is
hindering adoption of their standards and even technological progress
in general. Good interoperability is critical with radio standards.


## Lower Layers

The Coldcard Mk4 has an chip that acts as a Type 5 NFC tag.  The
radio standard is called "NFC-V" or ISO-15693, and operates on a
13.56 Mhz carrier wave.

The tag chip implements NFC standards to support reading and writing
commands appropriate to a typical Type 5 tag.

Effectively it exposes a flash memory chip, of up to 8k Bytes in
size. NDEF standards describes the organization of the data in that
memory. This document will describe what bytes are needed in those
records.

## Security

All NFC features of the Coldcard can be disabled from the settings
menu, and when that is done, the tag chip is completely disabled,
and there is no way to probe, detect or access the Coldcard over
RF. Even when NFC features are enabled, we keep the tag chip disabled
unless we are actively sharing something. We disable the "energy
harvesting" features of the chip, so it will not do anything when
the Coldcard is powered-down, regardless of the NFC setting.

If the above is not enough for you, the antenna can be destroyed
by cutting the trace labeled "NFC" inside the hole for the MicroSD
card. Use the point of a sharp knife to cut and peel up the trace.

The NFC traffic is not encrypted and is subject to eavesdropping.
While the NFC feature is active, your Coldcard can be uniquely
identified because the NFC protocol requires a unique ID (64 bits)
that is defined by the NFC tag chip and shared automatically as
part of the anti-collion protocol. Again, that happens only during
active transfers, not when idle.

## Desktop Testing

Most USB-powered desktop contactless card readers will not work
with the Coldcard because they do not implement NFC-V (ISO-15693).
Instead they are doing ISO-14443A or B.

Smartphones, on the other hand, all support NFC-V and they are the
intended targets. Generic NFC tag reading apps can view the data
we share, and that may be enough to be useful. Our long-term goal
is integration with mobile wallets.

# Types of Records

## Background

The "NDEF message" is a list of values ("NDEF records"). In most
cases we share only a a single value, but for more complex object
data we will use multiple records. The order is not defined and may
change. Each NDEF record has data-type information and a payload
of bytes.

If we can use "text" or "URI" records, we will, but we generally
need our own Bitcoin-specific types.

We are using "NFC Forum Local Types" for new stuff. Other Bitcoin
developers are welcome to use the same types as long as it doesn't
create interoperation problems.

Types are shown in full URN format (RFC 2141) but only the final
two parts are sent as part of the NDEF record (ie. `bitcoin.org:psbt`).
We are using TNF=4 (NFC Forum external type) to communicate the
prefix of `urn:nfc:ext:`

# Simple Data

## General QR Replacement

Anytime there is a QR displayed on the Coldcard screen, you can
press (3) and the same data will be shared over NFC. In these cases,
it will be shared as a simple text record, regardless of the content.

Type: `urn:nfc:wkt:T` (text)

Body: varies, but always ascii text.

Many values can be exported this way, include xpub and even seed
words after enough warning screens.

## Payment Address

This is typically a deposit address, generated on the Coldcard via
the address explorer. We share these by themselves as simple text
records for max compatibility.

Type: `urn:nfc:wkt:T` (text)

Body: bech32 or base58 encoded Bitcoin payment address

If there are multiple addresses (10 shown for address explorer case)
then they are separated by a single unix new line (`0x0a`).

# Complex Data

For Bitcoin-specific data we provide a few records together. The
first is a label, then various binary data related to what's going
on (such as a PSBT file after signing).

## Text Label

Coldcard's first record will be a simple text record (English, UTF-8) that
describes what is being shared.

Type: urn:nfc:wkt:T  (standard text)

Body: "Partly signed PSBT", "Deposit Address", "Signed Transaction" and similar.

Consider this a title for what's being offered for sharing purposes.

## SHA256 Checksum

When the Coldcard is sharing a larger object, such as a PSBT file,
we know the SHA256 of that object, so we share that as well. This value can
be ignored or used for end-to-end error detection. It does not
protect against tampering.

Type: `urn:nfc:ext:bitcoin.org:sha256`

Body: Exactly 32 bytes of binary. It's the SHA256 over the main 
payload (PSBT file, for example).

If present, this value will always directly preceed the object (txn
or PSBT) that it covers. NFC-V has CRC16 over each low-level message,
but that's all.

## TXID Value

When sharing a fully-signed transaction, the TXID, if known, will be
shared in hex.

Type: `urn:nfc:ext:bitcoin.org:txid`

Body: Exactly 32 bytes of binary. 

The transaction ID is calculated as a hash over the transaction.
Without signature witness data, it is simply SHA256 over the bytes
of the transaction. For segwit transactions, it's a bit more complex
to calculate.

## PSBT File

The payload is a binary PSBT file, per BIP-174. The PSBT may be unsigned,
partly signed, fully signed or otherwise incomplete.

Type: `urn:nfc:ext:bitcoin.org:psbt`

Body: Binary PSBT file, variable length. First five bytes will be `psbt\xff`.


## Bitcoin Transaction

A fully-signed, wire-ready Bitcoin transaction.

Type: `urn:nfc:ext:bitcoin.org:txn`

Body: Binary, variable length. First four bytes will typically be
`0x02 0x00 0x00 0x00` (version number two, in LE32).

When the Coldcard has signed and finalized a transaction, it can
share it in this format. Typically the user will want to broadcast
this new transaction on the Bitcoin P2P network.

# Examples

This section will include a number of examples, with analysis of the content.

- __comming soon__


