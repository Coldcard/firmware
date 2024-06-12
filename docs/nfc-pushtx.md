# NFC Push Tx

This feature allows single-tap broadcast of the freshly-signed transaction.

Once enabled with a URL, the COLDCARD will show the NFC animation
after signing the transaction. When the user taps their phone, the
phone will see an NFC tag with URL inside. That URL contains the
signed transaction ready to go, and once opening in the mobile
browser, that URL will load. The landing page will connect to a
Bitcoin node (or similar) and send the transaction on the public
Bitcoin network.

This feature is available on Q and Mk4 and requires NFC to be enabled.
See `Advanced/Tools > NFC Push Tx`

## Protocol Spec

The COLDCARD needs a URL prefix. To that it appends some values:

- `t=...` 
  - this is the transaction, in binary encoded with
    [base64url](https://datatracker.ietf.org/doc/html/rfc4648#section-5)

- `&c=...`
    - the rightmost 8 bytes of SHA256 over the transaction. Also `base64url` encoded.

- `&n=XTN`
    - if, and only if, the COLDCARD is set for Testnet, this value is appended to
      indicate that the transaction is for Testnet3 and not MainNet.
    - when RegTest is enabled, the value will be `XRT`

We provide a few default URL values to our customers, including one backend we
will operate on `colcard.com`. The URL can also be directly entered by the
customer. On the Q, it can be scanned from a QR code.

For COLDCARD backend, the url used is:

    https://coldcard.com/pushtx#

The complete URL with a typical transaction might look like this (but longer):

    https://coldcard.com/pushtx#t=AgAAAAMNCxXtp2GVYVhkRXHLMmdZFs4p3kbFK ⋯ ABf&c=uiSVRda-1tw

We are using hash symbol here so that our server logs do not get
contaminated with the arguments. The landing page uses javascript
to read the hash part of the URL and decodes from there. If you
prefer, your URL can end with `?` and then the arguments will be
sent by the phone's browser to your server. Your processing can be
entirely done in the backend in this case.

## Expectations for the Backend

Your code should decode the transaction and check the SHA-256 hash
matches. If it does not match, or if `c` value is missing, assume
the URL has been truncated and report that to the user.

Once decoded, your code should immediately broadcast the transaction.
A confirmation step is not required in our opinion. Once it is
submitted to Bitcoin Core (or other API), any status response should
be decoded and shown to the user so they know it is on it's way.
If it was not accepted, please report the error to the user as
clearly as possible.

Next, it would make sense to either link to the TXID on a block
explorer to provide further proof that it has been sent and that
it is now waiting in the mempool.

## Backend Implementations

- Mempool.space's [implementation of this feature](https://github.com/mempool/mempool/pull/5132).

- A single-file (html and javascript) file is available
  at [coldcard.com/static/coldcard-pushtx.html](https://coldcard.com/static/coldcard-pushtx.html).
  You can host this file anywhere your phone can reach, and then use that URL in your
  COLDCARD settings. It uses your phone's browser to submit directly
  to `mempool.space` and `blockstream.info` sites (both at same time). It is equivalent
  to the page hosted at `https://coldcard.com/pushtx#`

### Notes

- Complete URL might be as large as 8,000 bytes. Some web servers will not support beyond
  4k bytes and the NFC implementation of the phone may also have limits.
- The service URL provided must end in `?` or `#` or `&`.
- `base64url` values from COLDCARD will not have padding (`=` bytes) at end.
- POST cannot be used directly because the expect the phone to do a GET on the URL provided.
- Honest backends will not log the IP address of incoming transactions, but there is
  no way to enforce that, and CloudFlare sees all.

## Example URL

```
https://mempool.space/pushtx#t=AgAAAAOHqK3w3hC6PSC0buthnJA5R9Y88WAlEvm9cifNVUPhIwAAAABqRzBEAiB-M9YprNYoohqHdQHg4wY_qcEMwDmyIQH8prykk8-0KwIgARxcojKrtixicouiUxhk4jQq_MAl11ptIgHDlRjgk5ABIQM4bgMAVDbDSr_9CvLjbg5nxrWnDGI-kVmkfL81GXZtCf____8OaH0RxW7DjZKdIF6rvbHvvyFGCBQ0PTgpx20nA_wbLgAAAABqRzBEAiBwUFigORJDPK8ptnYPAntjV-RUn1jAuzphicQstwVv-QIgEbMC8FWXQ5Jve5DaAqKJsqoj3peK83iub_oOkmbiYg4BIQO5Ehn2t0oUG3hnK4cBnwCwMc33DcdJ8aSMWzRQ_wjZL_____-UG6M-eBeAun-EZp6EbVypvVJ3mXCQrN_fUDn-kwoEnQAAAABqRzBEAiAgFAtVTpQYTKplc9NuV7Ws7ZFYeNO8BCS4ozgWrgd2ogIgGTTcw98xQdcGWeWQhVfVm_vZorBIOYovQPQeK0Lg9t8BIQLPWPioVWvj1z4NMHBCkeirYOUalCa83wbSH0CREnGZvv____8CjM_wCAAAAAAZdqkUIJA8_yqzaj0NzhvYVEIBno5gETGIrIzP8AgAAAAAGXapFEaV7xTyleuEX9OejdlUlsz7RTr0iKwAAAAA&c=hre47vyMC78&n=XTN
```

- this transaction doesn't have valid inputs, and will cause an error
- mempool.space will redirect this to a testnet endpoint (because ends with `n=XTN`)


