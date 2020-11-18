# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# work thru examples given in SLIP-132
# in simulator
#
#   execfile('../../testing/devtest/unit_slip132.py')
#
from h import a2b_hex, b2a_hex
from chains import BitcoinMain
from stash import SensitiveValues
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

cases = [
(   AF_CLASSIC,
    "m/44'/0'/0'",
    "xprv9xpXFhFpqdQK3TmytPBqXtGSwS3DLjojFhTGht8gwAAii8py5X6pxeBnQ6ehJiyJ6nDjWGJfZ95WxByFXVkDxHXrqu53WCRGypk2ttuqncb",
    "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
    "m/44'/0'/0'/0/0",
    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
),

(   AF_P2WPKH_P2SH,
	"m/49'/0'/0'",
	"yprvAHwhK6RbpuS3dgCYHM5jc2ZvEKd7Bi61u9FVhYMpgMSuZS613T1xxQeKTffhrHY79hZ5PsskBjcc6C2V7DrnsMsNaGDaWev3GLRQRgV7hxF",
	"ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx9979FfaHxHcrArf3zbeJJJUZPf663zsP",
	"m/49'/0'/0'/0/0",
	"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
),

(   AF_P2WPKH,
	"m/84'/0'/0'",
	"zprvAdG4iTXWBoARxkkzNpNh8r6Qag3irQB8PzEMkAFeTRXxHpbF9z4QgEvBRmfvqWvGp42t42nvgGpNgYSJA9iefm1yYNZKEm7z6qUWCroSQnE",
	"zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs",
	"m/84'/0'/0'/0/0",
	"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
),
]

# abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about
# => 16 byte zero value
with SensitiveValues(b'\x80'+(b'\0'*16)) as sv:
    for fmt, root, prv, pub, p2, p2_addr in cases:
        node = sv.derive_path(root)
        got_pub = BitcoinMain.serialize_public(node, fmt)
        assert got_pub == pub, got_pub

        got_prv = BitcoinMain.serialize_private(node, fmt)
        assert got_prv == prv, got_prv

        n2 = sv.derive_path(p2)
        got_addr = BitcoinMain.address(n2, fmt)
        assert got_addr == p2_addr, got_addr

    # avoid an assert
    del sv.secret
