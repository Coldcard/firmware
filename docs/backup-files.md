# Backup Feature

The user can do a "full backup" of a Coldcard to external SD card.
Simply choose the option from the menu and
the Coldcard will pick a strong password for you and display it.

The file we create is a [standard 7z archive](https://en.wikipedia.org/wiki/7z)
with AES-256 encryption, in CBC mode. The 256-bit key is a SHA256 hash of a passphrase,
hashed in a particular way to support 7z compatibility. We know
the passphrase has at least 128-bits of entropy because the Coldcard
uses it's true random number generator (TRNG) to pick it.

Once decrypted, which is possible using any 7z archive tool, the
contents are a simple text file with everything you could need to
access your funds, in an emergency, using another wallet system.

Restoring the backup file onto a replacement Coldcard is a simple
process that merely requires entering the 12 words.

## Is it secure?

We use AES-256 encryption, wrapped in a [7z archive](https://en.wikipedia.org/wiki/7z).
The passphrase is chosen at random, as 12 words from the BIP39 word list.  This
gives effectively 132 bits of security without any key stretching.
The 7z file format adds a 16-byte salt and random 16-byte IV
(initialization vector), plus a few tens of thousands of rounds of key stretching.
We are not relying on that however, because of the long key itself
(128-bits).

## Proving It Works

Because we are using a standard file format, you can verify the
process and that the data is in fact encrypted. Any 7z tool that
supports AES256-SHA256 encryption should be able to read the files
we make. Take the 12 words and put them together with a single space
between each word (all lowercase). The decoded archive will contain
a single file, `ckcc-backup.txt`, which is a simple text file and
easy to read.

## Limitations

- The archive file names are not encrypted. You can see `ckcc-backup.txt` in
  the hex dump of the encrypted file, encoded as `utf-16-le` bytes.
- The device PIN code is not preserved during backup.
- We produce standards-compliant files, but do not support reading any
  file except the ones produced by Coldcard.
- Do not attempt to edit the file and restore it onto a Coldcard.
- You cannot construct a file for the Coldcard to read because we implement only
  enough to support reading files that we know that we've produced.
- There is no plausible deniability here: the 7z file is clearly a Coldcard backup file.

## Example File

### Encrypted File

```
% hd backup.7z 
00000000  37 7a bc af 27 1c 00 03  46 de 5e ba 30 02 00 00  |7z..'...F.^.0...|
00000010  00 00 00 00 6e 00 00 00  00 00 00 00 e0 5c a0 0e  |....n........\..|
00000020  68 1a 57 0a ed 5b 77 89  ea 4a 84 72 d4 75 d6 bd  |h.W..[w..J.r.u..|
00000030  45 13 fc 6a 66 34 47 30  1e c8 08 8e bc 4f 4f 4d  |E..jf4G0.....OOM|
00000040  1d a4 fc 93 2e 08 ff 28  a4 71 cd f7 fe 48 35 69  |.......(.q...H5i|
00000050  3a 6b c8 eb e4 90 6c f5  24 12 55 40 bb 20 59 e5  |:k....l.$.U@. Y.|
00000060  ae d5 62 7b cd 27 b6 4c  15 f5 cf 68 6c e9 30 87  |..b{.'.L...hl.0.|
00000070  96 dd 1d d1 98 e5 e3 cf  ce b3 81 47 f3 7a 14 b8  |...........G.z..|
00000080  c1 f2 48 55 69 09 3f aa  a5 7e 9f 3c 59 a9 c1 b6  |..HUi.?..~.<Y...|
00000090  71 a6 87 bf 9d 0e 26 bc  14 9e ed 3c d9 0c 90 5a  |q.....&....<...Z|
000000a0  7d ea d8 4a 2b 15 a2 cf  9b 38 3a fd a8 a2 b5 49  |}..J+....8:....I|
000000b0  d8 56 03 6a 26 65 c6 b2  c9 5a 67 b0 c7 44 0a 67  |.V.j&e...Zg..D.g|
000000c0  3a 36 29 43 e6 86 d8 f7  b9 36 2c d8 bc 31 36 46  |:6)C.....6,..16F|
000000d0  bb ba ae 77 1f b0 25 e6  ce 7a 58 67 c1 8a 99 69  |...w..%..zXg...i|
000000e0  84 89 94 dc c3 6f cc 1b  e8 4e 00 ca 7b 39 82 6a  |.....o...N..{9.j|
000000f0  8d ca 4f 81 21 95 d7 b8  a2 f9 ed d3 78 f8 a2 1b  |..O.!.......x...|
00000100  31 00 40 60 a3 a2 26 9f  08 f9 9c 4b db f4 86 f3  |1.@`..&....K....|
00000110  42 8b 9b 6a 7e 95 a9 47  18 a2 83 13 40 06 1f f0  |B..j~..G....@...|
00000120  02 e6 48 59 08 ca 37 ad  ce 28 62 2f ab 1b 7a 97  |..HY..7..(b/..z.|
00000130  1a 49 c3 04 dc 89 fb 7b  44 d4 c1 45 a3 7e 95 d8  |.I.....{D..E.~..|
00000140  47 44 8a f3 d2 ba ef d7  fd 11 e0 55 b9 1e f9 ee  |GD.........U....|
00000150  91 6d 9c 4b 3d 88 bc d7  fb 07 10 12 41 b8 b7 4e  |.m.K=.......A..N|
00000160  6a 2b b4 72 38 4a bb f9  65 32 00 6f ec 0a b8 f6  |j+.r8J..e2.o....|
00000170  1a 0b b8 9a 6a a7 2d 40  e4 ca 07 aa 0f 42 8f b4  |....j.-@.....B..|
00000180  62 95 b0 02 b8 c7 25 06  48 4b 3b d5 bd 50 71 26  |b.....%.HK;..Pq&|
00000190  b2 08 95 00 aa 39 46 74  45 73 e5 fe 59 ae 14 d4  |.....9FtEs..Y...|
000001a0  f1 25 47 c8 13 42 bc ef  7f d3 56 52 5d e6 78 19  |.%G..B....VR].x.|
000001b0  68 1c 19 46 52 34 ed 18  84 a7 5f 88 49 4b 89 06  |h..FR4...._.IK..|
000001c0  67 14 dc 34 59 b7 9a ed  93 ca b1 b3 a9 8b b7 39  |g..4Y..........9|
000001d0  b9 1f a0 ed 97 fa 0c 14  dd 08 ba a5 18 34 b7 48  |.............4.H|
000001e0  4d 1a b2 2e 3d 26 47 2c  28 b5 65 91 c6 3b 86 69  |M...=&G,(.e..;.i|
000001f0  51 71 20 88 c1 c7 0d 35  bf 16 a3 20 a4 c3 1e e8  |Qq ....5... ....|
00000200  02 1e 99 f8 27 53 df 14  30 37 22 08 10 e4 62 55  |....'S..07"...bU|
00000210  71 4d 25 e9 00 74 75 e0  9e a6 51 3c 29 5b 27 ab  |qM%..tu...Q<)['.|
00000220  37 71 f1 23 6f e4 20 af  74 68 93 2c 3f 2e 20 db  |7q.#o. .th.,?. .|
00000230  56 f0 5f 58 20 27 a8 6b  1f 89 2b 26 c0 4b 00 e3  |V._X '.k..+&.K..|
00000240  ea 35 87 f5 69 9f 09 f6  e0 a3 c7 ab c2 f3 35 a8  |.5..i.........5.|
00000250  01 04 06 00 01 09 c0 30  02 00 07 0b 01 00 01 24  |.......0.......$|
00000260  06 f1 07 01 22 cd ff 0a  01 01 28 37 a5 67 2c 1f  |....".....(7.g,.|
00000270  83 d6 74 ad 31 65 25 29  95 14 28 fc c1 46 93 51  |..t.1e%)..(..F.Q|
00000280  83 96 8a fd 30 99 7f 01  00 0c c0 2f 02 00 08 0a  |....0....../....|
00000290  01 95 db 3b 71 00 00 05  01 11 21 00 63 00 6b 00  |...;q.....!.c.k.|
000002a0  63 00 63 00 2d 00 62 00  61 00 63 00 6b 00 75 00  |c.c.-.b.a.c.k.u.|
000002b0  70 00 2e 00 74 00 78 00  74 00 00 00 00 00        |p...t.x.t.....|
000002be
```

If you are playing along at home, the passphrase for the above file is:

    spice until comfort zoo divide album erode yard inmate change quantum skate

You can grab the [example file here](backup.7z) and test it yourself, or use
a real Coldcard to make your own.

### Archive Contents

```
% 7z l backup.7z 

7-Zip [64] 15.09 beta : Copyright (c) 1999-2015 Igor Pavlov : 2015-10-16
p7zip Version 15.09 beta (locale=utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs x64)

Scanning the drive for archives:
1 file, 702 bytes (1 KiB)

Listing archive: backup.7z

--
Path = backup.7z
Type = 7z
Physical Size = 702
Headers Size = 142
Method = 7zAES
Solid = -
Blocks = 1

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
                    .....          559          560  ckcc-backup.txt
------------------- ----- ------------ ------------  ------------------------
                                   559          560  1 files
```

No passphrase is required to do this, and it does check CRC32 values, so 
simple truncation or unintentional corruption can be easily detected, without
knowledge of the passphrase.


### Decrypt Archive (requires passphrase)

```
7z x backup.7z

7-Zip [64] 15.09 beta : Copyright (c) 1999-2015 Igor Pavlov : 2015-10-16
p7zip Version 15.09 beta (locale=utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs x64)

Scanning the drive for archives:
1 file, 702 bytes (1 KiB)

Extracting archive: backup.7z
--
Path = backup.7z
Type = 7z
Physical Size = 702
Headers Size = 142
Method = 7zAES
Solid = -
Blocks = 1

    
Enter password (will not be echoed):
Everything is Ok      

Size:       559
Compressed: 702
```

This process creates a file `ckcc-backup.txt` in the current directory.


### Contents of ckcc-backup.txt

```
% cat ckcc-backup.txt 
# Coldcard backup file! DO NOT CHANGE.

# Private key details
mnemonic = "index abuse oil swift wolf clarify broom auto student media ribbon blossom hundred brief tomato abandon copy design angle memory narrow urge bulk resemble"
xprv = "xprv9s21ZrQH143K2pSWq6uW4ARspjhHfzVWM1ceM2sPVJWS9QWeuHYRHbYFcL3F3199vUPFE2SpFEhxnZJKQhqbZSZxFkYCt1LJidizB8tqXM6"
raw_secret = "8272c026676defcc53c7307cd7714ee40c06f237f9000030077823457931dec785"

# Firmware version (informational)
fw_date = "2018-02-30"
fw_version = "SIM"

# User preferences
setting.terms_ok = 1

# EOF
```

As you can see, it is a simple text file and if you needed to access your funds
without the help of a Coldcard, it would be a simple matter to import either the `xprv`
(BIP32 master) or the mnemonic (BIP39) into another wallet system.

