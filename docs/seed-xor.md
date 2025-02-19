# Seed XOR

## The Problem

What do I do to secure my [SEEDPLATE](https://bitcoinmetalbackup.com/)?

Most people now understand that metal seed backups are paramount,
as paper burns. The challenge is how to store clear-text secrets?
Anyone with physical access could use it and gain complete
control of your funds! Encrypted digital backups are great, but they
are not discrete and you could be compelled to produce the passphrase.

Enter [_Seed XOR_](https://seedxor.com), a plausibly deniable means
of storing secrets in two or more parts that look and behave just
like the original secret. One 12 or 24-word seed phrase becomes two or more parts
that are also BIP-39 compatible seeds phrases. These should be backed up in your
preferred method, metal or otherwise. These parts can be individually loaded
with honeypot funds as each one has same word length, with the last being
the checksum and will work as such in any normal BIP-39 compatible wallet.

This one more solution for your game-theory arsenal.

- *Q*: I'm lazy, can I do this to my Existing Seed?
- *A*: Yes. You can split the words you have already in your Coldcard, making
  2, 3 or 4 new SEEDPLATES. You could also use any number of existing SEEDPLATES
  you have, and combine them to make a new random wallet that is the XOR of
  their values. Effectively that makes a new random wallet.

## Background

[_Seed XOR_](https://seedxor.com) works by taking any number of
seed phrases in BIP-39 style, and simply XOR-ing them together,
bit-by-bit into a new phrase. All seed phrases have to be of the same length.

The last word contains checksum.
For the "parts" (sometimes called "shares") this checksum 
is calculated as normal for BIP-39, but those final bits are not used in
the XOR process. But the checksums still protects the integrity of the
individual parts. In 24-words XOR last 8 bits are checksum and in 12-words
XOR last 4 bits are checksum.

Useful properties of this approach:

- Every "part" looks and operates as a valid BIP-39 wallet.
- All the parts can be combined in any order and you arrive at the same result.
- You must have all parts, because any combination of less than all parts is a
  valid Seed XOR wallet too.
- Each "part" can be recorded on a SEEDPLATE like normal and no new recording tools
  are needed. No information about you original seed is leaked by finding up
  to N-1 of the parts.
- You can store funds on the seeds of any part, and any subset of parts, which
  opens even more duress options.

We recommend storing the checksum word of the original
wallet along with your N parts. This allows you to be sure you've
gotten all the parts and assembled them correctly. This does reveal
3 bits of your real wallet however, and also reveals that a
working and correct subset of parts has been assembled.

It is not hard to calculate a Seed XOR on paper (or to verify or
reconstruct a seed split by Coldcard). Below is a complete example,
and a lookup table that allows you to XOR together hex digits. You
can do the XOR at the bit level, but we recommend looking up each
word and finding it's 3-digit hex value (0x000 to 0x7FF), and going
hex-digit by hex-digit (4 bits).

## How Parts are Generated

Create new parts on your Coldcard:

Advanced > Danger Zone > Seed Functions > Seed XOR > Split Existing

You can choose between 2, 3 or 4 parts. You can also choose (next
screen) to generate them deterministically or using the TRNG. The
advantage of the deterministic approach is you'll always get the
same answers, so you can check that you've recorded the correct 
words right the next day.

When the parts are made deterministically, we take a double-SHA256 over
a fixed string (`Batshitoshi`), your master secret, and the text
`1 of 4 parts` which changes for each part.

In random mode, we simply pick 32 random bytes (and then double-SHA256
them) from the Coldcard's True Random Number Generator (TRNG)..

This is done to make all but the one part. The final part is the
value needed to get back to your secret, so it's the XOR of the
other N-1 parts. It contains just as much entropy as the other
parts.

### Other Notes

- So many possible duress games are possible once you've split your
seed up, and you are able to "give up" all of the seed phrases,
except one, and the attackers will still get nothing. You can load
various possible combinations of your Seed XOR's with various amounts,
so none are obviously empty and so on.

- Any two or more SEEDPLATES you have already encoded can be used
together to make a new wallet based on their XOR. No changes to
their existing values are needed... just import the set into a new
Coldcard and effectively a new random seed is in play at that point.

- One downside of the deterministic approach is that it allows
attackers to verify they have a seed that was split by Coldcard.
They can import the N parts into a Coldcard, and then split them
again on that Coldcard, and should arrive at the same values. If
they don't then either you used the TRNG, or they have some subset
of all the parts.

- You can pick your XOR parts randomly, and the result when XOR'ed
together, is a random wallet. However, it would be best to get the
last word checksum recorded correctly, so please use a tool such
as the Coldcard to lookup the 24th word and save that (for each
part).  For example, you might take a fresh Coldcard (no secret)
and draw 23 words from a hat. After providing the 23rd word, the
Coldcard will show 8 possible final words. You can pick randomly
from that list, or simply use the first one, and then cancel the seed
import process on the Coldcard. Record that final word along
with the others on a SEEDPLATE.


## XOR Lookup Table


| XOR | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F 
|----:|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---
|**0**| 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | A | B | C | D | E | F 
|**1**| 1 | 0 | 3 | 2 | 5 | 4 | 7 | 6 | 9 | 8 | B | A | D | C | F | E 
|**2**| 2 | 3 | 0 | 1 | 6 | 7 | 4 | 5 | A | B | 8 | 9 | E | F | C | D 
|**3**| 3 | 2 | 1 | 0 | 7 | 6 | 5 | 4 | B | A | 9 | 8 | F | E | D | C 
|**4**| 4 | 5 | 6 | 7 | 0 | 1 | 2 | 3 | C | D | E | F | 8 | 9 | A | B 
|**5**| 5 | 4 | 7 | 6 | 1 | 0 | 3 | 2 | D | C | F | E | 9 | 8 | B | A 
|**6**| 6 | 7 | 4 | 5 | 2 | 3 | 0 | 1 | E | F | C | D | A | B | 8 | 9 
|**7**| 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 | F | E | D | C | B | A | 9 | 8 
|**8**| 8 | 9 | A | B | C | D | E | F | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 
|**9**| 9 | 8 | B | A | D | C | F | E | 1 | 0 | 3 | 2 | 5 | 4 | 7 | 6 
|**A**| A | B | 8 | 9 | E | F | C | D | 2 | 3 | 0 | 1 | 6 | 7 | 4 | 5 
|**B**| B | A | 9 | 8 | F | E | D | C | 3 | 2 | 1 | 0 | 7 | 6 | 5 | 4 
|**C**| C | D | E | F | 8 | 9 | A | B | 4 | 5 | 6 | 7 | 0 | 1 | 2 | 3 
|**D**| D | C | F | E | 9 | 8 | B | A | 5 | 4 | 7 | 6 | 1 | 0 | 3 | 2 
|**E**| E | F | C | D | A | B | 8 | 9 | 6 | 7 | 4 | 5 | 2 | 3 | 0 | 1 
|**F**| F | E | D | C | B | A | 9 | 8 | 7 | 6 | 5 | 4 | 3 | 2 | 1 | 0 


- XOR = EOR = &oplus; = Exclusive OR [Wikipedia](https://en.wikipedia.org/wiki/Exclusive_or)
- values in table are: x &oplus; y in hex
- go sideways for first digit, then look down for second digit
- in fact, doesn't matter if you do row or column first
- example: 2 XOR 6 => 4  same as   6 XOR 2 => 4
- any values XOR itself is zero (diagonal on this table)
- alternative view: (x) XOR (y) = flip bits of (x) that are set in (y)
    - XOR with zero does nothing (flips no bits)
    - XOR with 0xF flips all four bits
    - XOR with self flips all set bits, so gives zero
- to XOR three values together, do (a&oplus;b)=X then (X&oplus;c)=answer
    - right to A, down to B ... take that number, and go to that column
    - down to C, that is answer: a &oplus; b &oplus; c

---

# 24 Words XOR Seed Example Using 3 Parts

## Seed A  (1 of 3)

      1=romance [5DC], 2=wink [7DE], 3=lottery [420], 4=autumn [07D], 5=shop [635], 6=bring [0E1],
      7=dawn [1BF], 8=tongue [723], 9=range [58E], 10=crater [194], 11=truth [74E], 12=ability [001],
      13=miss [46E], 14=spice [68C], 15=fitness [2BF], 16=easy [22E], 17=legal [3FB], 18=release [5A9],
      19=recall [59B], 20=obey [4BF], 21=exchange [275], 22=recycle [59F], 23=dragon [210], 24=room [5DF]

      A = 5DC 7DE 420 07D 635 0E1 1BF 723 58E 194 74E 001 46E 68C 2BF 22E 3FB 5A9 59B 4BF 275 59F 210 5DF


## Seed B  (2 of 3)

      1=lion [411], 2=misery [46D], 3=divide [1FF], 4=hurry [37D], 5=latin [3EB], 6=fluid [2CD], 7=camp [106],
      8=advance [01F], 9=illegal [388], 10=lab [3E0], 11=pyramid [578], 12=unaware [763], 13=eager [227],
      14=fringe [2E8], 15=sick [63E], 16=camera [105], 17=series [620], 18=noodle [4B0], 19=toy [733],
      20=crowd [1A2], 21=jeans [3BD], 22=select [61A], 23=depth [1D9], 24=lounge [422]

      B = 411 46D 1FF 37D 3EB 2CD 106 01F 388 3E0 578 763 227 2E8 63E 105 620 4B0 733 1A2 3BD 61A 1D9 422


## Seed C  (3 of 3)

      1=vault [78E], 2=nominee [4AF], 3=cradle [18F], 4=silk [644], 5=own [4F0], 6=frown [2EC], 7=throw [70A],
      8=leg [3FA], 9=cactus [100], 10=recall [59B], 11=talent [6EB], 12=worry [7EE], 13=gadget [2F5],
      14=surface [6D1], 15=shy [63C], 16=planet [52F], 17=purpose [573], 18=coffee [169], 19=drip [219],
      20=few [2AC], 21=seven [625], 22=term [6FB], 23=squeeze [69C], 24=educate [234]

      C = 78E 4AF 18F 644 4F0 2EC 70A 3FA 100 59B 6EB 7EE 2F5 6D1 63C 52F 573 169 219 2AC 625 6FB 69C 234


## Calculation (XOR each hex digit)

      A = 5DC 7DE 420 07D 635 0E1 1BF 723 58E 194 74E 001 46E 68C 2BF 22E 3FB 5A9 59B 4BF 275 59F 210 5DF
      B = 411 46D 1FF 37D 3EB 2CD 106 01F 388 3E0 578 763 227 2E8 63E 105 620 4B0 733 1A2 3BD 61A 1D9 422
      C = 78E 4AF 18F 644 4F0 2EC 70A 3FA 100 59B 6EB 7EE 2F5 6D1 63C 52F 573 169 219 2AC 625 6FB 69C 234
          |               |               |               |               |               |           |  
    XOR = 643 71C 450 544 12E 0C0 7B3 4C6 706 7EF 4DD 08C 4BC 2B5 2BD 604 0A8 070 0B1 7B1 7ED 57E 555 3xx


## Resulting Seed Phrase

      1=silent [643], 2=toe [71C], 3=meat [450], 4=possible [544], 5=chair [12E], 6=blossom [0C0],
      7=wait [7B3], 8=occur [4C6], 9=this [706], 10=worth [7EF], 11=option [4DD], 12=bag [08C],
      13=nurse [4BC], 14=find [2B5], 15=fish [2BD], 16=scene [604], 17=bench [0A8], 18=asthma [070],
      19=bike [0B1], 20=wage [7B1], 21=world [7ED], 22=quit [57E], 23=primary [555]

      final word between: gas [300] - lend [3FF]
      correct final word: indoor [398]



# 12 Words XOR Seed Example Using 3 Parts

## Seed A  (1 of 3)

      1=romance [5DC], 2=wink [7DE], 3=lottery [420], 4=autumn [07D], 5=shop [635], 6=bring [0E1],
      7=dawn [1BF], 8=tongue [723], 9=range [58E], 10=crater [194], 11=truth [74E], 12=ability [001]

      A = 5DC 7DE 420 07D 635 0E1 1BF 723 58E 194 74E 001


## Seed B  (2 of 3)

      1=boat [0C6], 2=unfair [768], 3=shell [62B], 4=violin [7A2], 5=tree [73F], 6=robust [5DA], 7=open [4D9],
      8=ride [5CB], 9=visual [7A7], 10=forest [2D9], 11=vintage [7A1], 12=approve [056]

      B = 0C6 768 62B 7A2 73F 5DA 4D9 5CB 7A7 2D9 7A1 056


## Seed C  (3 of 3)

      1=lion [411], 2=misery [46D], 3=divide [1FF], 4=hurry [37D], 5=latin [3EB], 6=fluid [2CD], 7=camp [106],
      8=advance [01F], 9=illegal [388], 10=lab [3E0], 11=pyramid [578], 12=unhappy [76A]

      C = 411 46D 1FF 37D 3EB 2CD 106 01F 388 3E0 578 76A


## Calculation (XOR each hex digit)

      A = 5DC 7DE 420 07D 635 0E1 1BF 723 58E 194 74E 001
      B = 0C6 768 62B 7A2 73F 5DA 4D9 5CB 7A7 2D9 7A1 056
      C = 411 46D 1FF 37D 3EB 2CD 106 01F 388 3E0 578 76A
          |               |               |              
    XOR = 10B 4DB 3F4 4A2 2E1 7F6 460 2F7 1A1 0AD 597 73x


## Resulting Seed Phrase

      1=cannon [10B], 2=opinion [4DB], 3=leader [3F4], 4=nephew [4A2], 5=found [2E1], 6=yard [7F6],
      7=metal [460], 8=galaxy [2F7], 9=crouch [1A1], 10=between [0AD], 11=real [597]

      final word between: toward [730] - tree [73F]
      correct final word: trade [735]



- It's not possible to calculate the checksum of the final seed phrase on paper (needs SHA256).
- But it must start with the indicated digit(s). If using 24 words XOR, there will be only one
  suitable choice offered by the Coldcard in that range (x00 to xFF),
  once you have entered the other 23 words.
- The checksum of each of the XOR-parts protects the final result, assuming your XOR
  math is correct.