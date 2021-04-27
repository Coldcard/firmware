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

# XOR Seed Example Using 3 Parts

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
- It's not possible to calculate the checksum of the final seed phrase on paper (needs SHA256).
- But it must start with the indicated digit, and there will be only one
  suitable choice offered by the Coldcard in that range (x00 to xFF),
  once you have entered the other 23 words.
- The checksum of each of the XOR-parts protects the final result, assuming your XOR
  math is correct.

