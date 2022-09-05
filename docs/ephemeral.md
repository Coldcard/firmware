# Ephemeral Seeds

Ephemeral seed is temporary secret stored only in Coldcard volatile
memory (RAM). It only survives single boot, meaning after Coldcard
restart it is gone.  Ephemeral seeds *completely* defeats the design
of Coldcard's security model based on secure elements.

Make sure you know what you're doing!


## Usage

- go to `Advanced/Tools -> Ephemeral Seed`
- if ephemeral seed is already in use, the menu option `CLEAR [<xfp>]` is visible
  with fingerprint of ephemeral master secret
- an ephemeral seed can be Imported or Generated at random 
- `Generate`:
  - `Advanced/Tools -> Ephemeral Seed -> Generate`
  - same options as generating new seeds, dice rolls included
- `Import`:
  - `Advanced/Tools -> Ephemeral Seed -> Import`
  - same options as importing seeds
- an ephemeral seed can also be a BIP-85 derived value

