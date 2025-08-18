# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Verify hobble works: a restricted access mode, without export/view of seed and more.
#
# - spending policy menu and txn checks should not be in this file, instead expand
#    test_ccc.py or create test_sssp.py
#
import pytest, time, re, pdb
from helpers import prandom, xfp2str, str2xfp, str_to_path
from bbqr import join_qrs
from charcodes import KEY_QR, KEY_NFC
from base64 import b32encode
from constants import *
from test_ephemeral import SEEDVAULT_TEST_DATA
from test_backup import make_big_notes

'''TODO

When hobbled...

- check adv menu is minimal
- load a secure note/pw; check readonly once hobbled
    - cannot export
    - cannot edit
    - can view / use for kbd emulation
- check notes not offered if none defined
- check readonly features on notes when note pre-defined before entering hobbled mode
- notes hidden if the exist but access disabled in policy

- key teleport
    - check KT only offered if MS wallet setup
    - scan a KT and have it rejected if not PSBT type: so R and E types
    - MS psbt KT should still work in hobbled mode: test_teleport.py::test_teleport_ms_sign

- verify no settings menu
- temp seeds are read only: no create, no rename, etc.
- seed vault can be accessed tho

- login sequence
    1) system has lgto value: should get bypass pin, main pin, delay, then main pin again
    2) using a trick PIN with delay, after bypass pin should delay
    3) bypass pin + duress wallet PIN => should work => but not a useful trick combo
   
- word entry during login
    - q1 vs mk4 style
    - wrong values given, etc

- verify whitelist of QR types is correct when in hobbled mode
    - no private key material, no teleport starting, unless "okeys" is set

- update menu tree w/ hobble mode view

'''
