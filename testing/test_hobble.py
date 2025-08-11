# (c) Copyright 2025 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Verify hobble works: a restricted access mode, without export/view of seed and more.
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

- check adv menu is minimal
- load a secure note/pw; check readonly once hobbled
    - cannot export
    - cannot edit
    - can view / use for kbd emulation
- check KT only offered if MS wallet setup
- scan a KT and have it rejected if not PSBT type: so R and E types
- MS psbt KT should still work in hobbled mode: test_teleport.py::test_teleport_ms_sign
- verify no settings menu


'''
