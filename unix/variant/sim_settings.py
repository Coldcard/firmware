# do NOT import main from this file.
# do NOT 'from main import settings' either

import os, sys
from sim_secel import SECRETS

if '-w' in sys.argv:
    # clean out olds pins/secrets.. start with nothing
    sim_defaults = dict(_age=0)
    SECRETS = dict()

elif '-l' in sys.argv:
    # clean out olds pins/secrets.. start with nothing, except a pin code
    sim_defaults = { '_age': 1,
        'terms_ok': 1,
        '_skip_pin': '12-12',
    }

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })
    
else:
    # default values for simulator
    # CAUTION: many test cases will rely on these
    sim_defaults = {
        '_age': 42,
        #'chain': 'BTC',
        #'xpub': 'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7',
        'chain': 'XTN',
        'xpub': 'tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh',
        '_skip_pin': '12-12',
        'terms_ok': 1,
        'xfp': 1130956047,
        'idle_to': 0,
    }

    # annoying trick pin defaults
    #'tp': {'!p': [7, 32768, 3], '22-22': [3, 0, 12345], '11-11': [0, 2048, 12345], '99-99': [4, 1024, 4626]},

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '82faf8c43d8835d20aef178a530bb658071a5252b722ba910a4143d9010ebfded9000000000000000000000000000000000000000000000000000000000000000000000000000000',
    })

if '--pin' in sys.argv:
    pin = sys.argv[sys.argv.index('--pin') + 1]
    sim_defaults.pop('_skip_pin', 0)
    SECRETS['_pin1'] = pin

if '-2' in sys.argv:
    # enable second wallet, but no seeds
    sim_defaults.pop('_skip_pin', 0)
    SECRETS.update({
        '_pin2': '33-33',
        '_pin2_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })

if '-p' in sys.argv:
    # pretend BIP39 words don't exist (affects menus mostly)
    sim_defaults['words'] = False

if '--ms' in sys.argv:
    # Include useful multisig wallet, and shortcut to MS menu

    if '--p2wsh' in sys.argv:
        sim_defaults['miniscript'] = [['P2WSH--2-of-4', 'wsh(sortedmulti(2,@0/**,@1/**))', ['[0f056943/48h/1h/0h/2h]tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP', '[6ba6cfd0/48h/1h/0h/2h]tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm', '[747b698e/48h/1h/0h/2h]tpubDExj5FnaUnPAn7sHGUeBqD3buoNH5dqmjAT6884vbDpH1iDYWigb7kFo2cA97dc8EHb54u13TRcZxC4kgRS9gc3Ey2xc8c5urytEzTcp3ac', '[7bb026be/48h/1h/0h/2h]tpubDFiuHYSJhNbHcbLJoxWdbjtUcbKR6PvLq53qC1Xq6t93CrRx78W3wcng8vJyQnY3giMJZEgNCRVzTojLb8RqPFpW5Ms2dYpjcJYofN1joyu'], {'af': 14, 'm_n': (2, 4), 'b67': 1, 'ct': 'XTN'}]]
    elif '--wrap' in sys.argv:
        # p2wsh-p2sh case
        sim_defaults['miniscript'] = [['CC-2-of-4', 'sh(wsh(sortedmulti(2,@0/**,@1/**)))', ['[0f056943/48h/1h/0h/1h]tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP', '[6ba6cfd0/48h/1h/0h/1h]tpubDFcrvj5n7gyatVbr8dHCUfHT4CGvL8hREBjtxc4ge7HZgqNuPhFimPRtVg6fRRwfXiQthV9EBjNbwbpgV2VoQeL1ZNXoAWXxP2L9vMtRjax', '[747b698e/48h/1h/0h/1h]tpubDExj5FnaUnPAjjgzELoSiNRkuXJG8Cm1pbdiA4Hc5vkAZHphibeVcUp6mqH5LuNVKbtLVZxVSzyja5X26Cfmx6pzRH6gXBUJAH7MiqwNyuM', '[7bb026be/48h/1h/0h/1h]tpubDFiuHYSJhNbHaGtB5skiuDLg12tRboh2uVZ6KGXxr8WVr28pLcS7F3gv8SsHFa2tm1jtx3VAuw56YfgRkdo6DXyfp51oygTKY3nJFT5jBMt'], {'af': 26, 'm_n': (2, 4), 'b67': 1, 'ct': 'XTN'}]]
    else:
        # P2SH: 2of4 using BIP39 passwords: "Me", "Myself", "and I", and (empty string) on simulator
        sim_defaults['miniscript'] = [['MeMyself', 'sh(sortedmulti(2,@0/**,@1/**))', ['[6ba6cfd0/45h]tpubD9429UXFGCTKJ9NdiNK4rC5ygqSUkginycYHccqSg5gkmyQ7PZRHNjk99M6a6Y3NY8ctEUUJvCu6iCCui8Ju3xrHRu3Ez1CKB4ZFoRZDdP9', '[747b698e/45h]tpubD97nVL37v5tWyMf9ofh5rznwhh1593WMRg6FT4o6MRJkKWANtwAMHYLrcJFsFmPfYbY1TE1LLQ4KBb84LBPt1ubvFwoosvMkcWJtMwvXgSc', '[7bb026be/45h]tpubD9ArfXowvGHnuECKdGXVKDMfZVGdephVWg8fWGWStH3VKHzT4ph3A4ZcgXWqFu1F5xGTfxncmrnf3sLC86dup2a8Kx7z3xQ3AgeNTQeFxPa', '[0f056943/45h]tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n'], {'af': 8, 'm_n': (2, 4), 'b67': 1, 'ct': 'XTN'}]]
    sim_defaults['fee_limit'] = -1

if '--xfp' in sys.argv:
    # --xfp aabbccdd   => pretend we know that key (won't be able to sign)
    from ustruct import unpack
    from utils import xfp2str
    from ubinascii import unhexlify as a2b_hex

    xfp = sys.argv[sys.argv.index('--xfp') + 1]
    sim_defaults['xfp'] = unpack("<I", a2b_hex(xfp))[0]
    print("Override XFP: " + xfp2str(sim_defaults['xfp']))

if '--mainnet' in sys.argv:
    sim_defaults['chain'] = 'BTC'

if '--seed' in sys.argv:
    # --seed "word1 word2 ... word24" => import that seed phrase at start
    import bip39
    from ubinascii import hexlify as b2a_hex

    words = sys.argv[sys.argv.index('--seed') + 1].split(' ')
    assert len(words) in {12, 18, 24}, "Expected space-separated words: add some quotes"

    seed = bip39.a2b_words(words)
    if len(seed) == 16:
        raw = bytes([0x80]) + seed
    elif len(seed) == 24:
        raw = bytes([0x81]) + seed
    elif len(seed) == 32:
        raw = bytes([0x82]) + seed
    raw += bytes(72 - len(raw))

    SECRETS.update({
        '_pin1_secret': b2a_hex(raw),
    })

    sim_defaults['terms_ok'] = 1
    sim_defaults['_skip_pin'] = '12-12'
    sim_defaults['chain'] = 'XTN'
    sim_defaults['words'] = len(words)
    sim_defaults.pop('xfp')
    sim_defaults.pop('xpub')
    print("Using seed phrase from argv!")

    

if '--secret' in sys.argv:
    # --secret 01a1a1a....   Set SE master secret directly. See SecretStash.encode
    from ubinascii import unhexlify as a2b_hex
    from ubinascii import hexlify as b2a_hex

    val = sys.argv[sys.argv.index('--secret') + 1]
    val = a2b_hex(val)
    assert val[0] in { 0x01, 0x80, 0x81, 0x82} or 16 <= val[0] <= 64, "bad first byte"
    val += bytes(72 - len(val))

    SECRETS.update({
        '_pin1_secret': b2a_hex(val),
    })

    sim_defaults['terms_ok'] = 1
    sim_defaults['_skip_pin'] = '12-12'
    sim_defaults['chain'] = 'XTN'
    sim_defaults['words'] = bool(val[0] & 0x80)
    sim_defaults.pop('xfp')
    sim_defaults.pop('xpub')


if '-g' in sys.argv:
    # do login.. but does not work if _skip_pin got saved into settings already
    sim_defaults.pop('_skip_pin', 0)

if '--fails' in sys.argv:
    # fast-forward as if N PIN failures have already happened.
    count = int(sys.argv[sys.argv.index('--fails') + 1])
    import ckcc
    ckcc.SE_STATE.force_fails(count)
    sim_defaults.pop('_skip_pin', 0)

if '--nick' in sys.argv:
    nick = sys.argv[sys.argv.index('--nick') + 1]
    sim_defaults['nick'] = nick
    sim_defaults['terms_ok'] = 1
    sim_defaults.pop('_skip_pin', 0)

if '--delay' in sys.argv:
    delay = int(sys.argv[sys.argv.index('--delay') + 1])
    sim_defaults['lgto'] = delay

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })

if '--idle' in sys.argv:
    delay = int(sys.argv[sys.argv.index('--idle') + 1])
    sim_defaults['idle_to'] = delay

if '--set' in sys.argv:
    # use: --set foo=23
    # overrides/predefines anything
    for n, a in enumerate(sys.argv):
        if a != '--set': continue

        val = sys.argv[n+ 1]
        k,v = val.split('=', 1)
        try:
            v = int(v) if '.' not in v else float(v)
        except: pass
        sim_defaults[k] = v

if '--users' in sys.argv:
    sim_defaults['usr'] = { 
            # time based OTP
            # otpauth://totp/totp?secret=UR4LAZMTSJOF52FE&issuer=Coldcard%20simulator
            'totp': [1, 'UR4LAZMTSJOF52FE', 0],

            # OBSCURE: counter-based, not time
            # - no way to get your counter in sync w/ simulator
            # otpauth://hotp/hotp?secret=DBDCOKLQKM6BAKXD&issuer=Coldcard%20simulator
            'hotp': [2, 'DBDCOKLQKM6BAKXD', 0],

            # password
            # pw / 1234abcd
            'pw': [3, 'THNUHHFTG44NLI4EC7H7D6MU5AYMC3B3ER2ZFIBHQVUBOLGADA7Q', 0],
        }


# EOF
