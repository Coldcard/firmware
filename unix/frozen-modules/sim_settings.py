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
    # CAUTION: some test cases will rely on these
    sim_defaults = {
        '_age': 42,
        #'chain': 'BTC',
        #'xpub': 'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7',
        'chain': 'XTN',
        'xpub': 'tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh',
        '_skip_pin': '12-12',
        'terms_ok': 1,
        'xfp': 1130956047,
        'idle_to': 28800
    }

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '82faf8c43d8835d20aef178a530bb658071a5252b722ba910a4143d9010ebfded9000000000000000000000000000000000000000000000000000000000000000000000000000000',
    })

if '-2' in sys.argv:
    # enable second wallet, but no seeds
    sim_defaults.pop('_skip_pin', 0)
    SECRETS.update({
        '_pin2': '33-33',
        '_pin2_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })

if '-p' in sys.argv:
    # pretend BIP39 password is active (just for menus)
    sim_defaults['words'] = False

if '-m' in sys.argv:
    # Include useful multisig wallet, and shortcut to MS menu

    if '--p2wsh' in sys.argv:
        sim_defaults['multisig'] = [["P2WSH--2-of-4", [2, 4], [[1130956047, "tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP"], [3503269483, "tpubDFcrvj5n7gyaxWQkoX69k2Zij4vthiAwvN2uhYjDrE6wktKoQaE7gKVZRiTbYdrAYH1UFPGdzdtWJc6WfR2gFMq6XpxA12gCdQmoQNU9mgm"], [2389277556, "tpubDExj5FnaUnPAn7sHGUeBqD3buoNH5dqmjAT6884vbDpH1iDYWigb7kFo2cA97dc8EHb54u13TRcZxC4kgRS9gc3Ey2xc8c5urytEzTcp3ac"], [3190206587, "tpubDFiuHYSJhNbHcbLJoxWdbjtUcbKR6PvLq53qC1Xq6t93CrRx78W3wcng8vJyQnY3giMJZEgNCRVzTojLb8RqPFpW5Ms2dYpjcJYofN1joyu"]], {"pp": "48'/1'/0'/2'", "ch": "XTN", "ft": 14}]]
    elif '--wrap' in sys.argv:
        # p2wsh-p2sh case
        sim_defaults['multisig'] = [["CC-2-of-4", [2, 4], [[1130956047, "tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP"], [3503269483, "tpubDFcrvj5n7gyatVbr8dHCUfHT4CGvL8hREBjtxc4ge7HZgqNuPhFimPRtVg6fRRwfXiQthV9EBjNbwbpgV2VoQeL1ZNXoAWXxP2L9vMtRjax"], [2389277556, "tpubDExj5FnaUnPAjjgzELoSiNRkuXJG8Cm1pbdiA4Hc5vkAZHphibeVcUp6mqH5LuNVKbtLVZxVSzyja5X26Cfmx6pzRH6gXBUJAH7MiqwNyuM"], [3190206587, "tpubDFiuHYSJhNbHaGtB5skiuDLg12tRboh2uVZ6KGXxr8WVr28pLcS7F3gv8SsHFa2tm1jtx3VAuw56YfgRkdo6DXyfp51oygTKY3nJFT5jBMt"]], {"pp": "48'/1'/0'/1'", "ch": "XTN", "ft": 26}]]
    else:
        # P2SH: 2of4 using BIP39 passwords: "Me", "Myself", "and I", and (empty string) on simulator
        sim_defaults['multisig'] = [['MeMyself', [2, 4], [[3503269483, 'tpubD9429UXFGCTKJ9NdiNK4rC5ygqSUkginycYHccqSg5gkmyQ7PZRHNjk99M6a6Y3NY8ctEUUJvCu6iCCui8Ju3xrHRu3Ez1CKB4ZFoRZDdP9'], [2389277556, 'tpubD97nVL37v5tWyMf9ofh5rznwhh1593WMRg6FT4o6MRJkKWANtwAMHYLrcJFsFmPfYbY1TE1LLQ4KBb84LBPt1ubvFwoosvMkcWJtMwvXgSc'], [3190206587, 'tpubD9ArfXowvGHnuECKdGXVKDMfZVGdephVWg8fWGWStH3VKHzT4ph3A4ZcgXWqFu1F5xGTfxncmrnf3sLC86dup2a8Kx7z3xQ3AgeNTQeFxPa'], [1130956047, 'tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n']], {'ch': 'XTN', 'pp': "45'"}]]
    sim_defaults['fee_limit'] = -1


    # start in multisig wallet
    from main import numpad
    numpad.inject('9')
    numpad.inject('y')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')

if '-s' in sys.argv:
    # MicroSD menu
    from main import numpad
    numpad.inject('4')
    numpad.inject('y')
    numpad.inject('4')

if '-p' in sys.argv:
    # Paper wallet menu
    from main import numpad
    numpad.inject('3')
    numpad.inject('y')
    numpad.inject('4')
    numpad.inject('8')
    numpad.inject('y')

if '--xfp' in sys.argv:
    # --xfp aabbccdd   => pretend we know that key (won't be able to sign)
    from ustruct import unpack
    from utils import xfp2str
    from ubinascii import unhexlify as a2b_hex

    xfp = sys.argv[sys.argv.index('--xfp') + 1]
    sim_defaults['xfp'] = unpack(">I", a2b_hex(xfp))[0]
    print("Override XFP: " + xfp2str(sim_defaults['xfp']))


# EOF
