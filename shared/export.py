# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# export.py - Export and share various semi-public data
#
import stash, chains, sys
#from ubinascii import hexlify as b2a_hex
#from ubinascii import unhexlify as a2b_hex
from utils import xfp2str, swab32
from ux import ux_show_story
import version, ujson
from uio import StringIO
from glob import settings

def generate_public_contents():
    # Generate public details about wallet.
    #
    # simple text format: 
    #   key = value
    # or #comments
    # but value is JSON
    from public_constants import AF_CLASSIC

    num_rx = 5

    chain = chains.current_chain()

    with stash.SensitiveValues() as sv:

        xfp = xfp2str(swab32(sv.node.my_fp()))

        yield ('''\
# Coldcard Wallet Summary File
## For wallet with master key fingerprint: {xfp}

Wallet operates on blockchain: {nb}

For BIP-44, this is coin_type '{ct}', and internally we use
symbol {sym} for this blockchain.

## IMPORTANT WARNING

Do **not** deposit to any address in this file unless you have a working
wallet system that is ready to handle the funds at that address!

## Top-level, 'master' extended public key ('m/'):

{xpub}

What follows are derived public keys and payment addresses, as may
be needed for different systems.


'''.format(nb=chain.name, xpub=chain.serialize_public(sv.node), 
            sym=chain.ctype, ct=chain.b44_cointype, xfp=xfp))

        for name, path, addr_fmt in chains.CommonDerivations:

            if '{coin_type}' in path:
                path = path.replace('{coin_type}', str(chain.b44_cointype))

            if '{' in name:
                name = name.format(core_name=chain.core_name)

            show_slip132 = ('Core' not in name)

            yield ('''## For {name}: {path}\n\n'''.format(name=name, path=path))
            yield ('''First %d receive addresses (account=0, change=0):\n\n''' % num_rx)

            submaster = None
            for i in range(num_rx):
                subpath = path.format(account=0, change=0, idx=i)

                # find the prefix of the path that is hardneded
                if "'" in subpath:
                    hard_sub = subpath.rsplit("'", 1)[0] + "'"
                else:
                    hard_sub = 'm'

                if hard_sub != submaster:
                    # dump the xpub needed

                    if submaster:
                        yield "\n"

                    node = sv.derive_path(hard_sub, register=False)
                    yield ("%s => %s\n" % (hard_sub, chain.serialize_public(node)))
                    if show_slip132 and addr_fmt != AF_CLASSIC and (addr_fmt in chain.slip132):
                        yield ("%s => %s   ##SLIP-132##\n" % (
                                    hard_sub, chain.serialize_public(node, addr_fmt)))

                    submaster = hard_sub
                    node.blank()
                    del node

                # show the payment address
                node = sv.derive_path(subpath, register=False)
                yield ('%s => %s\n' % (subpath, chain.address(node, addr_fmt)))

                node.blank()
                del node

            yield ('\n\n')

    from multisig import MultisigWallet
    if MultisigWallet.exists():
        yield '\n# Your Multisig Wallets\n\n'
        from uio import StringIO

        for ms in MultisigWallet.get_all():
            fp = StringIO()

            ms.render_export(fp)
            print("\n---\n", file=fp)

            yield fp.getvalue()
            del fp

async def write_text_file(fname_pattern, body, title, total_parts=72):
    # - total_parts does need not be precise
    from glob import dis
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    # choose a filename
    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wb') as fd:
                for idx, part in enumerate(body):
                    dis.progress_bar_show(idx / total_parts)
                    fd.write(part.encode())

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''%s file written:\n\n%s''' % (title, nice)
    await ux_show_story(msg)

async def make_summary_file(fname_pattern='public.txt'):
    from glob import dis

    # record **public** values and helpful data into a text file
    dis.fullscreen('Generating...')

    # generator function:
    body = generate_public_contents()

    await write_text_file(fname_pattern, body, 'Summary')

async def make_bitcoin_core_wallet(account_num=0, fname_pattern='bitcoin-core.txt'):
    from glob import dis
    import ustruct
    xfp = xfp2str(settings.get('xfp'))

    dis.fullscreen('Generating...')

    # make the data
    examples = []
    payload = ujson.dumps(list(generate_bitcoin_core_wallet(examples, account_num)))

    body = '''\
# Bitcoin Core Wallet Import File

https://github.com/Coldcard/firmware/blob/master/docs/bitcoin-core-usage.md

## For wallet with master key fingerprint: {xfp}

Wallet operates on blockchain: {nb}

## Bitcoin Core RPC

The following command can be entered after opening Window -> Console
in Bitcoin Core, or using bitcoin-cli:

importmulti '{payload}'

## Resulting Addresses (first 3)

'''.format(payload=payload, xfp=xfp, nb=chains.current_chain().name)

    body += '\n'.join('%s => %s' % t for t in examples)

    body += '\n'

    await write_text_file(fname_pattern, body, 'Bitcoin Core')

def generate_bitcoin_core_wallet(example_addrs, account_num):
    # Generate the data for an RPC command to import keys into Bitcoin Core
    # - yields dicts for json purposes
    from descriptor import append_checksum
    import ustruct

    from public_constants import AF_P2WPKH

    chain = chains.current_chain()

    derive = "84'/{coin_type}'/{account}'".format(account=account_num, coin_type=chain.b44_cointype)

    with stash.SensitiveValues() as sv:
        prefix = sv.derive_path(derive)
        xpub = chain.serialize_public(prefix)

        for i in range(3):
            sp = '0/%d' % i
            node = sv.derive_path(sp, master=prefix)
            a = chain.address(node, AF_P2WPKH)
            example_addrs.append( ('m/%s/%s' % (derive, sp), a) )

    xfp = settings.get('xfp')
    txt_xfp = xfp2str(xfp).lower()

    chain = chains.current_chain()

    _,vers,_ = version.get_mpy_version()

    for internal in [False, True]:
        desc = "wpkh([{fingerprint}/{derive}]{xpub}/{change}/*)".format(
            derive=derive.replace("'", "h"),
            fingerprint=txt_xfp,
            coin_type=chain.b44_cointype,
            account=0,
            xpub=xpub,
            change=(1 if internal else 0))

        yield {
            'desc': append_checksum(desc),
            'range': [0, 1000],
            'timestamp': 'now',
            'internal': internal,
            'keypool': True,
            'watchonly': True
        }

def generate_wasabi_wallet():
    # Generate the data for a JSON file which Wasabi can open directly as a new wallet.
    import ustruct, version

    # bitcoin (xpub) is used, even for testnet case (ie. no tpub)
    # - altho, doesn't matter; the wallet operates based on it's own settings for test/mainnet
    #   regardless of the contents of the wallet file
    btc = chains.BitcoinMain

    with stash.SensitiveValues() as sv:
        xpub = btc.serialize_public(sv.derive_path("84'/0'/0'"))

    xfp = settings.get('xfp')
    txt_xfp = xfp2str(xfp)

    chain = chains.current_chain()
    assert chain.ctype in {'BTC', 'XTN'}, "Only Bitcoin supported"

    _,vers,_ = version.get_mpy_version()

    return dict(MasterFingerprint=txt_xfp,
                ColdCardFirmwareVersion=vers,
                ExtPubKey=xpub)

def generate_unchained_export(acct_num=0):
    # They used to rely on our airgapped export file, so this is same style
    # - for multisig purposes
    # - BIP-45 style paths for now
    # - no account numbers (at this level)
    from public_constants import AF_P2SH, AF_P2WSH_P2SH, AF_P2WSH

    chain = chains.current_chain()
    todo = [
        ( "m/45'", 'p2sh', AF_P2SH),       # iff acct_num == 0
        ( "m/48'/{coin}'/{acct_num}'/1'", 'p2sh_p2wsh', AF_P2WSH_P2SH ),
        ( "m/48'/{coin}'/{acct_num}'/2'", 'p2wsh', AF_P2WSH ),
    ]

    xfp = xfp2str(settings.get('xfp', 0))
    rv = dict(account=acct_num, xfp=xfp)

    with stash.SensitiveValues() as sv:
        for deriv, name, fmt in todo:
            if fmt == AF_P2SH and acct_num:
                continue
            dd = deriv.format(coin=chain.b44_cointype, acct_num=acct_num)
            node = sv.derive_path(dd)
            xp = chain.serialize_public(node, fmt)

            rv['%s_deriv' % name] = dd
            rv[name] = xp

    return rv

def generate_generic_export(account_num=0):
    # Generate data that other programers will use to import Coldcard (single-signer)
    from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2WSH, AF_P2WSH_P2SH
    from public_constants import AF_P2SH

    chain = chains.current_chain()

    rv = dict(chain=chain.ctype,
                xpub = settings.get('xpub'),
                xfp = xfp2str(settings.get('xfp')),
                account = account_num,
            )

    with stash.SensitiveValues() as sv:
        # each of these paths would have /{change}/{idx} in usage (not hardened)
        for name, deriv, fmt, atype, is_ms in [
            ( 'bip44', "m/44'/{ct}'/{acc}'", AF_CLASSIC, 'p2pkh', False ),
            ( 'bip49', "m/49'/{ct}'/{acc}'", AF_P2WPKH_P2SH, 'p2sh-p2wpkh', False ),   # was "p2wpkh-p2sh"
            ( 'bip84', "m/84'/{ct}'/{acc}'", AF_P2WPKH, 'p2wpkh', False ),
            ( 'bip48_1', "m/48'/{ct}'/{acc}'/1'", AF_P2WSH_P2SH, 'p2sh-p2wsh', True ),
            ( 'bip48_2', "m/48'/{ct}'/{acc}'/2'", AF_P2WSH, 'p2wsh', True ),
            ( 'bip45', "m/45'", AF_P2SH, 'p2sh', True ),
        ]:
            if fmt == AF_P2SH and account_num:
                continue

            dd = deriv.format(ct=chain.b44_cointype, acc=account_num)
            node = sv.derive_path(dd)
            xfp = xfp2str(swab32(node.my_fp()))
            xp = chain.serialize_public(node, AF_CLASSIC)
            zp = chain.serialize_public(node, fmt) if fmt != AF_CLASSIC else None

            rv[name] = dict(deriv=dd, xpub=xp, xfp=xfp, name=atype)

            if not is_ms:
                # bonus/check: first non-change address: 0/0
                node.derive(0, False).derive(0, False)
                rv[name]['first'] = chain.address(node, fmt)

            if zp:
                rv[name]['_pub'] = zp

    return rv

def generate_electrum_wallet(addr_type, account_num=0):
    # Generate line-by-line JSON details about wallet.
    #
    # Much reverse enginerring of Electrum here. It's a complex
    # legacy file format.
    from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

    chain = chains.current_chain()

    xfp = settings.get('xfp')

    # Must get the derivation path, and the SLIP32 version bytes right!
    if addr_type == AF_CLASSIC:
        mode = 44
    elif addr_type == AF_P2WPKH:
        mode = 84
    elif addr_type == AF_P2WPKH_P2SH:
        mode = 49
    else:
        raise ValueError(addr_type)

    derive = "m/{mode}'/{coin_type}'/{account}'".format(mode=mode,
                                    account=account_num, coin_type=chain.b44_cointype)

    with stash.SensitiveValues() as sv:
        top = chain.serialize_public(sv.derive_path(derive), addr_type)

    # most values are nicely defaulted, and for max forward compat, don't want to set
    # anything more than I need to

    rv = dict(seed_version=17, use_encryption=False, wallet_type='standard')

    lab = 'Coldcard Import %s' % xfp2str(xfp)
    if account_num:
        lab += ' Acct#%d' % account_num

    # the important stuff.
    rv['keystore'] = dict(  ckcc_xfp=xfp,
                            ckcc_xpub=settings.get('xpub'),
                            hw_type='coldcard', type='hardware',
                            label=lab, derivation=derive, xpub=top)
        
    return rv

async def make_json_wallet(label, generator, fname_pattern='new-wallet.json'):
    # Record **public** values and helpful data into a JSON file

    from glob import dis
    from files import CardSlot, CardMissingError
    from actions import needs_microsd

    dis.fullscreen('Generating...')

    body = generator()

    # choose a filename
        
    try:
        with CardSlot() as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wt') as fd:
                ujson.dump(body, fd)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '''%s file written:\n\n%s''' % (label, nice)
    await ux_show_story(msg)

# EOF

