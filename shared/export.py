# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# export.py - Export and share various semi-public data
#
import stash, chains, version, ujson, ngu
from uio import StringIO
from ucollections import OrderedDict
from utils import xfp2str, swab32, chunk_writer
from ux import ux_show_story
from glob import settings
from auth import write_sig_file
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH, AF_P2WSH, AF_P2WSH_P2SH, AF_P2SH, AF_P2TR
from charcodes import KEY_NFC, KEY_CANCEL, KEY_QR
from ownership import OWNERSHIP

async def export_by_qr(body, label, type_code):
    # render as QR and show on-screen
    from ux import show_qr_code

    try:
        # ignore label/title - provides no useful info
        # makes qr smaller and harder to read
        await show_qr_code(body)
    except (ValueError, RuntimeError, TypeError):
        if version.has_qwerty:
            # do BBQr on Q
            from ux_q1 import show_bbqr_codes
            await show_bbqr_codes(type_code, body, label)

        # on Mk4, if too big ... just do nothing (but JSON should have fit?)

    return

def generate_public_contents():
    # Generate public details about wallet.
    #
    # simple text format: 
    #   key = value
    # or #comments
    # but value is JSON

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

**NEVER** deposit to any address in this file unless you have a working
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
                if "h" in subpath:
                    hard_sub = subpath.rsplit("h", 1)[0] + "h"
                else:
                    hard_sub = 'm'

                if hard_sub != submaster:
                    # dump the xpub needed

                    if submaster:
                        yield "\n"

                    node = sv.derive_path(hard_sub, register=False)
                    yield ("%s => %s\n" % (hard_sub, chain.serialize_public(node)))
                    if show_slip132 and addr_fmt not in (AF_CLASSIC, AF_P2TR) and (addr_fmt in chain.slip132):
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
    exists, exists_other_chain = MultisigWallet.exists()
    if exists:
        yield '\n# Your Multisig Wallets\n\n'

        for ms in MultisigWallet.get_all():
            fp = StringIO()

            ms.render_export(fp)
            print("\n---\n", file=fp)

            yield fp.getvalue()
            del fp

async def write_text_file(fname_pattern, body, title, derive, addr_fmt):
    # Export data as a text file.
    from glob import dis, NFC
    from files import CardSlot, CardMissingError, needs_microsd
    from ux import import_export_prompt

    choice = await import_export_prompt("%s file" % title, is_import=False,
                                        no_qr=(not version.has_qwerty))
    if choice == KEY_CANCEL:
        return
    elif choice == KEY_QR:
        await export_by_qr(body, title, "U")
        return
    elif choice == KEY_NFC:
        await NFC.share_text(body)
        return

    # choose a filename
    try:
        dis.fullscreen("Saving...")
        with CardSlot(**choice) as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wb') as fd:
                chunk_writer(fd, body)

            sig_nice = None
            if addr_fmt != AF_P2TR:
                h = ngu.hash.sha256s(body.encode())
                sig_nice = write_sig_file([(h, fname)], derive, addr_fmt)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '%s file written:\n\n%s' % (title, nice)
    if sig_nice:
        msg += '\n\n%s signature file written:\n\n%s' % (title, sig_nice)
    await ux_show_story(msg)

async def make_summary_file(fname_pattern='public.txt'):
    from glob import dis

    # record **public** values and helpful data into a text file
    dis.fullscreen('Generating...')

    # generator function:
    body = "".join(list(generate_public_contents()))
    ch = chains.current_chain()
    await write_text_file(fname_pattern, body, 'Summary',
                          "m/44h/%dh/0h/0/0" % ch.b44_cointype,
                          AF_CLASSIC)

async def make_bitcoin_core_wallet(account_num=0, fname_pattern='bitcoin-core.txt'):
    from glob import dis
    xfp = xfp2str(settings.get('xfp'))

    dis.fullscreen('Generating...')

    # make the data
    examples = []
    imp_multi, imp_desc, imp_desc_tr = generate_bitcoin_core_wallet(account_num, examples)

    imp_multi = ujson.dumps(imp_multi)
    imp_desc = ujson.dumps(imp_desc)
    imp_desc_tr = ujson.dumps(imp_desc_tr)

    body = '''\
# Bitcoin Core Wallet Import File

https://github.com/Coldcard/firmware/blob/master/docs/bitcoin-core-usage.md

## For wallet with master key fingerprint: {xfp}

Wallet operates on blockchain: {nb}

## Bitcoin Core RPC

The following command can be entered after opening Window -> Console
in Bitcoin Core, or using bitcoin-cli:

p2wpkh:
  importdescriptors '{imp_desc}'
p2tr:
  importdescriptors '{imp_desc_tr}'

> **NOTE** If your UTXO was created before generating `importdescriptors` command, you should adjust the value of `timestamp` before executing command in bitcoin core. 
  By default it is set to `now` meaning do not rescan the blockchain. If approximate time of UTXO creation is known - adjust `timestamp` from `now` to UNIX epoch time.
  0 can be specified to scan the entire blockchain. Alternatively `rescanblockchain` command can be used after executing importdescriptors command.

### Bitcoin Core before v0.21.0 

This command can be used on older versions, but it is not as robust
and "importdescriptors" should be prefered if possible:

importmulti '{imp_multi}'

## Resulting Addresses (first 3)

'''.format(imp_multi=imp_multi, imp_desc=imp_desc, imp_desc_tr=imp_desc_tr,
           xfp=xfp, nb=chains.current_chain().name)

    body += '\n'.join('%s => %s' % t for t in examples)

    body += '\n'

    OWNERSHIP.note_wallet_used(AF_P2WPKH, account_num)
    OWNERSHIP.note_wallet_used(AF_P2TR, account_num)

    ch = chains.current_chain()
    derive = "84h/{coin_type}h/{account}h".format(account=account_num, coin_type=ch.b44_cointype)
    await write_text_file(fname_pattern, body, 'Bitcoin Core', derive + "/0/0", AF_P2WPKH)

def generate_bitcoin_core_wallet(account_num, example_addrs):
    # Generate the data for an RPC command to import keys into Bitcoin Core
    # - yields dicts for json purposes
    from descriptor import Descriptor, Key

    chain = chains.current_chain()

    derive_v0 = "84h/{coin_type}h/{account}h".format(
        account=account_num, coin_type=chain.b44_cointype
    )
    derive_v1 = "86h/{coin_type}h/{account}h".format(
        account=account_num, coin_type=chain.b44_cointype
    )
    with stash.SensitiveValues() as sv:
        prefix = sv.derive_path(derive_v0)
        xpub_v0 = chain.serialize_public(prefix)

        for i in range(3):
            sp = '0/%d' % i
            node = sv.derive_path(sp, master=prefix)
            a = chain.address(node, AF_P2WPKH)
            example_addrs.append(('m/%s/%s' % (derive_v0, sp), a))

    with stash.SensitiveValues() as sv:
        prefix = sv.derive_path(derive_v1)
        xpub_v1 = chain.serialize_public(prefix)

        for i in range(3):
            sp = '0/%d' % i
            node = sv.derive_path(sp, master=prefix)
            a = chain.address(node, AF_P2TR)
            example_addrs.append(('m/%s/%s' % (derive_v1, sp), a))

    xfp = settings.get('xfp')
    key0 = Key.from_cc_data(xfp, derive_v0, xpub_v0)
    desc_v0 = Descriptor(key=key0)
    desc_v0.set_from_addr_fmt(AF_P2WPKH)

    key1 = Key.from_cc_data(xfp, derive_v1, xpub_v1)
    desc_v1 = Descriptor(key=key1)
    desc_v1.set_from_addr_fmt(AF_P2TR)

    OWNERSHIP.note_wallet_used(AF_P2WPKH, account_num)
    OWNERSHIP.note_wallet_used(AF_P2TR, account_num)

    # for importmulti
    imm_list = [
        {
            'desc': desc_v0.to_string(external, internal),
            'range': [0, 1000],
            'timestamp': 'now',
            'internal': internal,
            'keypool': True,
            'watchonly': True
        }
        for external, internal in [(True, False), (False, True)]
    ]
    # for importdescriptors
    imd_list = desc_v0.bitcoin_core_serialize()
    imd_list_v1 = desc_v1.bitcoin_core_serialize()
    return imm_list, imd_list, imd_list_v1


def generate_wasabi_wallet():
    # Generate the data for a JSON file which Wasabi can open directly as a new wallet.
    import version

    # bitcoin (xpub) is used, even for testnet case (i.e. no tpub)
    # even though wasabi can properly parse tpub and generate correct addresses
    # it would be confusing for user if he sees tpub in our export and then xpub in wasabi
    # therefore we rather export xpub with correct testnet derivation path
    btc = chains.BitcoinMain

    with stash.SensitiveValues() as sv:
        dd = "84h/%dh/0h" % chains.current_chain().b44_cointype
        xpub = btc.serialize_public(sv.derive_path(dd))

    xfp = settings.get('xfp')
    txt_xfp = xfp2str(xfp)

    # chain = chains.current_chain()
    # https://docs.wasabiwallet.io/using-wasabi/Testnet.html#activating-testnet-in-wasabi
    # https://github.com/zkSNACKs/WalletWasabi/blob/master/WalletWasabi.Documentation/WasabiSetupRegtest.md
    # as we do not shitcoin here - check is useless
    # would yikes on XRT
    # assert chain.ctype in {'BTC', 'XTN', 'XRT'}, "Only Bitcoin supported"

    _,vers,_ = version.get_mpy_version()

    rv = OrderedDict(ColdCardFirmwareVersion=vers, MasterFingerprint=txt_xfp, ExtPubKey=xpub)
    return ujson.dumps(rv), dd + "/0/0", AF_P2WPKH

def generate_unchained_export(account_num=0):
    # They used to rely on our airgapped export file, so this is same style
    # - for multisig purposes
    # - BIP-45 style paths for now
    # - no account numbers (at this level)

    chain = chains.current_chain()
    todo = [
        ( "m/48h/{coin}h/{acct_num}h/2h", 'p2wsh', AF_P2WSH ),
        ( "m/48h/{coin}h/{acct_num}h/1h", 'p2sh_p2wsh', AF_P2WSH_P2SH),
        ( "m/45h", 'p2sh', AF_P2SH),  # if acct_num == 0
    ]

    xfp = xfp2str(settings.get('xfp', 0))
    rv = OrderedDict(xfp=xfp, account=account_num)

    with stash.SensitiveValues() as sv:
        for deriv, name, fmt in todo:
            if fmt == AF_P2SH and account_num:
                continue
            dd = deriv.format(coin=chain.b44_cointype, acct_num=account_num)
            node = sv.derive_path(dd)
            xp = chain.serialize_public(node, fmt)

            OWNERSHIP.note_wallet_used(fmt, account_num)

            rv['%s_deriv' % name] = dd
            rv[name] = xp

    # sig_deriv = "m/44'/{ct}'/{acc}'".format(ct=chain.b44_cointype, acc=account_num) + "/0/0"
    # return ujson.dumps(rv), sig_deriv, AF_CLASSIC
    return ujson.dumps(rv), False, False

def generate_generic_export(account_num=0):
    # Generate data that other programers will use to import Coldcard (single-signer)
    from descriptor import Descriptor, Key
    from desc_utils import multisig_descriptor_template

    chain = chains.current_chain()
    master_xfp = settings.get("xfp")
    master_xfp_str = xfp2str(master_xfp)

    rv = OrderedDict(chain=chain.ctype,
                     xfp=master_xfp_str,
                     account=account_num,
                     xpub=settings.get('xpub'))

    with stash.SensitiveValues() as sv:
        # each of these paths would have /{change}/{idx} in usage (not hardened)
        for name, deriv, fmt, atype, is_ms in [
            ('bip44', "m/44h/{ct}h/{acc}h", AF_CLASSIC, 'p2pkh', False),
            ('bip49', "m/49h/{ct}h/{acc}h", AF_P2WPKH_P2SH, 'p2sh-p2wpkh', False),   # was "p2wpkh-p2sh"
            ('bip84', "m/84h/{ct}h/{acc}h", AF_P2WPKH, 'p2wpkh', False),
            ('bip86', "m/86h/{ct}h/{acc}h", AF_P2TR, 'p2tr', False),
            ('bip48_1', "m/48h/{ct}h/{acc}h/1h", AF_P2WSH_P2SH, 'p2sh-p2wsh', True),
            ('bip48_2', "m/48h/{ct}h/{acc}h/2h", AF_P2WSH, 'p2wsh', True),
            ('bip48_3', "m/48h/{ct}h/{acc}h/3h", AF_P2TR, 'p2tr', True),
            ('bip45', "m/45h", AF_P2SH, 'p2sh', True),
        ]:
            if fmt == AF_P2SH and account_num:
                continue

            dd = deriv.format(ct=chain.b44_cointype, acc=account_num)
            node = sv.derive_path(dd)
            xfp = xfp2str(swab32(node.my_fp()))
            xp = chain.serialize_public(node, AF_CLASSIC)
            zp = chain.serialize_public(node, fmt) if fmt not in (AF_CLASSIC, AF_P2TR) else None
            if is_ms:
                desc = multisig_descriptor_template(xp, dd, master_xfp_str, fmt)
            else:
                key = Key.from_cc_data(master_xfp, dd, xp)
                desc_obj = Descriptor(key=key)
                desc_obj.set_from_addr_fmt(fmt)
                desc = desc_obj.to_string()

                OWNERSHIP.note_wallet_used(fmt, account_num)

            rv[name] = OrderedDict(name=atype,
                                   xfp=xfp,
                                   deriv=dd,
                                   xpub=xp,
                                   desc=desc)

            if zp and zp != xp:
                rv[name]['_pub'] = zp

            if not is_ms:
                # bonus/check: first non-change address: 0/0
                node.derive(0, False).derive(0, False)
                rv[name]['first'] = chain.address(node, fmt)

    sig_deriv = "m/44h/{ct}h/{acc}h".format(ct=chain.b44_cointype, acc=account_num) + "/0/0"
    return ujson.dumps(rv), sig_deriv, AF_CLASSIC

def generate_electrum_wallet(addr_type, account_num):
    # Generate line-by-line JSON details about wallet.
    #
    # Much reverse enginerring of Electrum here. It's a complex
    # legacy file format.

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

    OWNERSHIP.note_wallet_used(addr_type, account_num)

    derive = "m/{mode}h/{coin_type}h/{account}h".format(mode=mode,
                                    account=account_num, coin_type=chain.b44_cointype)

    with stash.SensitiveValues() as sv:
        top = chain.serialize_public(sv.derive_path(derive), addr_type)

    # most values are nicely defaulted, and for max forward compat, don't want to set
    # anything more than I need to

    rv = OrderedDict(seed_version=17, use_encryption=False, wallet_type='standard')

    lab = 'Coldcard Import %s' % xfp2str(xfp)
    if account_num:
        lab += ' Acct#%d' % account_num

    # the important stuff.
    rv['keystore'] = OrderedDict(type='hardware',
                                 hw_type='coldcard',
                                 label=lab,
                                 ckcc_xfp=xfp,
                                 ckcc_xpub=settings.get('xpub'),
                                 derivation=derive,
                                 xpub=top)

    return ujson.dumps(rv), derive + "/0/0", addr_type

async def make_json_wallet(label, func, fname_pattern='new-wallet.json'):
    # Record **public** values and helpful data into a JSON file
    # - OWNERSHIP.note_wallet_used(..) should be called already by our caller or func

    from glob import dis, NFC
    from files import CardSlot, CardMissingError, needs_microsd
    from ux import import_export_prompt
    from qrs import MAX_V11_CHAR_LIMIT

    dis.fullscreen('Generating...')
    json_str, derive, addr_fmt = func()
    skip_sig = derive is False and addr_fmt is False

    choice = await import_export_prompt("%s file" % label, is_import=False,
                    no_qr=(not version.has_qwerty and len(json_str) >= MAX_V11_CHAR_LIMIT))

    if choice == KEY_CANCEL:
        return
    elif choice == KEY_NFC:
        await NFC.share_json(json_str)
        return
    elif choice == KEY_QR:
        # render as QR and show on-screen
        # - on mk4, this isn't offered if more than about 300 bytes because we can't
        #   show that as a single QR
        await export_by_qr(json_str, label, "J")
        return

    # choose a filename and save
    try:
        with CardSlot(**choice) as card:
            fname, nice = card.pick_filename(fname_pattern)

            # do actual write
            with open(fname, 'wt') as fd:
                chunk_writer(fd, json_str)

            if not skip_sig:
                h = ngu.hash.sha256s(json_str.encode())
                sig_nice = write_sig_file([(h, fname)], derive, addr_fmt)

    except CardMissingError:
        await needs_microsd()
        return
    except Exception as e:
        await ux_show_story('Failed to write!\n\n\n'+str(e))
        return

    msg = '%s file written:\n\n%s' % (label, nice)
    if not skip_sig:
        msg += '\n\n%s signature file written:\n\n%s' % (label, sig_nice)

    await ux_show_story(msg)


async def make_descriptor_wallet_export(addr_type, account_num=0, mode=None, int_ext=True,
                                        fname_pattern="descriptor.txt"):
    from descriptor import Descriptor, Key
    from glob import dis

    dis.fullscreen('Generating...')
    chain = chains.current_chain()

    xfp = settings.get('xfp')
    dis.progress_bar_show(0.1)
    if mode is None:
        if addr_type == AF_CLASSIC:
            mode = 44
        elif addr_type == AF_P2WPKH:
            mode = 84
        elif addr_type == AF_P2WPKH_P2SH:
            mode = 49
        elif addr_type == AF_P2TR:
            mode = 86
        else:
            raise ValueError(addr_type)

    OWNERSHIP.note_wallet_used(addr_type, account_num)

    derive = "m/{mode}h/{coin_type}h/{account}h".format(
        mode=mode, account=account_num, coin_type=chain.b44_cointype
    )
    dis.progress_bar_show(0.2)
    with stash.SensitiveValues() as sv:
        dis.progress_bar_show(0.3)
        xpub = chain.serialize_public(sv.derive_path(derive))

    dis.progress_bar_show(0.7)

    key = Key.from_cc_data(xfp, derive, xpub)
    desc = Descriptor(key=key)
    desc.set_from_addr_fmt(addr_type)
    dis.progress_bar_show(0.8)
    if int_ext:
        #  with <0;1> notation
        body = desc.to_string()
    else:
        # external descriptor
        # internal descriptor
        body = "%s\n%s" % (
            desc.to_string(internal=False),
            desc.to_string(external=False),
        )

    dis.progress_bar_show(1)
    await write_text_file(fname_pattern, body, "Descriptor", derive + "/0/0", addr_type)

# EOF

