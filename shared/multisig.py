# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# multisig.py - ms coordinator code mostly + some utils
#
import stash, chains, ustruct, ure, uio, sys, ngu, uos, ujson, version
from public_constants import AF_P2WSH, AF_P2WSH_P2SH
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, problem_file_line, get_filesize
from files import CardSlot, CardMissingError, needs_microsd
from ux import ux_show_story, ux_dramatic_pause, ux_enter_number, ux_enter_bip32_index
from public_constants import MAX_SIGNERS
from opcodes import OP_CHECKMULTISIG
from glob import settings
from charcodes import KEY_QR
from desc_utils import Key, KeyOriginInfo


def disassemble_multisig_mn(redeem_script):
    # pull out just M and N from script. Simple, faster, no memory.

    if redeem_script[-1] != OP_CHECKMULTISIG:
        return None, None

    M = redeem_script[0] - 80
    N = redeem_script[-2] - 80

    return M, N

def make_redeem_script(M, nodes, subkey_idx, bip67=True):
    # take a list of BIP-32 nodes, and derive Nth subkey (subkey_idx) and make
    # a standard M-of-N redeem script for that. Applies BIP-67 sorting by default.
    N = len(nodes)
    assert 1 <= M <= N <= MAX_SIGNERS

    pubkeys = []
    for n in nodes:
        copy = n.copy()
        copy.derive(subkey_idx, False)
        # 0x21 = 33 = len(pubkey) = OP_PUSHDATA(33)
        pubkeys.append(b'\x21' + copy.pubkey())
        del copy

    if bip67:
        pubkeys.sort()

    # serialize redeem script
    pubkeys.insert(0, bytes([80 + M]))
    pubkeys.append(bytes([80 + N, OP_CHECKMULTISIG]))

    return b''.join(pubkeys)


async def ms_coordinator_qr(af_str, my_xfp):
    # Scan a number of JSON files from BBQr w/ derive, xfp and xpub details.
    #
    from ux_q1 import QRScannerInteraction, decode_qr_result, QRDecodeExplained

    def convertor(got):
        file_type, _, data = decode_qr_result(got, expect_bbqr=True)
        if isinstance(data, bytes):
            # we expect BBQr, but simple QR also possible here
            data = data.decode()

        if file_type == 'U':
            data = data.strip()
            if data[0] == '{' and data[-1] == '}':
                file_type = 'J'
        if file_type == 'J':
            try:
                return ujson.loads(data)
            except:
                raise QRDecodeExplained('Unable to decode JSON data')
        else:
            for line in data.split("\n"):
                if len(line) > 112 and ("pub" in line):
                    return line.strip()

    num_mine = 0
    num_files = 0
    keys = []

    msg = 'Scan Exported XPUB from Coldcard'
    while True:
        key = await QRScannerInteraction().scan_general(msg, convertor, enter_quits=True)
        if key is None:
            break
        try:
            if isinstance(key, dict):
                k = Key.from_cc_json(key, af_str)
            else:
                k = Key.from_string(key)

            num_mine += k.validate(my_xfp)
            keys.append(k)

        except KeyError as e:
            # random JSON will end up here
            msg = "Missing value: %s" % str(e)
            continue
        except Exception as e:
            # other QR codes, not BBQr (json) will stop here.
            msg = "Failure: %s" % str(e)
            continue

        num_files += 1

        msg = "Number of keys scanned: %d" % num_files

    return keys, num_mine, num_files


async def ms_coordinator_file(af_str, my_xfp, slot_b=None):
    num_mine = 0
    num_files = 0
    keys = []
    try:
        with CardSlot(slot_b=slot_b) as card:
            for path in card.get_paths():
                for fn, ftype, *var in uos.ilistdir(path):
                    if ftype == 0x4000:
                        # ignore subdirs
                        continue

                    if fn.endswith('.bsms'):
                        pass  # allows files with [xfp/p/a/t/h]xpub
                    elif not fn.startswith('ccxp-') or not fn.endswith('.json'):
                        # wrong prefix/suffix: ignore
                        continue

                    full_fname = path + '/' + fn

                    # Conside file size
                    # sigh, OS/filesystem variations
                    file_size = var[1] if len(var) == 2 else get_filesize(full_fname)

                    if not (0 <= file_size <= 1500):
                        # out of range size
                        continue

                    try:
                        with open(full_fname, 'rt') as fp:
                            try:
                                # CC multisig XPUBs JSON expected
                                vals = ujson.load(fp)
                            except:
                                # try looking for BIP-380 key expression
                                fp.seek(0)
                                for line in fp.readlines():
                                    if len(line) > 112 and ("pub" in line):
                                        vals = line.strip()
                                        break

                        if isinstance(vals, dict):
                            k = Key.from_cc_json(vals, af_str)
                        else:
                            k = Key.from_string(vals)

                        num_mine += k.validate(my_xfp)
                        keys.append(k)

                        num_files += 1

                    except CardMissingError:
                        raise

                    except Exception as exc:
                        # show something for coders, but no user feedback
                        # sys.print_exception(exc)
                        continue

    except CardMissingError:
        await needs_microsd()
        return

    return keys, num_mine, num_files


def add_own_xpub(chain, acct_num, addr_fmt, secret=None):
    # Build out what's required for using master secret (or another
    # encoded secret) as a co-signer
    deriv = "48h/%dh/%dh/%dh" % (chain.b44_cointype, acct_num,
                                 2 if addr_fmt == AF_P2WSH else 1)

    with stash.SensitiveValues(secret=secret) as sv:
        the_xfp = xfp2str(sv.get_xfp())
        koi = KeyOriginInfo.from_string(the_xfp + "/" + deriv)
        node = sv.derive_path(deriv, register=False)
        key = Key(node, koi, chain_type=chain.ctype)
        return key


async def ondevice_multisig_create(mode='p2wsh', addr_fmt=AF_P2WSH, is_qr=False, for_ccc=None):
    # collect all xpub- exports (must be >= 1) to make "air gapped" wallet
    # - function f specifies a way how to collect co-signer info - currently SD and QR (Q only)
    # - ask for M value
    # - create wallet, save and also export
    # - also create electrum skel to go with that
    # - only expected to work with our ccxp-foo.json export file format
    from glob import dis

    chain = chains.current_chain()
    my_xfp = settings.get('xfp')

    if is_qr:
        keys, num_mine, num_files = await ms_coordinator_qr(mode, my_xfp)
    else:
        keys, num_mine, num_files = await ms_coordinator_file(mode, my_xfp)
        if CardSlot.both_inserted():
            # handle dual slot usage: assumes slot A used by first call above
            bkeys, bnum_mine, bnum_files = await ms_coordinator_file(mode, my_xfp,
                                                                     slot_b=True)
            keys.extend(bkeys)
            num_mine += bnum_mine
            num_files += bnum_files

    # remove dups; easy to happen if you double-tap the export
    keys = list(set(keys))

    if not keys or (len(keys) == 1 and num_mine):
        if is_qr:
            msg = "No XPUBs scanned. Exit."
        else:
            msg = ("Unable to find any Coldcard exported keys on this card."
                   " Must have filename: ccxp-....json")
        await ux_show_story(msg)
        return

    if for_ccc:
        secret, ccc_ms_count = for_ccc
        # Always include 2 keys from CCC: own master (key A) and key C
        # - force them to same derivation.
        acct = await ux_enter_bip32_index('CCC Account Number:') or 0

        dis.fullscreen("Wait...")
        a = add_own_xpub(chain, acct, addr_fmt)  # master: key A
        c = add_own_xpub(chain, acct, addr_fmt, secret=secret)

        # problem: above file searching may find xpub export from key C
        # (or our master seed, exported) .. we can't add them again,
        # since xfp are not unique and that's probably not what they wanted
        got_xfps = [a.origin.fingerprint, c.origin.fingerprint]
        keys = [k for k in keys if k.origin.fingerprint not in got_xfps]

        if not keys:
            await ux_show_story("Need at least one other co-signer (key B).")
            return

        # master seed is always key0, key C is key1, k2..kn backup keys
        keys = [a, c] + keys
        num_mine += 2

    elif not num_mine:
        # add myself if not included already? As an option.
        ch = await ux_show_story("Add current Coldcard with above XFP ?",
                                 title="[%s]" % xfp2str(my_xfp))
        if ch == "y":
            acct = await ux_enter_bip32_index('Account Number:') or 0
            dis.fullscreen("Wait...")
            keys.append(add_own_xpub(chain, acct, addr_fmt))
            num_mine += 1

    N = len(keys)

    if (N > MAX_SIGNERS) or (N < 2):
        await ux_show_story("Invalid number of signers,min is 2 max is %d." % MAX_SIGNERS)
        return

    if for_ccc:
        M = 2
    else:
        # pick useful M value to start
        M = await ux_enter_number("How many need to sign?(M)", N, can_cancel=True)
        if not M:
            await ux_dramatic_pause('Aborted.', 2)
            return  # user cancel

    dis.fullscreen("Wait...")

    # create appropriate object
    assert 1 <= M <= N <= MAX_SIGNERS

    if for_ccc:
        name = "Coldcard Co-sign" if version.has_qwerty else "CCC"
        if ccc_ms_count:
            # make name unique for each CCC wallet, but they can edit
            name += " #%d" % (ccc_ms_count + 1)
    else:
        name = 'CC-%d-of-%d' % (M, N)

    from miniscript import Sortedmulti, Number
    from wallet import MiniScriptWallet
    from descriptor import Descriptor

    desc_obj = Descriptor(miniscript=Sortedmulti(Number(M), *keys),
                          addr_fmt=addr_fmt)
    # no need to validate here - as all the keys are already validated
    msc = MiniScriptWallet.from_descriptor_obj(name, desc_obj)

    if num_mine:
        from auth import NewMiniscriptEnrollRequest, UserAuthorizedAction

        UserAuthorizedAction.active_request = NewMiniscriptEnrollRequest(msc)

        # menu item case: add to stack
        from ux import the_ux
        the_ux.push(UserAuthorizedAction.active_request)
    else:
        # we cannot enroll multisig in which we do not participate
        # thou we can put descriptor on screen or on SD
        # cannot sign export if my key not included
        await msc.export_wallet_file(sign=False)


async def create_ms_step1(*a, for_ccc=None):
    # Show story, have them pick address format.
    ch = None
    is_qr = False

    if version.has_qr:
        # They have a scanner, could do QR codes...
        ch = await ux_show_story("Press " + KEY_QR + " to scan multisg XPUBs from "
                                                     "QR codes (BBQr) or ENTER to use SD card(s).",
                                 title="QR or SD Card?")

    if ch == KEY_QR:
        is_qr = True
        ch = await ux_show_story("Press ENTER for default address format (P2WSH, segwit), "
                                 "otherwise, press (1) for P2SH-P2WSH.", title="Address Format",
                                 escape="1")

    else:
        ch = await ux_show_story('''\
Insert SD card (or eject SD card to use Virtual Disk) with exported XPUB files \
from at least one other Coldcard. A multisig wallet will be constructed using \
those keys and this device.

Default is P2WSH addresses (segwit) or press (1) for P2SH-P2WSH.''', escape='1')

    if ch == 'y':
        n, f = 'p2wsh', AF_P2WSH
    elif ch == '1':
        n, f = 'p2sh_p2wsh', AF_P2WSH_P2SH
    else:
        return

    try:
        return await ondevice_multisig_create(n, f, is_qr, for_ccc=for_ccc)
    except Exception as e:
        # sys.print_exception(e)
        await ux_show_story('Failed to create multisig.\n\n%s\n%s' % (e, problem_file_line(e)),
                            title="ERROR")
# EOF
