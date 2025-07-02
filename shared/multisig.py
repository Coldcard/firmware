# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# multisig.py - support code for multisig signing and p2sh in general.
#
import stash, chains, ustruct, ure, uio, sys, ngu, uos, ujson, version
from ubinascii import hexlify as b2a_hex
from utils import xfp2str, keypath_to_str
from utils import check_xpub
from ux import ux_show_story, ux_dramatic_pause, ux_clear_keys
from ux import OK, X
from public_constants import AF_P2SH, MAX_SIGNERS, AF_CLASSIC
from opcodes import OP_CHECKMULTISIG
from exceptions import FatalPSBTIssue
from glob import settings
from serializations import disassemble
from wallet import BaseStorageWallet


def disassemble_multisig_mn(redeem_script):
    # pull out just M and N from script. Simple, faster, no memory.

    if redeem_script[-1] != OP_CHECKMULTISIG:
        return None, None

    M = redeem_script[0] - 80
    N = redeem_script[-2] - 80

    return M, N

def disassemble_multisig(redeem_script):
    # Take apart a standard multisig's redeem/witness script, and return M/N and public keys
    # - only for multisig scripts, not general purpose
    # - expect OP_1 (pk1) (pk2) (pk3) OP_3 OP_CHECKMULTISIG for 1 of 3 case
    # - returns M, N, (list of pubkeys)
    # - for very unlikely/impossible asserts, don't document reason; otherwise do.
    M, N = disassemble_multisig_mn(redeem_script)
    assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
    assert len(redeem_script) == 1 + (N * 34) + 1 + 1, 'bad len'

    # generator function
    dis = disassemble(redeem_script)

    # expect M value first
    ex_M, opcode =  next(dis)
    assert ex_M == M and opcode is None, 'bad M'

    # need N pubkeys
    pubkeys = []
    for idx in range(N):
        data, opcode = next(dis)
        assert opcode is None and len(data) == 33, 'data'
        assert data[0] == 0x02 or data[0] == 0x03, 'Y val'
        pubkeys.append(data)

    assert len(pubkeys) == N

    # next is N value
    ex_N, opcode = next(dis)
    assert ex_N == N and opcode is None

    # finally, the opcode: CHECKMULTISIG
    data, opcode = next(dis)
    assert opcode == OP_CHECKMULTISIG

    # must have reached end of script at this point
    try:
        next(dis)
        raise AssertionError("too long")
    except StopIteration:
        # expected, since we're reading past end
        pass

    return M, N, pubkeys

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

class MultisigWallet(BaseStorageWallet):

    def assert_matching(self, M, N, xfp_paths):
        # compare in-memory wallet with details recovered from PSBT
        # - xfp_paths must be sorted already
        assert (self.M, self.N) == (M, N), "M/N mismatch"
        assert len(xfp_paths) == N, "XFP count"
        if self.disable_checks: return
        assert self.matching_subpaths(xfp_paths), "wrong XFP/derivs"


    def has_similar(self):
        # check if we already have a saved duplicate to this proposed wallet
        # - return (name_change, diff_items, count_similar) where:
        #   - name_change is existing wallet that has exact match, different name
        #   - diff_items: text list of similarity/differences
        #   - count_similar: same N, same xfp+paths

        lst = self.get_xfp_paths()
        c = self.find_match(self.M, self.N, lst, addr_fmt=self.addr_fmt)
        if c:
            # All details are same: M/N, paths, addr fmt
            if sorted(self.xpubs) != sorted(c.xpubs):
                # this also applies to non-BIP-67 type multisig wallets
                # multi(2,A,B) is treated as duplicate of multi(2,B,A)
                # consensus-wise they are different script/wallet but CC
                # don't allow to import one if other already imported
                return None, ['xpubs'], 0
            elif self.bip67 != c.bip67:
                # treat same keys inside different desc multi/sortedmulti as duplicates
                # sortedmulti(2,A,B) is considered same as multi(2,A,B) or multi(2,B,A)
                # do not allow to import multi if sortedmulti with the same set of keys
                # already imported and vice-versa
                return None, ["BIP-67 clash"], 1
            elif self.name == c.name:
                return None, [], 1
            else:
                return c, ['name'], 0

        similar = MultisigWallet.find_candidates(lst)
        if not similar:
            # no matches, good.
            return None, [], 0

        # See if the xpubs are changing, which is risky... other differences like
        # name are okay.
        diffs = set()
        for c in similar:
            if c.M != self.M:
                diffs.add('M differs')
            if c.addr_fmt != self.addr_fmt:
                diffs.add('address type')
            if c.name != self.name:
                diffs.add('name')
            if c.xpubs != self.xpubs:
                diffs.add('xpubs')

        return None, diffs, len(similar)

    async def export_electrum(self):
        # Generate and save an Electrum JSON file.
        from export import export_contents

        def doit():
            rv = dict(seed_version=17, use_encryption=False,
                        wallet_type='%dof%d' % (self.M, self.N))

            ch = self.chain

            # the important stuff.
            for idx, (xfp, deriv, xpub) in enumerate(self.xpubs): 

                node = None
                if self.addr_fmt != AF_P2SH:
                    # CHALLENGE: we must do slip-132 format [yz]pubs here when not p2sh mode.
                    node = ch.deserialize_node(xpub, AF_P2SH); assert node
                    xp = ch.serialize_public(node, self.addr_fmt)
                else:
                    xp = xpub

                rv['x%d/' % (idx+1)] = dict(
                                hw_type='coldcard', type='hardware',
                                ckcc_xfp=xfp,
                                label='Coldcard %s' % xfp2str(xfp),
                                derivation=deriv, xpub=xp)

            # sign export with first p2pkh key
            return ujson.dumps(rv), self.get_my_deriv(settings.get('xfp'))+"/0/0", AF_CLASSIC
            
        await export_contents('Electrum multisig wallet', doit,
                              self.make_fname('el', 'json'), is_json=True)


    @classmethod
    def import_from_psbt(cls, M, N, xpubs_list):
        # given the raw data from PSBT global header, offer the user
        # the details, and/or bypass that all and just trust the data.
        # - xpubs_list is a list of (xfp+path, binary BIP-32 xpub)
        # - already know not in our records.
        trust_mode = cls.get_trust_policy()

        if trust_mode == TRUST_VERIFY:
            # already checked for existing import and wasn't found, so fail
            raise FatalPSBTIssue("XPUBs in PSBT do not match any existing wallet")

        # build up an in-memory version of the wallet.
        #  - capture address format based on path used for my leg (if standards compliant)

        assert N == len(xpubs_list)
        assert 1 <= M <= N <= MAX_SIGNERS, 'M/N range'
        my_xfp = settings.get('xfp')

        expect_chain = chains.current_chain().ctype
        xpubs = []
        has_mine = 0

        for k, v in xpubs_list:
            xfp, *path = ustruct.unpack_from('<%dI' % (len(k)//4), k, 0)
            xpub = ngu.codecs.b58_encode(v)
            is_mine, item = check_xpub(xfp, xpub, keypath_to_str(path, skip=0),
                                       expect_chain, my_xfp, cls.disable_checks)
            xpubs.append(item)
            if is_mine:
                has_mine += 1
                addr_fmt = cls.guess_addr_fmt(path)

        assert has_mine == 1         # 'my key not included'

        name = 'PSBT-%d-of-%d' % (M, N)
        # this will always create sortedmulti multisig (BIP-67)
        # because BIP-174 came years after wide spread acceptance of BIP-67 policy
        ms = cls(name, (M, N), xpubs, addr_fmt=addr_fmt or AF_P2SH) # TODO why legacy

        # may just keep in-memory version, no approval required, if we are
        # trusting PSBT's today, otherwise caller will need to handle UX w.r.t new wallet
        return ms, (trust_mode != TRUST_PSBT)

    def validate_psbt_xpubs(self, xpubs_list):
        # The xpubs provided in PSBT must be exactly right, compared to our record.
        # But we're going to use our own values from setup time anyway.
        # Check:
        # - chain codes match what we have stored already
        # - pubkey vs. path will be checked later
        # - xfp+path already checked when selecting this wallet
        # - some cases we cannot check, so count those for a warning
        # Any issue here is a fraud attempt in some way, not innocent.
        # But it would not have tricked us and so the attack targets some other signer.
        assert len(xpubs_list) == self.N

        for k, v in xpubs_list:
            xfp, *path = ustruct.unpack_from('<%dI' % (len(k)//4), k, 0)
            xpub = ngu.codecs.b58_encode(v)

            # cleanup and normalize xpub
            tmp = []
            is_mine, item = check_xpub(xfp, xpub, keypath_to_str(path, skip=0),
                                       chains.current_chain().ctype, 0, self.disable_checks)
            tmp.append(item)
            (_, deriv, xpub_reserialized) = tmp[0]
            assert deriv            # because given as arg

            if self.disable_checks:
                # allow wrong derivation paths in PSBT; but also allows usage when
                # old pre-3.2.1 MS wallet lacks derivation details for all legs
                continue

            # find in our records.
            for (x_xfp, x_deriv, x_xpub) in self.xpubs: 
                if x_xfp != xfp: continue
                # found matching XFP
                assert deriv == x_deriv

                assert xpub_reserialized == x_xpub, 'xpub wrong (xfp=%s)' % xfp2str(xfp)
                break
            else:
                assert False            # not reachable, since we picked wallet based on xfps

    async def confirm_import(self):
        # prompt them about a new wallet, let them see details and then commit change.
        M, N = self.M, self.N

        if M == N == 1:
            exp = 'The one signer must approve spends.'
        elif M == N:
            exp = 'All %d co-signers must approve spends.' % N
        elif M == 1:
            exp = 'Any signature from %d co-signers will approve spends.' % N
        else:
            exp = '{M} signatures, from {N} possible co-signers, will be required to approve spends.'.format(M=M, N=N)

        # Look for duplicate stuff
        name_change, diff_items, num_dups = self.has_similar()

        is_dup = False
        if name_change:
            story = 'Update NAME only of existing multisig wallet?'
        elif num_dups and isinstance(diff_items, list):
            # failures only
            story = "Duplicate wallet."
            if diff_items:
                story += diff_items[0]
            else:
                story += ' All details are the same as existing!'
            is_dup = True
        elif diff_items:
            # Concern here is overwrite when similar, but we don't overwrite anymore, so 
            # more of a warning about funny business.
            story = '''\
WARNING: This new wallet is similar to an existing wallet, but will NOT replace it. Consider deleting previous wallet first. Differences: \
''' + ', '.join(diff_items)
        else:
            story = 'Create new multisig wallet?'

        derivs, dsum = self.get_deriv_paths()

        if not self.bip67 and not is_dup:
            # do not need to warn if duplicate, won;t be allowed to import anyways
            story += "\nWARNING: BIP-67 disabled! Unsorted multisig - order of keys in descriptor/backup is crucial"

        story += '''\n
Wallet Name:
  {name}

Policy: {M} of {N}

{exp}

Addresses:
  {at}

Derivation:
  {dsum}

Press (1) to see extended public keys, '''.format(M=M, N=N, name=self.name, exp=exp, dsum=dsum,
                                                  at=self.render_addr_fmt(self.addr_fmt))
        if not is_dup:
            story += ('%s to approve, %s to cancel.' % (OK, X))
        else:
            story += '%s to cancel' % X

        ux_clear_keys(True)
        while 1:
            ch = await ux_show_story(story, escape='1')

            if ch == '1':
                await self.show_detail(verbose=False)
                continue

            if ch == 'y' and not is_dup:
                # save to nvram, may raise WalletOutOfSpace
                if name_change:
                    name_change.delete()

                assert self.storage_idx == -1
                self.commit()
                await ux_dramatic_pause("Saved.", 2)
            break

        return ch



async def validate_xpub_for_ms(obj, af_str, chain, my_xfp, xpubs):
    # Read xpub and validate from JSON received via SD card or BBQr
    # - obj => JSON object (mapping)
    # - af_str => address format we expect/need

    # value in file is BE32, but we want LE32 internally
    # - KeyError here handled by caller
    xfp = str2xfp(obj['xfp'])
    deriv = cleanup_deriv_path(obj[af_str + '_deriv'])
    ln = obj.get(af_str)

    is_mine, item = check_xpub(xfp, ln, deriv, chain.ctype, my_xfp, xpubs)
    xpubs.append(item)
    return is_mine


async def ms_coordinator_qr(af_str, my_xfp, chain):
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
                import json
                return json.loads(data)
            except:
                raise QRDecodeExplained('Unable to decode JSON data')
        else:
            for line in data.split("\n"):
                if len(line) > 112:
                    l_data = extract_cosigner(line, af_str)
                    if l_data:
                        return l_data

    num_mine = 0
    num_files = 0
    xpubs = []

    msg = 'Scan Exported XPUB from Coldcard'
    while True:
        vals = await QRScannerInteraction().scan_general(msg, convertor, enter_quits=True)
        if vals is None:
            break
        try:
            is_mine = await validate_xpub_for_ms(vals, af_str, chain, my_xfp, xpubs)
        except KeyError as e:
            # random JSON will end up here
            msg = "Missing value: %s" % str(e)
            continue
        except Exception as e:
            # other QR codes, not BBQr (json) will stop here.
            msg = "Failure: %s" % str(e)
            continue

        if is_mine:
            num_mine += 1
        num_files += 1

        msg = "Number of keys scanned: %d" % num_files

    return xpubs, num_mine, num_files


async def ms_coordinator_file(af_str, my_xfp, chain, slot_b=None):
    num_mine = 0
    num_files = 0
    xpubs = []
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
                                    vals = extract_cosigner(line, af_str)
                                    if vals:
                                        break

                        is_mine = await validate_xpub_for_ms(vals, af_str, chain,
                                                             my_xfp, xpubs)
                        if is_mine:
                            num_mine += 1

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

    return xpubs, num_mine, num_files


def add_own_xpub(chain, acct_num, addr_fmt, secret=None):
    # Build out what's required for using master secret (or another
    # encoded secret) as a co-signer
    deriv = "m/48h/%dh/%dh/%dh" % (chain.b44_cointype, acct_num,
                                   2 if addr_fmt == AF_P2WSH else 1)

    with stash.SensitiveValues(secret=secret) as sv:
        node = sv.derive_path(deriv)
        the_xfp = sv.get_xfp()
        return (the_xfp, deriv, chain.serialize_public(node, AF_P2SH))


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
        xpubs, num_mine, num_files = await ms_coordinator_qr(mode, my_xfp, chain)
    else:
        xpubs, num_mine, num_files = await ms_coordinator_file(mode, my_xfp, chain)
        if CardSlot.both_inserted():
            # handle dual slot usage: assumes slot A used by first call above
            bxpubs, bnum_mine, bnum_files = await ms_coordinator_file(mode, my_xfp,
                                                                      chain, True)
            xpubs.extend(bxpubs)
            num_mine += bnum_mine
            num_files += bnum_files

    # remove dups; easy to happen if you double-tap the export
    xpubs = list(set(xpubs))

    if not xpubs or (len(xpubs) == 1 and num_mine):
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
        got_xfps = [a[0], c[0]]
        xpubs = [x for x in xpubs if x[0] not in got_xfps]

        if not xpubs:
            await ux_show_story("Need at least one other co-signer (key B).")
            return

        # master seed is always key0, key C is key1, k2..kn backup keys
        xpubs = [a, c] + xpubs
        num_mine += 2

    elif not num_mine:
        # add myself if not included already? As an option.
        ch = await ux_show_story("Add current Coldcard with above XFP ?",
                                 title="[%s]" % xfp2str(my_xfp))
        if ch == "y":
            acct = await ux_enter_bip32_index('Account Number:') or 0
            dis.fullscreen("Wait...")
            xpubs.append(add_own_xpub(chain, acct, addr_fmt))
            num_mine += 1

    N = len(xpubs)

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

    ms = MultisigWallet(name, (M, N), xpubs, addr_fmt=addr_fmt)

    if num_mine:
        from auth import NewMiniscriptEnrollRequest, UserAuthorizedAction

        UserAuthorizedAction.active_request = NewMiniscriptEnrollRequest(ms)

        # menu item case: add to stack
        from ux import the_ux
        the_ux.push(UserAuthorizedAction.active_request)
    else:
        # we cannot enroll multisig in which we do not participate
        # thou we can put descriptor on screen or on SD
        await ms.export_wallet_file(descriptor=True, desc_pretty=False)


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
        await ux_show_story('Failed to create multisig.\n\n%s\n%s' % (e, problem_file_line(e)),
                            title="ERROR")
# EOF
