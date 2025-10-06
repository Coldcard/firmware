# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# ownership.py - store a cache of hashes related to addresses we might control.
#
import os, chains, ngu, struct, version
from glob import settings
from ucollections import namedtuple
from ubinascii import hexlify as b2a_hex
from exceptions import UnknownAddressExplained
from utils import problem_file_line, show_single_address
from public_constants import AFC_SCRIPT, AF_P2WPKH_P2SH, AF_P2SH, AF_P2WSH_P2SH, AF_P2TR

# Track many addresses, but in compressed form
# - map from random Bech32/Base58 payment address to (wallet) + keypath
# - won't consider any keypath that does not end in <0;1>/*
# - store only hints, since we can re-construct any address and want to fully verify
# - try to keep private between different duress wallets, and seed vaults
# - storing bulk data into LFS, not settings
# - okay to wipe, can restore anytime; with CPU cost
# - doesn't really have a gap limit concept, but limited to first N addresses in a wallet
# - cannot be used to accelerate address explorer because we don't store full addresses
# - data stored in binary, fixed-length header, then fixed-length records
# - multisig and single sig, and someday taproot, miniscript too
# - searching leaves behind a cache for next time
# - data building/saves happens when are searching, but might grab some during addr expl export?
# - performance: 1m40s for one P2PKH wallet (change, and external addresses: 1528 in all)
#

# length of hashed & truncated address record
HASH_ENC_LEN = const(2)

# File header
OwnershipFileHdr = namedtuple('OwnershipFileHdr', 'file_magic change_idx flags')
OWNERSHIP_FILE_HDR = 'HHI'
OWNERSHIP_FILE_HDR_LEN = 8

OWNERSHIP_MAGIC = 0x10A0            # "Address Ownership" v1.0
# flags: none yet, but 32 bits reserved

# target 3 flash blocks, max file size => 764 addresses
MAX_ADDRS_STORED = const(764)       # =((3*512) - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN
BONUS_AFTER_MATCH = const(20)       # number of addresses to still generate after match found

def encode_addr(addr, salt):
    # Convert text address to something we can store while preserving privacy.
    return ngu.hash.sha256s(salt + addr)[0:HASH_ENC_LEN]

class AddressCacheFile:

    def __init__(self, wallet, change_idx):
        self.wallet = wallet
        self.change_idx = change_idx
        desc = wallet.to_descriptor().to_string(internal=False)
        h = b2a_hex(ngu.hash.sha256d(wallet.chain.ctype + desc))
        self.fname = h[0:32] + '-%d.own' % change_idx
        self.salt = h[32:]
        self.count = 0
        self.hdr = None
        self.fd = None

        self.peek()

    def nice_name(self):
        rv = self.wallet.name
        if self.change_idx:
            rv += ' (change)'
        return rv

    def peek(self):
        # see what we have on-disk; just reads header.
        try:
            with open(self.fname, 'rb') as fd:
                hdr = fd.read(OWNERSHIP_FILE_HDR_LEN)
                assert len(hdr) == OWNERSHIP_FILE_HDR_LEN
                flen = fd.seek(0, 2)
            self.hdr = OwnershipFileHdr(*struct.unpack(OWNERSHIP_FILE_HDR, hdr))
            assert self.hdr.file_magic == OWNERSHIP_MAGIC
            assert self.hdr.change_idx == self.change_idx
        except OSError:
            return
        except Exception as exc:
            # sys.print_exception(exc)
            self.count = 0
            self.hdr = None
            return

        self.count = (flen - OWNERSHIP_FILE_HDR_LEN) // HASH_ENC_LEN

    def setup(self, change_idx, start_idx):
        assert self.change_idx == change_idx

        if self.count or self.hdr:
            assert start_idx == self.count, 'not an append'

            # Open for append, header should be right already
            self.fd = open(self.fname, 'ab')
        else:
            # Start new file
            assert start_idx == 0
            self.fd = open(self.fname, 'wb')
            self.hdr = OwnershipFileHdr(OWNERSHIP_MAGIC, self.change_idx, 0x0)
            hdr = struct.pack(OWNERSHIP_FILE_HDR, *self.hdr)
            self.fd.write(hdr)

    def append(self, addr):
        self.fd.write(encode_addr(addr, self.salt))

    def close(self):
        # close file, done
        if self.fd is not None:
            self.fd.close()
            self.fd = None

    def fast_search(self, addr):
        # Do the easy part of the searching, using the existing file's contents.
        # - generates candidate path subcomponents; might be false positive
        # - working in-memory, since complete file isn't very large, and speed
        from glob import dis

        if not self.hdr or not self.count:
            # cache empty
            return

        with open(self.fname, 'rb') as fd:
            fd.seek(OWNERSHIP_FILE_HDR_LEN)
            buf = fd.read(self.count * HASH_ENC_LEN)

        assert len(buf) == (self.count * HASH_ENC_LEN)

        chk = encode_addr(addr, self.salt)
        for idx in range(self.count):
            if buf[idx*HASH_ENC_LEN : (idx*HASH_ENC_LEN)+HASH_ENC_LEN] == chk:
                yield self.change_idx, idx

            dis.progress_sofar(idx, self.count)

    def check_match(self, want_addr, subpath):
        # need to double-check matches, to get rid of false positives.
        got = self.wallet.render_address(*subpath)
        # chg, idx = subpath
        #print('(%d, %d) => %s ?= %s' % (chg, idx, got, want_addr))
        return want_addr == got

    def build_and_search(self, addr):
        # build many more addresses
        # - return subpath for a hit or None
        from glob import dis

        match = None

        start_idx = self.count
        count = MAX_ADDRS_STORED - start_idx

        if count <= 0:
            return match

        self.setup(self.change_idx, start_idx)

        bonus = None
        for idx,here,*_ in self.wallet.yield_addresses(start_idx, count, self.change_idx):
            self.append(here)
            self.count += 1

            if bonus:
                if bonus >= BONUS_AFTER_MATCH:
                    # do (at most) 20 more - limited by 'start_idx' & 'count'
                    break
                bonus += 1


            if here == addr:
                # match but keep going
                match = (self.change_idx, idx)
                bonus = 1

            dis.progress_sofar(idx - start_idx, count)

        self.close()
        return match

class OwnershipCache:

    @classmethod
    def saver(cls, wallet, change_idx, start_idx, count):
        # when we are generating many addresses for export, capture them (if suitable)
        # as we go with this function
        if not count:
            return
        if change_idx not in (0, 1):
            return
        if start_idx >= MAX_ADDRS_STORED:
            return

        file = AddressCacheFile(wallet, change_idx)
        current_pos = file.count

        if start_idx > current_pos:
            # nothing to do here, we are missing some addresses in the middle
            return
        if (start_idx + count) <= current_pos:
            # we already have all these addresses
            return

        file.setup(change_idx, current_pos)

        def doit(addr, idx):
            if addr is None:
                file.close()
            elif (idx < MAX_ADDRS_STORED) and idx >= current_pos:
                file.append(addr)

        return doit

    @classmethod
    def filter(cls, addr, args):
        # Filter possible candidates!
        # - if you start w/ testnet, we'll follow that
        from wallet import MiniScriptWallet
        from glob import dis

        ch = chains.current_chain()
        args = args or {}

        addr_fmt = ch.possible_address_fmt(addr)
        if not addr_fmt:
            # might be valid address over on testnet vs mainnet
            raise UnknownAddressExplained('That address is not valid on ' + ch.name)

        # user has specified specific (named) wallet
        named_wal = args.get("wallet", None)
        if named_wal:
            # quick search without deserialization
            res = list(MiniScriptWallet.iter_wallets(name=named_wal))
            if not res:
                raise UnknownAddressExplained("Wallet '%s' not defined." % named_wal)

            # only return desired named wallet, no other wallets are searched
            return res

        possibles = []
        if addr_fmt == AF_P2TR:
            possibles.extend([w for w in MiniScriptWallet.iter_wallets() if w.addr_fmt == AF_P2TR])
        if addr_fmt & AFC_SCRIPT:
            # multisig or script at least... must exist already
            afs = [addr_fmt]
            if addr_fmt == AF_P2SH:
                # might look like P2SH but actually be AF_P2WSH_P2SH
                # wrapped segwit is more used than legacy
                afs = [AF_P2WSH_P2SH, AF_P2SH]

                # Might be single-sig p2wpkh wrapped in p2sh ... but that was a transition
                # thing that hopefully is going away, so if they have any multisig wallets,
                # defined, assume that that's the only p2sh address source.
                addr_fmt = AF_P2WPKH_P2SH

            possibles.extend(MiniScriptWallet.iter_wallets(addr_fmts=afs))

        try:
            # Construct possible single-signer wallets, always at least account=0 case
            from wallet import MasterSingleSigWallet
            w = MasterSingleSigWallet(addr_fmt, account_idx=0)
            possibles.append(w)

            # add all account idx they have ever looked at, w/ this addr fmt (single sig)
            ex = settings.get('accts', [])
            for af, acct_num in ex:
                if af == addr_fmt and acct_num:
                    w = MasterSingleSigWallet(addr_fmt, account_idx=acct_num)
                    possibles.append(w)
        except (KeyError, ValueError):
            pass  # if not single sig address format

        if not possibles:
            # can only happen w/ scripts; for single-signer we have things to check
            raise UnknownAddressExplained(
                        "No suitable multisig/miniscript wallets are currently defined.")

        # ordering here
        return possibles

    @classmethod
    def search_wallet_cache(cls, addr, cf):
        # - returns wallet object, and tuple2 of final 2 subpath components
        # "quick" check first, before doing any generations
        # external chain first, then internal (change)
        for maybe in cf.fast_search(addr):
            ok = cf.check_match(addr, maybe)
            if ok:
                return cf.wallet, maybe
        return None, None


    @classmethod
    def search_build_wallet(cls, addr, cf):
        # maybe we haven't calculated all the addresses yet, so do that
        # - very slow, but only needed once; any negative (failed) search causes this
        # - could stop when match found, but we go a bit beyond that for next time
        # - we could search all in parallel, rather than serially because
        #   more likely to find a match with low index... but seen as too much memory
        result = cf.build_and_search(addr)
        if result:
            # found it, so report it and stop
            return cf.wallet, result

        # possible phase 3: other seedvault... slow, rare and not implemented
        return None, None

    @classmethod
    def search(cls, addr, args=None):
        from glob import dis

        dis.fullscreen("Wait...")

        matches = OWNERSHIP.filter(addr, args)

        # build cache files for both external & internal chain
        cachefs = []
        for w in matches:
            cachefs.append(AddressCacheFile(w, 0))
            cachefs.append(AddressCacheFile(w, 1))

        for cf in cachefs:
            msg = "Searching wallet(s)..." if dis.has_lcd else "Searching..."
            dis.fullscreen(msg, line2=cf.nice_name())
            wallet, subpath = OWNERSHIP.search_wallet_cache(addr, cf)
            if wallet:
                # first arg from_cache=True
                return True, wallet, subpath

        # nothing found in existing cache files
        c = 0
        for cf in cachefs:
            msg = "Generating addresses..." if dis.has_lcd else "Generating..."
            dis.fullscreen(msg, line2=cf.nice_name())
            wallet, subpath = OWNERSHIP.search_build_wallet(addr, cf)
            c += cf.count
            if wallet:
                # first arg from_cache=False
                return False, wallet, subpath

        else:
            raise UnknownAddressExplained('Searched %d candidate addresses in %d wallet(s)'
                                          ' without finding a match.' % (c, len(matches)))

    @classmethod
    async def search_ux(cls, addr, args):
        # Provide a simple UX. Called functions do fullscreen, progress bar stuff.
        from ux import ux_show_story, show_qr_code
        from charcodes import KEY_QR
        from wallet import MiniScriptWallet
        from public_constants import AFC_BECH32, AFC_BECH32M

        try:
            _, wallet, subpath = cls.search(addr, args)
            is_complex = isinstance(wallet, MiniScriptWallet)

            msg = show_single_address(addr)
            msg += '\n\nFound in wallet:\n' + wallet.name

            msg += '\n\nDerivation path:\n'
            if hasattr(wallet, "render_path"):
                sp = wallet.render_path(*subpath)
                msg += sp
            else:
                sp = None
                msg += ".../%d/%d" % subpath

            if is_complex:
                esc = ""
            else:
                esc = "0"
                msg += "\n\nPress (0) to sign message with this key."

            title = "Verified"
            if version.has_qwerty:
                esc += KEY_QR
                title += " Address"
            else:
                msg += ' (1) for address QR'
                esc += '1'
                title += "!"

            while 1:
                ch = await ux_show_story(msg, title=title, escape=esc, hint_icons=KEY_QR)
                if ch in ("1"+KEY_QR):
                    await show_qr_code(
                        addr,
                        is_alnum=(wallet.addr_fmt & (AFC_BECH32 | AFC_BECH32M)),
                        msg=addr, is_addrs=True
                    )
                elif not is_complex and (ch == "0"):  # only singlesig
                    from msgsign import sign_with_own_address
                    await sign_with_own_address(sp, wallet.addr_fmt)
                else:
                    break

        except UnknownAddressExplained as exc:
            await ux_show_story(show_single_address(addr) + '\n\n' + str(exc), title="Unknown Address")
        except Exception as e:
            await ux_show_story('Ownership search failed.\n\n%s\n%s' % (e, problem_file_line(e)))


    @classmethod
    def note_subpath_used(cls, subpath):
        # when looking at PSBT, the address format is only implied
        # - but assume BIP-44/48/etc are being respected, and map to addr_fmt
        # - subpath is integers from PSBT contents already
        # - ignore coin_type
        from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH

        subpath = subpath[1:]       # ignore xfp
        if len(subpath) < 3 or subpath[0] < 0x80000000 or subpath[2] < 0x80000000:
            # weird path w/o expected hardened levels - ignore
            return

        top = subpath[0] & 0x7fffffff
        acct = subpath[2] & 0x7fffffff
        if top == 44:
            af = AF_CLASSIC
        elif top == 49:
            af = AF_P2WPKH_P2SH
        elif top == 84:
            af = AF_P2WPKH
        else:
            return

        cls.note_wallet_used(af, acct)

    @classmethod
    def note_wallet_used(cls, addr_fmt, subaccount):
        # we track single-sig wallets they seem to use
        # - if they explore it (non-zero subaccount)
        # - if they sign those paths
        # - but ignore testnet vs. not
        if subaccount == 0:
            # only interested in non-zero subaccounts
            return

        here = [addr_fmt, subaccount]

        ex = settings.get('accts', [])

        if here in ex:
            # known.
            return

        ex = list(ex)
        ex.append(here)
        settings.set('accts', ex)
                
    @classmethod
    def wipe_all(cls):
        # clear all cached addresses. will affect other seeds in vault
        for fn in os.listdir():
            if fn.endswith('.own'):
                os.remove(fn)

# singleton, but also only created as needed; holds no state.
OWNERSHIP = OwnershipCache()

# EOF
