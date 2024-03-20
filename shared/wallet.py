# (c) Copyright 2024 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# wallet.py - A place you find UTXO, addresses and descriptors.
#
import chains
from descriptor import Descriptor
from public_constants import AF_CLASSIC, AF_P2WPKH, AF_P2WPKH_P2SH
from stash import blank_object, SensitiveValues

class WalletABC:
    # How to make this ABC useful without consuming memory/code space??
    # - be more of an "interface" than a base class
    
    #   name
    #   addr_fmt
    #   chain

    def yield_addresses(self, start_idx, count, change_idx=0, censored=True):
        # TODO: expected tuples?
        pass

    def to_descriptor(self):
        pass

class MasterSingleSigWallet(WalletABC):
    # Refers to current master seed phrase, whichever is loaded
    def __init__(self, addr_fmt, path=None, account_idx=0, chain_name=None):
        # Construct a wallet based on current master secret, and chain.
        # - path is optional, and then we use standard path for addr_fmt
        # - path can be overriden when we come here via address explorer

        if addr_fmt == AF_P2WPKH:
            n = 'Segwit'
            prefix = path or 'm/84h/{coin_type}h/{account}h'
        elif addr_fmt == AF_CLASSIC:
            n = 'Classic'
            prefix = path or 'm/44h/{coin_type}h/{account}h'
        elif addr_fmt == AF_P2WPKH_P2SH:
            n =  'P2WPKH-in-P2SH'
            prefix = path or 'm/49h/{coin_type}h/{account}h'
        else:
            raise ValueError(addr_fmt)

        if chain_name:
            self.chain = chains.get_chain(chain_name)
        else:
            self.chain = chains.current_chain()

        if self.chain.ctype != 'BTC':
            n += ' ' + self.chain.menu_name

        self.name = n
        self.addr_fmt = addr_fmt

        # Figure out the derivation path
        # - we want to store path w/o change and index part
        p = prefix.format(account=account_idx, coin_type=self.chain.b44_cointype,
                                                    change='C', idx='I')
        if p.endswith('/C/I'):
            p = p[:-4]
        if p.endswith('/I'):
            # custom path in addr explorer can get this
            p = p[:-2]

        self._path = p


    def yield_addresses(self, start_idx, count, change_idx=None, censored=True):
        # Render a range of addresses. Slow to start, since accesses SE in general
        # - if count==1, don't derive any subkey, just do path.
        path = self._path
        if change_idx is not None:
            assert 0 <= change_idx <= 1
            path += '/%d' % change_idx

        with SensitiveValues() as sv:
            node = sv.derive_path(path)

            if count == 1:
                address = self.chain.address(node, self.addr_fmt)
                yield 0, address, path
                return

            path += '/'
            for idx in range(start_idx, start_idx+count):
                try:
                    here = node.copy()
                    here.derive(idx, False)            # works in-place
                    address = self.chain.address(here, self.addr_fmt)
                finally:
                    here.blank()
                    del here

                yield idx, address, path+str(idx)

    def to_descriptor(self):
        from glob import settings
        xfp = settings.get('xfp')
        xpub = settings.get('xpub')
        keys = (xfp, self._path, xpub)
        return Descriptor([keys], self.addr_fmt)


# EOF
