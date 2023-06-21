# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import chains
from glob import settings


class WalletOutOfSpace(RuntimeError):
    pass


class BaseWallet:
    key_name = None

    def __init__(self, chain_type=None):
        self.storage_idx = -1
        self.chain_type = chain_type or 'BTC'

    @property
    def chain(self):
        return chains.get_chain(self.chain_type)

    @classmethod
    def none_setup_yet(cls, other_chain=False):
        return '(none setup yet)' + ("*" if other_chain else "")

    @classmethod
    def is_correct_chain(cls, o, curr_chain):
        if o[1] is None:
            # mainnet
            ch = "BTC"
        else:
            ch = o[1]

        if ch == curr_chain.ctype:
            return True
        return False

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        exists = False
        exists_other_chain = False
        c = chains.current_key_chain()
        for o in settings.get(cls.key_name, []):
            if cls.is_correct_chain(o, c):
                exists = True
            else:
                exists_other_chain = True

        return exists, exists_other_chain

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        return cls.iter_wallets()

    @classmethod
    def iter_wallets(cls):
        # - this is only place we should be searching this list, please!!
        lst = settings.get(cls.key_name, [])
        c = chains.current_key_chain()

        for idx, rec in enumerate(lst):
            if cls.is_correct_chain(rec, c):
                yield cls.deserialize(rec, idx)

    def serialize(self):
        raise NotImplemented

    @classmethod
    def deserialize(cls, c, idx=-1):
        raise NotImplemented

    @classmethod
    def get_by_idx(cls, nth):
        # instance from index number (used in menu)
        lst = settings.get(cls.key_name, [])
        try:
            obj = lst[nth]
        except IndexError:
            return None

        return cls.deserialize(obj, nth)

    def commit(self):
        # data to save
        # - important that this fails immediately when nvram overflows
        obj = self.serialize()

        v = settings.get(self.key_name, [])
        orig = v.copy()
        if not v or self.storage_idx == -1:
            # create
            self.storage_idx = len(v)
            v.append(obj)
        else:
            # update in place
            v[self.storage_idx] = obj

        settings.set(self.key_name, v)

        # save now, rather than in background, so we can recover
        # from out-of-space situation
        try:
            settings.save()
        except:
            # back out change; no longer sure of NVRAM state
            try:
                settings.set(self.key_name, orig)
                settings.save()
            except: pass        # give up on recovery

            raise WalletOutOfSpace

    def delete(self):
        # remove saved entry
        # - important: not expecting more than one instance of this class in memory
        assert self.storage_idx >= 0
        lst = settings.get(self.key_name, [])
        try:
            del lst[self.storage_idx]
            settings.set(self.key_name, lst)
            settings.save()
        except IndexError: pass
        self.storage_idx = -1