# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
from glob import settings


class WalletOutOfSpace(RuntimeError):
    pass


class BaseWallet:
    key_name = None

    def __init__(self):
        self.storage_idx = -1

    @classmethod
    def delete_all(cls):
        settings.set(cls.key_name, [])
        settings.save()

    @classmethod
    def exists(cls):
        # are there any wallets defined?
        return bool(settings.get(cls.key_name, False))

    @classmethod
    def get_all(cls):
        # return them all, as a generator
        return cls.iter_wallets()

    @classmethod
    def iter_wallets(cls):
        # - this is only place we should be searching this list, please!!
        lst = settings.get(cls.key_name, [])

        for idx, rec in enumerate(lst):
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