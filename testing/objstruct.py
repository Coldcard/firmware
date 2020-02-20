# (c) Copyright 2020 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# objstruct.py
#

class ObjectStruct(dict):
    '''An object like both a dict and also an object that you can 
       easily use attr reference to get members. Construct with a 
       dict or like a dict.
    '''

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            # Do not return a default here because it breaks things
            raise AttributeError('No such attribute: %s' % name)

    def __setattr__(self, name, value):
        self[name] = value

    def __delattr__(self, name):
        del self[name]

    def __repr__(self):
        ret =  '<%s:' % self.__class__.__name__
        for k,v in self.items():
            ret += ' %s=%r' % (k, v)
        return ret + '>'

    @classmethod
    def promote(cls, x):
        # Often I get a dict() from an API wrapper that's taken some json and
        # run it thru json.loads(). It would be better to have that as nested
        # ObjectStruct (which is easily done with some arguments to loads, but
        # usually they don't provide that feature)... so call this function
        #

        if isinstance(x, list):
            return [cls.promote(i) for i in x]

        if isinstance(x, dict):
            x = cls(x)
            for k in x:
                x[k] = cls.promote(x[k])

        return x

class DefaultObjectStruct(ObjectStruct):
    ''' Same, but can provide a default value if get_default is overriden'''
    def get_default(self, fldname):
        # override me
        return None

    def __getattr__(self, name):
        if name in self:
            return self[name]
        else:
            # sometimes you do want a default.
            return self.get_default(name)

# EOF
