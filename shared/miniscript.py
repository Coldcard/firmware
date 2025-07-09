# (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Copyright (c) 2020 Stepan Snigirev MIT License embit/miniscript.py
#
import ngu
from binascii import unhexlify as a2b_hex
from binascii import hexlify as b2a_hex
from serializations import ser_compact_size
from desc_utils import Key, read_until
from public_constants import MAX_TR_SIGNERS


class Number:
    def __init__(self, num):
        self.num = num

    @classmethod
    def read_from(cls, s, taproot=False):
        num = 0
        char = s.read(1)
        while char in b"0123456789":
            num = 10 * num + int(char.decode())
            char = s.read(1)
        s.seek(-1, 1)
        return cls(num)

    def compile(self):
        if self.num == 0:
            return b"\x00"
        if self.num <= 16:
            return bytes([80 + self.num])
        b = self.num.to_bytes(32, "little").rstrip(b"\x00")
        if b[-1] >= 128:
            b += b"\x00"
        return bytes([len(b)]) + b

    def __len__(self):
        return len(self.compile())

    def to_string(self, *args, **kwargs):
        return "%d" % self.num


class KeyHash(Key):
    @classmethod
    def parse_key(cls, k: bytes, *args, **kwargs):
        # convert to string
        kd = k.decode()
        # raw 20-byte hash
        if len(kd) == 40:
            return kd, None
        return super().parse_key(k, *args, **kwargs)

    def serialize(self, *args, **kwargs):
        start = 1 if self.taproot else 0
        return ngu.hash.hash160(self.node.pubkey()[start:33])

    def __len__(self):
        return 21 # <20:pkh>

    def compile(self):
        d = self.serialize()
        return ser_compact_size(len(d)) + d


class Raw:
    def __init__(self, raw):
        if len(raw) != self.LEN * 2:
            raise ValueError("Invalid raw element length: %d" % len(raw))
        self.raw = a2b_hex(raw)

    @classmethod
    def read_from(cls, s, taproot=False):
        return cls(s.read(2 * cls.LEN).decode())

    def to_string(self, *args, **kwargs):
        return b2a_hex(self.raw).decode()

    def compile(self):
        return ser_compact_size(len(self.raw)) + self.raw

    def __len__(self):
        return len(ser_compact_size(self.LEN)) + self.LEN


class Raw32(Raw):
    LEN = 32
    def __len__(self):
        return 33


class Raw20(Raw):
    LEN = 20
    def __len__(self):
        return 21


class Miniscript:
    def __init__(self, *args, **kwargs):
        self.args = args
        self.taproot = kwargs.get("taproot", False)

    def compile(self):
        return self.inner_compile()

    def verify(self):
        for arg in self.args:
            if isinstance(arg, Miniscript):
                arg.verify()

    @property
    def keys(self):
        res = []
        for arg in self.args:
            if isinstance(arg, Miniscript):
                res += arg.keys
            elif isinstance(arg, Key):  # KeyHash is subclass of Key
                res.append(arg)
        return res

    def is_sane(self, taproot=False):
        err = "multi mixin"
        forbiden = (Sortedmulti, Multi) if taproot else (Sortedmulti_a, Multi_a)
        assert type(self) not in forbiden, err

        for arg in self.args:
            assert type(arg) not in forbiden, err
            if isinstance(arg, Miniscript):
                arg.is_sane(taproot=taproot)

    @staticmethod
    def key_derive(key, idx, key_map=None, change=False):
        if key_map and key in key_map:
            kd = key_map[key]
        else:
            kd = key.derive(idx, change=change)
        return kd

    def derive(self, idx, key_map=None, change=False):
        args = []
        for arg in self.args:
            if isinstance(arg, Key):  # KeyHash is subclass of Key
                arg = self.key_derive(arg, idx, key_map, change=change)
            elif hasattr(arg, "derive"):
                arg = arg.derive(idx, key_map, change)

            args.append(arg)
        return type(self)(*args)

    @property
    def properties(self):
        return self.PROPS

    @property
    def type(self):
        return self.TYPE

    @classmethod
    def read_from(cls, s, taproot=False):
        op, char = read_until(s, b"(")
        op = op.decode()
        wrappers = ""
        if ":" in op:
            wrappers, op = op.split(":")
        if char != b"(":
            raise ValueError("Missing operator")
        if op not in OPERATOR_NAMES:
            raise ValueError("Unknown operator '%s'" % op)
        # number of arguments, classes of arguments, compile function, type, validity checker
        MiniscriptCls = OPERATORS[OPERATOR_NAMES.index(op)]
        args = MiniscriptCls.read_arguments(s, taproot=taproot)
        miniscript = MiniscriptCls(*args, taproot=taproot)
        for w in reversed(wrappers):
            if w not in WRAPPER_NAMES:
                raise ValueError("Unknown wrapper %s" % w)
            WrapperCls = WRAPPERS[WRAPPER_NAMES.index(w)]
            miniscript = WrapperCls(miniscript, taproot=taproot)
        return miniscript

    @classmethod
    def read_arguments(cls, s, taproot=False):
        args = []
        if cls.NARGS is None:
            if type(cls.ARGCLS) == tuple:
                firstcls, nextcls = cls.ARGCLS
            else:
                firstcls, nextcls = cls.ARGCLS, cls.ARGCLS

            args.append(firstcls.read_from(s, taproot=taproot))
            while True:
                char = s.read(1)
                if char == b",":
                    args.append(nextcls.read_from(s, taproot=taproot))
                elif char == b")":
                    break
                else:
                    raise ValueError(
                        "Expected , or ), got: %s" % (char + s.read())
                    )
        else:
            for i in range(cls.NARGS):
                args.append(cls.ARGCLS.read_from(s, taproot=taproot))
                if i < cls.NARGS - 1:
                    char = s.read(1)
                    if char != b",":
                        raise ValueError("Missing arguments, %s" % char)
            char = s.read(1)
            if char != b")":
                raise ValueError("Expected ) got %s" % (char + s.read()))
        return args

    def to_string(self, external=True, internal=True):
        # meh
        res = type(self).NAME + "("
        res += ",".join([
            arg.to_string(external, internal)
            for arg in self.args
        ])
        res += ")"
        return res

    def __len__(self):
        """Length of the compiled script, override this if you know the length"""
        return len(self.compile())

    def len_args(self):
        return sum([len(arg) for arg in self.args])

########### Known fragments (miniscript operators) ##############


class OneArg(Miniscript):
    NARGS = 1
    # small handy functions
    @property
    def arg(self):
        return self.args[0]

    @property
    def carg(self):
        return self.arg.compile()


class PkK(OneArg):
    # <key>
    NAME = "pk_k"
    ARGCLS = Key
    TYPE = "K"
    PROPS = "ondu"

    def inner_compile(self):
        return self.carg

    def __len__(self):
        return self.len_args()


class PkH(OneArg):
    # DUP HASH160 <HASH160(key)> EQUALVERIFY
    NAME = "pk_h"
    ARGCLS = KeyHash
    TYPE = "K"
    PROPS = "ndu"

    def inner_compile(self):
        return b"\x76\xa9" + self.carg + b"\x88"

    def __len__(self):
        return self.len_args() + 3

class Older(OneArg):
    # <n> CHECKSEQUENCEVERIFY
    NAME = "older"
    ARGCLS = Number
    TYPE = "B"
    PROPS = "z"

    def inner_compile(self):
        return self.carg + b"\xb2"

    def verify(self):
        super().verify()
        if (self.arg.num < 1) or (self.arg.num >= 0x80000000):
            raise ValueError(
                "%s should have an argument in range [1, 0x80000000)" % self.NAME
            )

    def __len__(self):
        return self.len_args() + 1

class After(Older):
    # <n> CHECKLOCKTIMEVERIFY
    NAME = "after"

    def inner_compile(self):
        return self.carg + b"\xb1"


class Sha256(OneArg):
    # SIZE <32> EQUALVERIFY SHA256 <h> EQUAL
    NAME = "sha256"
    ARGCLS = Raw32
    TYPE = "B"
    PROPS = "ondu"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa8" + self.carg + b"\x87"

    def __len__(self):
        return self.len_args() + 6

class Hash256(Sha256):
    # SIZE <32> EQUALVERIFY HASH256 <h> EQUAL
    NAME = "hash256"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xaa" + self.carg + b"\x87"


class Ripemd160(Sha256):
    # SIZE <32> EQUALVERIFY RIPEMD160 <h> EQUAL
    NAME = "ripemd160"
    ARGCLS = Raw20

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa6" + self.carg + b"\x87"


class Hash160(Ripemd160):
    # SIZE <32> EQUALVERIFY HASH160 <h> EQUAL
    NAME = "hash160"

    def inner_compile(self):
        return b"\x82" + Number(32).compile() + b"\x88\xa9" + self.carg + b"\x87"


class AndOr(Miniscript):
    # [X] NOTIF [Z] ELSE [Y] ENDIF
    NAME = "andor"
    NARGS = 3
    ARGCLS = Miniscript

    @property
    def type(self):
        # type same as Y/Z
        return self.args[1].type

    def verify(self):
        # requires: X is Bdu; Y and Z are both B, K, or V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("andor: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise ValueError("andor: X should be 'du'")
        if self.args[1].type != self.args[2].type:
            raise ValueError("andor: Y and Z should have the same types")
        if self.args[1].type not in "BKV":
            raise ValueError("andor: Y and Z should be B K or V")

    @property
    def properties(self):
        # props: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
        props = ""
        px, py, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in py and "z" in pz:
            props += "z"
        if ("z" in px and "o" in py and "o" in pz) or (
            "o" in px and "z" in py and "z" in pz
        ):
            props += "o"
        if "u" in py and "u" in pz:
            props += "u"
        if "d" in pz:
            props += "d"
        return props

    def inner_compile(self):
        return (
            self.args[0].compile()
            + b"\x64"
            + self.args[2].compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 3

class AndV(Miniscript):
    # [X] [Y]
    NAME = "and_v"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile()

    def __len__(self):
        return self.len_args()

    def verify(self):
        # X is V; Y is B, K, or V
        super().verify()
        if self.args[0].type != "V":
            raise ValueError("and_v: X should be 'V'")
        if self.args[1].type not in "BKV":
            raise ValueError("and_v: Y should be B K or V")

    @property
    def type(self):
        # same as Y
        return self.args[1].type

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
        px, py = [arg.properties for arg in self.args]
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "u" in py:
            props += "u"
        return props


class AndB(Miniscript):
    # [X] [Y] BOOLAND
    NAME = "and_b"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile() + b"\x9a"

    def __len__(self):
        return self.len_args() + 1

    def verify(self):
        # X is B; Y is W
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("and_b: X should be B")
        if self.args[1].type != "W":
            raise ValueError("and_b: Y should be W")

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; d=dXdY; u
        px, py = [arg.properties for arg in self.args]
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "d" in px and "d" in py:
            props += "d"
        props += "u"
        return props


class AndN(Miniscript):
    # [X] NOTIF 0 ELSE [Y] ENDIF
    # andor(X,Y,0)
    NAME = "and_n"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return (
            self.args[0].compile()
            + b"\x64"
            + Number(0).compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 4

    @property
    def type(self):
        # type same as Y/Z
        return self.args[1].type

    def verify(self):
        # requires: X is Bdu; Y and Z are both B, K, or V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("and_n: X should be 'B'")
        px = self.args[0].properties
        if "d" not in px and "u" not in px:
            raise ValueError("and_n: X should be 'du'")
        if self.args[1].type != "B":
            raise ValueError("and_n: Y should be B")

    @property
    def properties(self):
        # props: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
        props = ""
        px, py = [arg.properties for arg in self.args]
        pz = "zud"
        if "z" in px and "z" in py and "z" in pz:
            props += "z"
        if ("z" in px and "o" in py and "o" in pz) or (
            "o" in px and "z" in py and "z" in pz
        ):
            props += "o"
        if "u" in py and "u" in pz:
            props += "u"
        if "d" in pz:
            props += "d"
        return props


class OrB(Miniscript):
    # [X] [Z] BOOLOR
    NAME = "or_b"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + self.args[1].compile() + b"\x9b"

    def __len__(self):
        return self.len_args() + 1

    def verify(self):
        # X is Bd; Z is Wd
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_b: X should be B")
        if "d" not in self.args[0].properties:
            raise ValueError("or_b: X should be d")
        if self.args[1].type != "W":
            raise ValueError("or_b: Z should be W")
        if "d" not in self.args[1].properties:
            raise ValueError("or_b: Z should be d")

    @property
    def properties(self):
        # z=zXzZ; o=zXoZ or zZoX; d; u
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if ("z" in px and "o" in pz) or ("z" in pz and "o" in px):
            props += "o"
        props += "du"
        return props


class OrC(Miniscript):
    # [X] NOTIF [Z] ENDIF
    NAME = "or_c"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "V"

    def inner_compile(self):
        return self.args[0].compile() + b"\x64" + self.args[1].compile() + b"\x68"

    def __len__(self):
        return self.len_args() + 2

    def verify(self):
        # X is Bdu; Z is V
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_c: X should be B")
        if self.args[1].type != "V":
            raise ValueError("or_c: Z should be V")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise ValueError("or_c: X should be du")

    @property
    def properties(self):
        # z=zXzZ; o=oXzZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if "o" in px and "z" in pz:
            props += "o"
        return props


class OrD(Miniscript):
    # [X] IFDUP NOTIF [Z] ENDIF
    NAME = "or_d"
    NARGS = 2
    ARGCLS = Miniscript
    TYPE = "B"

    def inner_compile(self):
        return self.args[0].compile() + b"\x73\x64" + self.args[1].compile() + b"\x68"

    def __len__(self):
        return self.len_args() + 3

    def verify(self):
        # X is Bdu; Z is B
        super().verify()
        if self.args[0].type != "B":
            raise ValueError("or_d: X should be B")
        if self.args[1].type != "B":
            raise ValueError("or_d: Z should be B")
        px = self.args[0].properties
        if "d" not in px or "u" not in px:
            raise ValueError("or_d: X should be du")

    @property
    def properties(self):
        # z=zXzZ; o=oXzZ; d=dZ; u=uZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "z"
        if "o" in px and "z" in pz:
            props += "o"
        if "d" in pz:
            props += "d"
        if "u" in pz:
            props += "u"
        return props


class OrI(Miniscript):
    # IF [X] ELSE [Z] ENDIF
    NAME = "or_i"
    NARGS = 2
    ARGCLS = Miniscript

    def inner_compile(self):
        return (
            b"\x63"
            + self.args[0].compile()
            + b"\x67"
            + self.args[1].compile()
            + b"\x68"
        )

    def __len__(self):
        return self.len_args() + 3

    def verify(self):
        # both are B, K, or V
        super().verify()
        if self.args[0].type != self.args[1].type:
            raise ValueError("or_i: X and Z should be the same type")
        if self.args[0].type not in "BKV":
            raise ValueError("or_i: X and Z should be B K or V")

    @property
    def type(self):
        return self.args[0].type

    @property
    def properties(self):
        # o=zXzZ; u=uXuZ; d=dX or dZ
        props = ""
        px, pz = [arg.properties for arg in self.args]
        if "z" in px and "z" in pz:
            props += "o"
        if "u" in px and "u" in pz:
            props += "u"
        if "d" in px or "d" in pz:
            props += "d"
        return props


class Thresh(Miniscript):
    # [X1] [X2] ADD ... [Xn] ADD ... <k> EQUAL
    NAME = "thresh"
    NARGS = None
    ARGCLS = (Number, Miniscript)
    TYPE = "B"

    def inner_compile(self):
        return (
            self.args[1].compile()
            + b"".join([arg.compile()+b"\x93" for arg in self.args[2:]])
            + self.args[0].compile()
            + b"\x87"
        )

    def __len__(self):
        return self.len_args() + len(self.args) - 1

    def verify(self):
        # 1 <= k <= n; X1 is Bdu; others are Wdu
        super().verify()
        if self.args[0].num < 1 or self.args[0].num >= len(self.args):
            raise ValueError(
                "thresh: Invalid k! Should be 1 <= k <= %d, got %d"
                % (len(self.args) - 1, self.args[0].num)
            )
        if self.args[1].type != "B":
            raise ValueError("thresh: X1 should be B")
        px = self.args[1].properties
        if "d" not in px or "u" not in px:
            raise ValueError("thresh: X1 should be du")
        for i, arg in enumerate(self.args[2:]):
            if arg.type != "W":
                raise ValueError("thresh: X%d should be W" % (i + 1))
            p = arg.properties
            if "d" not in p or "u" not in p:
                raise ValueError("thresh: X%d should be du" % (i + 1))

    @property
    def properties(self):
        # z=all are z; o=all are z except one is o; d; u
        props = ""
        parr = [arg.properties for arg in self.args[1:]]
        zarr = ["z" for p in parr if "z" in p]
        if len(zarr) == len(parr):
            props += "z"
        noz = [p for p in parr if "z" not in p]
        if len(noz) == 1 and "o" in noz[0]:
            props += "o"
        props += "du"
        return props


class Multi(Miniscript):
    # <k> <key1> ... <keyn> <n> CHECKMULTISIG
    NAME = "multi"
    NARGS = None
    ARGCLS = (Number, Key)
    TYPE = "B"
    PROPS = "ndu"
    N_MAX = 20

    def inner_compile(self):
        # scr = [arg.compile() for arg in self.args[1:]]
        # optimization - it is all keys with known length (xonly keys not allowed here)
        scr = [b'\x21' + arg.key_bytes() for arg in self.args[1:]]
        if self.NAME == "sortedmulti":
            scr.sort()
        return (
            self.args[0].compile()
            + b"".join(scr)
            + Number(len(self.args) - 1).compile()
            + b"\xae"
        )

    def __len__(self):
        return self.len_args() + 2

    def m_n(self):
        return self.args[0].num, len(self.args[1:])

    def verify(self):
        super().verify()
        N = (len(self.args) - 1)
        assert N <= self.N_MAX, 'M/N range'
        M = self.args[0].num
        if M < 1 or M > N:
            raise ValueError(
                "M must be <= N: 1 <= M <= %d, got %d" % ((len(self.args) - 1), self.args[0].num)
            )


class Sortedmulti(Multi):
    # <k> <key1> ... <keyn> <n> CHECKMULTISIG
    NAME = "sortedmulti"


class Multi_a(Multi):
    # <key1> CHECKSIG <key> CHECKSIGADD ... <keyn> CHECKSIGADD EQUALVERIFY
    NAME = "multi_a"
    PROPS = "du"
    N_MAX = MAX_TR_SIGNERS

    def inner_compile(self):
        from opcodes import OP_CHECKSIGADD, OP_NUMEQUAL, OP_CHECKSIG
        script = b""
        # scr = [arg.compile() for arg in self.args[1:]]
        # optimization - it is all keys with known length (only xonly keys allowed here)
        scr = [b"\x20" + arg.key_bytes() for arg in self.args[1:]]
        if self.NAME == "sortedmulti_a":
            scr.sort()

        for i, key in enumerate(scr):
            script += key
            if i == 0:
                script += bytes([OP_CHECKSIG])
            else:
                script += bytes([OP_CHECKSIGADD])

        script += self.args[0].compile()  # M (threshold)
        script += bytes([OP_NUMEQUAL])
        return script

    def __len__(self):
        # len(M) + len(k0) ... + len(kN) + len(keys) + 1
        return self.len_args() + len(self.args)


class Sortedmulti_a(Multi_a):
    # <key1> CHECKSIG <key> CHECKSIGADD ... <keyn> CHECKSIGADD EQUALVERIFY
    NAME = "sortedmulti_a"


class Pk(OneArg):
    # <key> CHECKSIG
    NAME = "pk"
    ARGCLS = Key
    TYPE = "B"
    PROPS = "ondu"

    def inner_compile(self):
        return self.carg + b"\xac"

    def __len__(self):
        return self.len_args() + 1


class Pkh(OneArg):
    # DUP HASH160 <HASH160(key)> EQUALVERIFY CHECKSIG
    NAME = "pkh"
    ARGCLS = KeyHash
    TYPE = "B"
    PROPS = "ndu"

    def inner_compile(self):
        return b"\x76\xa9" + self.carg + b"\x88\xac"

    def __len__(self):
        return self.len_args() + 4


OPERATORS = [
    PkK,
    PkH,
    Older,
    After,
    Sha256,
    Hash256,
    Ripemd160,
    Hash160,
    AndOr,
    AndV,
    AndB,
    AndN,
    OrB,
    OrC,
    OrD,
    OrI,
    Thresh,
    Multi,
    Sortedmulti,
    Multi_a,
    Sortedmulti_a,
    Pk,
    Pkh,
]
OPERATOR_NAMES = [cls.NAME for cls in OPERATORS]


class Wrapper(OneArg):
    ARGCLS = Miniscript

    @property
    def op(self):
        return type(self).__name__.lower()

    def to_string(self, *args, **kwargs):
        # more wrappers follow
        if isinstance(self.arg, Wrapper):
            return self.op + self.arg.to_string(*args, **kwargs)
        # we are the last wrapper
        return self.op + ":" + self.arg.to_string(*args, **kwargs)


class A(Wrapper):
    # TOALTSTACK [X] FROMALTSTACK
    TYPE = "W"

    def inner_compile(self):
        return b"\x6b" + self.carg + b"\x6c"

    def __len__(self):
        return len(self.arg) + 2

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("a: X should be B")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        if "d" in px:
            props += "d"
        if "u" in px:
            props += "u"
        return props


class S(Wrapper):
    # SWAP [X]
    TYPE = "W"

    def inner_compile(self):
        return b"\x7c" + self.carg

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("s: X should be B")
        if "o" not in self.arg.properties:
            raise ValueError("s: X should be o")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        if "d" in px:
            props += "d"
        if "u" in px:
            props += "u"
        return props


class C(Wrapper):
    # [X] CHECKSIG
    TYPE = "B"

    def inner_compile(self):
        return self.carg + b"\xac"

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "K":
            raise ValueError("c: X should be K")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        for p in ["o", "n", "d"]:
            if p in px:
                props += p
        props += "u"
        return props


class T(Wrapper):
    # [X] 1
    TYPE = "B"

    def inner_compile(self):
        return self.carg + Number(1).compile()

    def __len__(self):
        return len(self.arg) + 1

    @property
    def properties(self):
        # z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
        px = self.arg.properties
        py = "zu"
        props = ""
        if "z" in px and "z" in py:
            props += "z"
        if ("z" in px and "o" in py) or ("z" in py and "o" in px):
            props += "o"
        if "n" in px or ("z" in px and "n" in py):
            props += "n"
        if "u" in py:
            props += "u"
        return props


class D(Wrapper):
    # DUP IF [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x76\x63" + self.carg + b"\x68"

    def __len__(self):
        return len(self.arg) + 3

    def verify(self):
        super().verify()
        if self.arg.type != "V":
            raise ValueError("d: X should be V")
        if "z" not in self.arg.properties:
            raise ValueError("d: X should be z")

    @property
    def properties(self):
        # https://github.com/bitcoin/bitcoin/pull/24906
        if self.taproot:
            props = "ndu"
        else:
            props = "nd"
        px = self.arg.properties
        if "z" in px:
            props += "o"
        return props


class V(Wrapper):
    # [X] VERIFY (or VERIFY version of last opcode in [X])
    TYPE = "V"

    def inner_compile(self):
        """Checks last check code and makes it verify"""
        if self.carg[-1] in [0xAC, 0xAE, 0x9C, 0x87]:
            return self.carg[:-1] + bytes([self.carg[-1] + 1])
        return self.carg + b"\x69"

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("v: X should be B")

    @property
    def properties(self):
        props = ""
        px = self.arg.properties
        for p in ["z", "o", "n"]:
            if p in px:
                props += p
        return props


class J(Wrapper):
    # SIZE 0NOTEQUAL IF [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x82\x92\x63" + self.carg + b"\x68"

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("j: X should be B")
        if "n" not in self.arg.properties:
            raise ValueError("j: X should be n")

    @property
    def properties(self):
        props = "nd"
        px = self.arg.properties
        for p in ["o", "u"]:
            if p in px:
                props += p
        return props


class N(Wrapper):
    # [X] 0NOTEQUAL
    TYPE = "B"

    def inner_compile(self):
        return self.carg + b"\x92"

    def __len__(self):
        return len(self.arg) + 1

    def verify(self):
        super().verify()
        if self.arg.type != "B":
            raise ValueError("n: X should be B")

    @property
    def properties(self):
        props = "u"
        px = self.arg.properties
        for p in ["z", "o", "n", "d"]:
            if p in px:
                props += p
        return props


class L(Wrapper):
    # IF 0 ELSE [X] ENDIF
    TYPE = "B"

    def inner_compile(self):
        return b"\x63" + Number(0).compile() + b"\x67" + self.carg + b"\x68"

    def __len__(self):
        return len(self.arg) + 4

    def verify(self):
        # both are B, K, or V
        super().verify()
        if self.arg.type != "B":
            raise ValueError("or_i: X and Z should be the same type")

    @property
    def properties(self):
        # o=zXzZ; u=uXuZ; d=dX or dZ
        props = "d"
        pz = self.arg.properties
        if "z" in pz:
            props += "o"
        if "u" in pz:
            props += "u"
        return props


class U(L):
    # IF [X] ELSE 0 ENDIF
    def inner_compile(self):
        return b"\x63" + self.carg + b"\x67" + Number(0).compile() + b"\x68"

    def __len__(self):
        return len(self.arg) + 4


WRAPPERS = [A, S, C, T, D, V, J, N, L, U]
WRAPPER_NAMES = [w.__name__.lower() for w in WRAPPERS]