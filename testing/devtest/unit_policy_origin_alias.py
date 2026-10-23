# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import ngu, chains
from desc_utils import bip388_validate_policy, bip388_wallet_policy_to_descriptor
from descriptor import Descriptor
from stash import SensitiveValues
from utils import swab32, xfp2str

with SensitiveValues() as sv:
    mine = chains.current_key_chain().serialize_public(sv.node)

foreign = ngu.hdnode.HDNode().from_master(bytes(range(32)))
foreign_fp = xfp2str(swab32(foreign.my_fp()))
foreign.derive(7, False)
foreign.derive(8, False)
foreign_xpub = chains.current_key_chain().serialize_public(foreign)
first = '[%s/7/8]%s' % (foreign_fp, foreign_xpub)

# Foreign origins cannot be verified locally. Reject ambiguous policy entries
# rather than silently choosing a path that changes signer routing on reload.
for origin in (foreign_fp + '/7/8', foreign_fp + '/9/10', '00000000/7/8'):
    second = '[%s]%s' % (origin, foreign_xpub)
    for left, right in ((first, second), (second, first)):
        for text in (
            'tr(%s/<0;1>/*,{pk(%s/<2;3>/*),pk(%s/<4;5>/*)})' % (mine, left, right),
            'tr(%s/<0;1>/*,{pk(%s/<2;3>/*),pk(%s/<2;3>/*)})' % (mine, left, right),
            'tr(musig(%s,%s)/<0;1>/*,pk(%s/<2;3>/*))' % (mine, left, right),
        ):
            desc = Descriptor.from_string(text)
            if first != second:
                for disable_checks in (False, True):
                    try:
                        desc.validate(disable_checks=disable_checks)
                    except AssertionError as exc:
                        assert str(exc) == 'Conflicting key origin', str(exc)
                    else:
                        assert False, 'ambiguous origin accepted'
                continue

            desc.validate()
            template, info = desc.bip388_wallet_policy()
            assert len(info) == 2
            assert 'pub' not in template
            bip388_validate_policy(template.encode(), info)
            restored = Descriptor.from_string(bip388_wallet_policy_to_descriptor(template, info))
            assert restored.xfp_paths() == desc.xfp_paths()
            for change in (False, True):
                for index in (0, 7):
                    assert restored.derive(None, change=change).derive(index).script_pubkey() == \
                        desc.derive(None, change=change).derive(index).script_pubkey()
