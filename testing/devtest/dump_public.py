# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import export, stash

for ln in export.generate_public_contents():
    RV.write(ln)

with stash.SensitiveValues() as sv:
    RV.write('\n\n#DEBUG#\n%s' % sv.chain.serialize_private(sv.node))

