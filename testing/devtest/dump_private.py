# (c) Copyright 2020 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
import backups, stash

with stash.SensitiveValues() as sv:
    RV.write('%s' % sv.chain.serialize_private(sv.node))
