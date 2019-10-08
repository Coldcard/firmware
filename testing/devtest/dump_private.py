import backups, stash

with stash.SensitiveValues() as sv:
    RV.write('%s' % sv.chain.serialize_private(sv.node))
