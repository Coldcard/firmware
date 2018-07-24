import backups, stash

for ln in backups.generate_public_contents():
    RV.write(ln)

with stash.SensitiveValues() as sv:
    RV.write('\n\n#DEBUG#\n%s' % sv.chain.serialize_private(sv.node))

