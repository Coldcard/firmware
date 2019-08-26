# Unit test for shared/backups.py
#
# this will run on the simulator only
# run manually with:
#   execfile('../../testing/devtest/backups.py')

from ubinascii import hexlify as b2a_hex
from ubinascii import unhexlify as a2b_hex

import tcc, ustruct
from main import settings, sf

if 1:
    # test file contents: completeness, syntax
    from backups import render_backup_contents

    comments = 0
    blanks = 0
    checklist = set('mnemonic chain xprv xpub raw_secret fw_date fw_version fw_timestamp serial '
                'setting.terms_ok setting.idle_to setting.chain'.split(' '))
    optional = set('setting.words'.split(' '))

    for ln in render_backup_contents().split('\n'):
        ln = ln.strip()

        if not ln:
            blanks += 1
            continue
        if ln[0] == '#':
            comments += 1
            continue
            
        assert '=' in ln, ln
        k, v = ln.split(' = ', 1)
        assert v and k
        assert (k in checklist) or (k in optional), "Unknown key: "+k
        checklist.discard(k)

    assert not checklist, "Missing: %r" % checklist
    assert comments >= 4
    assert blanks >= 3

async def test_7z():
    # test full 7z round-trip
    # Altho cleartext mode is not for real, if the code is written, I must test it.
    from backups import write_complete_backup, restore_complete_doit
    from sffile import SFFile
    import tcc
    from main import settings, sf, numpad

    today = tcc.random.uniform(1000000)

    import machine
    machine.reset = lambda: None

    for chain in ['BTC', 'LTC']:
        for words in ( [], ['abc', 'def'] ):
            settings.set('check', today)
            settings.set('chain', chain)

            ll, sha = await write_complete_backup(words, None, True)

            result = SFFile(0, ll).read()

            if words:
                #open('debug.7z', 'wb').write(result)
                assert ll > 800
                assert len(sha) == 32
                assert result[0:6] == b"7z\xbc\xaf'\x1c"
                assert tcc.sha256(result).digest() == sha
                assert len(set(result)) >= 240      # encrypted
            else:
                sr = str(result, 'ascii')
                print("Backup contents:\n" + sr)
                assert sr[0] == '#', result
                assert 'Coldcard' in sr
                assert len(set(sr)) < 100       # cleartext, english
                assert ('chain = "%s"' % chain) in result

            # test restore
            # - cant wipe flash, since the backup file is there
            # - cant wipe all settings becuase PIN and stuff is simulated there
            del settings.current['check']


            with SFFile(0, ll) as fd:
                numpad.inject('y')      # for 'success' message
                await restore_complete_doit(fd, words)

                assert settings.get('check') == today, \
                            (settings.get('check'), '!=',  today)
                assert settings.get('chain') == chain, \
                            (settings.get('chain'), '!=',  chain)

            today += 3

            import ux
            ux.restore_menu()


from main import loop
loop.run_until_complete(test_7z())


# test recovery/reset
sf.chip_erase()
settings.load()


# EOF
