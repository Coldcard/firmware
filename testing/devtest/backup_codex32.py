# (c) Copyright 2026 by Coinkite Inc. This file is covered by license found in COPYING-CC.
# Pending shares belong to the local recovery session, not the wallet backup.

def run():
    import backups, version
    from glob import settings
    from pincodes import pa

    # Public share for a wallet unrelated to the simulator's active master.
    share = 'MS12W7F2AQQQSYQCYQ5RQWZQFPG9SCRGWPUAM077H9XN5W88'
    original = dict(settings.current)
    raw = bytes(pa.fetch())
    try:
        settings.master_set('c32_shares', [share])
        settings.set('nick', 'Backup control')
        contents = backups.render_backup_contents()
        assert 'setting.c32_shares' not in contents
        assert share not in contents
        assert 'raw_secret = ' in contents
        assert 'setting.nick = "Backup control"' in contents
        assert settings.master_get('c32_shares') == [share]

        if version.has_qwerty:
            import teleport
            captured = []

            async def approve(*a, **kw):
                return 'y'

            async def capture(rx_pubkey, type_code, raw):
                assert type_code == 'b'
                captured.append(raw)

            old_story, old_send = teleport.ux_show_story, teleport.kt_do_send
            try:
                teleport.ux_show_story, teleport.kt_do_send = approve, capture
                # Both awaited UI/transport stubs complete without yielding.
                coro = teleport.SecretPickerMenu(None).share_full_backup()
                try:
                    coro.send(None)
                except StopIteration:
                    pass
                else:
                    assert False, 'unexpected Teleport suspension'
            finally:
                teleport.ux_show_story, teleport.kt_do_send = old_story, old_send

            assert len(captured) == 1
            assert b'setting.c32_shares' not in captured[0]
            assert share.encode() not in captured[0]
            assert b'raw_secret = ' in captured[0]
            assert b'setting.nick = "Backup control"' in captured[0]
            assert settings.master_get('c32_shares') == [share]

        # A legacy/crafted backup can still contain this field. Ignore it while
        # restoring ordinary settings and the wallet successfully.
        vals = backups.text_bk_parser(contents.encode())
        vals['setting.c32_shares'] = [share]
        vals['setting.nick'] = 'Restored control'
        settings.remove_key('c32_shares')
        settings.save()
        error, _ = backups.restore_from_dict_ll(vals, raw)
        assert error is None
        assert settings.get('c32_shares') is None
        assert settings.get('nick') == 'Restored control'
        assert bytes(pa.fetch()) == raw
        settings.load()
        assert settings.get('c32_shares') is None
        assert settings.get('nick') == 'Restored control'
    finally:
        settings.current = original
        settings.save()


run()
