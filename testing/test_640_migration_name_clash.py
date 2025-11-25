# needs to run against simulator with '--name-clash-mig' flag as multisigs need to be there before login sequence executes


def test_name_clash(settings_append, clear_miniscript, settings_remove, goto_home, pick_menu_item,
                    settings_get):
    # names need to be unique per miniscript/multisig
    # but now we are merging them together - check and resolve
    # miniscript names are preserved, multisig names can be altered if needed
    # clear_miniscript()
    # settings_remove("multisig")

    # new_msc6 = list(msc6)
    # new_msc6[0] = "ms0"  # same name as ms0

    # length issue, name cannot be longer than 30 chars
    # but adding '1' would cause length failure - need some replacing
    # now handled in sim_settings
    # new_ms2 = list(ms2)
    # new_ms2[0] = 35*"a"

    # new_msc16 = list(msc16)
    # new_msc16[0] = 31*"a"
    #
    # new_msc11 = list(msc11)
    # new_msc11[0] = 32*"a"
    #
    # for w in [new_msc6, new_msc11, new_msc16]:
    #     settings_append("miniscript", w)
    # settings_set("multisig", [ms0, ms1, new_ms2, ms3])

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")

    # multisig key preserved in settings
    assert len(settings_get("multisig")) == 6
    miniscripts = settings_get("miniscript")

    assert all([len(m[0]) <= 30 for m in miniscripts])
    assert len(set([m[0] for m in miniscripts])) == 9