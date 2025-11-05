# needs to run against simulator with '--der-pth-mig' flag as multisigs need to be there before login sequence executes
import time, base64

def test_multisig_derivation_path_migration(start_sign, end_sign, settings_set, goto_home, clear_miniscript,
                                            pick_menu_item, cap_story, cap_menu, press_cancel, settings_get):

    # psbt from nunchuk, with global xpubs belonging to above ms wallet
    b64_psbt = "cHNidP8BAF4CAAAAAfkDjXlS32gzOjVhSRArKxvkAecMTnp1g8wwMJTtq74/AAAAAAD9////AekaAAAAAAAAIgAgzs2e4h4vctbFvvauK+QVFAPzCFnMi1H9hTacH7498P8AAAAATwEENYfPBC7g3O2AAAACLvzTgnL7V0DNOnISJdvOgq/6Pw6DAtkPflmZ+Hc04qwC5CShG0rDIlh8gu7gH2NMBLfrIzYSzoSomnVHeMxtxVQUDwVpQzAAAIAAAACAIQAAgAIAAIBPAQQ1h88EkEB8moAAAALv/1L+Cfeg2EPc01pS00f18DIdU5BOeExlGsXyEFOKGwL71tcAiRuL4Bs+uT1JJjU6AbR3j3X60/rI+rTMJmnOgRRiIUGIMAAAgAAAAIBjAACAAgAAgAABAIkCAAAAAZ5Im3CxbYDyByyrr4luss5vr+s0r7Vt8pK+OvicPLO7AAAAAAD9////AnM2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnTmvqUXAAAAACJRIJF/VcIeZ3E4f+ZEjwiUl5AUUxBJgoaEaPaHHJecq18lq+4qAAEBK3M2AAAAAAAAIgAgvZi0zfKCeBasTet1hNKm73GA4MEkwiSVwCB9cN0/EnQiAgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3kcwRAIgHNmbk4J9wu4ljq6UouY132eX1i/2jWvJjuuWWyLRFScCIBPyPCuZ/Hmd06h9KtVkSropBonIuqIc/BK8JZ50YKp/AQEDBAEAAAABBUdSIQMBr34TVHrqSk8K6505//5YTOkHmHqF83J8iUURtL/ptCEDUXZhsRMLD/PMbva5f7RgF6u5D5v+99Mk8kOlx0C/w95SriIGAwGvfhNUeupKTwrrnTn//lhM6QeYeoXzcnyJRRG0v+m0HA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAAAAAAiBgNRdmGxEwsP88xu9rl/tGAXq7kPm/730yTyQ6XHQL/D3hxiIUGIMAAAgAAAAIBjAACAAgAAgAAAAAAAAAAAAAEBR1IhAscIZVvBcy3Q0GKO4UqR3gDB3pm/tWas8siH3Ej8MmuCIQN8lTj0MMTpT+Dlk2MbMdAaL93hezzNP3WDsRn/gwlVQlKuIgICxwhlW8FzLdDQYo7hSpHeAMHemb+1ZqzyyIfcSPwya4IcYiFBiDAAAIAAAACAYwAAgAIAAIAAAAAAAQAAACICA3yVOPQwxOlP4OWTYxsx0Bov3eF7PM0/dYOxGf+DCVVCHA8FaUMwAACAAAAAgCEAAIACAACAAAAAAAEAAAAA"

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")  # migration happens here
    time.sleep(.1)

    names = ["ms", "ms1", "ms2"]
    menu = cap_menu()
    for n in names:
        assert n in menu

    assert len(settings_get("multisig")) == 3
    msc = settings_get("miniscript")
    assert len(msc) == 3
    for w in msc:
        assert len(w) == 4  # new format (name, policy, keys, opts)

    # in time of creation of PSBT, lopp was making testnet3 unusable...
    settings_set("fee_limit", -1)
    start_sign(base64.b64decode(b64_psbt))
    title, story = cap_story()
    assert title == "OK TO SEND?"
    end_sign()
    settings_set("fee_limit", 10)  # rollback
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")
    for msi in names:  # three wallets imported
        pick_menu_item(msi)
        pick_menu_item("View Details")
        time.sleep(.1)
        _, story = cap_story()
        assert "'" not in story
        press_cancel()
        press_cancel()
