# needs to run against simulator with "--multi-mig" flag as multisigs need to be there before login sequence executes

import base64, pytest
from test_640_miniscript_migration import (msc0, msc1, msc2, msc3, msc4, msc5, msc6, msc7, msc8, msc9, msc10,
                                           msc11, msc12, msc14, msc15, msc16, msc17, msc18, msc19, msc20)

# MULTISIGS
ms0 = ['ms0', (2, 2), [(1130956047, 1, 'tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP'), (4118082990, 0, 'tpubDDX85PzueTZjod816TDBdJPk8vWhqyZkSAXJ5xUjvSd1PyuEKnjt5UxiinKJSZzTTFVGSsSEm57LtpxQGdmSjQJtBmz1KUKtA9H63EzZmbA')], {'d': ['m/44h/1h/0h', 'm/48h/1h/0h/2h'], 'ch': 'XTN', 'ft': 14}, 0]
ms_psbt0 = 'cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAJACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBZgD/////AgDyBSoBAAAAIgAgmpn9BiIVcQF8SNxOBdxHZnr4zV50wqEfgao3H2nXwQYAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABASsA8gUqAQAAACIAIJqZ/QYiFXEBfEjcTgXcR2Z6+M1edMKhH4GqNx9p18EGAQVHUiEDpu0LHSZwTffTfIc4jmXAz2wEHnpdj8wqeEmXnjhsLmQhA2TIP6eApQSJp8iL+LUKERNbAllqpwd359L99FBGOPdtUq4iAgNkyD+ngKUEiafIi/i1ChETWwJZaqcHd+fS/fRQRjj3bUcwRAIgWd1qBvLJ3w7BCnKnf/lqC2NWx+k2ZckyogR7jvIa6Z0CIEGD4eI8QB34FHub2MqS6+V4pKbAVPW9Yb2f3e+3u6uhAQEDBAEAAAAiBgNkyD+ngKUEiafIi/i1ChETWwJZaqcHd+fS/fRQRjj3bRiu9XT1LAAAgAEAAIAAAACAAAAAAAAAAAAiBgOm7QsdJnBN99N8hziOZcDPbAQeel2PzCp4SZeeOGwuZBwPBWlDMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAAQ4g4ufuvyFOaMtZDSxF3z96nMBVdUModjxZLZnWC+AJdMwBDwQAAAAAARAE/f///wABAUdSIQOjp2xvvj06HYuo4Nu5+DDkWJK2g6Nw3I4z0U645qLW+iEDHguZsfImfX5ke8u+ZPYHqIQ2OchLKxSdQ9O+uL1qfSZSriICAx4LmbHyJn1+ZHvLvmT2B6iENjnISysUnUPTvri9an0mGK71dPUsAACAAQAAgAAAAIAAAAAAAQAAACICA6OnbG++PTodi6jg27n4MORYkraDo3DcjjPRTrjmotb6HA8FaUMwAACAAQAAgAAAAIACAACAAAAAAAEAAAABBCIAIA6r03dk/6wErujg+YtRD4AykJKKhjg6az38chGPiG2OAQMISOYFKgEAAAAA'

ms1 = ['ms1', (2, 2), [(1130956047, 1, 'tpubDF2rnouQaaYrXF4noGTv6rQYmx87cQ4GrUdhpvXkhtChwQPbdGTi8GA88NUaSrwZBwNsTkC9bFkkC8vDyGBVVAQTZ2AS6gs68RQXtXcCvkP'), (642592534, 0, 'tpubDCRchFK4N5fkmpD19kfdVBTPcRbcG321XpZc9EF5y9uH2d6DZdiYsVWvuZ6mTQpfqNuTVjqgb4ye33bFGHdhdS1eNwqrdbVQAwSwsftTCGZ')], {'d': ['m/44h/1h/0h', 'm/48h/1h/0h/2h'], 'ch': 'XTN', 'ft': 14}]
ms_psbt1 = 'cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAJACAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBZgD/////AgDyBSoBAAAAIgAgO7Et1Pc0tJ02+BhzSyIaAyUnI0+XDeJSG1+9yVYYKhQAAAAAAAAAACZqJKohqe3i9hw/cdHe/T+pmd+jaVN1XGkGiXmZYrSL69g2l06M+QAAAAABASsA8gUqAQAAACIAIDuxLdT3NLSdNvgYc0siGgMlJyNPlw3iUhtfvclWGCoUAQVHUiEDgwkO0ZNeLYTc0jARk0ubSvJSVLUeWXbOJI5gspAixFghA6btCx0mcE3303yHOI5lwM9sBB56XY/MKnhJl544bC5kUq4iAgODCQ7Rk14thNzSMBGTS5tK8lJUtR5Zds4kjmCykCLEWEcwRAIgI2cs69L4CIcU83erd/vww+0gfITnEDGSVTfCl55d33ICIDujRu9l8AUSkHUaz7syn5mJwnP81D3pxUYIBvoVmX30AQEDBAEAAAAiBgODCQ7Rk14thNzSMBGTS5tK8lJUtR5Zds4kjmCykCLEWBgWL00mLAAAgAEAAIAAAACAAAAAAAAAAAAiBgOm7QsdJnBN99N8hziOZcDPbAQeel2PzCp4SZeeOGwuZBwPBWlDMAAAgAEAAIAAAACAAgAAgAAAAAAAAAAAAQ4g1dxbBflVNuLZ2Ul1HWuYv3YvB+1WVb8try3mMtNWnpEBDwQAAAAAARAE/f///wABAUdSIQI1DhBwGxC7cQhnJ80CPFsg5dA/8ZVi447B1hj12FYq8yEDo6dsb749Oh2LqODbufgw5FiStoOjcNyOM9FOuOai1vpSriICAjUOEHAbELtxCGcnzQI8WyDl0D/xlWLjjsHWGPXYVirzGBYvTSYsAACAAQAAgAAAAIAAAAAAAQAAACICA6OnbG++PTodi6jg27n4MORYkraDo3DcjjPRTrjmotb6HA8FaUMwAACAAQAAgAAAAIACAACAAAAAAAEAAAABBCIAIBzbGbUkOtQUlU758Be6etJ319rIzQhJ2CMnsdGC4PFQAQMISOYFKgEAAAAA'

ms2 = ['ms2', (2, 2), [(1130956047, 1, 'tpubDF2rnouQaaYrUEy2JM1YD3RFzew4onawGM4X2Re67gguTf5CbHonBRiFGe3Xjz7DK88dxBFGf2i7K1hef3PM4cFKyUjcbJXddaY9F5tJBoP'), (2783214288, 0, 'tpubDCqWSUR4xtNPhMrVjQ2h5rdN2BACCHfviVnUrAynei9WaqvuykcjGyvGcbY9hJfpeovM4xVy5E3jMPw1tUc19PeqpVT9LxiTvgS9bZT5ceE')], {'d': ['m/44h/1h/0h', 'm/48h/1h/0h/1h'], 'ch': 'XTN', 'ft': 26}]
ms_psbt2 = 'cHNidP8BAgQCAAAAAQMEAAAAAAEEAQEBBQEBAfsEAgAAAAABAIUCAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/////wMBZgD/////AgDyBSoBAAAAF6kUb91OzriEjIgsWsSckPDC0Q+Jg6SHAAAAAAAAAAAmaiSqIant4vYcP3HR3v0/qZnfo2lTdVxpBol5mWK0i+vYNpdOjPkAAAAAAQEgAPIFKgEAAAAXqRRv3U7OuISMiCxaxJyQ8MLRD4mDpIcBBCIAIAtFYt0+m5ogPeAsF0wFYNUBTIr8zh9b3qyzA/GacXm0AQVHUiECOW8/hX0o1kO8nwuxBxbuW4vBfkcUSC7HQfJzbz2kUU0hA0AM5GQodaOUjCy0igI+AveDhgmkPzUR7Uq5tMXXqdTRUq4iAgI5bz+FfSjWQ7yfC7EHFu5bi8F+RxRILsdB8nNvPaRRTUcwRAIgYAx0HVnw1ptPsDxwA8LO/btP44LaPvKneUUYHY7hyG8CIEk1IDl6R5zJDHqGYkXoBwmLamUuHQ0XR814wPo1JYjUAQEDBAEAAAAiBgI5bz+FfSjWQ7yfC7EHFu5bi8F+RxRILsdB8nNvPaRRTRjQeuSlLAAAgAEAAIAAAACAAAAAAAAAAAAiBgNADORkKHWjlIwstIoCPgL3g4YJpD81Ee1KubTF16nU0RwPBWlDMAAAgAEAAIAAAACAAQAAgAAAAAAAAAAAAQ4gui/D81PS/KT/SauPldOYn71xRmcYZ0Kj2dxDPpRW0ZABDwQAAAAAARAE/f///wABACIAIEB0TJfmwXDzSb/VIr0lxfWIilZ4/9NxxZIw1ckjnQuxAQFHUiEDSK842mj16CcwA8Oxafwy+HR4T9vgB3S6eLdqeeAcetchA4mgQByfozPkgmIIhTWOPBs3dPU0X6FoXoJSvAM0VIHJUq4iAgNIrzjaaPXoJzADw7Fp/DL4dHhP2+AHdLp4t2p54Bx61xjQeuSlLAAAgAEAAIAAAACAAAAAAAEAAAAiAgOJoEAcn6Mz5IJiCIU1jjwbN3T1NF+haF6CUrwDNFSByRwPBWlDMAAAgAEAAIAAAACAAQAAgAAAAAABAAAAAQQXqRSPvHXlyB6V3gbZGQNf3pn0ajFr2IcBAwho5AUqAQAAAAA='

# originless key
ms3 = ['ms3', (2, 2), [(1130956047, 1, 'tpubDC7jGaaSE66Pn4dgtbAAstde4bCyhSUs4r3P8WhMVvPByvcRrzrwqSvpF9Ghx83Z1LfVugGRrSBko5UEKELCz9HoMv5qKmGq3fqnnbS5E9r'), (2267113793, 0, 'tpubDCGx6bNmE4zRFgfeV2PbGfcuhg6aeqtLYgNEGZ2pghgFiarh8j2yVruetVWUd6ykfkxaGgB8GhEkaGva1jXvqJrLXC3LboxsQTHqqCZD5Jj')], {'ch': 'XTN', 'd': ['m', 'm/84h/1h/0h'], 'ft': 14}]
ms_psbt3 = 'cHNidP8BAP0rAgIAAAABiAr0KRSDIDrFzMjggzrMgec11iCNOWObVMLaS1YBmJcAAAAAAP3///8M13zXFwAAAAAiACCIXzxTyZhwf3wFuDAnwTG88beXgJqnTozLss1ohcqk7wCE1xcAAAAAIgAg87m+7F8IaAPlGfRYYJiZjknBo9r+sfEeBEt8ExvGONwAhNcXAAAAACIAIJuNLOQqs0+h0lWYdUlbrWXXNeukLAP24T3hBrbqjAJwAITXFwAAAAAiACB+ZHaeEe5IEV8nIx18MLb+0IDx8A3SL9PRBu50xfW3ygCE1xcAAAAAIgAgv0EeId65n2gTVpZgUlgZuzt3FljhpvQsyc1QXSWeRfYAhNcXAAAAACIAIOaXgRS/wZSFXqQ8nyuVHUuZ1+Het25p5natNgpHi/GCAITXFwAAAAAiACDqvw3wmGpyoafU7oHMclQealvGvMkJNyfbRrMFcBpYwACE1xcAAAAAIgAgJFG9XpSgdWV6Q6mtxxg8y3CkMravdGxFJT6lEYtj96UAhNcXAAAAACIAIKsAbY9THQbI9Jq5JEn1Wmyz+c7fJMpgmqO240sswwaEAITXFwAAAAAiACAHyt0zi3+Z7Ylv4LuCsxg9NbZH+g+/rKN7ESuId1t05gCE1xcAAAAAIgAgJCbTIe9pTeL1XbRLsUCGkrvUfDilu1x58VygpoEn3UcAZc0dAAAAABYAFIHEkVYuDZvkQagsTkJQ94tUhBINAAAAAAABAH0CAAAAAf1034t7VhYi7VoboMpCMPqrv54cf8c5623mE47KpmswAAAAAAD9////AgARECQBAAAAIgAggWlPe2jpUpA3h2R/WyCpSdQvONk9Van3RoiBQyrQpukM1fUFAAAAABYAFBuBGObzc2t9SzkWFXwk9WgwuaHJZQAAAAEBKwARECQBAAAAIgAggWlPe2jpUpA3h2R/WyCpSdQvONk9Van3RoiBQyrQpukBBUdSIQJ94+nVKG2Fp5Lorr5u7BL4yNkD2gqw2jtNzojYX0qVOSEC/i4dtVARCRWtROG0HHoGcaVklzJUcwo5homgGkSNAnJSriIGAn3j6dUobYWnkuiuvm7sEvjI2QPaCrDaO03OiNhfSpU5DEFpIYcAAAAAAAAAACIGAv4uHbVQEQkVrUThtBx6BnGlZJcyVHMKOYaJoBpEjQJyGA8FaUNUAACAAQAAgAAAAIAAAAAAAAAAAAABAUdSIQOP64NYuuiwxH2PjueYTdjaCPyPw5cD9tVT2G6xiKFojCEDqlCO+Z05GQe2FGQaBxqIRvGNOVnv8Mbvs+Tk1MkshkpSriICA4/rg1i66LDEfY+O55hN2NoI/I/DlwP21VPYbrGIoWiMGA8FaUNUAACAAQAAgAAAAIAAAAAAAQAAACICA6pQjvmdORkHthRkGgcaiEbxjTlZ7/DG77Pk5NTJLIZKDEFpIYcAAAAAAQAAAAABAUdSIQIIx7Qn8M0dJ18SGL9uszUiSFosIX3FVs/y/dV5zSN8iiEDRvg+STRArYr4KT0Il+jVZovQSb7k0ewlSfphDZYNWcxSriICAgjHtCfwzR0nXxIYv26zNSJIWiwhfcVWz/L91XnNI3yKDEFpIYcAAAAAAgAAACICA0b4Pkk0QK2K+Ck9CJfo1WaL0Em+5NHsJUn6YQ2WDVnMGA8FaUNUAACAAQAAgAAAAIAAAAAAAgAAAAABAUdSIQIa1PR4Q0sF1cFGDDDH6yVZrHALb7SAc5n3ZOhK639F9CEDOlzzHZK7hfCQ92nTa/kIdgan/Z8ytDih95/b/icwJ5tSriICAhrU9HhDSwXVwUYMMMfrJVmscAtvtIBzmfdk6Errf0X0GA8FaUNUAACAAQAAgAAAAIAAAAAAAwAAACICAzpc8x2Su4XwkPdp02v5CHYGp/2fMrQ4ofef2/4nMCebDEFpIYcAAAAAAwAAAAABAUdSIQM4chGJnXg783SSa71bZcic/aOmnhKdif6zJOQKF7yrSyEDvTz5yVA7DbIcwtG0EBTu+YwSTVx072Mz7kKDj8g8X9NSriICAzhyEYmdeDvzdJJrvVtlyJz9o6aeEp2J/rMk5AoXvKtLGA8FaUNUAACAAQAAgAAAAIAAAAAABAAAACICA708+clQOw2yHMLRtBAU7vmMEk1cdO9jM+5Cg4/IPF/TDEFpIYcAAAAABAAAAAABAUdSIQLQsT6IRUDYMQZvSPrhR8s2ODq0D3Yn0zu4nYMUgx7t8SEDu7OKPPpFQ3R2UPsFKGehgSYLeNok8UYvzCHzAp9E05JSriICAtCxPohFQNgxBm9I+uFHyzY4OrQPdifTO7idgxSDHu3xGA8FaUNUAACAAQAAgAAAAIAAAAAABQAAACICA7uzijz6RUN0dlD7BShnoYEmC3jaJPFGL8wh8wKfRNOSDEFpIYcAAAAABQAAAAABAUdSIQKuASHAzn7QLFH/phGWBJogBTARh38AZqbQ6fjOgUwM0yEDZl5kBWt6sCBGwmdAsEAOYxb0dTvc2E/bISbrjrMB/+RSriICAq4BIcDOftAsUf+mEZYEmiAFMBGHfwBmptDp+M6BTAzTDEFpIYcAAAAABgAAACICA2ZeZAVrerAgRsJnQLBADmMW9HU73NhP2yEm646zAf/kGA8FaUNUAACAAQAAgAAAAIAAAAAABgAAAAABAUdSIQIHpl7cTOyYAjsfct8itufbrfeFiNPepx/pCJ4vxiZE2iEDvX0JkYUNdYHS0YFClEK3not13QVIftqElMmbXivc/fdSriICAgemXtxM7JgCOx9y3yK259ut94WI096nH+kIni/GJkTaDEFpIYcAAAAABwAAACICA719CZGFDXWB0tGBQpRCt56Ldd0FSH7ahJTJm14r3P33GA8FaUNUAACAAQAAgAAAAIAAAAAABwAAAAABAUdSIQL+CIiB59NSCssOJRGiMYQK1chahgAaaJpIXE41Cyir+yEDsuVnvmWYoM/JDq5Y78LIuKJURrMMIwR+Gqxj6P1Aw25SriICAv4IiIHn01IKyw4lEaIxhArVyFqGABpomkhcTjULKKv7GA8FaUNUAACAAQAAgAAAAIABAAAAAAAAACICA7LlZ75lmKDPyQ6uWO/CyLiiVEazDCMEfhqsY+j9QMNuDEFpIYcBAAAAAAAAAAABAUdSIQIJCucqVh38T68yRyB7gPO1I/Z9pCLkqCr1hDExzeYdxCECW0dEcucFs83wTUvh5fXjFtJZzjPcl5Jl4Au4pEevJPVSriICAgkK5ypWHfxPrzJHIHuA87Uj9n2kIuSoKvWEMTHN5h3EGA8FaUNUAACAAQAAgAAAAIAAAAAACAAAACICAltHRHLnBbPN8E1L4eX14xbSWc4z3JeSZeALuKRHryT1DEFpIYcAAAAACAAAAAABAUdSIQIlOebM4u8iz9IE3lv9ECT0E62y+jmMb2b72eAtX6runiECN9h5w9Ec4VuWIXSZhjiQa1uXQbfn6vA7iVsaMU4PqjVSriICAiU55szi7yLP0gTeW/0QJPQTrbL6OYxvZvvZ4C1fqu6eGA8FaUNUAACAAQAAgAAAAIAAAAAACQAAACICAjfYecPRHOFbliF0mYY4kGtbl0G35+rwO4lbGjFOD6o1DEFpIYcAAAAACQAAAAABAUdSIQNymaS3YPqgit6oOc2gMjW81bjsdGTIrbEgQ8UXOEZfXyEDtsrOjhTlqC5/KZHjX8QcTahxC7mtxJRvFTu1LNaC5uZSriICA3KZpLdg+qCK3qg5zaAyNbzVuOx0ZMitsSBDxRc4Rl9fGA8FaUNUAACAAQAAgAAAAIAAAAAACgAAACICA7bKzo4U5agufymR41/EHE2ocQu5rcSUbxU7tSzWgubmDEFpIYcAAAAACgAAAAAA'


def test_multisig(settings_set, settings_get, try_sign, goto_home, pick_menu_item, cap_menu,
                  clear_miniscript):
    # # try one by one
    # for ms, psbt in [(ms0, ms_psbt0), (ms1, ms_psbt1), (ms2, ms_psbt2), (ms3, ms_psbt3)]:
    #     clear_miniscript()
    #     name = ms[0]
    #     settings_set("multisig", [ms])
    #     goto_home()
    #     pick_menu_item("Settings")
    #     pick_menu_item("Multisig/Miniscript")  # migration happens here
    #     time.sleep(.1)
    #     assert name in cap_menu()
    #     assert settings_get("multisig", None) is None
    #     msc = settings_get("miniscript")
    #     assert len(msc) == 1
    #     assert len(msc[0]) == 4  # new format (name, policy, keys, opts)
    #     assert msc[0][0] == name
    #     try_sign(base64.b64decode(psbt))

    # now try bulk migration
    # clear_miniscript()
    # settings_set("multisig", [ms0, ms1, ms2, ms3])
    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")  # migration happens here
    menu = cap_menu()
    for name in ["ms0", "ms1", "ms2", "ms3"]:
        assert name in menu

    assert len(settings_get("multisig")) == 4  # preserved
    msc = settings_get("miniscript")
    assert len(msc) == 4
    for x in msc:
        assert len(x) == 4  # new format (name, policy, keys, opts)

    for i, psbt in enumerate([ms_psbt0, ms_psbt1, ms_psbt2, ms_psbt3]):
        try_sign(base64.b64decode(psbt), miniscript="ms%d" % i)


def test_multisig_miniscript_migration(settings_append, clear_miniscript, settings_get,
                                       settings_remove, settings_set, goto_home, pick_menu_item):

    # clear_miniscript()
    # settings_remove("multisig")

    for msc in [msc0, msc1, msc2, msc3, msc4, msc5, msc6, msc7, msc8, msc9, msc10,
                msc11, msc12, msc14, msc15, msc16, msc17, msc18, msc19, msc20]:
        settings_append("miniscript", msc)

    # settings_set("multisig", [ms0, ms1, ms2, ms3])

    goto_home()
    pick_menu_item("Settings")
    pick_menu_item("Multisig/Miniscript")  # migration happened here

    miniscripts = settings_get("miniscript")
    assert len(miniscripts) == 24  # 20 miniscript wallets & 4 multisigs
    for m in miniscripts:
        assert len(m) == 4

    assert len(settings_get("multisig")) == 4
