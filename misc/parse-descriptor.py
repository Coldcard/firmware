
# wrote some code to parse the "key descriptor" in bitcoin-core 0.18 ... seems useful.

    '''
{'address': '2NDT3ymKZc8iMfbWqsNd1kmZckcuhixT5U4',
'desc': "sh(wsh(multi(2,[cb336aef]02f9c33362e7c4d9d21e9145e1478a36f341f2f0cfe7055abe92380bb806d9ce78,[edd08053/0'/0'/38']02fe422967a84e5612975d16d7b7ad3ec6a34c691aa643d6d50b8440589bcad4cd)))#fm8wdgdw",
'embedded': {'address': 'tb1qpcv2rkc003p5v8lrglrr6lhz2jg8g4qa9vgtrgkt0p5rteae5xtqn6njw9',
          'hex': '522102f9c33362e7c4d9d21e9145e1478a36f341f2f0cfe7055abe92380bb806d9ce782102fe422967a84e5612975d16d7b7ad3ec6a34c691aa643d6d50b8440589bcad4cd52ae',
          'isscript': True,
          'iswitness': True,
          'pubkeys': ['02f9c33362e7c4d9d21e9145e1478a36f341f2f0cfe7055abe92380bb806d9ce78',
                      '02fe422967a84e5612975d16d7b7ad3ec6a34c691aa643d6d50b8440589bcad4cd'],
          'script': 'multisig',
          'scriptPubKey': '00200e18a1db0f7c43461fe347c63d7ee2549074541d2b10b1a2cb786835e7b9a196',
          'sigsrequired': 2,
          'witness_program': '0e18a1db0f7c43461fe347c63d7ee2549074541d2b10b1a2cb786835e7b9a196',
          'witness_version': 0},
'hex': '00200e18a1db0f7c43461fe347c63d7ee2549074541d2b10b1a2cb786835e7b9a196',
'ischange': False,
'ismine': False,
'isscript': True,
'iswatchonly': False,
'iswitness': False,
'label': 'sim-cosign',
'labels': [{'name': 'sim-cosign', 'purpose': 'send'}],
'script': 'witness_v0_scripthash',
'scriptPubKey': 'a914dd9f26f478171e1509048c06d3d1e601de59fd6887',
'solvable': True}
'''
    match = re.search(r"\[([0-9a-f]{8})/([0-9'/]+)\]([0-9a-f]{64,68})", info['desc'])
    bc_xfp = match.group(1)
    bc_deriv = 'm/' + match.group(2)
    bc_pubkey = match.group(3)
