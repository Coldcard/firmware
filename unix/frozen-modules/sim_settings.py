import os, sys

from sim_secel import SECRETS

if '-w' in sys.argv:
    # clean out olds pins/secrets.. start with nothing
    sim_defaults = dict(_age=0)
    SECRETS = dict()

elif '-l' in sys.argv:
    # clean out olds pins/secrets.. start with nothing, except a pin code
    sim_defaults = { '_age': 1,
        'terms_ok': 1,
        '_skip_pin': '12-12',
    }

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })
    
else:
    # default values for simulator
    # CAUTION: some test cases may rely on these?
    sim_defaults = {
        '_age': 42,
        #'chain': 'BTC',
        #'xpub': 'xpub661MyMwAqRbcGC9DmWbtbAmuUjpMYxw4BWE88NSDHB3jSjfUK7KtYJuKa52GbowD3DVLkgsxH9QwPnTx5mjdHykYFEncnmAsNsCTbWzBhA7',
        'chain': 'XTN',
        'xpub': 'tpubD6NzVbkrYhZ4XzL5Dhayo67Gorv1YMS7j8pRUvVMd5odC2LBPLAygka9p7748JtSq82FNGPppFEz5xxZUdasBRCqJqXvUHq6xpnsMcYJzeh',
        '_skip_pin': '12-12',
        'terms_ok': 1,
        'xfp': 1130956047,
        'idle_to': 28800
    }

    SECRETS.update({
        '_pin1': '12-12',
        '_pin1_secret': '82faf8c43d8835d20aef178a530bb658071a5252b722ba910a4143d9010ebfded9000000000000000000000000000000000000000000000000000000000000000000000000000000',
    })

if '-2' in sys.argv:
    # enable second wallet, but no seeds
    sim_defaults.pop('_skip_pin', 0)
    SECRETS.update({
        '_pin2': '33-33',
        '_pin2_secret': '000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    })

if '-p' in sys.argv:
    sim_defaults['b39pw'] = 'test'
    #del sim_defaults['xpub']
    #del sim_defaults['xfp']

if '-m' in sys.argv:
    # Include random multisig wallet, and shortcut to MS menu
    sim_defaults['multisig'] = [('Sample-3-15', (3, 15), [(2044885442, 'tpubD9h2yEghZWRp4Mvi4MPhyP7ZN8GDqYVRMk6rNf5omds7WTjmRZiok8xgwEP3uXLVbpxVrqnjm4bNXL6tLwHtYF9J7uVSG9u95Yid38fX9dT'), (3035660899, 'tpubD8zYsexbkYEiCbTso12bUsE8Y1CUn3WHjLER3fWqc8mcP7FhDK1Rc6Tixr6v3SQ4XBi5d4bbTskUCxe4eZujkL2cQ3enCDENtBYJYzYuUaR'), (3343279201, 'tpubD8yeTfF4L8aCEaQbuPjjzNeyPs2WGJPNWcBMDuDP7NP2VjLBCB5afvfhAg3oTytxvnLXZbMBWyEhs2nt3wmduwSCMotB8RHcxxkvMRtZHrq'), (1010565321, 'tpubD9jpJX26AjUzTjCuZb9PfWmKjrSjFzXfNjBFwMY6ckt9qw3m9rpYw3NGD2yZut6UbFuQZm2xttchgchzGjJn26Fu1uZp1tveV1WcmUaXpay'), (3514371631, 'tpubD8cBsaZfRPmyPGVeThECbc9QSVeMwbPFiSjP9sL18wWvgmr4d5zRKt6Ui4ULRh1upZ2PyEkkYYRpkLm54A9kNTtS6bdyfr1spz2VnKheikt'), (2015339643, 'tpubD9AqW9bXwRSdDeCroC88GD4DGyst1Q3gN4FfdZQRow2zR3ctEMLoVSqGghVKYFk1PhEaGuRxkYSEEL8gxK36JuTCV8Lx8cn7SNQsChcgEEd'), (3288774263, 'tpubD99AL1Y6SZd21cfQUYQMn9CZ2qUaLV1TtNeHdiF6zLdP8EiEpKAbfnyjFupZhfacc6SR3GCv3HcTNDaYBPnXkpmefrvwKUmAhfkfiegQ5jP'), (4221684237, 'tpubD8N1Mwa4k3qCBuTBUMRRjhYoinWKV4RL3F7ejGmyqdm6iJJrdkEgwUw8Bme9DKdda4VEPT6BxnaPXkXXtF4Z6Z9HS4zdrwiMHnvkaMRgGVo'), (2921731989, 'tpubD9MgmFNaPdLHfFX7bZvyiDir5vM7DL2P8cXAMKNdhrnnUwcj4ts1PpjkXKNZcSBozs9dfnw3TrEYaSPmGbhpkVN6hunUheyBvzmwiD27k9E'), (4230381039, 'tpubDA2DxRfGUHmsbj3TthZSUyaBYhxgKc2wDMTAmTyN1ZhkTjB6LwFFTL9QCaRKUQKm4sBAxyr5mEdaj5BDK85ERSyb3qAVyrGkC5fJcVhMczu'), (1964861156, 'tpubD9wVkBGpo7g3jpWe7HZ72aHcXawpvb8k7RpfhXP3P8pcKTzXxgbu8zQas4kmRno3LW9n5KL6PoDfiQxEmXu3Dio6dndP8WvZWQoptPvJPNW'), (1834774641, 'tpubD96VF6RREC5d9oVPgjC2iTDve65yNw3yCGm27bFgstzwS5bT77HJPL6UGtn73qthqvHWq9LmKM6GExum5WL1hVMuY62FuEyU695Pv9rGpny'), (1980081501, 'tpubD8x3oveobb62Fnjt5gqr22PgcBuSHLdYxoQVvZSpmhWeFpSuTyZQ9pWAKVTNxZ4xUsJ3TvdyCZbyE767xkxeXU3i4YPzXeWggMUHvGHhFX9'), (4014485539, 'tpubD8X8Rg6iL6cFEFJW6mUyF4mfEVKRJDn4EUWkFg6mrk6XheRuy5zCBk5KPeZVgH1GgWo52nJLJHj4vm5PpJZbSJf5DWFQDwbtv1N1DSH67Fn'), (1130956047, 'tpubD8NXmKsmWp3a3DXhbihAYbYLGaRNVdTnr6JoSxxfXYQcmwVtW2hv8QoDwng6JtEonmJoL3cNEwfd2cLXMpGezwZ2vL2dQ7259bueNKj9C8n')], {'ch': 'XTN', 'pp': "45'"})]

    from main import numpad
    numpad.inject('9')
    numpad.inject('y')
    numpad.inject('9')
    numpad.inject('5')
    numpad.inject('y')


# EOF
