# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# based on <http://click.pocoo.org/5/setuptools/#setuptools-integration>
#
# To use this, install with:
#
#   pip install --editable .

from setuptools import setup

setup(
    name='signit',
    version='1.0',
    #py_modules=['ckcc'],
    install_requires=[
        'Click',
    ],
    entry_points='''
        [console_scripts]
        signit=signit:main
    ''',
)

