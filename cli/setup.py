# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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

