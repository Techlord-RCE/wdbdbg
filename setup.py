#! /usr/bin/env python
# coding: utf-8
#
# Author: Yannick Formaggio
from setuptools import setup, find_packages

PROJECT = 'WdbDBG'
VERSION = '0.1'

setup(
    name=PROJECT,
    version=VERSION,
    author='Yannick Formaggio',
    author_email='yannick.formaggio@gmail.com',
    url='https://bitbucket.org/yformaggio/wdbdbg',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python',
        'Intended Audience :: Developers',
        'Environment :: Console',
    ],
    platforms=['Any'],
    description=(
        'VxWorks v5 and v6 remote debugger framework using WDB RPC'
    ),
    long_description=open('README.md').read(),
    packages=find_packages(exclude=['image']),
    include_package_data=True,
)
