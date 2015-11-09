#!/usr/bin/env python

from setuptools import setup


setup(
    pbr=True,
    setup_requires=['pbr'],
    test_suite='block_finder.test',
)
