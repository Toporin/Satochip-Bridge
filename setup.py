#!/usr/bin/env python3

# python setup.py sdist --format=zip,gztar

import os
import sys
import platform
import importlib.util
import argparse
import subprocess

from setuptools import setup, find_packages
from setuptools.command.install import install

MIN_PYTHON_VERSION = "3.6.1"
_min_python_version_tuple = tuple(map(int, (MIN_PYTHON_VERSION.split("."))))

# todo: check actual minimum version required...
if sys.version_info[:3] < _min_python_version_tuple:
    sys.exit("Error: Satochip-Bridge requires Python version >= %s..." % MIN_PYTHON_VERSION)

with open('contrib/requirements/requirements.txt') as f:
    requirements = f.read().splitlines()

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'satochip_bridge/version.py')
version_module = version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

setup(
    name="Satochip-Bridge",
    version=version.SATOCHIP_BRIDGE_VERSION,
    python_requires='>={}'.format(MIN_PYTHON_VERSION),
    install_requires=requirements,
    packages=['satochip_bridge'],
    package_dir={
        'satochip_bridge': 'satochip_bridge'
    },
    package_data={
        'satochip_bridge': ['*.png', '*.ico'],
    },

    scripts=['satochip_bridge/SatochipBridge.py'],
    description="Bridging the gap between a wallet and Satochip",
    author="Toporin",
    author_email="satochip.wallet@gmail.com",
    license="GNU Lesser General Public License v3 (LGPLv3)",
    url='https://github.com/Toporin/Satochip-Bridge',
    project_urls={
        'Github': 'https://github.com/Toporin',
        'Webshop': 'https://satochip.io/',
        'Telegram': 'https://t.me/Satochip',
        'Twitter': 'https://twitter.com/satochipwallet',
        'Source': 'https://github.com/Toporin/Satochip-Bridge',
        'Tracker': 'https://github.com/Toporin/Satochip-Bridge/issues',
    },
    long_description="""Bridging the gap between a wallet and Satochip""",
)
