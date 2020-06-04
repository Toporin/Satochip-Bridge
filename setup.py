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

with open('contrib/requirements/requirements-hw.txt') as f:
    requirements_hw = f.read().splitlines()

# load version.py; needlessly complicated alternative to "imp.load_source":
version_spec = importlib.util.spec_from_file_location('version', 'satochip_bridge/version.py')
version_module = version = importlib.util.module_from_spec(version_spec)
version_spec.loader.exec_module(version_module)

data_files = []

if platform.system() in ['Linux', 'FreeBSD', 'DragonFly']:
    parser = argparse.ArgumentParser()
    parser.add_argument('--root=', dest='root_path', metavar='dir', default='/')
    opts, _ = parser.parse_known_args(sys.argv[1:])
    usr_share = os.path.join(sys.prefix, "share")
    icons_dirname = 'pixmaps'
    if not os.access(opts.root_path + usr_share, os.W_OK) and \
       not os.access(opts.root_path, os.W_OK):
        icons_dirname = 'icons'
        if 'XDG_DATA_HOME' in os.environ.keys():
            usr_share = os.environ['XDG_DATA_HOME']
        else:
            usr_share = os.path.expanduser('~/.local/share')
    # data_files += [
        # (os.path.join(usr_share, 'applications/'), ['electrum.desktop']),
        # (os.path.join(usr_share, icons_dirname), ['electrum/gui/icons/electrum.png']),
    # ]

extras_require = {
    'hardware': requirements_hw,
    'gui': ['pyqt5'],
}
extras_require['full'] = [pkg for sublist in list(extras_require.values()) for pkg in sublist]


setup(
    name="Satochip-Bridge",
    version=version.SATOCHIP_BRIDGE_VERSION,
    python_requires='>={}'.format(MIN_PYTHON_VERSION),
    install_requires=requirements,
    extras_require=extras_require,
    packages=['satochip_bridge'],
    package_dir={
        'satochip_bridge': 'satochip_bridge'
    },
    package_data={
        'satochip_bridge': ['*.png', '*.ico'],
        #'satochip_bridge.gui': ['icons/*',],
    },
    # packages=[
        # 'electrum',
        # 'electrum.gui',
        # 'electrum.gui.qt',
        # 'electrum.plugins',
    # ] + [('electrum.plugins.'+pkg) for pkg in find_packages('electrum/plugins')],
    # package_dir={
        # 'electrum': 'electrum'
    # },
    # package_data={
        # '': ['*.txt', '*.json', '*.ttf', '*.otf'],
        # 'electrum': [
            # 'wordlist/*.txt',
            # 'locale/*/LC_MESSAGES/electrum.mo',
        # ],
        # 'electrum.gui': [
            # 'icons/*',
        # ],
    # },
    #scripts=['electrum/electrum'],
    scripts=['satochip_bridge/SatochipBridge.py'],
    #data_files=data_files,
    description="Bridging the gap between a wallet and Satochip",
    author="Toporin",
    author_email="satochip.wallet@gmail.com",
    license="GNU Lesser General Public License v3 (LGPLv3)",
    url="https://satochip.io",
    long_description="""Bridging the gap between a wallet and Satochip""",
)
