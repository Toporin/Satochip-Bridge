# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys, os

PACKAGE='Electrum'
PYPKG='satochip_bridge'
MAIN_SCRIPT=PYPKG+ '/SatochipBridge.py'
ICONS_FILE=PYPKG + '/satochip.ico'


for i, x in enumerate(sys.argv):
    if x == '--name':
        VERSION = sys.argv[i+1]
        break
else:
    VERSION = 'v0.0.0-test'
    # raise Exception('no version')

electrum = os.path.abspath(".") + "/"
block_cipher = None

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('pkg_resources')  # workaround for https://github.com/pypa/setuptools/issues/1963
hiddenimports += collect_submodules('smartcard') # satochip
hiddenimports += collect_submodules('websocket') # needed?

datas = [
    (electrum + PYPKG + '/*.png', PYPKG),
    (electrum + PYPKG + '/*.ico', PYPKG),
    (electrum + PYPKG + '/*.ini', PYPKG),
]
datas += collect_data_files('pysatochip')

# # Add libusb so Trezor and Safe-T mini will work
# binaries = [(electrum + "contrib/osx/libusb-1.0.dylib", ".")]
# binaries += [(electrum + "contrib/osx/libsecp256k1.0.dylib", ".")]
# binaries += [(electrum + "contrib/osx/libzbar.0.dylib", ".")]

# # Workaround for "Retro Look":
# binaries += [b for b in collect_dynamic_libs('PyQt5') if 'macstyle' in b[0]]

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([electrum+ PYPKG+ '/SatochipBridge.py',
              electrum+ PYPKG+ '/Client.py',
              electrum+ PYPKG+ '/handler.py',
              electrum+ PYPKG+ '/sato2FA.py',
              electrum+ PYPKG+ '/utils.py',
              electrum+ PYPKG+ '/version.py',
              electrum+ PYPKG+ '/wc_callback.py',
              ],
             binaries=[],
             datas=datas,
             hiddenimports=hiddenimports,
             hookspath=[])

# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# # Strip out parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
# qt_bins2remove=('qtweb', 'qt3d', 'qtgame', 'qtdesigner', 'qtquick', 'qtlocation', 'qttest', 'qtxml')
# print("Removing Qt binaries:", *qt_bins2remove)
# for x in a.binaries.copy():
#     for r in qt_bins2remove:
#         if x[0].lower().startswith(r):
#             a.binaries.remove(x)
#             print('----> Removed x =', x)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# exe = EXE(
#     pyz,
#     a.scripts,
#     exclude_binaries=True,
#     name=MAIN_SCRIPT,
#     debug=False,
#     strip=False,
#     upx=True,
#     icon=electrum+ICONS_FILE,
#     console=False,
# )

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name=MAIN_SCRIPT,
    debug=True,
    strip=False,
    upx=True,
    icon=electrum+ICONS_FILE,
    console=True,
)

app = BUNDLE(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    version = VERSION,
    name=PACKAGE + '.app',
    icon=electrum+ICONS_FILE,
    bundle_identifier=None,
    info_plist={
        'NSHighResolutionCapable': 'True',
        'NSSupportsAutomaticGraphicsSwitching': 'True'
    },
)
