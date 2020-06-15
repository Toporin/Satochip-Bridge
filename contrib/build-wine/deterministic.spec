# -*- mode: python -*-

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, collect_dynamic_libs

import sys
for i, x in enumerate(sys.argv):
    if x == '--name':
        cmdline_name = sys.argv[i+1]
        break
else:
    raise Exception('no name')

PYHOME = 'c:/python3'

home = 'C:\\electrum\\'

# see https://github.com/pyinstaller/pyinstaller/issues/2005
hiddenimports = []
hiddenimports += collect_submodules('websocket')
hiddenimports += collect_submodules('smartcard') 
#hiddenimports += collect_submodules('PySimpleGUIQt.SystemTray') 

# Add libusb binary
#binaries = [(PYHOME+"/libusb-1.0.dll", ".")]

# Workaround for "Retro Look":
#binaries += [b for b in collect_dynamic_libs('PyQt5') if 'qwindowsvista' in b[0]]

# pyscard binaries for Satochip
binaries += [('C:/python*/Lib/site-packages/smartcard/scard/_scard.cp36-win32.pyd', '.')] #satochip

datas = [
	(home+'satochip_bridge/*.png', '.'),
]

# Hook for the mnemonic package: https://pypi.org/project/mnemonic/
#datas2= collect_data_files('mnemonic')
datas+= collect_data_files('mnemonic')
print('Datas= '+repr(datas))

# We don't put these files in to actually include them in the script but to make the Analysis method scan them for imports
a = Analysis([
              home+'satochip_bridge/SatochipBridge.py',
			  home+'satochip_bridge/Client.py',
			  home+'satochip_bridge/handler.py',
			  home+'satochip_bridge/version.py'
              ],
             binaries=binaries,
             datas=datas,
             #pathex=[home+'lib', home+'gui', home+'plugins'],
             hiddenimports=hiddenimports,
             hookspath=[])


# http://stackoverflow.com/questions/19055089/pyinstaller-onefile-warning-pyconfig-h-when-importing-scipy-or-scipy-signal
for d in a.datas:
    if 'pyconfig' in d[0]:
        a.datas.remove(d)
        break

# Strip out parts of Qt that we never use. Reduces binary size by tens of MBs. see #4815
#qt_bins2remove=('qt5web', 'qt53d', 'qt5game', 'qt5designer', 'qt5quick', 'qt5location', 'qt5test', 'qt5xml', r'pyqt5\qt\qml\qtquick')
#print("Removing Qt binaries:", *qt_bins2remove)
#for x in a.binaries.copy():
#    for r in qt_bins2remove:
#        if x[0].lower().startswith(r):
#            a.binaries.remove(x)
#            print('----> Removed x =', x)

#qt_data2remove=(r'pyqt5\qt\translations\qtwebengine_locales', )
#print("Removing Qt datas:", *qt_data2remove)
#for x in a.datas.copy():
#    for r in qt_data2remove:
#        if x[0].lower().startswith(r):
#            a.datas.remove(x)
#            print('----> Removed x =', x)

# hotfix for #3171 (pre-Win10 binaries)
a.binaries = [x for x in a.binaries if not x[1].lower().startswith(r'c:\windows')]

pyz = PYZ(a.pure)


#####
# "standalone" exe with all dependencies packed into it

exe_standalone = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=os.path.join('build\\pyi.win32\\electrum', cmdline_name + "console.exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=home+'satochip_bridge/gui/icons/electrum.ico', #home+'electrum/gui/icons/electrum.ico',
    console=True)
    # console=True makes an annoying black box pop up, but it does make Electrum output command line commands, with this turned off no output will be given but commands can still be used

exe_standalone = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name=os.path.join('build\\pyi.win32\\electrum', cmdline_name + ".exe"),
    debug=False,
    strip=None,
    upx=False,
    icon=home+'satochip_bridge/gui/icons/electrum.ico', #home+'electrum/gui/icons/electrum.ico',
    console=False)


coll = COLLECT(
    exe_dependent,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=None,
    upx=True,
    debug=False,
    icon=home+'satochip_bridge/gui/icons/electrum.ico', #home+'electrum/gui/icons/electrum.ico',
    console=False,
    name=os.path.join('dist', 'electrum'))
