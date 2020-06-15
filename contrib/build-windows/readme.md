# Satochip-Bridge packaging for windows

This building process is NOT deterministic.
To create windows binaries with pyinstaller, run this command from this location, on a Windows machine:

    $pyinstaller -wF --clean --name SatochipBridge-vXXX.exe --additional-hooks-dir=. --add-data "../../satochip_bridge/*.png;."  "../../satochip_bridge/SatochipBridge.py" -i "../../satochip_bridge/satochip.ico" 
	
	$pyinstaller -cF --clean --name SatochipBridge-console-vXXX.exe --additional-hooks-dir=. --add-data "../../satochip_bridge/*.png;."  "../../satochip_bridge/SatochipBridge.py" -i "../../satochip_bridge/satochip.ico" 
	
To generate a folder instead of a single file executable, use '-D' instead of '-F'. To add the log console, use '-c' instead of '-w'.
