#!/bin/bash

set -e

APPDIR="$(dirname "$(readlink -e "$0")")"

export LD_LIBRARY_PATH="${APPDIR}/usr/lib/:${APPDIR}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
export PATH="${APPDIR}/usr/bin:${PATH}"
export LDFLAGS="-L${APPDIR}/usr/lib/x86_64-linux-gnu -L${APPDIR}/usr/lib"

#debug satochip-bridge
export PYTHONPATH="${APPDIR}/usr/lib/python3.6/site-packages:$PYTHONPATH"

#exec "${APPDIR}/usr/bin/python3.6" -s "${APPDIR}/usr/bin/electrum" "$@"
#exec "${APPDIR}/usr/bin/python3.6" -s "${APPDIR}/usr/bin/SatochipBridge.py" "$@"
exec "${APPDIR}/usr/bin/python3.6" -s "${APPDIR}/usr/lib/python3.6/site-packages/satochip_bridge/SatochipBridge.py" "$@"