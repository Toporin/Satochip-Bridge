#!/bin/bash

set -e

PROJECT_ROOT="$(dirname "$(readlink -e "$0")")/../../.."
CONTRIB="$PROJECT_ROOT/contrib"
CONTRIB_APPIMAGE="$CONTRIB/build-linux/appimage"
DISTDIR="$PROJECT_ROOT/dist"
BUILDDIR="$CONTRIB_APPIMAGE/build/appimage"
APPDIR="$BUILDDIR/satochip_bridge.AppDir" #APPDIR="$BUILDDIR/electrum.AppDir" #todo
CACHEDIR="$CONTRIB_APPIMAGE/.cache/appimage"

# pinned versions
PYTHON_VERSION=3.6.8
PKG2APPIMAGE_COMMIT="eb8f3acdd9f11ab19b78f5cb15daa772367daf15"
LIBSECP_VERSION="b408c6a8b287003d1ade5709e6f7bc3c7f1d5be7"
SQUASHFSKIT_COMMIT="ae0d656efa2d0df2fcac795b6823b44462f19386"


VERSION=`git describe --tags --dirty --always`
APPIMAGE="$DISTDIR/satochip_bridge-$VERSION-x86_64.AppImage" #APPIMAGE="$DISTDIR/electrum-$VERSION-x86_64.AppImage"

. "$CONTRIB"/build_tools_util.sh

rm -rf "$BUILDDIR"
mkdir -p "$APPDIR" "$CACHEDIR" "$DISTDIR"

# potential leftover from setuptools that might make pip put garbage in binary
rm -rf "$PROJECT_ROOT/build"


info "downloading some dependencies."
download_if_not_exist "$CACHEDIR/functions.sh" "https://raw.githubusercontent.com/AppImage/pkg2appimage/$PKG2APPIMAGE_COMMIT/functions.sh"
verify_hash "$CACHEDIR/functions.sh" "78b7ee5a04ffb84ee1c93f0cb2900123773bc6709e5d1e43c37519f590f86918"

download_if_not_exist "$CACHEDIR/appimagetool" "https://github.com/AppImage/AppImageKit/releases/download/12/appimagetool-x86_64.AppImage"
verify_hash "$CACHEDIR/appimagetool" "d918b4df547b388ef253f3c9e7f6529ca81a885395c31f619d9aaf7030499a13"

download_if_not_exist "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "https://www.python.org/ftp/python/$PYTHON_VERSION/Python-$PYTHON_VERSION.tar.xz"
verify_hash "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" "35446241e995773b1bed7d196f4b624dadcadc8429f26282e756b2fb8a351193"


info "building python."
tar xf "$CACHEDIR/Python-$PYTHON_VERSION.tar.xz" -C "$BUILDDIR"
(
    cd "$BUILDDIR/Python-$PYTHON_VERSION"
    export SOURCE_DATE_EPOCH=1530212462
    LC_ALL=C export BUILD_DATE=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%b %d %Y")
    LC_ALL=C export BUILD_TIME=$(date -u -d "@$SOURCE_DATE_EPOCH" "+%H:%M:%S")
    # Patch taken from Ubuntu python3.6_3.6.8-1~18.04.1.debian.tar.xz
    patch -p1 < "$CONTRIB_APPIMAGE/patches/python-3.6.8-reproducible-buildinfo.diff"
    ./configure \
      --cache-file="$CACHEDIR/python.config.cache" \
      --prefix="$APPDIR/usr" \
      --enable-ipv6 \
      --enable-shared \
      --with-threads \
      -q
    make -j4 -s || fail "Could not build Python"
    make -s install > /dev/null || fail "Could not install Python"
    # When building in docker on macOS, python builds with .exe extension because the
    # case insensitive file system of macOS leaks into docker. This causes the build
    # to result in a different output on macOS compared to Linux. We simply patch
    # sysconfigdata to remove the extension.
    # Some more info: https://bugs.python.org/issue27631
    sed -i -e 's/\.exe//g' "$APPDIR"/usr/lib/python3.6/_sysconfigdata*
)

# info "DEBUG: check if QT5 present?"
# apt list qt5-default -a



info "Building squashfskit"
git clone "https://github.com/squashfskit/squashfskit.git" "$BUILDDIR/squashfskit"
(
    cd "$BUILDDIR/squashfskit"
    git checkout "$SQUASHFSKIT_COMMIT"
    make -C squashfs-tools mksquashfs || fail "Could not build squashfskit"
)
MKSQUASHFS="$BUILDDIR/squashfskit/squashfs-tools/mksquashfs"

appdir_python() {
  env \
    PYTHONNOUSERSITE=1 \
    LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}" \
    "$APPDIR/usr/bin/python3.6" "$@"
}

python='appdir_python'


info "installing pip."
"$python" -m ensurepip

info "DEBUG: update pip and setuptools"
"$python" -m pip install --upgrade pip

#todo
info "installing Satochip-Bridge and its dependencies."
mkdir -p "$CACHEDIR/pip_cache"
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/requirements/requirements.txt"
#"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/requirements/requirements-hw.txt"
#"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements.txt"
#"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" -r "$CONTRIB/deterministic-build/requirements-binaries.txt"

info "installing Satochip-Bridge."
"$python" -m pip install --no-warn-script-location --cache-dir "$CACHEDIR/pip_cache" "$PROJECT_ROOT"

#debug: test python & pysimplegui
#$python

# info "desktop integration."
cp "$PROJECT_ROOT/satochip_bridge.desktop" "$APPDIR/satochip_bridge.desktop"
cp "$PROJECT_ROOT/satochip_bridge/gui/icons/satochip.png" "$APPDIR/satochip.png"


# add launcher
cp "$CONTRIB_APPIMAGE/apprun.sh" "$APPDIR/AppRun"

info "finalizing AppDir."
(
    export PKG2AICOMMIT="$PKG2APPIMAGE_COMMIT"
    . "$CACHEDIR/functions.sh"

    cd "$APPDIR"
    # copy system dependencies
    copy_deps; copy_deps; copy_deps
    move_lib

    # apply global appimage blacklist to exclude stuff
    # move usr/include out of the way to preserve usr/include/python3.6m.
    mv usr/include usr/include.tmp
    delete_blacklisted
    mv usr/include.tmp usr/include
) || fail "Could not finalize AppDir"

# # We copy some libraries here that are on the AppImage excludelist
# info "Copying additional libraries"
# (
    # # On some systems it can cause problems to use the system libusb
    # cp -f /usr/lib/x86_64-linux-gnu/libusb-1.0.so "$APPDIR/usr/lib/libusb-1.0.so" || fail "Could not copy libusb"
# )

info "stripping binaries from debug symbols."
# "-R .note.gnu.build-id" also strips the build id
# "-R .comment" also strips the GCC version information
strip_binaries()
{
  chmod u+w -R "$APPDIR"
  {
    printf '%s\0' "$APPDIR/usr/bin/python3.6"
    find "$APPDIR" -type f -regex '.*\.so\(\.[0-9.]+\)?$' -print0
  } | xargs -0 --no-run-if-empty --verbose strip -R .note.gnu.build-id -R .comment
}
# strip_binaries #debug =>  ImportError: /tmp/.mount_electrmmVOQb/usr/lib/python3.6/site-packages/PySide2/QtWidgets.abi3.so: cannot change memory protections

remove_emptydirs()
{
  find "$APPDIR" -type d -empty -print0 | xargs -0 --no-run-if-empty rmdir -vp --ignore-fail-on-non-empty
}
remove_emptydirs #debug


info "removing some unneeded stuff to decrease binary size."
#debug
rm -rf "$APPDIR"/usr/{share,include}
PYDIR="$APPDIR"/usr/lib/python3.6
rm -rf "$PYDIR"/{test,ensurepip,lib2to3,idlelib,turtledemo}
rm -rf "$PYDIR"/{ctypes,sqlite3,tkinter,unittest}/test
rm -rf "$PYDIR"/distutils/{command,tests}
rm -rf "$PYDIR"/config-3.6m-x86_64-linux-gnu
rm -rf "$PYDIR"/site-packages/{opt,pip,setuptools,wheel}
rm -rf "$PYDIR"/site-packages/Cryptodome/SelfTest
rm -rf "$PYDIR"/site-packages/{psutil,qrcode,websocket}/tests
# for component in connectivity declarative help location multimedia quickcontrols2 serialport webengine websockets xmlpatterns ; do
  # rm -rf "$PYDIR"/site-packages/PyQt5/Qt/translations/qt${component}_*
  # rm -rf "$PYDIR"/site-packages/PyQt5/Qt/resources/qt${component}_*
# done
# rm -rf "$PYDIR"/site-packages/PyQt5/Qt/{qml,libexec}
# rm -rf "$PYDIR"/site-packages/PyQt5/{pyrcc.so,pylupdate.so,uic}
# rm -rf "$PYDIR"/site-packages/PyQt5/Qt/plugins/{bearer,gamepads,geometryloaders,geoservices,playlistformats,position,renderplugins,sceneparsers,sensors,sqldrivers,texttospeech,webview}
# for component in Bluetooth Concurrent Designer Help Location NetworkAuth Nfc Positioning PositioningQuick Qml Quick Sensors SerialPort Sql Test Web Xml ; do
    # rm -rf "$PYDIR"/site-packages/PyQt5/Qt/lib/libQt5${component}*
    # rm -rf "$PYDIR"/site-packages/PyQt5/Qt${component}*
# done
# rm -rf "$PYDIR"/site-packages/PyQt5/Qt.so

for component in connectivity declarative help location multimedia quickcontrols2 serialport webengine websockets xmlpatterns ; do
  rm -rf "$PYDIR"/site-packages/PySide2/Qt/translations/qt${component}_*
  rm -rf "$PYDIR"/site-packages/PySide2/Qt/resources/qt${component}_*
done
rm -rf "$PYDIR"/site-packages/PySide2/Qt/{qml,libexec}
rm -rf "$PYDIR"/site-packages/PySide2/{pyrcc.so,pylupdate.so,uic}
rm -rf "$PYDIR"/site-packages/PySide2/Qt/plugins/{bearer,gamepads,geometryloaders,geoservices,playlistformats,position,renderplugins,sceneparsers,sensors,sqldrivers,texttospeech,webview}
for component in Bluetooth Concurrent Designer Help Location NetworkAuth Nfc Positioning PositioningQuick Quick Sensors SerialPort Sql Test Web Xml ; do
    rm -rf "$PYDIR"/site-packages/PySide2/Qt/lib/libQt5${component}*
    rm -rf "$PYDIR"/site-packages/PySide2/Qt${component}*
done
rm -rf "$PYDIR"/site-packages/PySide2/Qt.so


# these are deleted as they were not deterministic; and are not needed anyway
info "removing some unneeded stuff (not deterministic)"
find "$APPDIR" -path '*/__pycache__*' -delete
#rm "$APPDIR"/usr/lib/libsecp256k1.a
# warning, packages such as eth-utils that use 'pkg_resources.get_distribution' need *.dist-info folders!
# note that jsonschema-*.dist-info is needed by that package as it uses 'pkg_resources.get_distribution'
# Import exception for eth_keys keyAPI
# DistributionNotFound(Requirement.parse('eth-utils'), None)
#for f in "$PYDIR"/site-packages/jsonschema-*.dist-info; do mv "$f" "$(echo "$f" | sed s/\.dist-info/\.dist-info2/)"; done
#for f in "$PYDIR"/site-packages/eth_utils-*.dist-info; do mv "$f" "$(echo "$f" | sed s/\.dist-info/\.dist-info2/)"; done
#rm -rf "$PYDIR"/site-packages/*.dist-info/
#rm -rf "$PYDIR"/site-packages/*.egg-info/
#for f in "$PYDIR"/site-packages/jsonschema-*.dist-info2; do mv "$f" "$(echo "$f" | sed s/\.dist-info2/\.dist-info/)"; done
#for f in "$PYDIR"/site-packages/eth_utils-*.dist-info2; do mv "$f" "$(echo "$f" | sed s/\.dist-info2/\.dist-info/)"; done

find -exec touch -h -d '2000-11-11T11:11:11+00:00' {} +

info "creating the AppImage."
(
    cd "$BUILDDIR"
    cp "$CACHEDIR/appimagetool" "$CACHEDIR/appimagetool_copy"
    # zero out "appimage" magic bytes, as on some systems they confuse the linker
    sed -i 's|AI\x02|\x00\x00\x00|' "$CACHEDIR/appimagetool_copy"
    chmod +x "$CACHEDIR/appimagetool_copy"
    "$CACHEDIR/appimagetool_copy" --appimage-extract
    # We build a small wrapper for mksquashfs that removes the -mkfs-fixed-time option
    # that mksquashfs from squashfskit does not support. It is not needed for squashfskit.
    cat > ./squashfs-root/usr/lib/appimagekit/mksquashfs << EOF
#!/bin/sh
args=\$(echo "\$@" | sed -e 's/-mkfs-fixed-time 0//')
"$MKSQUASHFS" \$args
EOF
    env VERSION="$VERSION" ARCH=x86_64 SOURCE_DATE_EPOCH=1530212462 ./squashfs-root/AppRun --no-appstream --verbose "$APPDIR" "$APPIMAGE"
)


info "done."
ls -la "$DISTDIR"
sha256sum "$DISTDIR"/*
