#! /bin/bash

# based on  https://github.com/Pext/Pext/blob/master/travis/build-appimage.sh
# see also: https://github.com/AppImage/AppImageKit/wiki/Bundling-Python-apps
# and https://github.com/linuxdeploy/linuxdeploy-plugin-conda
# NOT TESTED - FOR DEBUG PURPOSE ONLY

set -x
set -e

# use RAM disk if possible
if [ -d /dev/shm ] && [ "$CI" != "" ]; then
    TEMP_BASE=/dev/shm
else
    TEMP_BASE=/tmp
fi

BUILD_DIR=$(mktemp -d -p "$TEMP_BASE" Pext-AppImage-build-XXXXXX)

cleanup () {
    if [ -d "$BUILD_DIR" ]; then
        rm -rf "$BUILD_DIR"
    fi
}

trap cleanup EXIT

# store repo root as variable
REPO_ROOT=$(readlink -f $(dirname $(dirname "$0")))
OLD_CWD=$(readlink -f .)

pushd "$BUILD_DIR"/

# set up custom AppRun script
cat > AppRun.sh <<\EAT
#! /bin/sh

#set -e

# make sure to set APPDIR when run directly from the AppDir
if [ -z $APPDIR ]; then APPDIR=$(readlink -f $(dirname "$0")); fi
export LD_LIBRARY_PATH="$APPDIR"/usr/lib

#APPDIR="$(dirname "$(readlink -e "$0")")"
#export LD_LIBRARY_PATH="${APPDIR}/usr/lib/:${APPDIR}/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH+:$LD_LIBRARY_PATH}"
# export PATH="${APPDIR}/usr/bin:${PATH}"
# export LDFLAGS="-L${APPDIR}/usr/lib/x86_64-linux-gnu -L${APPDIR}/usr/lib"

#debug satochip-bridge
#export PYTHONPATH="${APPDIR}/usr/lib/python3.6/site-packages:$PYTHONPATH"

#exec "${APPDIR}/usr/bin/python3.6" -s "${APPDIR}/usr/bin/electrum" "$@"
exec "${APPDIR}/usr/bin/python3.6" -s "${APPDIR}/usr/bin/SatochipBridge.py" "$@"

EAT

chmod +x AppRun.sh

# get linuxdeploy and its conda plugin
wget https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
wget https://raw.githubusercontent.com/TheAssassin/linuxdeploy-plugin-conda/e714783a1ca6fffeeb9dd15bbfce83831bb196f8/linuxdeploy-plugin-conda.sh  # We use an older linuxdeploy-plugin-conda because commit 76c8c8bf4e7dd435eda9c9a1de88a980c697f58f breaks the Pext build
#wget -c "https://raw.githubusercontent.com/linuxdeploy/linuxdeploy-plugin-conda/master/linuxdeploy-plugin-conda.sh" 

# Don't remove include, needed for compiling some extensions
sed -i 's;rm -rf include/;;g' linuxdeploy-plugin-conda.sh

# Don't remove setuptools, needed for some packages modules may need (https://github.com/Pext/Pext/issues/291)
sed -i 's;rm -rf lib/python?.?/site-packages/setuptools;;g' linuxdeploy-plugin-conda.sh

# can use the plugin's environment variables to ease some setup
# export CONDA_CHANNELS=conda-forge
# export CONDA_PACKAGES=xorg-libxi

export CONDA_CHANNELS="anaconda;conda-forge"
export CONDA_PACKAGES="qt;pyside2"
export PIP_REQUIREMENTS="."

# mkdir -p AppDir/usr/share/metainfo/
# cp "$REPO_ROOT"/*.appdata.xml AppDir/usr/share/metainfo/

# continuous releases should use the latest continuous build for updates
# APPIMAGEUPDATE_TAG=continuous

# if building for a tag, embed "latest" to make AppImageUpdate use the latest tag on updates
# you could call it the "stable" channel
# if [ "$TRAVIS_TAG" != "" ]; then
    # APPIMAGEUPDATE_TAG=latest
# fi

# if [ "$PEXT_BUILD_PORTABLE" -eq 1 ]; then
  # export UPD_INFO="gh-releases-zsync|Pext|Pext|$APPIMAGEUPDATE_TAG|Pext-portable-*x86_64.AppImage.zsync"
# else
  # export UPD_INFO="gh-releases-zsync|Pext|Pext|$APPIMAGEUPDATE_TAG|Pext*x86_64.AppImage.zsync"
# fi

chmod +x linuxdeploy*.{sh,AppImage}

# make sure linuxdeploy-plugin-conda switches to repo root so that the "." pip requirement can be satisfied
export PIP_WORKDIR="$REPO_ROOT"
export PIP_VERBOSE=1

#./linuxdeploy-x86_64.AppImage --appdir AppDir --plugin conda -d "$REPO_ROOT"/io.pext.pext.desktop -i "$REPO_ROOT"/pext/images/scalable/pext.svg --custom-apprun AppRun.sh
./linuxdeploy-x86_64.AppImage --appdir AppDir --plugin conda -d "$REPO_ROOT"/satochip_bridge.desktop -i "$REPO_ROOT"/satochip.png --custom-apprun AppRun.sh

# remove unused files from AppDir manually
# these files are nothing the conda plugin could remove manually
rm AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/QtWebEngine* || true
rm -r AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/translations/qtwebengine* || true
rm AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/resources/qtwebengine* || true
rm -r AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/qml/QtWebEngine* || true
rm AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/plugins/webview/libqtwebview* || true
rm AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/libexec/QtWebEngineProcess* || true
rm AppDir/usr/conda/lib/python3.6/site-packages/PyQt5/Qt/lib/libQt5WebEngine* || true

# now, actually build AppImage
# the extracted AppImage files will be cleaned up now
#./linuxdeploy-x86_64.AppImage --appdir AppDir --output appimage

ls -al AppDir/

python "$REPO_ROOT/setup.py" || true
# if [ "$PEXT_BUILD_PORTABLE" -eq 1 ]; then
  # export VERSION=portable-$(cat "$REPO_ROOT/pext/VERSION")
# else
  # export VERSION=$(cat "$REPO_ROOT/pext/VERSION")
# fi

wget https://github.com/AppImage/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage
chmod +x appimagetool*.AppImage
#./appimagetool*.AppImage AppDir -u "$UPD_INFO"
./appimagetool*.AppImage AppDir 

# Print version to test if the AppImage runs at all
chmod +x Pext*.AppImage*
#xvfb-run ./Pext*.AppImage* --version

# move AppImage back to old CWD
mv Pext*.AppImage* "$OLD_CWD"/