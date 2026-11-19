#!/bin/bash
# Build "Keep Hub.app" and keep-hub-<version>-macos-<arch>.dmg (run on a Mac, after
# `cargo build --release -p keep-hub`). Adapted from ShareKeep's make-dmg.sh.
#
#   installer/macos/make-dmg.sh 0.1.0 [target/release] [arch]
#
# Until keep-launcher can install on a Mac, the hub has this disk image (the spec, "How the
# hub gets onto the computer"). The app bundle has no window (LSUIElement): it only carries
# the hub program where the daemon runs it. It is signed ad hoc (no Developer ID yet, as the
# other Keep apps). The DMG also holds "Install Keep Hub.command" and "Remove Keep Hub.command".
set -euo pipefail
VERSION="${1:?version, like 0.1.0}"
BIN="${2:-target/release}"
ARCH="${3:-$(uname -m | sed 's/arm64/aarch64/')}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$ROOT/dist"
STAGE="$OUT/dmg"
APP="$STAGE/Keep Hub.app"
rm -rf "$STAGE"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BIN/keep-hub" "$APP/Contents/MacOS/"
sed "s/@VERSION@/$VERSION/g" "$HERE/Info.plist" > "$APP/Contents/Info.plist"
# an app opens its own copy in Terminal when it offers to make this Mac the hub
cp "$HERE/install-hub.command" "$HERE/remove-hub.command" "$APP/Contents/Resources/"
chmod +x "$APP/Contents/Resources/install-hub.command" "$APP/Contents/Resources/remove-hub.command"
cp "$HERE/install-hub.command" "$STAGE/Install Keep Hub.command"
chmod +x "$STAGE/Install Keep Hub.command"
cp "$HERE/remove-hub.command" "$STAGE/Remove Keep Hub.command"
chmod +x "$STAGE/Remove Keep Hub.command"
cp "$ROOT/LICENSE-MIT" "$ROOT/LICENSE-APACHE" "$ROOT/NOTICE" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
codesign --force --deep --sign - "$APP"
# keep-launcher finds it by this name
DMG="$OUT/keep-hub-$VERSION-macos-$ARCH.dmg"
rm -f "$DMG"
hdiutil create -volname "Keep Hub $VERSION" -srcfolder "$STAGE" -ov -format UDZO "$DMG"
shasum -a 256 "$DMG" | sed "s|  .*/|  |" > "$DMG.sha256"
cat "$DMG.sha256"
