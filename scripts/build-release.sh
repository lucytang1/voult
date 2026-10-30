#!/usr/bin/env bash
set -euo pipefail

# Build a Voult.app bundle + DMG for arm64 macOS (unsigned).
# Usage: ./scripts/build-release.sh [--skip-client-build]
# Requires: node/npm, cargo, hdiutil (macOS)

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_DIR="$ROOT/build"
STAGE_DIR="$BUILD_DIR/stage"
APP_NAME="Voult"
APP_BUNDLE="$STAGE_DIR/$APP_NAME.app"
VERSION="${VERSION:-1.0.0}"

SKIP_CLIENT=false
if [[ "${1:-}" == "--skip-client-build" ]]; then
  SKIP_CLIENT=true
fi

echo "=== Voult release build (arm64, unsigned) ==="
echo "Root: $ROOT"
echo "Version: $VERSION"

# --- 1. Client build ---
if [[ "$SKIP_CLIENT" == false ]]; then
  # vault-core is a separate npm package consumed via `file:`. Its own
  # dependencies (zod, typescript) are not installed by the client's `npm ci`,
  # so build it here first — this is the step that used to fail on CI with
  # "Cannot find module 'zod'". See scripts/build-vault-core.sh for details.
  echo "--- Building shared vault-core package ---"
  bash "$ROOT/scripts/build-vault-core.sh"
  echo "--- Building client (Expo web export) ---"
  pushd "$ROOT/apps/client" > /dev/null
  npm ci
  npm run sync:sqlite-web
  # Clear EXPO_PUBLIC_API_URL so client uses same-origin /api
  EXPO_PUBLIC_API_URL= npm run build:web
  npx tsc --noEmit
  popd > /dev/null
else
  echo "--- Skipping client build (--skip-client-build) ---"
fi

if [[ ! -f "$ROOT/apps/client/dist/index.html" ]]; then
  echo "ERROR: apps/client/dist/index.html not found. Client build failed or --skip-client-build used with no prior build."
  exit 1
fi

# --- 2. Server build (arm64) ---
echo "--- Building server (pass-manager, release, aarch64-apple-darwin) ---"
pushd "$ROOT/apps/server" > /dev/null
# Ensure target exists
rustup target add aarch64-apple-darwin 2>/dev/null || true
cargo build --release --target aarch64-apple-darwin --bin pass-manager
popd > /dev/null

SERVER_BIN="$ROOT/apps/server/target/aarch64-apple-darwin/release/pass-manager"
if [[ ! -f "$SERVER_BIN" ]]; then
  echo "ERROR: server binary not found at $SERVER_BIN"
  exit 1
fi
echo "Server binary: $SERVER_BIN ($(file -b "$SERVER_BIN" | head -c 120))"

# --- 3. Launcher build (arm64) ---
echo "--- Building launcher (release, aarch64-apple-darwin) ---"
pushd "$ROOT/launcher" > /dev/null
cargo build --release --target aarch64-apple-darwin
popd > /dev/null

LAUNCHER_BIN="$ROOT/launcher/target/aarch64-apple-darwin/release/launcher"
if [[ ! -f "$LAUNCHER_BIN" ]]; then
  echo "ERROR: launcher binary not found at $LAUNCHER_BIN"
  exit 1
fi
echo "Launcher binary: $LAUNCHER_BIN ($(file -b "$LAUNCHER_BIN" | head -c 120))"

# --- 4. Stage Voult.app bundle ---
echo "--- Staging $APP_NAME.app ---"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$APP_BUNDLE/Contents/Resources/dist"

# Binaries
cp "$LAUNCHER_BIN" "$APP_BUNDLE/Contents/MacOS/Voult"
cp "$SERVER_BIN" "$APP_BUNDLE/Contents/MacOS/voult-server"
chmod +x "$APP_BUNDLE/Contents/MacOS/Voult"
chmod +x "$APP_BUNDLE/Contents/MacOS/voult-server"

# Static site
echo "Copying client/dist → Resources/dist"
cp -R "$ROOT/apps/client/dist/"* "$APP_BUNDLE/Contents/Resources/dist/"

# Cloud provider OAuth config — bundle every configured provider (Google Drive,
# Dropbox) so testers get working cloud backup without needing a .env. Only
# provider keys and CORS_ORIGINS are copied; DATABASE_URL/SESSION_COOKIE_KEY are
# deliberately left out so the per-install logic in config.rs still wins.
# Values come from apps/server/.env locally, or from environment variables
# (GitHub Actions secrets) on CI. See scripts/bundle-cloud-env.sh.
echo "--- Bundling cloud provider config ---"
bash "$ROOT/scripts/bundle-cloud-env.sh" "$APP_BUNDLE/Contents/Resources"

# Info.plist
if [[ -f "$ROOT/resources/Info.plist" ]]; then
  cp "$ROOT/resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
  # Inject version if `plutil` available
  if command -v plutil >/dev/null 2>&1; then
    plutil -replace CFBundleVersion -string "$VERSION" "$APP_BUNDLE/Contents/Info.plist" || true
    plutil -replace CFBundleShortVersionString -string "$VERSION" "$APP_BUNDLE/Contents/Info.plist" || true
  fi
else
  echo "WARNING: resources/Info.plist not found, creating minimal plist"
  cat > "$APP_BUNDLE/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>Voult</string>
  <key>CFBundleIdentifier</key><string>com.voult.app</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleExecutable</key><string>Voult</string>
  <key>LSUIElement</key><true/>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict>
</plist>
PLIST
fi

# PkgInfo (optional, for Finder)
echo "APPL????" > "$APP_BUNDLE/Contents/PkgInfo"

# Ad-hoc code sign so Gatekeeper doesn't report "damaged" for unsigned builds.
# Without any signature, macOS 13+ with quarantine treats the bundle as damaged
# instead of showing the normal "unidentified developer" dialog.
# `codesign -` is an ad-hoc signature (no Apple ID / not notarized) — just enough
# to make `spctl`/`Gatekeeper` allow "Move to Bin" → `xattr -cr` workflow, and
# `codesign --verify` passes. Testers still need to right-click Open or clear
# quarantine on first launch, but they won't get the "damaged" error.
if command -v codesign >/dev/null 2>&1; then
  echo "Ad-hoc signing $APP_BUNDLE ..."
  codesign --force --deep --sign - "$APP_BUNDLE" 2>&1 || echo "WARNING: codesign failed (non-fatal)"
  echo "codesign verify: $(codesign --verify --verbose "$APP_BUNDLE" 2>&1 || true)"
else
  echo "WARNING: codesign not found — bundle will be unsigned and may show 'damaged' on download"
fi

echo "Staged bundle:"
find "$APP_BUNDLE" -maxdepth 4 -print | head -n 40
ls -lh "$APP_BUNDLE/Contents/MacOS/"

# --- 5. Create DMG + tar.gz ---
echo "--- Creating DMG and tar.gz ---"
mkdir -p "$BUILD_DIR"

# Prepare DMG source folder with Applications symlink
DMG_SRC="$BUILD_DIR/dmg-src"
rm -rf "$DMG_SRC"
mkdir -p "$DMG_SRC"
cp -R "$APP_BUNDLE" "$DMG_SRC/"
ln -s /Applications "$DMG_SRC/Applications"

DMG_PATH="$BUILD_DIR/Voult-aarch64.dmg"
TARGZ_PATH="$BUILD_DIR/Voult-aarch64.tar.gz"

rm -f "$DMG_PATH"
if command -v hdiutil >/dev/null 2>&1; then
  hdiutil create -volname "Voult" -srcfolder "$DMG_SRC" -ov -format UDZO "$DMG_PATH"
  echo "DMG created: $DMG_PATH ($(du -h "$DMG_PATH" | cut -f1))"
else
  echo "hdiutil not found, skipping DMG (Linux CI?)"
fi

# Always create tar.gz
tar -czf "$TARGZ_PATH" -C "$STAGE_DIR" "$APP_NAME.app"
echo "tar.gz created: $TARGZ_PATH ($(du -h "$TARGZ_PATH" | cut -f1))"

# Checksums
if command -v shasum >/dev/null 2>&1; then
  echo "--- SHA256 ---"
  shasum -a 256 "$BUILD_DIR"/Voult-aarch64.* 2>/dev/null || true
fi

echo "=== Done ==="
echo "Bundle: $APP_BUNDLE"
[[ -f "$DMG_PATH" ]] && echo "DMG:    $DMG_PATH"
echo "tar.gz: $TARGZ_PATH"
echo ""
echo "To test locally:"
echo "  open \"$APP_BUNDLE\"   # or double-click in Finder"
echo "  # DB will be at ~/Library/Application Support/Voult/voult.db"
echo "  # Logs at ~/Library/Logs/Voult/server.log"
