#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="$ROOT_DIR/dist"
APP_BUNDLE="$DIST_DIR/ClaudeGuard.app"
CONTENTS="$APP_BUNDLE/Contents"
MACOS_DIR="$CONTENTS/MacOS"
HELPERS_DIR="$CONTENTS/Helpers"
RESOURCES_DIR="$CONTENTS/Resources"

echo "==> [1/4] 编译 Release 原生产物 (ClaudeGuard + claudeguard-cli + claudeguard-helper)…"
swift build --package-path "$ROOT_DIR" -c release

BIN_DIR="$(swift build --package-path "$ROOT_DIR" -c release --show-bin-path)"

echo "==> [2/4] 组装应用包 $APP_BUNDLE…"
rm -rf "$APP_BUNDLE"
mkdir -p "$MACOS_DIR" "$HELPERS_DIR" "$RESOURCES_DIR"

cp "$BIN_DIR/ClaudeGuard" "$MACOS_DIR/ClaudeGuard"
cp "$BIN_DIR/claudeguard-cli" "$HELPERS_DIR/claudeguard-cli"
cp "$BIN_DIR/claudeguard-helper" "$HELPERS_DIR/claudeguard-helper"
chmod 755 "$MACOS_DIR/ClaudeGuard" "$HELPERS_DIR/claudeguard-cli" "$HELPERS_DIR/claudeguard-helper"

echo "==> [3/4] 生成高清矢量 AppIcon.icns…"
ICONSET_TMP="$(mktemp -d)/AppIcon.iconset"
mkdir -p "$ICONSET_TMP"
for spec in \
    "16:icon_16x16.png" \
    "32:icon_16x16@2x.png" \
    "32:icon_32x32.png" \
    "64:icon_32x32@2x.png" \
    "128:icon_128x128.png" \
    "256:icon_128x128@2x.png" \
    "256:icon_256x256.png" \
    "512:icon_256x256@2x.png" \
    "512:icon_512x512.png" \
    "1024:icon_512x512@2x.png"
do
    px="${spec%%:*}"
    name="${spec#*:}"
    swift "$ROOT_DIR/scripts/generate-icon.swift" "$px" "$ICONSET_TMP/$name"
done
iconutil -c icns "$ICONSET_TMP" -o "$RESOURCES_DIR/AppIcon.icns"
rm -rf "$(dirname "$ICONSET_TMP")"

cat > "$CONTENTS/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>zh_CN</string>
    <key>CFBundleDisplayName</key>
    <string>ClaudeGuard</string>
    <key>CFBundleExecutable</key>
    <string>ClaudeGuard</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>CFBundleIdentifier</key>
    <string>com.claudeguard.app</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>ClaudeGuard</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>LSMinimumSystemVersion</key>
    <string>14.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
EOF

echo "==> [4/4] 执行本机 Ad-hoc 代码签名与完整性校验…"
codesign --force --sign - "$HELPERS_DIR/claudeguard-helper"
codesign --force --sign - "$HELPERS_DIR/claudeguard-cli"
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict "$APP_BUNDLE"

echo ""
echo "✓ 构建成功：$APP_BUNDLE"
echo "  可直接拖入 /Applications 双击运行，在图形向导中一键完成授权与白名单配置。"
