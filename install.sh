#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="macclean"
DIST="$DIR/dist/$BIN"

if [[ ! -f "$DIST" ]]; then
  echo "Binary tidak ditemukan: $DIST"
  echo "Jalanin: pyinstaller macclean.spec dulu"
  exit 1
fi

chmod +x "$DIST"

if [[ -d /opt/homebrew/bin ]]; then
  TARGET="/opt/homebrew/bin/$BIN"
elif [[ -d /usr/local/bin ]]; then
  TARGET="/usr/local/bin/$BIN"
else
  echo "Gak nemu /opt/homebrew/bin atau /usr/local/bin"
  echo "Pilih target manual, contoh: sudo cp $DIST /usr/local/bin/$BIN"
  exit 1
fi

if [[ -w "$(dirname "$TARGET")" ]]; then
  cp "$DIST" "$TARGET"
else
  sudo cp "$DIST" "$TARGET"
fi

echo "Installed: $TARGET"
"$TARGET" --help | head -2
