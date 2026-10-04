#!/usr/bin/env bash
#
# Audit Status - build a single executable binary for this machine.
#
# Usage:  scripts/build-binary.sh
# Output: auditstatus-<linux|darwin>-<x64|arm64>
#
# The binary is the Node.js executable running this script with the
# bundled CLI injected, so build with an official Node.js release.

set -euo pipefail

cd "$(dirname "$0")/.."

case "$(uname -s)" in
  Linux) PLATFORM=linux ;;
  Darwin) PLATFORM=darwin ;;
  *) echo "Unsupported platform: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64 | amd64) ARCH=x64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

BINARY="auditstatus-${PLATFORM}-${ARCH}"
POSTJECT_VERSION="1.0.0-alpha.6"
FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2"

node scripts/build-sea.mjs
node --experimental-sea-config sea-config.json

rm -f "$BINARY"
cp "$(command -v node)" "$BINARY"
chmod u+w "$BINARY"

if [ "$PLATFORM" = darwin ]; then
  codesign --remove-signature "$BINARY"
  npx --yes "postject@${POSTJECT_VERSION}" "$BINARY" NODE_SEA_BLOB sea-prep.blob --sentinel-fuse "$FUSE" --macho-segment-name NODE_SEA
  codesign --sign - "$BINARY"
else
  npx --yes "postject@${POSTJECT_VERSION}" "$BINARY" NODE_SEA_BLOB sea-prep.blob --sentinel-fuse "$FUSE"
fi

chmod 0755 "$BINARY"
rm -f sea-prep.blob

# Smoke test.
"./$BINARY" version
"./$BINARY" help > /dev/null
echo "Built $BINARY"
