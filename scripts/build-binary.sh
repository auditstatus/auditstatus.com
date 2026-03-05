#!/bin/bash
#
# Audit Status - Build SEA Binary
#
# Builds a platform-specific Single Executable Application binary.
# Called by the CI release workflow for each platform.
#
# Usage:
#   ./scripts/build-binary.sh
#
# Environment:
#   PLATFORM  - Target platform (linux, darwin, win)
#   ARCH      - Target architecture (x64, arm64)
#
# Output:
#   auditstatus-${PLATFORM}-${ARCH}[.exe]
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PLATFORM="${PLATFORM:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
ARCH="${ARCH:-$(uname -m)}"

# Normalize arch
case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64) ARCH="arm64" ;;
esac

# Normalize platform
case "$PLATFORM" in
  linux*) PLATFORM="linux" ;;
  darwin*) PLATFORM="darwin" ;;
  mingw*|msys*|cygwin*|windows*) PLATFORM="win" ;;
esac

BINARY_NAME="auditstatus-${PLATFORM}-${ARCH}"
if [ "$PLATFORM" = "win" ]; then
  BINARY_NAME="${BINARY_NAME}.exe"
fi

echo -e "${GREEN}Building Audit Status SEA binary${NC}"
echo -e "Platform: ${PLATFORM}"
echo -e "Architecture: ${ARCH}"
echo -e "Output: ${BINARY_NAME}"
echo ""

# Step 1: Bundle with esbuild
echo -e "${YELLOW}Step 1: Bundling CLI with esbuild...${NC}"
node scripts/build-sea.mjs

# Step 2: Generate SEA blob
echo -e "${YELLOW}Step 2: Generating SEA blob...${NC}"
node --experimental-sea-config sea-config.json

# Step 3: Copy node binary
echo -e "${YELLOW}Step 3: Copying Node.js binary...${NC}"
if [ "$PLATFORM" = "win" ]; then
  cp "$(which node).exe" "$BINARY_NAME" 2>/dev/null || cp "$(which node)" "$BINARY_NAME"
else
  cp "$(which node)" "$BINARY_NAME"
fi

# Step 4: Remove signature on macOS (required before postject)
if [ "$PLATFORM" = "darwin" ]; then
  echo -e "${YELLOW}Step 4: Removing existing code signature (macOS)...${NC}"
  codesign --remove-signature "$BINARY_NAME"
fi

# Step 5: Inject SEA blob with postject
echo -e "${YELLOW}Step 5: Injecting SEA blob...${NC}"
if [ "$PLATFORM" = "darwin" ]; then
  npx postject "$BINARY_NAME" NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA
else
  npx postject "$BINARY_NAME" NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
fi

# Step 6: Re-sign on macOS
if [ "$PLATFORM" = "darwin" ]; then
  echo -e "${YELLOW}Step 6: Ad-hoc code signing (macOS)...${NC}"
  codesign --sign - "$BINARY_NAME"
fi

# Step 7: Make executable
chmod +x "$BINARY_NAME"

# Step 8: Verify
echo ""
echo -e "${GREEN}Verifying binary...${NC}"
./"$BINARY_NAME" version
echo ""
./"$BINARY_NAME" --help | head -5
echo ""
echo -e "${GREEN}Binary built successfully: ${BINARY_NAME}${NC}"
