#!/bin/bash
#
# Audit Status CLI Installer
# https://github.com/auditstatus/auditstatus
#
# Usage:
#   curl -fsSL https://github.com/auditstatus/auditstatus/releases/latest/download/install.sh | bash
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo -e "${BLUE}║     ${GREEN}Audit Status CLI Installer${BLUE}                  ║${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════${NC}"
echo ""

# Detect OS and architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$OS" in
  linux*) PLATFORM="linux" ;;
  darwin*) PLATFORM="darwin" ;;
  *)
    echo -e "${RED}Error: Unsupported operating system: $OS${NC}"
    echo "Please install via npm instead: npm install -g auditstatus"
    exit 1
    ;;
esac

case "$ARCH" in
  x86_64) ARCH="x64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo -e "${RED}Error: Unsupported architecture: $ARCH${NC}"
    echo "Please install via npm instead: npm install -g auditstatus"
    exit 1
    ;;
esac

ARTIFACT="auditstatus-${PLATFORM}-${ARCH}"
BIN_DIR="${AUDITSTATUS_BIN_DIR:-/usr/local/bin}"

echo -e "Platform: ${GREEN}${PLATFORM}-${ARCH}${NC}"
echo ""

# Get latest release URL
RELEASE_URL="https://github.com/auditstatus/auditstatus/releases/latest/download/${ARTIFACT}"

echo -e "${YELLOW}Downloading ${ARTIFACT}...${NC}"

# Create temp directory
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

# Download with progress bar
if command -v curl &> /dev/null; then
  curl -fL --progress-bar "$RELEASE_URL" -o "$TMP_DIR/auditstatus"
elif command -v wget &> /dev/null; then
  wget --show-progress -q "$RELEASE_URL" -O "$TMP_DIR/auditstatus"
else
  echo -e "${RED}Error: curl or wget is required${NC}"
  exit 1
fi

# Make executable
chmod +x "$TMP_DIR/auditstatus"

# Install (may need sudo)
echo ""
echo -e "${YELLOW}Installing to ${BIN_DIR}...${NC}"

if [ -w "$BIN_DIR" ]; then
  mv "$TMP_DIR/auditstatus" "$BIN_DIR/auditstatus"
else
  echo "Requesting sudo access..."
  sudo mv "$TMP_DIR/auditstatus" "$BIN_DIR/auditstatus"
fi

# Verify installation
echo ""
if command -v auditstatus &> /dev/null; then
  VERSION=$(auditstatus version 2>/dev/null || echo "installed")
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
  echo -e "${GREEN}  Audit Status v${VERSION} installed successfully!${NC}"
  echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
  echo ""
  echo "Usage:"
  echo "  auditstatus check --project-root /srv/myapp"
  echo "  auditstatus audit --config ./auditstatus.config.yml"
  echo "  auditstatus --help"
else
  echo -e "${RED}Warning: auditstatus was installed but is not in PATH${NC}"
  echo "You may need to add ${BIN_DIR} to your PATH"
fi
