#!/usr/bin/env bash
#
# Audit Status installer
#
#   curl -fsSL https://github.com/auditstatus/auditstatus.com/releases/latest/download/install.sh | bash
#
# Environment:
#   AUDITSTATUS_VERSION   release to install, e.g. 2.0.0 (default: latest)
#   AUDITSTATUS_BIN_DIR   install directory (default: /usr/local/bin)
#
# The binary is checked against the release's SHA256SUMS before it is
# installed.  For servers, prefer pinning a version and its checksum in your
# configuration management instead of running this script.

set -euo pipefail

# Everything runs from main, called on the last line: a download cut short
# runs nothing.
main() {
  REPO="https://github.com/auditstatus/auditstatus.com"
  BIN_DIR="${AUDITSTATUS_BIN_DIR:-/usr/local/bin}"

  case "$(uname -s)" in
    Linux) PLATFORM=linux ;;
    Darwin) PLATFORM=darwin ;;
    *) echo "Unsupported operating system: $(uname -s)" >&2; exit 1 ;;
  esac

  case "$(uname -m)" in
    x86_64 | amd64) ARCH=x64 ;;
    aarch64 | arm64) ARCH=arm64 ;;
    *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
  esac

  ARTIFACT="auditstatus-${PLATFORM}-${ARCH}"
  if [ -n "${AUDITSTATUS_VERSION:-}" ]; then
    VERSION="${AUDITSTATUS_VERSION#v}"
    # A version is part of the download URL: nothing but a release number
    # (a "/" or ".." would reach another path, or another repository).
    if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]]; then
      echo "Invalid AUDITSTATUS_VERSION: $AUDITSTATUS_VERSION" >&2
      exit 1
    fi
    BASE="${REPO}/releases/download/v${VERSION}"
  else
    BASE="${REPO}/releases/latest/download"
  fi

  TMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_DIR"' EXIT

  download() {
    if command -v curl > /dev/null; then
      curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"
    elif command -v wget > /dev/null; then
      wget -q --https-only "$1" -O "$2"
    else
      echo "curl or wget is required" >&2
      exit 1
    fi
  }

  echo "Downloading ${ARTIFACT}..."
  download "${BASE}/${ARTIFACT}" "${TMP_DIR}/${ARTIFACT}"
  download "${BASE}/SHA256SUMS" "${TMP_DIR}/SHA256SUMS"

  EXPECTED="$(awk -v name="$ARTIFACT" '$2 == name || $2 == "*" name { print $1 }' "${TMP_DIR}/SHA256SUMS")"
  if command -v sha256sum > /dev/null; then
    ACTUAL="$(sha256sum "${TMP_DIR}/${ARTIFACT}" | awk '{ print $1 }')"
  else
    ACTUAL="$(shasum -a 256 "${TMP_DIR}/${ARTIFACT}" | awk '{ print $1 }')"
  fi

  if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
    echo "Checksum mismatch for ${ARTIFACT}; not installing." >&2
    exit 1
  fi

  chmod 0755 "${TMP_DIR}/${ARTIFACT}"
  if [ -w "$BIN_DIR" ]; then
    mv "${TMP_DIR}/${ARTIFACT}" "${BIN_DIR}/auditstatus"
  else
    sudo install -m 0755 "${TMP_DIR}/${ARTIFACT}" "${BIN_DIR}/auditstatus"
  fi

  echo "Installed $("${BIN_DIR}/auditstatus" version) to ${BIN_DIR}/auditstatus (sha256 ${ACTUAL})"
  echo "Verify its provenance with: gh attestation verify ${BIN_DIR}/auditstatus --repo auditstatus/auditstatus.com"
}

main "$@"
