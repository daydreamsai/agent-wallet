#!/bin/sh
# install.sh — one-liner installer for Secure Agent Wallet (SAW)
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/daydreamsai/agent-wallet/master/install.sh | sh
#
# Options (via environment variables):
#   SAW_VERSION   - specific version to install (e.g. "0.1.0"), default: latest
#   SAW_INSTALL   - install directory, default: ~/.saw/bin
#   SAW_ROOT      - data directory, default: ~/.saw

set -eu

REPO="daydreamsai/agent-wallet"
INSTALL_DIR="${SAW_INSTALL:-$HOME/.saw/bin}"
SAW_ROOT="${SAW_ROOT:-$HOME/.saw}"

# --- helpers ---------------------------------------------------------------

info()  { printf '  \033[1;34m>\033[0m %s\n' "$*"; }
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$*"; }
err()   { printf '  \033[1;31m✗\033[0m %s\n' "$*" >&2; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

need() {
  if ! command -v "$1" > /dev/null 2>&1; then
    err "Required tool '$1' not found. Please install it and retry."
    exit 1
  fi
}

# --- detect platform -------------------------------------------------------

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  OS_NAME="linux" ;;
    Darwin) OS_NAME="macos" ;;
    *)
      err "Unsupported OS: $OS (SAW requires Linux or macOS)"
      exit 1
      ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    arm64|aarch64)   ARCH="arm64"  ;;
    *)
      err "Unsupported architecture: $ARCH"
      exit 1
      ;;
  esac

  ARCHIVE="saw-${OS_NAME}-${ARCH}.tar.gz"
}

# --- resolve version -------------------------------------------------------

resolve_version() {
  if [ -n "${SAW_VERSION:-}" ]; then
    VERSION="$SAW_VERSION"
    info "Using requested version: v${VERSION}"
  else
    info "Fetching latest release..."
    VERSION=$(curl -sSL -H "Accept: application/json" \
      "https://api.github.com/repos/${REPO}/releases/latest" \
      | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\([^"]*\)".*/\1/p')

    if [ -z "$VERSION" ]; then
      err "Could not determine latest version."
      err "Set SAW_VERSION explicitly, e.g.:"
      err "  SAW_VERSION=0.1.0 curl -sSL ... | sh"
      exit 1
    fi
    info "Latest version: v${VERSION}"
  fi

  DOWNLOAD_URL="https://github.com/${REPO}/releases/download/v${VERSION}/${ARCHIVE}"
}

# --- download & install ----------------------------------------------------

download_and_install() {
  TMPDIR="$(mktemp -d)"
  trap 'rm -rf "$TMPDIR"' EXIT

  info "Downloading ${ARCHIVE}..."
  HTTP_CODE=$(curl -sSL -w '%{http_code}' -o "${TMPDIR}/${ARCHIVE}" "$DOWNLOAD_URL")

  if [ "$HTTP_CODE" != "200" ]; then
    err "Download failed (HTTP ${HTTP_CODE})"
    err "URL: ${DOWNLOAD_URL}"
    err ""
    err "If this is the first release, you may need to publish one first:"
    err "  git tag v0.1.0 && git push origin v0.1.0"
    exit 1
  fi

  info "Extracting..."
  tar xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"

  mkdir -p "$INSTALL_DIR"
  cp "${TMPDIR}/saw"        "$INSTALL_DIR/saw"
  cp "${TMPDIR}/saw-daemon"  "$INSTALL_DIR/saw-daemon"
  chmod +x "$INSTALL_DIR/saw" "$INSTALL_DIR/saw-daemon"

  ok "Installed saw and saw-daemon to ${INSTALL_DIR}"
}

# --- post-install setup ----------------------------------------------------

setup() {
  # Run saw install to create directory layout.
  # Older SAW builds can fail on macOS due to Linux-specific setup internals.
  if "${INSTALL_DIR}/saw" install --root "$SAW_ROOT" >/dev/null 2>&1; then
    ok "Initialized data directory at ${SAW_ROOT}"
    return
  fi

  if [ "${OS_NAME:-}" = "macos" ]; then
    info "SAW install fallback: creating data directory layout directly for macOS"
    mkdir -p "$SAW_ROOT" "$SAW_ROOT/keys"
    chmod 700 "$SAW_ROOT/keys" 2>/dev/null || true

    if [ ! -f "$SAW_ROOT/policy.yaml" ]; then
      printf 'wallets:\n' > "$SAW_ROOT/policy.yaml"
    fi
    if [ ! -f "$SAW_ROOT/audit.log" ]; then
      : > "$SAW_ROOT/audit.log"
    fi
    chmod 640 "$SAW_ROOT/policy.yaml" "$SAW_ROOT/audit.log" 2>/dev/null || true

    ok "Initialized data directory at ${SAW_ROOT}"
    return
  fi

  if [ -d "$SAW_ROOT" ]; then
    info "Data directory already exists at ${SAW_ROOT}"
    return
  fi

  err "Failed to initialize SAW data directory at ${SAW_ROOT}"
  exit 1
}

# --- PATH advice -----------------------------------------------------------

ensure_path() {
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) return ;;
  esac

  bold ""
  bold "Add SAW to your PATH:"
  echo ""

  SHELL_NAME="$(basename "${SHELL:-/bin/sh}")"
  case "$SHELL_NAME" in
    zsh)  RC_FILE="~/.zshrc" ;;
    bash) RC_FILE="~/.bashrc" ;;
    fish) RC_FILE="~/.config/fish/config.fish" ;;
    *)    RC_FILE="your shell's rc file" ;;
  esac

  if [ "$SHELL_NAME" = "fish" ]; then
    echo "  fish_add_path ${INSTALL_DIR}"
  else
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
  fi
  echo ""
  echo "  Add that line to ${RC_FILE} to make it permanent."
}

# --- main ------------------------------------------------------------------

main() {
  bold ""
  bold "  Secure Agent Wallet (SAW) Installer"
  bold ""

  need curl
  need tar

  detect_platform
  info "Platform: ${OS_NAME}/${ARCH}"

  resolve_version
  download_and_install
  setup

  bold ""
  bold "  Next steps:"
  echo ""
  echo "  1. Generate a wallet:"
  echo "     saw gen-key --chain evm --wallet main"
  echo ""
  echo "  2. Edit your policy:"
  echo "     \$EDITOR ~/.saw/policy.yaml"
  echo ""
  echo "  3. Start the daemon:"
  echo "     saw-daemon"
  echo ""

  ensure_path

  bold "  Docs: https://github.com/${REPO}"
  bold ""
}

if [ "${SAW_INSTALL_SH_NO_RUN:-0}" != "1" ]; then
  main
fi
