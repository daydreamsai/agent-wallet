#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo "==> case: macOS setup fallback creates layout"
(
  case_dir="${TMP_DIR}/mac-fallback"
  install_dir="${case_dir}/bin"
  saw_root="${case_dir}/root"
  mkdir -p "${install_dir}"

  export SAW_INSTALL_SH_NO_RUN=1
  export SAW_INSTALL="${install_dir}"
  export SAW_ROOT="${saw_root}"
  # shellcheck source=../install.sh
  source "${ROOT_DIR}/install.sh"

  OS_NAME="macos"
  cat > "${install_dir}/saw" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
echo "adduser: command not found" >&2
exit 1
EOF
  chmod +x "${install_dir}/saw"

  setup

  [[ -d "${saw_root}/keys" ]] || fail "expected keys directory to be created"
  [[ -f "${saw_root}/policy.yaml" ]] || fail "expected policy.yaml to be created"
  [[ -f "${saw_root}/audit.log" ]] || fail "expected audit.log to be created"
)

echo "==> case: macOS setup fallback is idempotent"
(
  case_dir="${TMP_DIR}/mac-rerun"
  install_dir="${case_dir}/bin"
  saw_root="${case_dir}/root"
  mkdir -p "${install_dir}"

  export SAW_INSTALL_SH_NO_RUN=1
  export SAW_INSTALL="${install_dir}"
  export SAW_ROOT="${saw_root}"
  # shellcheck source=../install.sh
  source "${ROOT_DIR}/install.sh"

  OS_NAME="macos"
  cat > "${install_dir}/saw" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 1
EOF
  chmod +x "${install_dir}/saw"

  setup
  setup

  grep -q "^wallets:" "${saw_root}/policy.yaml" || fail "expected policy.yaml skeleton"
)

echo "==> case: linux setup failure without existing root returns non-zero"
if (
  case_dir="${TMP_DIR}/linux-fail"
  install_dir="${case_dir}/bin"
  saw_root="${case_dir}/root"
  mkdir -p "${install_dir}"

  export SAW_INSTALL_SH_NO_RUN=1
  export SAW_INSTALL="${install_dir}"
  export SAW_ROOT="${saw_root}"
  # shellcheck source=../install.sh
  source "${ROOT_DIR}/install.sh"

  OS_NAME="linux"
  cat > "${install_dir}/saw" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exit 1
EOF
  chmod +x "${install_dir}/saw"

  setup
); then
  fail "expected linux setup failure to exit non-zero"
fi

echo "OK"
