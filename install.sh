#!/usr/bin/env bash
# ============================================================
# Reconpipeline Installer
# Made by frozeniceee
# Version: v2.5.1
# ============================================================
set -euo pipefail

RECONPIPELINE_VERSION="v2.5.1"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="reconpipeline"

# ─── Colours ─────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

ok()   { echo -e "  ${GREEN}OK${NC}"; }
fail() { echo -e "  ${RED}FAIL${NC}"; echo -e "${RED}ERROR: $1${NC}" >&2; exit 1; }
warn() { echo -e "  ${YELLOW}WARN${NC}  $1"; }

step() {
    local num="$1"
    local label="$2"
    printf "[%02d] %-32s" "$num" "$label"
}

# ─── Banner ──────────────────────────────────────────────────────────────────
echo ""
echo "Reconpipeline Installer"
echo "Made by frozeniceee"
echo "Version: ${RECONPIPELINE_VERSION}"
echo ""
echo "Checking system..."
echo ""

# ─── [01] Linux environment ──────────────────────────────────────────────────
step 1 "Linux Environment"
if [[ "$(uname -s)" != "Linux" ]]; then
    fail "Reconpipeline requires Linux. Detected: $(uname -s)"
fi
ok

# ─── [02] Architecture ───────────────────────────────────────────────────────
step 2 "Architecture"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  GOARCH="amd64" ;;
    aarch64) GOARCH="arm64" ;;
    armv7l)  GOARCH="arm"   ;;
    *)       fail "Unsupported architecture: $ARCH" ;;
esac
ok

# ─── [03] Go Environment ─────────────────────────────────────────────────────
step 3 "Go Environment"

GO_BIN=""

# Preferred: /usr/local/go/bin/go
if [[ -x "/usr/local/go/bin/go" ]]; then
    GO_BIN="/usr/local/go/bin/go"
else
    # Fallback: PATH-based detection
    if command -v go &>/dev/null; then
        GO_BIN="$(command -v go)"
    fi
fi

if [[ -z "$GO_BIN" ]]; then
    fail "Go is not installed.\n\nInstall Go from https://go.dev/dl/ and retry.\nPreferred location: /usr/local/go/bin/go"
fi
ok

echo ""
echo "  Go:"
echo "  ${GO_BIN}"
echo ""

# ─── [04] Go Compiler ────────────────────────────────────────────────────────
step 4 "Go Compiler"
GO_VERSION_OUTPUT="$("$GO_BIN" version 2>&1)"
if [[ $? -ne 0 ]]; then
    fail "Go binary at ${GO_BIN} is not functional."
fi

# Require at minimum Go 1.21.
GO_MINOR="$(echo "$GO_VERSION_OUTPUT" | grep -oP 'go1\.\K[0-9]+')"
if [[ -z "$GO_MINOR" ]] || [[ "$GO_MINOR" -lt 21 ]]; then
    fail "Go 1.21+ required. Found: $GO_VERSION_OUTPUT"
fi
ok

# ─── [05] Building Reconpipeline ─────────────────────────────────────────────
step 5 "Building Reconpipeline"

# Determine the project root (where install.sh lives).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Download/update module dependencies.
"$GO_BIN" mod download -x &>/dev/null 2>&1 || "$GO_BIN" mod tidy &>/dev/null 2>&1 || true

LDFLAGS="-s -w -X github.com/frozeniceee/Reconpipeline/internal/version.Version=${RECONPIPELINE_VERSION}"

"$GO_BIN" build \
    -ldflags "$LDFLAGS" \
    -o "${SCRIPT_DIR}/reconpipeline" \
    ./cmd/reconpipeline/

if [[ ! -f "${SCRIPT_DIR}/reconpipeline" ]]; then
    fail "Build failed — binary not produced."
fi
ok

# ─── [06] Installing Binary ──────────────────────────────────────────────────
step 6 "Installing Binary"

if [[ ! -d "$INSTALL_DIR" ]]; then
    sudo mkdir -p "$INSTALL_DIR"
fi

if [[ -w "$INSTALL_DIR" ]]; then
    cp "${SCRIPT_DIR}/reconpipeline" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
else
    sudo cp "${SCRIPT_DIR}/reconpipeline" "${INSTALL_DIR}/${BINARY_NAME}"
    sudo chmod 755 "${INSTALL_DIR}/${BINARY_NAME}"
fi
ok

# ─── [07] Creating Workspace ─────────────────────────────────────────────────
step 7 "Creating Workspace"

RUNTIME_DIR="${HOME}/.reconpipeline"
for d in tools versions cache config logs; do
    mkdir -p "${RUNTIME_DIR}/${d}"
done

for tool in subfinder httpx katana gau gf; do
    mkdir -p "${RUNTIME_DIR}/tools/${tool}"
done
ok

# ─── [08] Preparing Dependencies ─────────────────────────────────────────────
step 8 "Preparing Dependencies"
mkdir -p "${HOME}/.gf" "${RUNTIME_DIR}/patterns"
GOBIN="${RUNTIME_DIR}/tools/gf" "$GO_BIN" install github.com/tomnomnom/gf@latest >/dev/null 2>&1 || true

MANIFEST="${RUNTIME_DIR}/versions/manifest.json"
if [[ ! -f "$MANIFEST" ]]; then
    echo '{"tools":{}}' > "$MANIFEST"
fi
ok

# ─── [09] Verifying Installation ─────────────────────────────────────────────
step 9 "Verifying Installation"
INSTALLED_VERSION="$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>&1 | head -1)"
if [[ -z "$INSTALLED_VERSION" ]]; then
    fail "Installed binary did not respond to --version."
fi
ok

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}Reconpipeline ${RECONPIPELINE_VERSION} installed successfully.${NC}"
echo ""
echo "Run:"
echo ""
echo "    reconpipeline example.com"
echo ""

# Remind the user to ensure /usr/local/bin is in PATH if needed.
if ! command -v reconpipeline &>/dev/null; then
    echo -e "${YELLOW}NOTE: ${INSTALL_DIR} may not be in your PATH.${NC}"
    echo "Add the following to your shell profile:"
    echo ""
    echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    echo ""
fi
