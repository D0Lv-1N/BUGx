#!/usr/bin/env bash
#
# BUG-X Comprehensive Setup Installer
#
# Features:
# - Install 25+ bug hunting tools dengan multiple methods
# - Auto-detect existing installations
# - Multi-installation methods: go install, pip, npm, apt, manual
# - Auto-move binaries to PATH for global access
# - --delete flag untuk uninstall everything
# - Installation summary report
# - Support for Linux/macOS/Termux
#
# Usage:
#   ./setup.sh              # Install all tools
#   ./setup.sh --delete     # Remove all installed tools
#   ./setup.sh --check      # Check installation status
#

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# ========= Colors =========
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
MAGENTA='\033[35m'
CYAN='\033[36m'
NC='\033[0m' # No Color

# ========= Logging Functions =========
log_info()  { printf "${BLUE}[INFO]${NC} %s\n" "$*"; }
log_warn()  { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$*"; }
log_ok()    { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
log_step()  { printf "${MAGENTA}[STEP]${NC} %s\n" "$*"; }

# ========= Global Variables =========
INSTALL_DIR="/usr/local/bin"
HOME_BIN="$HOME/.local/bin"
TEMP_DIR="/tmp/bugx_setup_$$"
INSTALL_LOG="$TEMP_DIR/install.log"
INSTALLED_TOOLS=()
FAILED_TOOLS=()
SKIPPED_TOOLS=()

# ========= OS Detection =========
detect_os() {
    if [ -n "${PREFIX-}" ] && echo "$PREFIX" | grep -qi "com.termux"; then
        echo "termux"
        return
    fi

    local os
    os="$(uname -s 2>/dev/null || echo "")"
    case "$os" in
        Linux*) echo "linux" ;;
        Darwin*) echo "darwin" ;;
        *) echo "unknown" ;;
    esac
}

OS_TYPE="$(detect_os)"

# ========= Installation Directory Detection =========
detect_install_dir() {
    # Check if we can write to /usr/local/bin
    if [ -w "/usr/local/bin" ] || sudo [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
        return
    fi

    # Fallback to user local bin
    if [ -w "$HOME_BIN" ] || mkdir -p "$HOME_BIN" 2>/dev/null; then
        echo "$HOME_BIN"
        return
    fi

    # Last resort: current directory
    echo "$PROJECT_ROOT/bin"
}

INSTALL_DIR="$(detect_install_dir)"

# ========= Tool Definitions =========
# Format: name|method|package|install_cmd|description
TOOLS_LIST=$(cat <<'EOF'
# STAGE 1: SUBDOMAIN DISCOVERY
subfinder|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|go install -v|Subdomain enumeration
amass|go|github.com/owasp-amass/amass/v4/...@master|go install -v|Advanced subdomain discovery
assetfinder|go|github.com/tomnomnom/assetfinder@latest|go install -v|Finding related domains
findomain|manual|https://github.com/findomain/findomain/releases|download_bin|Fast subdomain finder
shuffledns|go|github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest|go install -v|Fast DNS resolver

# STAGE 2: HTTP PROBING & HOST DISCOVERY
httpx|go|github.com/projectdiscovery/httpx/cmd/httpx@latest|go install -v|Fast HTTP probe & tech detection
naabu|go|github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|go install -v|Fast port scanner
nuclei|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|go install -v|Vulnerability scanner
wappalyzer|npm|wappalyzer-cli|wget -qO-|Technology fingerprinting

# STAGE 3: URL DISCOVERY
gau|go|github.com/lc/gau/v2/cmd/gau@latest|go install -v|URL extraction dari multiple sources
waybackurls|go|github.com/tomnomnom/waybackurls@latest|go install -v|URLs dari wayback machine
katana|go|github.com/projectdiscovery/katana/cmd/katana@latest|go install -v|Fast web crawler
gospider|go|github.com/jaeles-project/gospider@latest|go install -v|Fast web spider

# STAGE 4: PARAMETER & ENDPOINT ANALYSIS
gf|go|github.com/tomnomnom/gf@latest|go install -v|Pattern matching for URLs
paramspider|pip|paramspider|pip3 install|Parameter discovery dari URLs
arjun|pip|arjun|pip3 install|Parameter detection & analysis
qsreplace|go|github.com/tomnomnom/qsreplace@latest|go install -v|Parameter manipulation tool
unfurl|go|github.com/tomnomnom/unfurl@latest|go install -v|Extract parameters from URLs
kxss|go|github.com/Emoe/kxss@latest|go install -v|XSS parameter finder

# UTILITY & HELPER TOOLS
anew|go|github.com/tomnomnom/anew@latest|go install -v|Add new lines ignoring duplicates
notify|go|github.com/projectdiscovery/notify/cmd/notify@latest|go install -v|Send notifications
interactsh|go|github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|go install -v|OOB interaction checking

# MANUAL TOOLS (Require manual installation)
sqlmap|python|sqlmap|pip3 install sqlmap|SQL injection testing (may need manual setup)
dirsearch|python|dirsearch|git clone|Web path scanner
gobuster|apt|gobuster|apt-get install -y|Directory/file brute forcing
nikto|apt|nikto|apt-get install -y|Web vulnerability scanner
hydra|apt|hydra|apt-get install -y|Brute force attacks
massdns|go|github.com/blechschmidt/massdns@latest|go install -v|High-performance DNS resolver
commix|python|commix|pip3 install commix|Command injection testing
dalfox|go|github.com/hahwul/dalfox/v2@latest|go install -v|Fast XSS scanner
ffuf|go|github.com/ffuf/ffuf@latest|go install -v|Fast web fuzzer
whatweb|apt|whatweb|apt-get install -y|Web application technology identification
dnsx|go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest|go install -v|DNS toolkit
EOF
)

# ========= Utility Functions =========

create_temp_dir() {
    mkdir -p "$TEMP_DIR"
    touch "$INSTALL_LOG"
}

cleanup_temp_dir() {
    rm -rf "$TEMP_DIR"
}

# Check if tool exists in PATH
tool_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check if tool exists in our install directory
tool_installed_here() {
    [ -x "$INSTALL_DIR/$1" ]
}

# Add tool to appropriate array
mark_tool_installed() {
    INSTALLED_TOOLS+=("$1")
    log_ok "✓ $1"
}

mark_tool_failed() {
    FAILED_TOOLS+=("$1")
    log_error "✗ $1"
}

mark_tool_skipped() {
    SKIPPED_TOOLS+=("$1")
    log_info "⊘ $1 (already installed)"
}

# ========= Installation Methods =========

install_go_tool() {
    local name="$1"
    local pkg="$2"
    local description="$3"

    log_step "Installing $name via go install..."

    if ! go install -v "$pkg" 2>&1 | tee -a "$INSTALL_LOG"; then
        log_error "Failed to go install $name"
        return 1
    fi

    # Find the binary
    local gopath gobin binary_path=""
    gobin="$(go env GOBIN 2>/dev/null || echo "")"
    gopath="$(go env GOPATH 2>/dev/null || echo "$HOME/go")"

    if [ -n "$gobin" ] && [ -x "$gobin/$name" ]; then
        binary_path="$gobin/$name"
    elif [ -f "$gopath/bin/$name" ]; then
        binary_path="$gopath/bin/$name"
    else
        log_error "Could not find installed binary for $name"
        return 1
    fi

    # Move to install directory
    mkdir -p "$INSTALL_DIR"
    if [ "$INSTALL_DIR" != "$(dirname "$binary_path")" ]; then
        if sudo cp "$binary_path" "$INSTALL_DIR/$name" 2>/dev/null || cp "$binary_path" "$INSTALL_DIR/$name"; then
            chmod +x "$INSTALL_DIR/$name" 2>/dev/null || true
        else
            log_error "Failed to copy $name to $INSTALL_DIR"
            return 1
        fi
    fi

    return 0
}

install_pip_tool() {
    local name="$1"
    local package="$2"
    local description="$3"

    log_step "Installing $name via pip..."

    if ! python3 -m pip install --user "$package" 2>&1 | tee -a "$INSTALL_LOG"; then
        log_error "Failed to pip install $name"
        return 1
    fi

    return 0
}

install_npm_tool() {
    local name="$1"
    local package="$2"
    local description="$3"

    log_step "Installing $name via npm..."

    if ! npm install -g "$package" 2>&1 | tee -a "$INSTALL_LOG"; then
        log_error "Failed to npm install $name"
        return 1
    fi

    return 0
}

install_apt_tool() {
    local name="$1"
    local package="$2"
    local description="$3"

    log_step "Installing $name via apt..."

    if ! sudo apt-get update && sudo apt-get install -y "$package" 2>&1 | tee -a "$INSTALL_LOG"; then
        log_error "Failed to apt install $name"
        return 1
    fi

    return 0
}

install_manual_tool() {
    local name="$1"
    local url="$2"
    local description="$3"

    log_warn "Manual installation required for $name"
    log_info "Please install $name manually:"
    log_info "  Website: $url"
    log_info "  Description: $description"

    return 1
}

download_binary_tool() {
    local name="$1"
    local url="$2"
    local description="$3"

    log_step "Downloading $name binary..."

    mkdir -p "$INSTALL_DIR"
    local binary_path="$INSTALL_DIR/$name"

    if wget -q "$url" -O "$binary_path" 2>&1 | tee -a "$INSTALL_LOG"; then
        chmod +x "$binary_path"
        return 0
    else
        log_error "Failed to download $name"
        return 1
    fi
}

git_clone_tool() {
    local name="$1"
    local url="$2"
    local description="$3"

    log_step "Cloning $name repository..."

    local temp_dir="$TEMP_DIR/$name"
    if git clone "$url" "$temp_dir" 2>&1 | tee -a "$INSTALL_LOG"; then
        # Look for install script or build manually
        if [ -f "$temp_dir/setup.py" ]; then
            cd "$temp_dir" && python3 setup.py install --user 2>&1 | tee -a "$INSTALL_LOG"
        elif [ -f "$temp_dir/install.sh" ]; then
            cd "$temp_dir" && bash install.sh 2>&1 | tee -a "$INSTALL_LOG"
        else
            log_error "No install method found for $name"
            return 1
        fi
        return 0
    else
        log_error "Failed to clone $name"
        return 1
    fi
}

# ========= Tool Installation Handler =========

install_single_tool() {
    local name="$1"
    local method="$2"
    local package="$3"
    local cmd="$4"
    local description="$5"

    # Check if already installed
    if tool_exists "$name" || tool_installed_here "$name"; then
        mark_tool_skipped "$name"
        return 0
    fi

    log_info "Installing $name ($description)..."

    case "$method" in
        "go")
            if install_go_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        "pip")
            if install_pip_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        "npm")
            if install_npm_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        "apt")
            if install_apt_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        "manual")
            install_manual_tool "$name" "$package" "$description"
            mark_tool_failed "$name"
            ;;
        "download")
            if download_binary_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        "git")
            if git_clone_tool "$name" "$package" "$description"; then
                mark_tool_installed "$name"
            else
                mark_tool_failed "$name"
            fi
            ;;
        *)
            log_error "Unknown installation method: $method"
            mark_tool_failed "$name"
            ;;
    esac
}

# ========= Delete Mode =========

delete_installed_tools() {
    log_warn "Mode --delete: Removing all installed tools by BUGx setup"

    # Remove all tools from install directory
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing tools from $INSTALL_DIR"
        while IFS='|' read -r name method package cmd description; do
            [ -z "$name" ] || [[ "$name" =~ ^#.* ]] && continue

            if [ -f "$INSTALL_DIR/$name" ]; then
                if sudo rm -f "$INSTALL_DIR/$name" 2>/dev/null || rm -f "$INSTALL_DIR/$name"; then
                    log_ok "Removed $INSTALL_DIR/$name"
                else
                    log_error "Failed to remove $INSTALL_DIR/$name"
                fi
            fi
        done <<< "$TOOLS_LIST"
    fi

    # Remove pip packages
    log_info "Removing Python packages..."
    while IFS='|' read -r name method package cmd description; do
        [ -z "$name" ] || [[ "$name" =~ ^#.* ]] && continue

        if [ "$method" = "pip" ]; then
            if python3 -m pip uninstall -y "$package" 2>/dev/null; then
                log_ok "Uninstalled Python package: $package"
            fi
        fi
    done <<< "$TOOLS_LIST"

    # Remove npm packages
    log_info "Removing Node.js packages..."
    while IFS='|' read -r name method package cmd description; do
        [ -z "$name" ] || [[ "$name" =~ ^#.* ]] && continue

        if [ "$method" = "npm" ]; then
            if npm uninstall -g "$package" 2>/dev/null; then
                log_ok "Uninstalled npm package: $package"
            fi
        fi
    done <<< "$TOOLS_LIST"

    # Remove temporary files
    cleanup_temp_dir

    log_ok "Cleanup completed!"
    exit 0
}

# ========= Check Mode =========

check_installation_status() {
    log_info "Checking installation status..."

    echo
    echo "=================================================="
    echo "           INSTALLATION STATUS"
    echo "=================================================="

    while IFS='|' read -r name method package cmd description; do
        [ -z "$name" ] || [[ "$name" =~ ^#.* ]] && continue

        if tool_exists "$name" || tool_installed_here "$name"; then
            printf "${GREEN}✓${NC} %-15s %s\n" "$name" "($description)"
        else
            printf "${RED}✗${NC} %-15s %s\n" "$name" "($description)"
        fi
    done <<< "$TOOLS_LIST"

    echo "=================================================="
}

# ========= Main Installation =========

main_install() {
    create_temp_dir

    log_info "Starting BUGx Comprehensive Setup"
    log_info "OS Type: $OS_TYPE"
    log_info "Install Directory: $INSTALL_DIR"
    log_info "Log File: $INSTALL_LOG"

    # Ensure required tools are available
    if ! command -v go >/dev/null 2>&1; then
        log_error "Go is required but not installed!"
        log_info "Please install Go from: https://golang.org/dl/"
        exit 1
    fi

    if ! command -v git >/dev/null 2>&1; then
        log_error "Git is required but not installed!"
        exit 1
    fi

    log_info "Required tools (go, git) are available"

    # Create install directory
    mkdir -p "$INSTALL_DIR"

    log_info "Installing tools..."
    echo

    # Install each tool
    while IFS='|' read -r name method package cmd description; do
        [ -z "$name" ] || [[ "$name" =~ ^#.* ]] && continue

        install_single_tool "$name" "$method" "$package" "$cmd" "$description"
        echo
    done <<< "$TOOLS_LIST"

    # Setup additional configurations
    setup_gau_config
    setup_gf_patterns

    # Print summary
    print_summary

    cleanup_temp_dir
}

# ========= Additional Setup =========

setup_gau_config() {
    local gau_config="$HOME/.gau.toml"

    if [ ! -f "$gau_config" ]; then
        log_info "Setting up gau configuration..."
        cat > "$gau_config" <<'EOF'
threads = 25
verbose = false
retries = 15
subdomains = false
parameters = false
providers = ["wayback","commoncrawl","otx","urlscan"]
blacklist = ["ttf","woff","svg","png","jpg"]
json = false

[urlscan]
  apikey = ""

[filters]
  from = ""
  to = ""
  matchstatuscodes = []
  matchmimetypes = []
  filterstatuscodes = []
  filtermimetypes = ["image/png", "image/jpg", "image/svg+xml"]
EOF
        log_ok "Gau configuration created"
    fi
}

setup_gf_patterns() {
    local gf_dir="$HOME/.gf"
    local patterns_dir="$HOME/Gf-Patterns"

    if [ ! -d "$gf_dir" ]; then
        mkdir -p "$gf_dir"
    fi

    if [ ! -d "$patterns_dir" ]; then
        log_info "Cloning GF patterns..."
        if git clone https://github.com/1ndianl33t/Gf-Patterns.git "$patterns_dir" 2>/dev/null; then
            log_ok "GF patterns cloned"
        else
            log_warn "Failed to clone GF patterns"
        fi
    fi

    if [ -d "$patterns_dir" ] && ls "$patterns_dir"/*.json >/dev/null 2>&1; then
        cp "$patterns_dir"/*.json "$gf_dir"/ 2>/dev/null || true
        log_ok "GF patterns copied to $gf_dir"
    fi
}

# ========= Summary =========

print_summary() {
    echo
    echo "=================================================="
    echo "                INSTALLATION SUMMARY"
    echo "=================================================="

    if [ ${#INSTALLED_TOOLS[@]} -gt 0 ]; then
        echo
        echo "Successfully Installed (${#INSTALLED_TOOLS[@]}):"
        for tool in "${INSTALLED_TOOLS[@]}"; do
            echo "  ✓ $tool"
        done
    fi

    if [ ${#SKIPPED_TOOLS[@]} -gt 0 ]; then
        echo
        echo "Already Installed (${#SKIPPED_TOOLS[@]}):"
        for tool in "${SKIPPED_TOOLS[@]}"; do
            echo "  ⊘ $tool"
        done
    fi

    if [ ${#FAILED_TOOLS[@]} -gt 0 ]; then
        echo
        echo "Failed/Manual Installation Required (${#FAILED_TOOLS[@]}):"
        for tool in "${FAILED_TOOLS[@]}"; do
            echo "  ✗ $tool"
        done
    fi

    echo
    echo "Installation Directory: $INSTALL_DIR"
    echo "Installation Log: $INSTALL_LOG"
    echo

    # PATH check
    if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
        log_warn "Install directory not in PATH. Add this to your shell profile:"
        echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    else
        log_ok "Install directory is in PATH"
    fi

    # Tool count summary
    local total=${#INSTALLED_TOOLS[@]}
    total=$((total + ${#SKIPPED_TOOLS[@]}))
    local success_rate=$(( (${#INSTALLED_TOOLS[@]} * 100) / total ))

    echo
    echo "Success Rate: $success_rate% (${#INSTALLED_TOOLS[@]}/$total tools ready to use)"
    echo "=================================================="
}

# ========= Entry Point =========

case "${1:-}" in
    --delete)
        delete_installed_tools
        ;;
    --check)
        check_installation_status
        ;;
    "")
        main_install
        ;;
    *)
        echo "Usage: $0 [OPTIONS]"
        echo
        echo "Options:"
        echo "  (no args)    Install all tools"
        echo "  --delete     Remove all installed tools"
        echo "  --check      Check installation status"
        echo
        echo "This script installs 25+ bug hunting tools using multiple methods."
        exit 1
        ;;
esac
