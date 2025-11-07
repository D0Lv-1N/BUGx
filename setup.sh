#!/usr/bin/env bash
#
# BUG-X setup.sh
#
# Fungsi:
# - Auto detect OS (Linux/macOS/Termux basic).
# - Deteksi & install tools eksternal yang dibutuhkan BUG-X (20 tools utama).
# - Hanya gunakan Go (go install) untuk install tools Go-based.
# - Jika binary sudah ada di PATH, skip.
# - Jika binary ada di GOPATH/bin tapi tidak di PATH, salin ke INSTALL_DIR.
# - Jika belum ada, coba install. Kalau gagal → STOP dan jelaskan.
# - Flag: ./setup.sh --delete
#   - Menghapus semua binary yang pernah dipasang oleh setup.sh dari INSTALL_DIR.
#   - Tidak menghapus:
#       - setup.sh
#       - Go & environment asli user
# - Jika Go tidak ada → STOP dengan pesan:
#     "silahkan install golang terlebih dahulu (https://go.dev/doc/install)"
#
# Catatan:
# - Script ini TIDAK membuat wordlists lokal dan tidak utak-atik sistem di luar scope.
# - INSTALL_DIR utama:
#     - $HOME/.local/bin (tanpa sudo)
#     - /usr/local/bin (jika bisa tulis)
# - Tools yang dikelola (core set):
#     - subfinder
#     - httpx
#     - gau
#     - waybackurls
#     - gf
#     - dalfox
#     - nuclei
#     - sqlmap         (manual)
#     - ffuf
#     - dirsearch      (manual)
#     - gobuster       (manual)
#     - feroxbuster    (manual)
#     - wpscan         (manual)
#     - whatweb        (manual)
#     - wappalyzer-cli (manual)
#     - oralyzer       (manual)
#     - massdns        (manual)
#     - dnsx
#     - amass
#     - assetfinder
#     - findomain      (manual)
#
# Rujukan:
# - Wordlists: https://github.com/D0Lv-1N/wordlist.git
# - GF patterns: https://github.com/1ndianl33t/Gf-Patterns
#
# Pada akhir setup:
# - Cetak tools yang terinstall & yang belum.
# - Cetak config default gau (~/.gau.toml) bila belum ada.
#

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"

# ========= Warna =========
RED="$(printf '\033[31m')"
GREEN="$(printf '\033[32m')"
YELLOW="$(printf '\033[33m')"
BLUE="$(printf '\033[34m')"
MAGENTA="$(printf '\033[35m')"
CYAN="$(printf '\033[36m')"
RESET="$(printf '\033[0m')"

log_info()  { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
log_warn()  { printf "${YELLOW}[WARN]${RESET} %s\n" "$*"; }
log_error() { printf "${RED}[ERROR]${RESET} %s\n" "$*"; }
log_ok()    { printf "${GREEN}[OK]${RESET} %s\n" "$*"; }

# ========= OS Detection =========

detect_os() {
  if [ -n "${PREFIX-}" ] && echo "$PREFIX" | grep -qi "com.termux"; then
    echo "termux"
    return
  fi

  local u
  u="$(uname -s 2>/dev/null || echo "")"
  case "$u" in
    Linux*) echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *) echo "unknown" ;;
  esac
}

OS_TYPE="$(detect_os)"

# ========= Go Detection & Version Check =========

ensure_go() {
  if ! command -v go >/dev/null 2>&1; then
    log_error "Go tidak ditemukan di PATH."
    printf "%s\n" "silahkan install golang terlebih dahulu (https://go.dev/doc/install)"
    exit 1
  fi

  local gov
  gov="$(go version 2>/dev/null || true)"
  if [ -z "$gov" ]; then
    log_error "Gagal membaca versi Go."
    printf "%s\n" "silahkan install golang terlebih dahulu (https://go.dev/doc/install)"
    exit 1
  fi

  log_ok "Go terdeteksi: $gov"
}

# ========= Install Target Detection =========

detect_install_dir() {
  # Semua tools hasil setup akan dipusatkan ke satu direktori global:
  #   /usr/local/bin
  # Script ini boleh dijalankan dengan:
  #   ./setup.sh
  # dan akan menggunakan sudo mv bila butuh hak akses lebih.
  echo "/usr/local/bin"
}

INSTALL_DIR="$(detect_install_dir)"

log_info "Direktori install default: $INSTALL_DIR"

# ========= Tool List =========
# Format: name|type|go_pkg
# type:
#   go      -> install dengan go install
#   manual  -> hanya cek, user install manual
TOOLS_DEFS="$(cat <<'EOF'
subfinder|go|github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
httpx|go|github.com/projectdiscovery/httpx/cmd/httpx@latest
gau|go|github.com/lc/gau/v2/cmd/gau@latest
waybackurls|go|github.com/tomnomnom/waybackurls@latest
gf|go|github.com/tomnomnom/gf@latest
dalfox|go|github.com/hahwul/dalfox/v2@latest
nuclei|go|github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ffuf|go|github.com/ffuf/ffuf@latest
dnsx|go|github.com/projectdiscovery/dnsx/cmd/dnsx@latest
amass|go|github.com/owasp-amass/amass/v4/...@latest
assetfinder|go|github.com/tomnomnom/assetfinder@latest
sqlmap|manual|
dirsearch|manual|
gobuster|manual|
feroxbuster|manual|
wpscan|manual|
whatweb|manual|
massdns|manual|
findomain|manual|
EOF
)"

# ========= Helpers =========

tool_exists_in_path() {
  command -v "$1" >/dev/null 2>&1
}

tool_exists_in_dir() {
  [ -x "$2/$1" ]
}

copy_if_needed() {
  # $1 = src, $2 = dest_dir, $3 = name
  local src="$1"
  local dest_dir="$2"
  local name="$3"

  if [ ! -e "$src" ]; then
    return 1
  fi

  mkdir -p "$dest_dir"

  # Jika sudah ada di dest dengan path benar, tidak perlu apa-apa
  if [ -x "$dest_dir/$name" ]; then
    log_ok "$name sudah ada di $dest_dir, skip move."
    return 0
  fi

  # Pindahkan dengan sudo mv agar konsisten di satu direktori
  if sudo mv "$src" "$dest_dir/$name"; then
    sudo chmod +x "$dest_dir/$name" || true
    log_ok "Moved $name -> $dest_dir/$name"
    return 0
  fi

  log_error "Gagal memindahkan $name dari $src ke $dest_dir/$name"
  return 1
}

install_go_tool() {
  local name="$1"
  local pkg="$2"

  log_info "Menginstall $name via go install ($pkg)..."

  if ! go install "$pkg"; then
    log_error "Gagal go install $pkg untuk $name."
    log_error "Silakan periksa koneksi, GOPATH/GOBIN, atau install manual."
    exit 1
  fi

  local gopath gobin candidate=""
  gopath="$(go env GOPATH 2>/dev/null || echo "")"
  gobin="$(go env GOBIN 2>/dev/null || echo "")"

  if [ -n "$gobin" ] && [ -x "$gobin/$name" ]; then
    candidate="$gobin/$name"
  elif [ -n "$gopath" ] && [ -x "$gopath/bin/$name" ]; then
    candidate="$gopath/bin/$name"
  fi

  if [ -z "$candidate" ]; then
    log_error "go install sukses tapi binary $name tidak ditemukan."
    log_error "Cek GOPATH/GOBIN Anda. Setup dihentikan."
    exit 1
  fi

  if ! copy_if_needed "$candidate" "$INSTALL_DIR" "$name"; then
    log_error "Gagal menyalin $name ke $INSTALL_DIR. Tambahkan $candidate ke PATH Anda."
    exit 1
  fi

  log_ok "$name terinstall di $INSTALL_DIR"
}

# ========= Delete Mode =========

delete_installed() {
  log_info "Mode --delete: menghapus tools yang dikelola setup.sh dari /usr/local/bin"
  log_info "Serta menghapus aset tambahan (wordlist & GF patterns) yang dipasang oleh setup.sh"

  echo "$TOOLS_DEFS" | while IFS='|' read -r name t pkg; do
    name="$(printf "%s" "$name" | sed 's/#.*$//')"
    [ -z "$name" ] && continue

    if [ -x "/usr/local/bin/$name" ]; then
      if sudo rm -f "/usr/local/bin/$name"; then
        log_ok "Deleted /usr/local/bin/$name"
      else
        log_error "Gagal menghapus /usr/local/bin/$name"
        exit 1
      fi
    fi
  done

  # Hapus clone wordlist jika dibuat oleh setup (lokasi standar)
  if [ -d "$HOME/wordlist" ]; then
    log_info "Menghapus direktori wordlist di $HOME/wordlist"
    rm -rf "$HOME/wordlist" || log_warn "Gagal menghapus $HOME/wordlist (hapus manual jika perlu)."
  fi

  # Hapus GF patterns yang dikloning oleh setup
  if [ -d "$HOME/Gf-Patterns" ]; then
    log_info "Menghapus direktori GF patterns di $HOME/Gf-Patterns"
    rm -rf "$HOME/Gf-Patterns" || log_warn "Gagal menghapus $HOME/Gf-Patterns (hapus manual jika perlu)."
  fi

  # Tidak menghapus ~/.gf karena bisa berisi pola milik user.
  # Hanya beri informasi agar user tahu.
  if [ -d "$HOME/.gf" ]; then
    log_info "~/.gf TIDAK dihapus oleh --delete (bisa mengandung pola kustom user)."
  fi

  log_ok "Selesai. setup.sh, Go environment, dan konfigurasi pribadi user tidak dihapus."
  exit 0
}

# ========= Main Install Logic =========

main_install() {
  ensure_go

  log_info "Memulai pengecekan & instalasi tools BUG-X..."
  log_info "Target install: $INSTALL_DIR"

  MISSING_REQUIRED=()
  MISSING_MANUAL=()
  INSTALLED=()

  echo "$TOOLS_DEFS" | while IFS='|' read -r name t pkg; do
    # bersihkan komentar / whitespace
    name="$(printf "%s" "$name" | sed 's/#.*$//')"
    t="$(printf "%s" "$t" | sed 's/#.*$//')"
    pkg="$(printf "%s" "$pkg" | sed 's/#.*$//')"
    [ -z "$name" ] && continue

    if [ "$t" = "go" ]; then
      # Cek di PATH atau INSTALL_DIR
      # Jika sudah ada di /usr/local/bin, anggap sudah beres
      if tool_exists_in_dir "$name" "$INSTALL_DIR"; then
        log_ok "$name sudah ada di $INSTALL_DIR."
        INSTALLED+=("$name")
        continue
      fi

      # Jika ada di PATH tapi bukan di INSTALL_DIR, pindahkan ke INSTALL_DIR
      if tool_exists_in_path "$name"; then
        src_path="$(command -v "$name")"
        if [ "$src_path" != "$INSTALL_DIR/$name" ]; then
          log_info "$name terdeteksi di $src_path, memindahkan ke $INSTALL_DIR..."
          if ! copy_if_needed "$src_path" "$INSTALL_DIR" "$name"; then
            exit 1
          fi
        else
          log_ok "$name sudah ada di $INSTALL_DIR."
        fi
        INSTALLED+=("$name")
        continue
      fi

      # Cek di GOPATH/GOBIN
      local gopath gobin found=""
      gopath="$(go env GOPATH 2>/dev/null || echo "")"
      gobin="$(go env GOBIN 2>/dev/null || echo "")"

      if [ -n "$gobin" ] && [ -x "$gobin/$name" ]; then
        found="$gobin/$name"
      elif [ -n "$gopath" ] && [ -x "$gopath/bin/$name" ]; then
        found="$gopath/bin/$name"
      fi

      if [ -n "$found" ]; then
        log_info "$name ditemukan di $found, memindahkan ke $INSTALL_DIR..."
        if ! copy_if_needed "$found" "$INSTALL_DIR" "$name"; then
          exit 1
        fi
        INSTALLED+=("$name")
        continue
      fi

      # Belum ada: install via go
      if [ -z "$pkg" ]; then
        log_error "Tidak ada paket Go untuk $name. Setup dihentikan."
        exit 1
      fi

      install_go_tool "$name" "$pkg"
      INSTALLED+=("$name")

    elif [ "$t" = "manual" ]; then
      # Untuk manual tools, hanya catat jika ada di PATH atau INSTALL_DIR
      if tool_exists_in_dir "$name" "$INSTALL_DIR"; then
        log_ok "$name terdeteksi di $INSTALL_DIR (manual)."
        INSTALLED+=("$name")
      elif tool_exists_in_path "$name"; then
        log_ok "$name terdeteksi di $(command -v "$name") (manual)."
        INSTALLED+=("$name")
      else
        log_warn "$name tidak ditemukan (manual install required)."
        MISSING_MANUAL+=("$name")
      fi
    else
      log_warn "Tipe tool tidak dikenal untuk: $name"
    fi
  done

  # Buat ~/.gau.toml default jika belum ada
  local gau_cfg="$HOME/.gau.toml"
  if [ ! -f "$gau_cfg" ]; then
    log_info "Membuat config default untuk gau di $gau_cfg"
    cat >"$gau_cfg" <<'EOF'
threads = 2
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
    log_ok "Config gau default dibuat."
  else
    log_info "Config gau sudah ada di $gau_cfg, tidak diubah."
  fi

  # ========= Wordlist Setup =========
  # Clone wordlist repo jika belum ada
  if [ ! -d "$HOME/wordlist" ]; then
    log_info "Meng-clone wordlist resmi ke $HOME/wordlist"
    if git clone https://github.com/D0Lv-1N/wordlist.git "$HOME/wordlist"; then
      log_ok "Wordlist ter-clone di $HOME/wordlist"
    else
      log_warn "Gagal clone repo wordlist. Silakan clone manual: https://github.com/D0Lv-1N/wordlist.git"
    fi
  else
    log_info "Direktori wordlist sudah ada di $HOME/wordlist, skip clone."
  fi

  # ========= GF Patterns Setup =========
  # 1. Pastikan folder pola ~/.gf ada
  if [ ! -d "$HOME/.gf" ]; then
    log_info "Membuat direktori pola GF di $HOME/.gf"
    mkdir -p "$HOME/.gf" || log_warn "Gagal membuat $HOME/.gf, cek permission."
  fi

  # 2. Clone pola komunitas jika belum ada
  if [ ! -d "$HOME/Gf-Patterns" ]; then
    log_info "Meng-clone GF patterns komunitas ke $HOME/Gf-Patterns"
    if git clone https://github.com/1ndianl33t/Gf-Patterns.git "$HOME/Gf-Patterns"; then
      log_ok "GF patterns ter-clone di $HOME/Gf-Patterns"
    else
      log_warn "Gagal clone GF patterns. Silakan clone manual: https://github.com/1ndianl33t/Gf-Patterns.git"
    fi
  else
    log_info "Direktori GF patterns sudah ada di $HOME/Gf-Patterns, skip clone."
  fi

  # 3. Salin pola .json ke ~/.gf (hanya jika sumber ada)
  if [ -d "$HOME/Gf-Patterns" ] && ls "$HOME/Gf-Patterns"/*.json >/dev/null 2>&1; then
    log_info "Menyalin pola GF (*.json) ke $HOME/.gf"
    cp "$HOME/Gf-Patterns"/*.json "$HOME/.gf"/ || log_warn "Gagal menyalin sebagian pola GF ke $HOME/.gf"
  else
    log_warn "Tidak menemukan file .json di $HOME/Gf-Patterns; lewati penyalinan pola GF."
  fi

  # ========= Summary =========
  log_info "=================================================="
  log_info "SUMMARY SETUP BUG-X"
  log_info "Install dir: $INSTALL_DIR"
  log_info "=================================================="

  # Cetak list tools terpasang & belum
  echo "Tools terpasang / terdeteksi:"
  echo "  - subfinder:      $(command -v subfinder  || echo 'MISSING')"
  echo "  - httpx:          $(command -v httpx      || echo 'MISSING')"
  echo "  - gau:            $(command -v gau        || echo 'MISSING')"
  echo "  - waybackurls:    $(command -v waybackurls|| echo 'MISSING')"
  echo "  - gf:             $(command -v gf         || echo 'MISSING')"
  echo "  - dalfox:         $(command -v dalfox     || echo 'MISSING')"
  echo "  - nuclei:         $(command -v nuclei     || echo 'MISSING')"
  echo "  - ffuf:           $(command -v ffuf       || echo 'MISSING')"
  echo "  - dnsx:           $(command -v dnsx       || echo 'MISSING')"
  echo "  - amass:          $(command -v amass      || echo 'MISSING')"
  echo "  - assetfinder:    $(command -v assetfinder|| echo 'MISSING')"
  echo "  - sqlmap:         $(command -v sqlmap     || echo 'MISSING (manual)')"
  echo "  - dirsearch:      $(command -v dirsearch  || echo 'MISSING (manual)')"
  echo "  - gobuster:       $(command -v gobuster   || echo 'MISSING (manual)')"
  echo "  - feroxbuster:    $(command -v feroxbuster|| echo 'MISSING (manual)')"
  echo "  - wpscan:         $(command -v wpscan     || echo 'MISSING (manual)')"
  echo "  - whatweb:        $(command -v whatweb    || echo 'MISSING (manual)')"

  echo "  - massdns:        $(command -v massdns    || echo 'MISSING (manual)')"
  echo "  - findomain:      $(command -v findomain  || echo 'MISSING (manual)')"

  echo
  log_info "Wordlists: gunakan repo resmi: https://github.com/D0Lv-1N/wordlist.git"
  log_info "GF Patterns: gunakan https://github.com/1ndianl33t/Gf-Patterns"
  log_ok "Setup BUG-X selesai. Semua binary go-based telah dipindahkan ke /usr/local/bin (jika sukses)."
  log_info "Pastikan /usr/local/bin ada di PATH Anda."
}

# ========= Entry Point =========

case "${1-}" in
  --delete)
    delete_installed
    ;;
  "")
    log_info "Menjalankan BUG-X setup..."
    main_install
    ;;
  *)
    log_error "Argumen tidak dikenal: $1"
    echo "Usage:"
    echo "  ./$SCRIPT_NAME        # jalankan setup/install"
    echo "  ./$SCRIPT_NAME --delete  # hapus tools yang diinstall setup"
    exit 1
    ;;
esac
