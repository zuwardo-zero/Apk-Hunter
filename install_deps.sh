#!/usr/bin/env bash
# install_deps.sh — install all dependencies for apk-hunter v2
# Supports: Debian/Ubuntu/Kali, macOS (Homebrew), Arch Linux

set -euo pipefail

RED='\033[91m'; YLW='\033[93m'; GRN='\033[92m'; CYN='\033[96m'
RST='\033[0m'; BLD='\033[1m'
info() { echo -e "  ${CYN}[*]${RST} $*"; }
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
err()  { echo -e "  ${RED}[-]${RST} $*"; exit 1; }

echo -e "\n${BLD}APK Hunter v2 — Dependency Installer${RST}\n"

# ── detect OS ─────────────────────────────────────────────────────────────────
OS="unknown"
if   [[ -f /etc/debian_version ]]; then OS="debian"
elif [[ -f /etc/arch-release ]];   then OS="arch"
elif [[ "$(uname)" == "Darwin" ]]; then OS="macos"
fi
info "detected OS: $OS"

# ── java ──────────────────────────────────────────────────────────────────────
if ! command -v java &>/dev/null; then
  info "installing Java..."
  case $OS in
    debian) sudo apt-get install -y default-jdk ;;
    arch)   sudo pacman -S --noconfirm jdk-openjdk ;;
    macos)
      brew install openjdk
      sudo ln -sfn "$(brew --prefix openjdk)/libexec/openjdk.jdk" \
        /Library/Java/JavaVirtualMachines/openjdk.jdk
      ;;
    *) err "please install Java manually: https://adoptium.net/" ;;
  esac
else
  ok "java: $(java -version 2>&1 | head -1)"
fi

# ── apktool ───────────────────────────────────────────────────────────────────
if ! command -v apktool &>/dev/null; then
  info "installing apktool..."
  case $OS in
    debian) sudo apt-get install -y apktool ;;
    arch)   sudo pacman -S --noconfirm apktool ;;
    macos)  brew install apktool ;;
    *)
      APKTOOL_VERSION="2.9.3"
      wget -q "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
        -O /usr/local/lib/apktool.jar
      wget -q "https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool" \
        -O /usr/local/bin/apktool
      chmod +x /usr/local/bin/apktool
      ;;
  esac
else
  ok "apktool: $(apktool --version 2>&1 | head -1)"
fi

# ── jadx ──────────────────────────────────────────────────────────────────────
if ! command -v jadx &>/dev/null; then
  info "installing jadx..."
  JADX_VERSION="1.5.3"
  JADX_ZIP="/tmp/jadx-${JADX_VERSION}.zip"
  JADX_DIR="$HOME/jadx"
  case $OS in
    macos) brew install jadx ;;
    arch)
      sudo pacman -S --noconfirm jadx 2>/dev/null || {
        wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O "$JADX_ZIP"
        unzip -q "$JADX_ZIP" -d "$JADX_DIR"
        sudo ln -sf "$JADX_DIR/bin/jadx" /usr/local/bin/jadx
      }
      ;;
    *)
      wget -q "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -O "$JADX_ZIP"
      unzip -q "$JADX_ZIP" -d "$JADX_DIR"
      sudo ln -sf "$JADX_DIR/bin/jadx" /usr/local/bin/jadx
      sudo chmod +x "$JADX_DIR/bin/jadx"
      ;;
  esac
else
  ok "jadx: $(jadx --version 2>&1 | head -1)"
fi

# ── apksigner ─────────────────────────────────────────────────────────────────
if ! command -v apksigner &>/dev/null; then
  info "installing apksigner..."
  case $OS in
    debian)
      sudo apt-get install -y apksigner 2>/dev/null \
        && ok "apksigner installed" \
        || warn "apksigner unavailable via apt — cert analysis will be skipped"
      ;;
    macos)
      brew install --cask android-platform-tools 2>/dev/null \
        || warn "install Android SDK to get apksigner"
      ;;
    *) warn "install Android SDK to get apksigner: https://developer.android.com/tools" ;;
  esac
else
  ok "apksigner: already installed"
fi

# ── binutils (strings) ────────────────────────────────────────────────────────
if ! command -v strings &>/dev/null; then
  info "installing binutils..."
  case $OS in
    debian) sudo apt-get install -y binutils ;;
    arch)   sudo pacman -S --noconfirm binutils ;;
    macos)  ok "strings is built-in on macOS" ;;
  esac
else
  ok "strings: available"
fi

# ── curl (needed for bash fallback Firebase probing) ─────────────────────────
if ! command -v curl &>/dev/null; then
  info "installing curl..."
  case $OS in
    debian) sudo apt-get install -y curl ;;
    arch)   sudo pacman -S --noconfirm curl ;;
    macos)  ok "curl is built-in on macOS" ;;
  esac
else
  ok "curl: available"
fi

# ── python3 ───────────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
  info "installing python3..."
  case $OS in
    debian) sudo apt-get install -y python3 ;;
    arch)   sudo pacman -S --noconfirm python ;;
    macos)  brew install python3 ;;
  esac
else
  ok "python3: $(python3 --version)"
fi

# ── unzip (needed for .apkm bundle extraction) ───────────────────────────────
if ! command -v unzip &>/dev/null; then
  info "installing unzip..."
  case $OS in
    debian) sudo apt-get install -y unzip ;;
    arch)   sudo pacman -S --noconfirm unzip ;;
    macos)  ok "unzip is built-in on macOS" ;;
  esac
else
  ok "unzip: available"
fi

# ── optional: download apkleaks patterns ─────────────────────────────────────
echo ""
read -rp "  Download apkleaks pattern file (190+ extra secret patterns)? [y/N] " yn_al
if [[ "$yn_al" =~ ^[Yy]$ ]]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  AL_URL="https://raw.githubusercontent.com/dwisiswant0/apkleaks/master/config/regexes.json"
  AL_DEST="$SCRIPT_DIR/apkleaks_regexes.json"
  if command -v wget &>/dev/null; then
    wget -q "$AL_URL" -O "$AL_DEST" && ok "saved to $AL_DEST"
  elif command -v curl &>/dev/null; then
    curl -sL "$AL_URL" -o "$AL_DEST" && ok "saved to $AL_DEST"
  else
    warn "wget/curl not found — download manually from:"
    warn "  $AL_URL"
  fi
  echo ""
  info "to use: python3 apk_hunter.py target.apk --apkleaks $AL_DEST"
fi

# ── optional: frida ───────────────────────────────────────────────────────────
echo ""
read -rp "  Install frida-tools + objection for dynamic analysis? [y/N] " yn_fr
if [[ "$yn_fr" =~ ^[Yy]$ ]]; then
  # Kali/Ubuntu 24+ have externally-managed Python — try pipx first, then venv
  if command -v pipx &>/dev/null; then
    pipx install frida-tools && pipx install objection
    ok "frida-tools + objection installed via pipx"
  elif python3 -m venv /tmp/venv_test &>/dev/null 2>&1; then
    rm -rf /tmp/venv_test
    info "creating venv at ~/.venv/frida ..."
    python3 -m venv "$HOME/.venv/frida"
    "$HOME/.venv/frida/bin/pip" install frida-tools objection -q
    ok "installed in ~/.venv/frida"
    warn "activate with: source ~/.venv/frida/bin/activate"
  else
    pip3 install --break-system-packages frida-tools objection
    ok "frida-tools + objection installed"
  fi
fi

echo -e "\n${BLD}${GRN}All dependencies installed!${RST}"
echo -e ""
echo -e "  Basic run:"
echo -e "    python3 apk_hunter.py target.apk"
echo -e ""
echo -e "  With apkleaks patterns (190+ extra secrets):"
echo -e "    python3 apk_hunter.py target.apk --apkleaks auto"
echo -e ""
echo -e "  Split APK bundle:"
echo -e "    python3 apk_hunter.py target.apkm"
echo -e ""
echo -e "  Skip Firebase probing (offline):"
echo -e "    python3 apk_hunter.py target.apk --no-firebase"
echo -e ""
