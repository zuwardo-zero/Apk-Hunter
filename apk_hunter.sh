#!/usr/bin/env bash
# apk_hunter.sh — wrapper around apk_hunter.py with pure-bash fallback
# Usage: ./apk_hunter.sh target.apk [output_dir] [extra python args...]
#
# Examples:
#   ./apk_hunter.sh target.apk
#   ./apk_hunter.sh target.apk /tmp/recon
#   ./apk_hunter.sh target.apk /tmp/recon --apkleaks auto
#   ./apk_hunter.sh target.apkm                        # split APK bundle

set -euo pipefail

APK="${1:?usage: $0 <target.apk|target.apkm> [output_dir] [extra args...]}"
EXT="${APK##*.}"
BASE="$(basename "$APK" ."$EXT")"
OUT="${2:-recon_${BASE}}"

RED='\033[91m'; YLW='\033[93m'; GRN='\033[92m'; CYN='\033[96m'; MAG='\033[95m'
RST='\033[0m'; BLD='\033[1m'; DIM='\033[2m'
info() { echo -e "  ${CYN}[*]${RST} $*"; }
ok()   { echo -e "  ${GRN}[+]${RST} $*"; }
warn() { echo -e "  ${YLW}[!]${RST} $*"; }
err()  { echo -e "  ${RED}[-]${RST} $*"; }
hdr()  { echo -e "\n${BLD}${MAG}▓▒░ $* ░▒▓${RST}"; }

echo -e ""
echo -e "${RED}    _    ____  _  __    ${MAG}_____  _   _ _   _ _  _______ ____${RST}"
echo -e "${RED}   / \\  |  _ \\| |/ /   ${MAG}|  _ \\| | | | | | | |/ /  ___|  _ \\${RST}"
echo -e "${RED}  / _ \\ | |_) | ' /    ${MAG}| |_) | |_| | | | | ' /| |_  | |_) |${RST}"
echo -e "${RED} / ___ \\|  __/| . \\    ${MAG}|  _ <|  _  | |_| | . \\|  _| |  _ <${RST}"
echo -e "${RED}/_/   \\_\\_|   |_|\\_\\   ${MAG}|_| \\|_\\_| |_|\\___/|_|\\_\\_|   |_| \\|_${RST}"
echo -e "${DIM}                    static APK analysis for bug bounty${RST}"
echo -e ""
echo -e "  ${DIM}apk  : $APK${RST}"
echo -e "  ${DIM}out  : $OUT${RST}"
echo -e ""

[[ -f "$APK" ]] || { err "file not found: $APK"; exit 1; }

# ── try Python tool first (preferred) ────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if command -v python3 &>/dev/null && [[ -f "$SCRIPT_DIR/apk_hunter.py" ]]; then
  info "launching apk_hunter.py ..."
  exec python3 "$SCRIPT_DIR/apk_hunter.py" "$APK" --output "$OUT" "${@:3}"
fi

warn "python3 or apk_hunter.py not found — running bash fallback mode"
warn "fallback does not support: .apkm bundles, apkleaks patterns, Firebase probing, PoC generation"

# ── bash fallback — pure bash minimal triage ──────────────────────────────────
mkdir -p "$OUT"

# .apkm: unzip and grab base.apk
if [[ "$EXT" == "apkm" ]]; then
  hdr "APKM BUNDLE — extracting"
  APKM_DIR="$OUT/apkm_extracted"
  mkdir -p "$APKM_DIR"
  unzip -q "$APK" -d "$APKM_DIR"
  if [[ -f "$APKM_DIR/base.apk" ]]; then
    APK="$APKM_DIR/base.apk"
    ok "using base.apk from bundle"
    SPLITS=("$APKM_DIR"/*.apk)
    info "found ${#SPLITS[@]} APK(s) in bundle — fallback mode only scans base.apk"
  else
    FIRST_APK=$(find "$APKM_DIR" -name "*.apk" | head -1)
    [[ -n "$FIRST_APK" ]] && APK="$FIRST_APK" || { err "no .apk found in bundle"; exit 1; }
    warn "base.apk not found, using: $APK"
  fi
fi

hdr "DECOMPILE — apktool"
if command -v apktool &>/dev/null; then
  apktool d "$APK" -o "$OUT/apktool" -f 2>/dev/null && ok "apktool done"
else
  warn "apktool not installed — skipping smali decompile"
fi

hdr "DECOMPILE — jadx"
if command -v jadx &>/dev/null; then
  JADX_DIR="$OUT/jadx"
  [[ -d "$JADX_DIR" ]] && rm -rf "$JADX_DIR"
  mkdir -p "$JADX_DIR"
  JADX_OPTS="-Xmx3g -XX:MaxRAMPercentage=80.0" \
    jadx -d "$(realpath "$JADX_DIR")" \
    --threads-count 4 --no-debug-info \
    "$(realpath "$APK")" 2>&1 | tail -5
  ok "jadx done"
else
  warn "jadx not installed — skipping Java source decompile"
fi

hdr "MANIFEST"
MANIFEST="$OUT/apktool/AndroidManifest.xml"
if [[ -f "$MANIFEST" ]]; then
  cp "$MANIFEST" "$OUT/AndroidManifest.xml"
  for flag in 'debuggable="true"' 'allowBackup="true"' 'usesCleartextTraffic="true"'; do
    grep -q "$flag" "$MANIFEST" \
      && warn "FOUND: $flag" \
      || ok  "not found: $flag"
  done
  EXPORTED=$(grep -c 'exported="true"' "$MANIFEST" || true)
  [[ "$EXPORTED" -gt 0 ]] \
    && warn "exported components: $EXPORTED — check for missing permission guards" \
    || ok "no exported components"
  # Generate basic PoC adb commands for exported components
  PKG=$(grep -oP 'package="\K[^"]+' "$MANIFEST" | head -1 || echo "")
  if [[ -n "$PKG" && "$EXPORTED" -gt 0 ]]; then
    POC_FILE="$OUT/poc_intents.sh"
    echo "#!/usr/bin/env bash" > "$POC_FILE"
    echo "# auto-generated PoC intent commands — run against connected device" >> "$POC_FILE"
    echo "" >> "$POC_FILE"
    grep -oP 'android:name="\K[^"]+(?="[^>]*exported="true")' "$MANIFEST" 2>/dev/null | while read -r COMP; do
      FULL="${COMP:0:1}" 
      [[ "${COMP:0:1}" == "." ]] && COMP="${PKG}${COMP}"
      echo "echo '>>> testing $COMP'" >> "$POC_FILE"
      echo "adb shell am start -n ${PKG}/${COMP}" >> "$POC_FILE"
      echo "adb shell am start -n ${PKG}/${COMP} -d 'https://attacker.com'" >> "$POC_FILE"
      echo "" >> "$POC_FILE"
    done
    chmod +x "$POC_FILE"
    ok "PoC intents written: $POC_FILE"
  fi
fi

hdr "URLS"
SDK_DIRS="okhttp3\|org/bouncycastle\|com/google/android\|kotlin/\|androidx/"
find "$OUT" \( -name "*.java" -o -name "*.kt" -o -name "*.xml" -o -name "*.json" \) 2>/dev/null \
  | grep -v "$SDK_DIRS" \
  | xargs grep -hoE "(https?://[a-zA-Z0-9./_?=%&+#@:~-]+)" 2>/dev/null \
  | grep -v "schemas\.android\.com\|www\.w3\.org\|developer\.android\.com\|%[a-z]" \
  | sort -u > "$OUT/urls.txt" || true
ok "URLs extracted: $(wc -l < "$OUT/urls.txt")"

hdr "SECRETS SCAN"
grep -rEn \
  "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|-----BEGIN (RSA |EC )?PRIVATE|sk_live_[0-9A-Za-z]{24}|SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}|hooks\.slack\.com/services/T[A-Z0-9]+|[a-z0-9-]{3,}\.firebaseio\.com|(password|passwd|pwd)\s*=\s*['\"][^'\"\$%{]{6,}['\"]|(twilio|account.?sid)\s*[=:]\s*['\"]?AC[a-f0-9]{32})" \
  "$OUT/jadx/sources/" "$OUT/apktool/res/" 2>/dev/null \
  | grep -vE "(okhttp3/|bouncycastle/|com/google/|kotlin/|androidx/|import |interface |extends )" \
  > "$OUT/secrets.txt" || true
ok "secrets: $(wc -l < "$OUT/secrets.txt") findings"

hdr "DANGEROUS APIs"
grep -rEn \
  "(\.setJavaScriptEnabled\(true\)|\.setAllowUniversalAccessFromFileURLs\(true\)|\.addJavascriptInterface\s*\(|Cipher\.getInstance\s*\(\s*['\"]AES/ECB|Cipher\.getInstance\s*\(\s*['\"]DES['\"]|MessageDigest\.getInstance\s*\(\s*['\"]MD5['\"]|NullHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|MODE_WORLD_READABLE|new\s+DexClassLoader\s*\(|Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(|\.rawQuery\s*\()" \
  "$OUT/jadx/sources/" 2>/dev/null \
  | grep -vE "(okhttp3/|bouncycastle/|com/google/|kotlin/|androidx/|import |interface )" \
  > "$OUT/dangerous_apis.txt" || true
ok "dangerous APIs: $(wc -l < "$OUT/dangerous_apis.txt") findings"

hdr "FIREBASE — quick probe"
if command -v curl &>/dev/null; then
  FB_FILE="$OUT/firebase_results.txt"
  echo "" > "$FB_FILE"
  grep -hoE "[a-z0-9-]{3,}\.firebaseio\.com" "$OUT/urls.txt" 2>/dev/null | sort -u | while read -r FB; do
    PROBE="https://${FB}/.json"
    RESP=$(curl -s --max-time 5 -o /dev/null -w "%{http_code}" "$PROBE" || echo "err")
    if [[ "$RESP" == "200" ]]; then
      DATA=$(curl -s --max-time 5 "$PROBE" | head -c 100)
      if [[ "$DATA" != "null" && -n "$DATA" ]]; then
        warn "VULNERABLE: $PROBE — returns data without auth"
        echo "VULNERABLE: $PROBE" >> "$FB_FILE"
        echo "  response: $DATA" >> "$FB_FILE"
      else
        ok "safe (returns null): $PROBE"
        echo "safe: $PROBE" >> "$FB_FILE"
      fi
    else
      ok "safe (HTTP $RESP): $PROBE"
      echo "safe (HTTP $RESP): $PROBE" >> "$FB_FILE"
    fi
  done
else
  warn "curl not found — skipping Firebase probe (install curl)"
fi

hdr "CERTIFICATES"
if command -v apksigner &>/dev/null; then
  apksigner verify --verbose --print-certs "$APK" > "$OUT/cert_info.txt" 2>&1 && ok "apksigner done"
fi
find "$OUT/apktool/" \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" -o -name "*.p12" \) \
  2>/dev/null > "$OUT/embedded_certs.txt" || true
grep -rn "BEGIN CERTIFICATE\|BEGIN RSA\|BEGIN PRIVATE" \
  "$OUT/apktool/" 2>/dev/null >> "$OUT/embedded_certs.txt" || true

hdr "NATIVE LIBS"
if command -v strings &>/dev/null; then
  find "$OUT/apktool/lib/" -name "*.so" 2>/dev/null \
    -exec strings {} \; \
    | grep -iE "(AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_|https?://[a-zA-Z0-9.-]{10,})" \
    | grep -viE "(clang|toolchain|android\.googlesource|cmake|gradle)" \
    | sort -u > "$OUT/native_strings.txt" || true
  ok "native strings: $(wc -l < "$OUT/native_strings.txt") findings"
fi

hdr "NETWORK SECURITY CONFIG"
NSC="$OUT/apktool/res/xml/network_security_config.xml"
if [[ -f "$NSC" ]]; then
  cp "$NSC" "$OUT/network_security_config.xml"
  grep -q 'cleartextTrafficPermitted.*true' "$NSC" \
    && warn "[HIGH] cleartext traffic permitted" \
    || ok "cleartext traffic not permitted"
  grep -q '"user"' "$NSC" \
    && warn "[HIGH] user certificate store trusted — Burp MITM ready without Frida" \
    || ok "user certs not trusted"
else
  info "network_security_config.xml not found"
fi

echo -e "\n${BLD}${GRN}=== DONE ===${RST}"
echo -e "  output dir : $OUT/"
echo -e "  urls       : $(wc -l < "$OUT/urls.txt"      2>/dev/null || echo 0)"
echo -e "  secrets    : $(wc -l < "$OUT/secrets.txt"   2>/dev/null || echo 0)"
echo -e "  api issues : $(wc -l < "$OUT/dangerous_apis.txt" 2>/dev/null || echo 0)"
echo -e "  poc file   : $OUT/poc_intents.sh"
echo ""
