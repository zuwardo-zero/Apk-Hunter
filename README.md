# 🔍 APK Hunter 

A bug bounty focused Android APK security analysis tool. Automatically decompiles an APK, extracts everything potentially sensitive or vulnerable, tests Firebase rules, generates PoC intents, and produces a single interactive HTML report.

---

## Features

- **Full decompilation**: via `apktool` (smali + resources) and `jadx` (Java source)
- **Manifest analysis**: debuggable, allowBackup, exported components, cleartext traffic, permissions
- **Secret & credential scanning**: AWS, Google API, Firebase, JWT, Stripe, Twilio, Slack, Discord, SendGrid, Mailgun, private keys, hardcoded passwords + 190 more via apkleaks
- **SDK noise filtering**: 50+ third-party SDK prefixes excluded by default (okhttp3, BouncyCastle, Google, Facebook, Tencent, etc.). near-zero false positives on app code
- **Dangerous API detection**: WebView misconfigurations, SSL bypass, AES-ECB/DES/MD5, world-readable storage, DexClassLoader, runtime exec, raw SQL, deep link injection
- **Firebase auto-tester**: probes every `*.firebaseio.com` URL for unauthenticated read access automatically
- **PoC intent generator**: generates ready-to-run `poc_intents.sh` with `adb shell am start/broadcast/startservice` commands for every exported component
- **URL & endpoint extraction**: all HTTP(S) endpoints from source and resources, SDK noise removed
- **Certificate analysis**: APK signing info, embedded `.pem`/`.crt`/`.p12`/`.bks`, inline PEM blocks
- **Network security config**: cleartext traffic, user cert trust (Burp-ready detection)
- **Native library analysis**: suspicious strings in `.so` files
- **Split APK / `.apkm` support**: extracts bundles, scans base.apk + all feature splits
- **apkleaks integration**: load 190+ community patterns from apkleaks `regexes.json`
- **Interactive HTML report**: self-contained, filterable tables, App/SDK tabs, sidebar nav
- **JSON output**: machine-readable for CI/CD pipelines
- **Pure bash fallback**: works without Python (includes Firebase probe via curl)

---

## Quickstart

```bash
git clone https://github.com/Wiz-Zero/apk-hunter
cd apk-hunter
chmod +x install_deps.sh apk_hunter.sh
./install_deps.sh
python3 apk_hunter.py target.apk
```

Open `recon_<target>/report.html` in your browser.

---

## Installation

### Debian / Ubuntu / Kali (manual)
```bash
sudo apt install default-jdk apktool apksigner binutils curl unzip

# jadx
wget https://github.com/skylot/jadx/releases/download/v1.5.3/jadx-1.5.3.zip
unzip jadx-1.5.3.zip -d ~/jadx
sudo ln -sf ~/jadx/bin/jadx /usr/local/bin/jadx
```

### macOS
```bash
brew install apktool jadx
```

### Automated (all platforms)
```bash
chmod +x install_deps.sh && ./install_deps.sh
```

The installer handles Java, apktool, jadx, apksigner, binutils, curl, unzip, optional apkleaks pattern download, and optional frida/objection install.

---

## Usage

```
python3 apk_hunter.py <target.apk|target.apkm> [options]

positional arguments:
  apk                     path to target .apk or .apkm file

options:
  -o, --output DIR        output directory (default: recon_<apkname>)
  --jadx-path PATH        path to jadx binary (default: jadx)
  --jadx-xmx SIZE         JVM heap for jadx, e.g. 4g (default: 3g)
  --jadx-threads N        jadx thread count (default: 4)
  --no-jadx               skip jadx, use apktool smali only (faster)
  --no-html               skip HTML report generation
  --no-firebase           skip Firebase security rule probing (offline mode)
  --apkleaks [FILE]       load extra patterns from apkleaks regexes.json
                          use 'auto' to download from GitHub automatically
  --include-sdk           include third-party SDK findings (more noise)
  --json-only             suppress terminal output, write JSON only
```

### Examples

```bash
# standard run
python3 apk_hunter.py target.apk

# with 190+ extra patterns from apkleaks (auto-download)
python3 apk_hunter.py target.apk --apkleaks auto

# with local apkleaks pattern file
python3 apk_hunter.py target.apk --apkleaks ./apkleaks_regexes.json

# split APK bundle from APKMirror
python3 apk_hunter.py target.apkm --apkleaks auto

# offline mode (no Firebase probing, no apkleaks download)
python3 apk_hunter.py target.apk --no-firebase

# custom output dir + more heap for large APKs
python3 apk_hunter.py target.apk -o /tmp/recon --jadx-xmx 4g

# fast triage — smali only, no jadx
python3 apk_hunter.py target.apk --no-jadx

# CI/CD pipeline — filter critical findings
python3 apk_hunter.py target.apk --json-only \
  | jq '.secrets[] | select(.severity=="critical")'

# bash wrapper (includes bash fallback mode)
./apk_hunter.sh target.apk
./apk_hunter.sh target.apk /tmp/recon --apkleaks auto
```

---

## Output Structure

```
recon_<apkname>/
├── report.html               ← interactive HTML report (open in browser)
├── report.json               ← full machine-readable results
├── secrets.txt               ← credential findings (app code vs SDK split)
├── urls.txt                  ← all extracted HTTP(S) endpoints
├── poc_intents.sh            ← ready-to-run adb PoC commands (chmod +x first)
├── firebase_results.txt      ← Firebase probe results (vulnerable/safe)
├── AndroidManifest.xml       ← decoded manifest
├── cert_info.txt             ← apksigner certificate output
├── embedded_certs.txt        ← embedded cert/key file list
├── native_strings.txt        ← suspicious strings from .so files
├── network_security_config.xml  (if present)
├── apktool/                  ← apktool decompile (smali, res, assets)
├── jadx/                     ← jadx decompile (Java source)
└── split_N_<name>/           ← per-split APK decompile (if .apkm input)
    ├── apktool/
    └── jadx/
```

---

## Secret Patterns

| Pattern | Severity | Notes |
|---|---|---|
| AWS Access Key (`AKIA...`) | Critical | |
| AWS Secret Key | Critical | requires key name context |
| Google API Key (`AIza...`) | Critical | |
| Google OAuth Client ID | High | |
| Firebase Database URL | High | auto-probed for open access |
| JWT Token | High | requires all 3 parts |
| Stripe Secret Key (`sk_live_`) | Critical | live keys only |
| Slack / Discord Webhook | High | full URL format |
| Twilio Account SID | High | requires `twilio`/`account_sid` context |
| SendGrid / Mailgun key | High | |
| Private Key Material (PEM) | Critical | |
| Hardcoded password/secret | High | requires quotes + min length |
| Internal dev endpoint | Medium | private IP ranges |
| + 190 more via `--apkleaks` | varies | community-maintained |

---

## Dangerous API Patterns

| Pattern | Severity |
|---|---|
| `addJavascriptInterface` | Critical |
| `setAllowUniversalAccessFromFileURLs(true)` | Critical |
| `TrustAllCerts` / `NullHostnameVerifier` | Critical |
| `checkServerTrusted` override body | Critical |
| `setJavaScriptEnabled(true)` | High |
| `setAllowFileAccess(true)` | High |
| `AES/ECB` or `DES` cipher | High |
| `DexClassLoader` | High |
| `Runtime.getRuntime().exec()` | High |
| `MODE_WORLD_READABLE` | High |
| `MD5` / `SHA-1` hash | Medium |
| `rawQuery()` / `execSQL()` | Medium |
| Deep link URI parsing | Medium |
| Mutable PendingIntent | Medium |

---

## PoC Intent Testing

The tool auto-generates `poc_intents.sh` for every exported component:

```bash
# run against connected device/emulator
chmod +x recon_target/poc_intents.sh
./recon_target/poc_intents.sh
```

Each exported activity gets three variants:
- Basic launch
- Launch with `https://attacker.com` as URI (deep link injection test)
- Launch with `url` and `token` extras (parameter injection test)

---

## Firebase Testing

Automatically tested during scan. Results in `firebase_results.txt`:

```
VULNERABLE: https://myapp-default-rtdb.firebaseio.com
  response: {"users":{"uid123":{"email":"...
safe (HTTP 401): https://secure-app.firebaseio.com
```

Skip with `--no-firebase` for offline use.

---

## Checklist (bug bounty order)

1. **`debuggable=true`** — `adb shell am start` then `adb jdwp` to attach debugger
2. **`allowBackup=true`** — `adb backup -f backup.ab com.target.app` then `android-backup-extractor`
3. **Firebase results** — check `firebase_results.txt` for open databases
4. **PoC intents** — run `poc_intents.sh` against a device, check for unintended behaviour
5. **Hardcoded API keys** — test each key scope (Google: Maps geocode endpoint, AWS: `sts get-caller-identity`)
6. **Exported WebViews** — if `addJavascriptInterface` + exported activity, test URI parameter
7. **User certs trusted** — set up Burp, MITM without Frida
8. **Cleartext HTTP** — check `urls.txt` for `http://` API endpoints
9. **Weak crypto** — `AES/ECB` in crypto utilities → trace callers in jadx source
10. **Native lib strings** — check `native_strings.txt` for keys not visible in Java source

---

## Contributing

Pull requests welcome. To add a secret pattern, append a `(name, regex, severity)` tuple to `SECRET_PATTERNS` in `apk_hunter.py`. To add an SDK exclusion prefix, append to `THIRD_PARTY_PREFIXES`.

---

## Disclaimer

For authorized security testing and bug bounty programs only. Only test applications you have explicit permission to assess.

---

## Redacted test on a production app
<img width="1289" height="641" alt="2026-05-25_15-35" src="https://github.com/user-attachments/assets/f4535a9e-39cc-4fdc-84b8-dfc98b301a13" />
<img width="1294" height="656" alt="2026-05-25_15-40" src="https://github.com/user-attachments/assets/b825951d-343a-49fa-8f01-9bd0731b1992" />
<img width="1283" height="640" alt="2026-05-25_15-29" src="https://github.com/user-attachments/assets/a4d8435f-4c36-4ee9-979e-3601438f6fa5" />

