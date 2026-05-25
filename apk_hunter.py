#!/usr/bin/env python3
"""
apk_hunter.py — Android APK static analysis for bug bounty
Author: Wiz-Zero  |  License: MIT

Usage:
    python3 apk_hunter.py target.apk
    python3 apk_hunter.py target.apk -o /tmp/recon
    python3 apk_hunter.py target.apk --jadx-xmx 4g
    python3 apk_hunter.py target.apk --include-sdk
"""

import argparse, json, os, re, shutil, subprocess, sys, urllib.request, urllib.error, zipfile, xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

# ── terminal colors ─────────────────────────────────────────────────────────
R = "\033[0m"
B = "\033[1m"
RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
DIM = "\033[2m"
MAG = "\033[95m"

def info(m):  print(f"  {CYN}[*]{R} {m}")
def ok(m):    print(f"  {GRN}[+]{R} {m}")
def warn(m):   print(f"  {YEL}[!]{R} {m}")
def err(m):   print(f"  {RED}[-]{R} {m}")
def dbg(m):   print(f"  {DIM}[~]{R} {m}")
def section(t):
    print(f"\n{B}{MAG}▓▒░ {t} ░▒▓{R}")
    print(f"{DIM}{'─'*68}{R}")

# ── banner ────────────────────────────────────────────────────────────────────
def banner():
    print(f"""
{RED}    _    ____  _  __    {MAG}_____  _   _ _   _ _  _______ ____{R}
{RED}   / \\  |  _ \\| |/ /   {MAG}|  _ \\| | | | | | | |/ /  ___|  _ \\{R}
{RED}  / _ \\ | |_) | ' /    {MAG}| |_) | |_| | | | | ' /| |_  | |_) |{R}
{RED} / ___ \\|  __/| . \\    {MAG}|  _ <|  _  | |_| | . \\|  _| |  _ <{R}
{RED}/_/   \\_\\_|   |_|\\_\\   {MAG}|_| \\|_\\_| |_|\\___/|_|\\_\\_|   |_| \\|_{R}
{DIM}                    static APK analysis for bug bounty{R}
""")

# ── SDK path exclusions ───────────────────────────────────────────────────────
THIRD_PARTY_PREFIXES = (
    "androidx/","android/support/","com/google/","com/android/",
    "com/facebook/","com/instagram/",
    "kotlin/","kotlinx/","org/jetbrains/",
    "okhttp3/","okio/","com/squareup/",
    "org/bouncycastle/","org/conscrypt/","org/spongycastle/",
    "org/apache/","org/jbox2d/",
    "com/tencent/","com/huawei/","com/hianalytics/",
    "com/umeng/","com/sensorsdata/","com/uc/crashsdk/",
    "com/bugly/","com/appsflyer/",
    "cn/jiguang/","com/xiaomi/push/","com/meizu/cloud/pushsdk/",
    "com/sina/weibo/","com/geetest/",
    "com/bumptech/","com/nostra13/","com/cameralibrary/",
    "com/qiniu/","com/ta/utdid2/","com/koushikdutta/",
    "com/github/","com/efs/sdk/","com/zdf/",
    "com/beloo/","com/shopify/","com/horcrux/",
    "com/caverock/","com/lqr/","com/bk/router/",
    "com/repackage/","org/repackage/","net/openid/",
    "zendesk/","coil/","butterknife/",
    "io/reactivex/","retrofit2/","com/jakewharton/",
    "com/reactnativecommunity/","com/swmansion/",
    "com/obs/",
)

SKIP_FILE_PATTERNS = (
    "lottie","animation_","_anim","animations/",
    "index.android.bundle",
    ".ttf",".otf",".woff",".dex",
)

def _norm_path(p: str) -> str:
    p = p.replace("\\", "/")
    for px in ("jadx/sources/","jadx/resources/","apktool/smali/",
               "apktool/smali_classes2/","apktool/smali_classes3/",
               "apktool/smali_classes4/","apktool/smali_classes5/"):
        if px in p:
            return p[p.index(px)+len(px):]
    return p

def is_third_party(rel: str) -> bool:
    return any(_norm_path(rel).startswith(tp) for tp in THIRD_PARTY_PREFIXES)

def skip_file(rel: str) -> bool:
    p = rel.lower()
    return any(pat in p for pat in SKIP_FILE_PATTERNS)

# ── secret patterns ───────────────────────────────────────────────────────────

SECRET_PATTERNS = [
    ("AWS Access Key",
     r"\bAKIA[0-9A-Z]{16}\b", "critical"),

    ("AWS Secret Key",
     r'(?i)(aws_secret_access_key|aws_secret|secret_access_key)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}["\']?',
     "critical"),

    ("Google API Key",
     r"\bAIza[0-9A-Za-z\-_]{35}\b", "critical"),

    ("Google OAuth Client ID",
     r"\b[0-9]{12}-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "high"),

    ("Firebase Database URL",
     r"\b[a-z0-9][a-z0-9\-]{2,}\.firebaseio\.com\b", "high"),

    ("JWT Token",
     r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "high"),

    ("Slack Webhook",
     r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}",
     "high"),

    ("Discord Webhook",
     r"https://discord(?:app)?\.com/api/webhooks/[0-9]{17,19}/[A-Za-z0-9_\-]{60,}",
     "high"),

    ("Stripe Secret Key",
     r"\bsk_live_[0-9A-Za-z]{24,}\b", "critical"),

    ("Stripe Publishable Key",
     r"\bpk_live_[0-9A-Za-z]{24,}\b", "medium"),

    ("Twilio Account SID",
     r'(?i)(?:twilio|account.?sid)\s*[=:]\s*["\']?(AC[a-f0-9]{32})["\']?', "high"),

    ("Twilio Auth Token",
     r'(?i)(?:twilio|auth.?token)\s*[=:]\s*[\'"][a-f0-9]{32}[\'"]', "high"),

    ("SendGrid API Key",
     r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "high"),

    ("Mailgun API Key",
     r"\bkey-[0-9a-f]{32}\b", "high"),

    ("Private Key Material",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),

    ("Hardcoded Password",
     r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\'\$%*\s{}<>]{6,}["\']', "high"),

    ("Hardcoded Secret",
     r'(?i)(?:api_secret|client_secret|app_secret)\s*[=:]\s*["\'][^"\'\$%*\s{}<>]{8,}["\']',
     "high"),

    ("Hardcoded API Token",
     r'(?i)(?:api_token|access_token|auth_token|bearer_token)\s*[=:]\s*["\'][^"\'\$%*\s{}<>]{8,}["\']',
     "high"),

    ("Internal Dev Endpoint",
     r"https?://(?:192\.168|10\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+)\.\d+(?::\d+)?/\S*",
     "medium"),
]

# ── dangerous API patterns ────────────────────────────────────────────────────

DANGEROUS_API_PATTERNS = [
    ("WebView JS Enabled",
     r"\.setJavaScriptEnabled\(\s*true\s*\)", "high"),

    ("WebView File Access",
     r"\.setAllowFileAccess\(\s*true\s*\)", "high"),

    ("WebView Universal File Access",
     r"\.setAllowUniversalAccessFromFileURLs\(\s*true\s*\)", "critical"),

    ("WebView File-from-File Access",
     r"\.setAllowFileAccessFromFileURLs\(\s*true\s*\)", "high"),

    ("addJavascriptInterface",
     r"\.addJavascriptInterface\s*\(", "critical"),

    ("SSL Pinning Bypass",
     r"checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{[^}]{0,60}\}", "critical"),

    ("Null Hostname Verifier",
     r"(?:NullHostnameVerifier\b|ALLOW_ALL_HOSTNAME_VERIFIER\b|"
     r"\.setHostnameVerifier\s*\(\s*(?:null|.*ALLOW_ALL))", "critical"),

    ("AES ECB Mode",
     r'Cipher\.getInstance\s*\(\s*["\']AES/ECB', "high"),

    ("DES Cipher Used",
     r'Cipher\.getInstance\s*\(\s*["\']DES["\']', "high"),

    ("Weak Hash MD5",
     r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', "medium"),

    ("Weak Hash SHA1",
     r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', "medium"),

    ("World Readable Storage",
     r"\bMODE_WORLD_READABLE\b|\bMODE_WORLD_WRITEABLE\b", "high"),

    ("Dynamic Code Loading",
     r"\bnew\s+DexClassLoader\s*\(", "high"),

    ("Runtime Command Execution",
     r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(", "high"),

    ("Raw SQL Query",
     r"\.rawQuery\s*\(|\.execSQL\s*\(", "medium"),

    ("Deep Link URI Parsing",
     r"getIntent\s*\(\s*\)\.getData\s*\(\s*\)", "medium"),

    ("Mutable Pending Intent",
     r"PendingIntent\.(?:getActivity|getService|getBroadcast)\s*\([^)]+FLAG_MUTABLE",
     "medium"),
]

# ── apkleaks pattern loader ───────────────────────────────────────────────────

APKLEAKS_URL = "https://raw.githubusercontent.com/dwisiswant0/apkleaks/master/config/regexes.json"

def load_apkleaks_patterns(patterns_file: str = None) -> list:
    raw = None
    if patterns_file and Path(patterns_file).exists():
        raw = Path(patterns_file).read_text()
        info(f"loaded apkleaks patterns from {patterns_file}")
    else:
        try:
            info("pulling apkleaks patterns from GitHub...")
            with urllib.request.urlopen(APKLEAKS_URL, timeout=10) as resp:
                raw = resp.read().decode("utf-8")
            ok("got apkleaks patterns")
        except Exception as e:
            warn(f"couldn't grab apkleaks patterns: {e}")
            return []
    try:
        data = json.loads(raw)
    except Exception as e:
        warn(f"failed to parse apkleaks patterns: {e}")
        return []

    patterns = []
    for name, val in data.items():
        try:
            if isinstance(val, dict):
                regex    = val.get("regex") or val.get("pattern") or ""
                severity = val.get("severity", "medium").lower()
            elif isinstance(val, str):
                regex    = val
                severity = "medium"
            elif isinstance(val, list):
                regex    = val[0] if val else ""
                severity = "medium"
            else:
                continue
            if not regex:
                continue
            re.compile(regex, re.IGNORECASE)
            if severity not in ("critical","high","medium","low","info"):
                severity = "medium"
            patterns.append((f"[apkleaks] {name}", regex, severity))
        except re.error:
            pass
    ok(f"loaded {len(patterns)} apkleaks patterns")
    return patterns


MANIFEST_CHECKS = [
    ("debuggable",    r'android:debuggable\s*=\s*"true"',           "critical", "App is debuggable — adb attach + memory dump possible"),
    ("allowBackup",   r'android:allowBackup\s*=\s*"true"',          "high",     "Backup enabled — full data extraction via adb backup"),
    ("cleartext",     r'android:usesCleartextTraffic\s*=\s*"true"',  "high",     "Cleartext HTTP traffic permitted"),
    ("exported comp", r'android:exported\s*=\s*"true"',             "high",     "Exported component(s) found — verify permission guards"),
    ("taskAffinity",  r'android:taskAffinity\s*=\s*"[^"]+"',        "medium",   "Custom taskAffinity — potential task hijacking"),
    ("intent-filter", r'<intent-filter',                             "info",     "Intent filter(s) — review for deep link injection"),
]

# ── placeholder / FP value filter ─────────────────────────────────────────────

FP_PREFIXES = re.compile(r'^[$][{(]|^%[a-z]|^<[a-z]', re.IGNORECASE)
FP_EXACT    = re.compile(
    r'^(?:your[_-]|YOUR[_-]|xxx|changeme|placeholder|todo|example|test_?key|'
    r'dummy|none|null|empty|default|\*+)',
    re.IGNORECASE,
)

def is_fp_value(v: str) -> bool:
    s = v.strip().strip(chr(34) + chr(39))
    return bool(FP_PREFIXES.match(s) or FP_EXACT.match(s))


# ── tool checks ───────────────────────────────────────────────────────────────

def check_tool(name, *args):
    try:
        subprocess.run([name,*args], capture_output=True, timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def require_tools(jadx_path):
    tools = {
        "apktool":   check_tool("apktool","--version"),
        "jadx":      check_tool(jadx_path,"--version"),
        "java":      check_tool("java","-version"),
        "strings":   check_tool("strings","--version"),
        "apksigner": check_tool("apksigner","version"),
    }
    for t,found in tools.items():
        (ok if found else warn)(f"{'found' if found else 'missing'}: {t}")
    if not tools["apktool"] or not tools["java"]:
        err("apktool and java required. Run: sudo apt install apktool default-jdk")
        sys.exit(1)
    if not tools["jadx"]:
        warn(f"jadx not found at '{jadx_path}' — skipping Java source decompile")
    return tools

# ── decompilation ─────────────────────────────────────────────────────────────

def decompile_apktool(apk, out):
    dest = out / "apktool"
    info(f"apktool d {apk.name} -o {dest} -f")
    r = subprocess.run(
        ["apktool","d",str(apk.resolve()),"-o",str(dest.resolve()),"-f"],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        warn(f"apktool exited {r.returncode}")
        if r.stderr: print(DIM+r.stderr[:400]+R)
    return dest

def decompile_jadx(apk, out, jadx_path, xmx="3g", threads=4):
    dest = out / "jadx"
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["JADX_OPTS"] = f"-Xmx{xmx} -XX:MaxRAMPercentage=80.0"
    cmd = [jadx_path, "-d", str(dest.resolve()),
           "--threads-count", str(threads),
           "--no-debug-info", "--show-bad-code",
           str(apk.resolve())]
    info(f"jadx -d {dest} (heap: {xmx})")
    collected = []
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, env=env, bufsize=1)
    for line in proc.stdout:
        line = line.rstrip()
        collected.append(line)
        if any(k in line for k in ("INFO  - load","INFO  - process","INFO  - done",
                                    "ERROR -","WARN  -","finished with")):
            print(DIM+"       "+line+R)
    proc.wait()
    full = "\n".join(collected)
    if proc.returncode != 0:
        if "finished with errors" in full:
            eline = next((l for l in collected if "finished with errors" in l),"")
            warn(f"jadx partial errors (normal for obfuscated APKs): {eline.strip()}")
        else:
            warn(f"jadx exited {proc.returncode} — last output:")
            print(DIM+"\n".join(collected[-30:])+R)
    return dest

# ── .apkm / split APK handling ────────────────────────────────────────────────

def extract_apkm(apkm_path: Path, out: Path) -> Path:
    extract_dir = out / "apkm_extracted"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    info("extracting .apkm bundle...")
    with zipfile.ZipFile(apkm_path, "r") as z:
        z.extractall(extract_dir)
    apks = list(extract_dir.glob("*.apk"))
    info(f"found {len(apks)} APK(s) inside bundle: {[a.name for a in apks]}")
    base = extract_dir / "base.apk"
    if not base.exists() and apks:
        base = apks[0]
        warn(f"base.apk not found, using {base.name}")
    return base, [a for a in apks if a != base]


# ── manifest ──────────────────────────────────────────────────────────────────

def analyze_manifest(apktool_dir):
    mp = apktool_dir / "AndroidManifest.xml"
    if not mp.exists():
        warn("AndroidManifest.xml not found"); return {}
    text = mp.read_text(errors="ignore")
    findings = []
    for name,pat,sev,desc in MANIFEST_CHECKS:
        if re.search(pat, text, re.I):
            findings.append({"check":name,"severity":sev,"description":desc,
                              "matches":len(re.findall(pat,text,re.I))})
    try:
        root = ET.parse(mp).getroot()
        ns = "http://schemas.android.com/apk/res/android"
        pkg = root.get("package","unknown")
        ver = root.get(f"{{{ns}}}versionName","unknown")
        perms = [e.get(f"{{{ns}}}name","") for e in root.findall(".//uses-permission")]
        exp = []
        for tag in ("activity","service","receiver","provider"):
            for el in root.findall(f".//{tag}"):
                if el.get(f"{{{ns}}}exported") == "true":
                    exp.append({"type":tag,
                                "name":el.get(f"{{{ns}}}name","?"),
                                "has_filter":el.find("intent-filter") is not None})
    except ET.ParseError:
        pkg,ver,perms,exp = "parse-error","?",[],[]
    return {"package":pkg,"version":ver,"permissions":perms,
            "exported_comps":exp,"findings":findings,"manifest_text":text}

# ── URL extraction ────────────────────────────────────────────────────────────

URL_RE = re.compile(r"(https?://[a-zA-Z0-9.\-_/?=%&+#@:~]+)", re.I)

URL_NOISE = (
    "http://schemas.android.com","http://www.w3.org","https://www.w3.org",
    "https://developer.android.com","https://docs.oracle.com",
    "http://xml.apache.org","https://xml.apache.org",
    "https://kotlinlang.org","https://android.googlesource.com",
    "https://source.android.com","https://github.com/google/",
    "https://github.com/square/","https://github.com/facebook/",
    "http://%","https://%",
)

SDK_URL_DIRS = (
    "org/bouncycastle","org/apache","okhttp3","okio",
    "com/google/android/gms","com/google/firebase",
    "com/facebook","kotlin/","androidx/",
    "com/tencent","com/huawei","com/umeng",
)

def extract_urls(search_dirs):
    urls = set()
    exts = {".java",".kt",".xml",".json",".html",".js",".smali",".txt",".properties"}
    for d in search_dirs:
        if not d.exists(): continue
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix not in exts: continue
            fp = str(f).replace("\\","/")
            if skip_file(fp): continue
            if any(s in fp for s in SDK_URL_DIRS): continue
            try:
                text = f.read_text(errors="ignore")
                for u in URL_RE.findall(text):
                    u = u.rstrip(".,;\"'")
                    if not any(u.startswith(n) for n in URL_NOISE):
                        urls.add(u)
            except Exception: pass
    return sorted(urls)

# ── grep scanning ─────────────────────────────────────────────────────────────

def grep_patterns(search_dirs, patterns):
    exts = {".java",".kt",".xml",".json",".html",".js",".smali",
            ".txt",".gradle",".properties"}
    seen = {}

    for d in search_dirs:
        if not d.exists(): continue
        is_jadx = "jadx" in str(d)
        for f in d.rglob("*"):
            if not f.is_file() or f.suffix not in exts: continue
            rel = str(f.relative_to(d.parent)).replace("\\","/")
            if skip_file(rel): continue
            tp = is_third_party(rel)
            try:
                text  = f.read_text(errors="ignore")
                lines = text.splitlines()
                for pname,pat,sev in patterns:
                    for m in re.finditer(pat, text, re.I|re.M):
                        ln    = text[:m.start()].count("\n")+1
                        ltext = lines[ln-1].strip()[:300] if ln<=len(lines) else ""
                        match = m.group(0)[:150]
                        if is_fp_value(match): continue
                        if tp:
                            if sev not in ("critical",): continue
                            if any(kw in ltext for kw in (
                                "import ","interface ","extends ","implements ",
                                "@interface","* @","* Copyright","* Licensed",
                            )): continue
                        ck = re.sub(r'\.(java|kt|smali)$','',_norm_path(rel))
                        key = (pname, ck)
                        finding = {"type":pname,"severity":sev,"file":rel,
                                   "line":ln,"match":match,"context":ltext,
                                   "third_party":tp}
                        if key not in seen:
                            seen[key] = finding
                        elif is_jadx and not seen[key]["file"].startswith("jadx"):
                            seen[key] = finding
            except Exception: pass
    return list(seen.values())

# ── Firebase security rule tester ────────────────────────────────────────────

def test_firebase_rules(urls: list) -> list:
    firebase_urls = set()
    fb_re = re.compile(r"https?://([a-z0-9][a-z0-9-]{2,})\.firebaseio\.com", re.I)
    for u in urls:
        m = fb_re.search(u)
        if m:
            firebase_urls.add(f"https://{m.group(1)}.firebaseio.com")

    results = []
    for base_url in sorted(firebase_urls):
        probe = f"{base_url}/.json"
        result = {"url": base_url, "probe": probe, "status": None,
                  "vulnerable": False, "response_preview": "", "error": None}
        try:
            req = urllib.request.Request(probe, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = resp.read(512).decode("utf-8", errors="ignore")
                result["status"] = resp.status
                result["response_preview"] = body[:200]
                result["vulnerable"] = (resp.status == 200 and
                                        body.strip() not in ("null", "[]", "{}", ""))
        except urllib.error.HTTPError as e:
            result["status"] = e.code
            result["vulnerable"] = False
            result["error"] = f"HTTP {e.code}"
        except Exception as e:
            result["error"] = str(e)[:100]
        results.append(result)
    return results


# ── certificates ──────────────────────────────────────────────────────────────

def analyze_certs(apk, apktool_dir):
    result = {"apksigner":"","embedded":[]}
    r = subprocess.run(["apksigner","verify","--verbose","--print-certs",str(apk)],
                       capture_output=True, text=True)
    result["apksigner"] = r.stdout+r.stderr
    for ext in ("*.pem","*.crt","*.cer","*.p12","*.bks","*.jks"):
        for f in apktool_dir.rglob(ext):
            result["embedded"].append(str(f))
    pem_re = re.compile(r"-----BEGIN [A-Z ]+-----")
    for f in apktool_dir.rglob("*"):
        if not f.is_file(): continue
        rel = str(f.relative_to(apktool_dir)).replace("\\","/")
        if is_third_party(rel) or skip_file(rel): continue
        try:
            if pem_re.search(f.read_text(errors="ignore")):
                result["embedded"].append(f"{f} (inline PEM block)")
        except Exception: pass
    return result

# ── native libs ───────────────────────────────────────────────────────────────

def analyze_native_libs(apktool_dir):
    lib_dir = apktool_dir/"lib"
    if not lib_dir.exists(): return []
    pat = re.compile(
        r"(AKIA[0-9A-Z]{16}"
        r"|AIza[0-9A-Za-z\-_]{35}"
        r"|sk_live_[0-9A-Za-z]{24}"
        r"|https?://(?!(?:www\.w3\.org|schemas\.android\.com|developer\.android\.com|"
        r"android\.googlesource\.com))[a-zA-Z0-9.\-_/?=%&+#@:~]{15,})", re.I)
    noise = re.compile(
        r"(clang version|Android \(|toolchain|llvm-project|cmake|"
        r"googlesource\.com|build-tools|ninja|gradle)", re.I)
    findings = []
    for so in lib_dir.rglob("*.so"):
        try:
            r = subprocess.run(["strings",str(so)],capture_output=True,text=True,timeout=30)
            for line in r.stdout.splitlines():
                if pat.search(line) and not noise.search(line):
                    findings.append(f"{so.name}: {line.strip()[:150]}")
        except Exception: pass
    return sorted(set(findings))

# ── network security config ───────────────────────────────────────────────────

def analyze_nsc(apktool_dir):
    nsc = apktool_dir/"res"/"xml"/"network_security_config.xml"
    if not nsc.exists():
        return {"found":False,"cleartext":False,"user_certs":False,"raw":""}
    text = nsc.read_text(errors="ignore")
    return {
        "found": True,
        "cleartext":  bool(re.search(r'cleartextTrafficPermitted\s*=\s*"true"',text,re.I)),
        "user_certs": '<certificates src="user"' in text,
        "raw":        text,
    }

# ── summary / output ──────────────────────────────────────────────────────────

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_CLR   = {"critical":RED,"high":YEL,"medium":CYN,"low":DIM,"info":DIM}

def print_summary(results):
    mf = results["manifest"]
    section("RESULTS")
    if mf.get("package"):
        ok(f"package: {mf['package']}  version: {mf['version']}")
        info(f"permissions declared: {len(mf['permissions'])}")
        exps = mf["exported_comps"]
        if exps:
            warn(f"exported components: {len(exps)}")
            for c in exps[:10]:
                flag = " ⚠ intent-filter" if c.get("has_filter") else ""
                print(f"       {DIM}{c['type']}: {c['name']}{flag}{R}")

    section("MANIFEST FINDINGS")
    for f in mf.get("findings",[]):
        c = SEV_CLR.get(f["severity"],R)
        print(f"  {c}[{f['severity'].upper()}]{R} {f['check']} — {f['description']}")

    def split(lst): return ([x for x in lst if not x.get("third_party")],
                            [x for x in lst if x.get("third_party")])

    section("SECRETS & CREDENTIALS")
    app_sec, sdk_sec = split(sorted(results["secrets"],key=lambda x:SEV_ORDER.get(x["severity"],9)))
    if app_sec:
        for f in app_sec:
            print(f"  {SEV_CLR.get(f['severity'],R)}[{f['severity'].upper()}]{R} {f['type']}")
            print(f"       {DIM}file: {f['file']}:{f['line']}{R}")
            print(f"       {DIM}match: {f['match'][:80]}{R}")
    else:
        ok("no secrets found in app code")
    if sdk_sec:
        info(f"{len(sdk_sec)} finding(s) in SDK code (lower confidence — see report.json)")

    section("DANGEROUS API CALLS")
    app_api, sdk_api = split(sorted(results["dangerous_apis"],key=lambda x:SEV_ORDER.get(x["severity"],9)))
    if app_api:
        seen = set()
        for f in app_api:
            key = (f["type"],f["file"])
            if key in seen: continue
            seen.add(key)
            print(f"  {SEV_CLR.get(f['severity'],R)}[{f['severity'].upper()}]{R} {f['type']}")
            print(f"       {DIM}{f['file']}:{f['line']}{R}")
    else:
        ok("no dangerous API patterns found in app code")
    if sdk_api:
        info(f"{len(sdk_api)} API finding(s) in SDK code (see report.json)")

    section("NETWORK")
    nsc = results.get("nsc",{})
    if nsc.get("cleartext"):
        warn("[HIGH] cleartext HTTP permitted in network_security_config.xml")
    if nsc.get("user_certs"):
        warn("[HIGH] user certs trusted — Burp MITM works without Frida")
    urls = results.get("urls",[])
    info(f"unique URLs/endpoints: {len(urls)}")
    for u in urls[:20]: print(f"       {DIM}{u}{R}")
    if len(urls)>20: print(f"       {DIM}... and {len(urls)-20} more (urls.txt){R}")

    section("CERTIFICATES")
    emb = results.get("certs",{}).get("embedded",[])
    if emb:
        warn(f"embedded cert/key files: {len(emb)}")
        for e in emb[:10]: print(f"       {DIM}{e}{R}")
    else:
        ok("no embedded cert/key files found")

    section("NATIVE LIBS")
    nat = results.get("native_strings",[])
    if nat:
        warn(f"suspicious strings in .so files: {len(nat)}")
        for s in nat[:10]: print(f"       {DIM}{s}{R}")
    else:
        ok("no suspicious strings in native libraries")

    section("FIREBASE SECURITY RULES")
    fb = results.get("firebase", [])
    if fb:
        vuln = [r for r in fb if r.get("vulnerable")]
        if vuln:
            for r in vuln:
                warn(f"[CRITICAL] open read access: {r['url']}")
                print(f"       {DIM}response: {r.get('response_preview','')[:80]}{R}")
        else:
            ok(f"tested {len(fb)} Firebase URL(s) — none open")
    else:
        info("no Firebase URLs found (or testing skipped)")

    section("POC INTENTS")
    pocs = results.get("poc_intents", [])
    if pocs:
        info(f"{len(pocs)} exported component(s) — poc_intents.sh written")
        for poc in pocs[:8]:
            c = YEL if poc["has_filter"] else DIM
            print(f"  {c}[{poc['type']}]{R} {poc['name']}")
            print(f"       {DIM}{poc['commands'][0]}{R}")
        if len(pocs) > 8:
            print(f"       {DIM}... and {len(pocs)-8} more — see poc_intents.sh{R}")
    else:
        ok("no exported components found")

    section("STATS")
    all_f = results["secrets"]+results["dangerous_apis"]
    app_f = [f for f in all_f if not f.get("third_party")]
    sdk_f = [f for f in all_f if f.get("third_party")]
    for sev,clr in [("critical",RED),("high",YEL),("medium",CYN)]:
        n = sum(1 for f in app_f if f["severity"]==sev)
        print(f"  {f'app {sev}':18} {clr}{n}{R}")
    print(f"  {'sdk findings':18} {DIM}{len(sdk_f)} (low confidence){R}")
    print(f"  {'urls':18} {len(urls)}")
    print(f"  {'secrets (app)':18} {len(app_sec)}")
    print(f"  {'api issues (app)':18} {len(app_api)}")

# ── PoC intent generator ──────────────────────────────────────────────────────

def generate_poc_intents(manifest: dict) -> list:
    pkg     = manifest.get("package", "com.example.app")
    pocs    = []
    for comp in manifest.get("exported_comps", []):
        ctype  = comp["type"]
        cname  = comp["name"]
        has_filter = comp.get("has_filter", False)
        full_name = cname if "." in cname[1:] else pkg + cname
        cmds = []

        if ctype == "activity":
            cmds.append(f"adb shell am start -n {pkg}/{full_name}")
            cmds.append(f'adb shell am start -n {pkg}/{full_name} -d "https://attacker.com"')
            cmds.append(f'adb shell am start -n {pkg}/{full_name} --es "url" "https://attacker.com" --es "token" "test123"')
            if has_filter:
                cmds.append(f'adb shell am start -a android.intent.action.VIEW -d "https://attacker.com" -n {pkg}/{full_name}')

        elif ctype == "service":
            cmds.append(f"adb shell am startservice -n {pkg}/{full_name}")
            cmds.append(f'adb shell am startservice -n {pkg}/{full_name} --es "cmd" "test"')

        elif ctype == "receiver":
            cmds.append(f"adb shell am broadcast -n {pkg}/{full_name}")
            cmds.append(f'adb shell am broadcast -n {pkg}/{full_name} --es "data" "test"')
            if has_filter:
                cmds.append(f"adb shell am broadcast -a android.intent.action.BOOT_COMPLETED -n {pkg}/{full_name}")

        elif ctype == "provider":
            cmds.append(f'adb shell content query --uri "content://{pkg}.provider/"')
            cmds.append(f'adb shell content query --uri "content://{pkg}/"')

        pocs.append({
            "type":       ctype,
            "name":       full_name,
            "package":    pkg,
            "has_filter": has_filter,
            "commands":   cmds,
            "risk_note":  _poc_risk_note(ctype, has_filter),
        })
    return pocs

def _poc_risk_note(ctype: str, has_filter: bool) -> str:
    notes = {
        "activity": ("Exported activity with intent-filter — any app can launch it with arbitrary URI/extras. "
                     "If it loads a WebView with the URI, this may be exploitable for XSS or open redirect."
                     if has_filter else
                     "Exported activity without intent-filter — can still be launched by any app on the device. "
                     "Test for privilege escalation or unintended data access."),
        "service":  ("Exported service — any app can bind to or start it. "
                     "Check if it performs privileged operations based on intent extras."),
        "receiver": ("Exported broadcast receiver — any app can send it intents. "
                     "Check for permission bypass or state manipulation."),
        "provider": ("Exported content provider — may expose app data to other apps. "
                     "Test for path traversal, SQL injection, or unauthenticated data access."),
    }
    return notes.get(ctype, "Exported component — review for permission bypass.")

def save_poc_intents(pocs: list, out: Path):
    if not pocs:
        return
    lines = [
        "#!/usr/bin/env bash",
        "# poc_intents.sh — auto-generated PoC intent tests",
        "# generated by apk-hunter",
        "# run against a connected device/emulator with adb",
        "",
        "set -e",
        'echo "[*] starting PoC intent tests"',
        'echo "[*] make sure device is connected: adb devices"',
        "",
    ]
    for poc in pocs:
        lines.append(f"# ── {poc['type'].upper()}: {poc['name']} ──────────────────────────")
        lines.append(f"# {poc['risk_note']}")
        lines.append("")
        for cmd in poc["commands"]:
            lines.append(f'echo ">>> {cmd}"')
            lines.append(cmd)
            lines.append('sleep 1')
            lines.append("")
    lines.append('echo "[+] done"')

    script = out / "poc_intents.sh"
    script.write_text("\n".join(lines))
    ok(f"PoC intents:  {script}  ({len(pocs)} components, {sum(len(p['commands']) for p in pocs)} commands)")


def save_outputs(results, out):
    clean = dict(results)
    if "manifest_text" in clean.get("manifest",{}):
        clean["manifest"] = {k:v for k,v in clean["manifest"].items() if k!="manifest_text"}
    (out/"report.json").write_text(json.dumps(clean,indent=2,default=str))
    ok(f"JSON report:  {out/'report.json'}")
    (out/"urls.txt").write_text("\n".join(results.get("urls",[])))
    ok(f"URLs list:    {out/'urls.txt'}")
    def split(lst): return ([x for x in lst if not x.get("third_party")],
                            [x for x in lst if x.get("third_party")])
    app_sec, sdk_sec = split(results.get("secrets",[]))
    lines = ["=== APP CODE FINDINGS ===\n"]
    for f in sorted(app_sec,key=lambda x:SEV_ORDER.get(x["severity"],9)):
        lines += [f"[{f['severity'].upper()}] {f['type']}",
                  f"  file:  {f['file']}:{f['line']}",
                  f"  match: {f['match']}",""]
    lines += ["\n=== SDK / THIRD-PARTY (lower confidence) ===\n"]
    for f in sorted(sdk_sec,key=lambda x:SEV_ORDER.get(x["severity"],9)):
        lines += [f"[{f['severity'].upper()}] {f['type']}",
                  f"  file:  {f['file']}:{f['line']}",
                  f"  match: {f['match']}",""]
    (out/"secrets.txt").write_text("\n".join(lines))
    ok(f"Secrets:      {out/'secrets.txt'}")
    if results.get("poc_intents"):
        save_poc_intents(results["poc_intents"], out)
    fb = results.get("firebase", [])
    if fb:
        fb_lines = []
        for r in fb:
            status = "VULNERABLE" if r.get("vulnerable") else f"safe ({r.get('status','?')})"
            fb_lines.append(f"[{status}] {r['url']}")
            if r.get("error"): fb_lines.append(f"  error: {r['error']}")
            if r.get("vulnerable"): fb_lines.append(f"  response: {r.get('response_preview','')[:100]}")
        (out/"firebase_results.txt").write_text("\n".join(fb_lines))
        ok(f"Firebase:     {out/'firebase_results.txt'}")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="APK static analysis for bug bounty",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__)
    p.add_argument("apk")
    p.add_argument("-o","--output",         help="output dir (default: recon_<name>)")
    p.add_argument("--jadx-path",           default="jadx")
    p.add_argument("--no-html",             action="store_true")
    p.add_argument("--no-jadx",             action="store_true")
    p.add_argument("--jadx-xmx",            default="3g")
    p.add_argument("--jadx-threads",        default=4, type=int)
    p.add_argument("--json-only",           action="store_true")
    p.add_argument("--include-sdk",         action="store_true",
                   help="include all SDK/third-party findings (more noise)")
    p.add_argument("--apkleaks",            nargs="?", const="auto", default=None,
                   metavar="FILE",
                   help="load extra patterns from apkleaks regexes.json "
                        "(auto=download from GitHub, or pass local file path)")
    p.add_argument("--no-firebase",         action="store_true",
                   help="skip Firebase security rule testing (saves time if no internet)")
    args = p.parse_args()

    apk = Path(args.apk).resolve()
    if not apk.exists():
        err(f"file not found: {apk}"); sys.exit(1)
    if apk.suffix not in (".apk",".apkm"):
        warn("unexpected extension, continuing")

    base = apk.stem
    out  = Path(args.output) if args.output else Path(f"recon_{base}")
    out.mkdir(parents=True, exist_ok=True)

    if not args.json_only:
        banner()
        print(f"  {DIM}target    : {apk.name}{R}")
        print(f"  {DIM}output    : {out}/{R}")
        print(f"  {DIM}time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}")
        print(f"  {DIM}sdk noise : {'included' if args.include_sdk else 'filtered'}{R}\n")

    section("CHECKING TOOLS")
    tools = require_tools(args.jadx_path)

    section("DECOMPILING")
    extra_apks = []
    if apk.suffix == ".apkm":
        apk, extra_apks = extract_apkm(apk, out)
        info(f"primary APK: {apk.name}  |  extra splits: {len(extra_apks)}")

    apktool_dir = decompile_apktool(apk, out)
    jadx_dir = None
    if not args.no_jadx and tools.get("jadx"):
        jadx_dir = decompile_jadx(apk, out, args.jadx_path,
                                   xmx=args.jadx_xmx, threads=args.jadx_threads)
    for i, split_apk in enumerate(extra_apks[:5]):
        split_out = out / f"split_{i}_{split_apk.stem}"
        info(f"scanning split APK: {split_apk.name}")
        split_apktool = decompile_apktool(split_apk, split_out)
        if not args.no_jadx and tools.get("jadx"):
            decompile_jadx(split_apk, split_out, args.jadx_path,
                           xmx=args.jadx_xmx, threads=args.jadx_threads)

    search_dirs = [d for d in [jadx_dir, apktool_dir] if d and d.exists()]
    for i in range(len(extra_apks[:5])):
        for subdir in (out / f"split_{i}_*").parent.glob(f"split_{i}_*"):
            search_dirs.extend([subdir/"jadx", subdir/"apktool"])
    search_dirs = [d for d in search_dirs if d and d.exists()]

    section("ANALYZING MANIFEST")
    manifest = analyze_manifest(apktool_dir)

    section("EXTRACTING URLS")
    urls = extract_urls(search_dirs)

    section("SCANNING FOR SECRETS")
    secret_patterns = list(SECRET_PATTERNS)
    if args.apkleaks:
        extra = load_apkleaks_patterns(args.apkleaks if args.apkleaks != "auto" else None)
        secret_patterns.extend(extra)
    secrets = grep_patterns(search_dirs, secret_patterns)

    section("SCANNING FOR DANGEROUS APIS")
    dangerous_apis = grep_patterns(search_dirs, DANGEROUS_API_PATTERNS)

    if not args.include_sdk:
        secrets        = [f for f in secrets        if not f.get("third_party")]
        dangerous_apis = [f for f in dangerous_apis if not f.get("third_party")]

    section("ANALYZING CERTIFICATES")
    certs = analyze_certs(apk, apktool_dir)

    section("ANALYZING NATIVE LIBRARIES")
    native_strings = analyze_native_libs(apktool_dir)

    section("ANALYZING NETWORK SECURITY CONFIG")
    nsc = analyze_nsc(apktool_dir)

    section("TESTING FIREBASE RULES")
    firebase_results = []
    if not args.no_firebase:
        firebase_results = test_firebase_rules(urls)
        vuln = [r for r in firebase_results if r.get("vulnerable")]
        if vuln:
            for r in vuln:
                warn(f"[CRITICAL] Firebase open read: {r['url']}")
                print(f"       {DIM}probe: {r['probe']}{R}")
                print(f"       {DIM}response: {r['response_preview'][:80]}{R}")
        elif firebase_results:
            ok(f"tested {len(firebase_results)} Firebase URL(s) — none open")
        else:
            info("no Firebase URLs found to test")
    else:
        info("Firebase testing skipped (--no-firebase)")

    section("GENERATING POC INTENTS")
    pocs = generate_poc_intents(manifest)
    info(f"generated PoC commands for {len(pocs)} exported component(s)")

    results = {
        "meta":         {"apk":apk.name,"timestamp":datetime.now().isoformat(),
                         "output":str(out),"sdk_filtered":not args.include_sdk},
        "manifest":     manifest,
        "urls":         urls,
        "secrets":      secrets,
        "dangerous_apis": dangerous_apis,
        "certs":        certs,
        "native_strings": native_strings,
        "nsc":          nsc,
        "firebase":     firebase_results,
        "poc_intents":  pocs,
    }

    section("SAVING OUTPUT")
    save_outputs(results, out)
    if not args.no_html:
        try:
            from html_report import render
            (out/"report.html").write_text(render(results, apk.name))
            ok(f"HTML report:  {out/'report.html'}")
        except Exception as e:
            warn(f"HTML report failed: {e}")

    if not args.json_only:
        print_summary(results)

    print(f"\n{GRN}{B}done. output: {out}/{R}\n")

if __name__ == "__main__":
    main()
