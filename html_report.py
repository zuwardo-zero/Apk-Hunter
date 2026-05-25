"""
html_report.py — generates a self-contained interactive HTML report
from apk_hunter.py results dict.
"""

from datetime import datetime

SEVERITY_COLOR = {
    "critical": "#e53935",
    "high":     "#f57c00",
    "medium":   "#f9a825",
    "low":      "#43a047",
    "info":     "#1e88e5",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _badge(severity):
    color = SEVERITY_COLOR.get(severity, "#888")
    return f'<span class="badge" style="background:{color}">{severity.upper()}</span>'

def _esc(s):
    return (str(s).replace("&","&amp;").replace("<","&lt;")
            .replace(">","&gt;").replace('"',"&quot;"))

def _counts(items):
    c = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for i in items:
        s = i.get("severity","info")
        c[s] = c.get(s,0)+1
    return c

def render(results, apk_name):
    meta         = results.get("meta", {})
    manifest     = results.get("manifest", {})
    all_secrets  = results.get("secrets", [])
    all_apis     = results.get("dangerous_apis", [])
    urls         = results.get("urls", [])
    certs        = results.get("certs", {})
    native       = results.get("native_strings", [])
    nsc          = results.get("nsc", {})
    firebase     = results.get("firebase", [])
    pocs         = results.get("poc_intents", [])
    timestamp    = meta.get("timestamp", datetime.now().isoformat())
    sdk_filtered = meta.get("sdk_filtered", True)

    # Split app vs SDK
    app_secrets = [f for f in all_secrets  if not f.get("third_party")]
    sdk_secrets = [f for f in all_secrets  if f.get("third_party")]
    app_apis    = [f for f in all_apis     if not f.get("third_party")]
    sdk_apis    = [f for f in all_apis     if f.get("third_party")]

    srt = lambda lst: sorted(lst, key=lambda x: SEVERITY_ORDER.get(x.get("severity"), 9))

    total_app   = len(app_secrets) + len(app_apis)
    crit_count  = sum(1 for f in app_secrets+app_apis if f.get("severity")=="critical")
    high_count  = sum(1 for f in app_secrets+app_apis if f.get("severity")=="high")

    # ── manifest rows ─────────────────────────────────────────────────────────
    mf_rows = "".join(
        f"<tr><td>{_badge(f['severity'])}</td>"
        f"<td><strong>{_esc(f['check'])}</strong></td>"
        f"<td>{_esc(f['description'])}</td>"
        f"<td>{f['matches']}</td></tr>"
        for f in manifest.get("findings", [])
    )

    exp_rows = "".join(
        f"<tr><td><code>{_esc(c['type'])}</code></td>"
        f"<td><code>{_esc(c['name'])}</code></td>"
        f"<td>{'⚠ Yes' if c.get('has_filter') else '—'}</td></tr>"
        for c in manifest.get("exported_comps", [])
    )

    DANGER_PERMS = {
        "READ_SMS","SEND_SMS","RECEIVE_SMS","READ_CONTACTS","READ_CALL_LOG",
        "RECORD_AUDIO","CAMERA","ACCESS_FINE_LOCATION","READ_EXTERNAL_STORAGE",
        "WRITE_EXTERNAL_STORAGE","PROCESS_OUTGOING_CALLS","READ_PHONE_STATE",
    }
    perms_html = "".join(
        f"<li><code>{_esc(p)}</code>"
        f"{'<span class=\"perm-danger\">⚠ dangerous</span>' if p.split('.')[-1] in DANGER_PERMS else ''}"
        f"</li>"
        for p in manifest.get("permissions", [])
    )

    # ── findings rows ─────────────────────────────────────────────────────────
    def findings_rows(items, limit=500):
        rows = []
        for f in srt(items)[:limit]:
            tp_tag = ' <span class="sdk-tag">SDK</span>' if f.get("third_party") else ""
            rows.append(
                f"<tr>"
                f"<td>{_badge(f['severity'])}</td>"
                f"<td>{_esc(f['type'])}{tp_tag}</td>"
                f"<td><code class='filepath'>{_esc(f['file'])}:{f['line']}</code></td>"
                f"<td><code class='match'>{_esc(f['match'][:120])}</code></td>"
                f"</tr>"
            )
        return "".join(rows)

    secret_rows_app = findings_rows(app_secrets)
    secret_rows_sdk = findings_rows(sdk_secrets[:100])
    api_rows_app    = findings_rows(app_apis)
    api_rows_sdk    = findings_rows(sdk_apis[:100])

    # ── URLs ──────────────────────────────────────────────────────────────────
    url_items = "\n".join(
        f'<li><a href="{_esc(u)}" target="_blank" rel="noopener">{_esc(u)}</a></li>'
        for u in urls[:500]
    )

    # ── native ────────────────────────────────────────────────────────────────
    native_items = "\n".join(f"<li><code>{_esc(s)}</code></li>" for s in native[:100])

    # firebase results rows
    firebase_rows = ""
    for r in firebase:
        vuln = r.get("vulnerable", False)
        status_html = ('<span style="color:#e53935;font-weight:600">⚠ VULNERABLE</span>'
                       if vuln else
                       f'<span style="color:#43a047">✓ Safe ({_esc(str(r.get("status","?")))})</span>')
        preview = _esc(r.get("response_preview","")[:80]) if vuln else ""
        error   = _esc(r.get("error","")) if r.get("error") else ""
        firebase_rows += (
            f"<tr>"
            f"<td><a href='{_esc(r['url'])}' target='_blank'>{_esc(r['url'])}</a></td>"
            f"<td>{status_html}</td>"
            f"<td><code>{_esc(r.get('probe',''))}</code></td>"
            f"<td><code>{preview or error}</code></td>"
            f"</tr>"
        )
    fb_vuln_count = sum(1 for r in firebase if r.get("vulnerable"))

    # PoC rows
    poc_rows = ""
    for poc in pocs:
        cmds_html = "<br>".join(f"<code>{_esc(c)}</code>" for c in poc["commands"])
        risk_cls = "badge-crit" if poc.get("has_filter") else "badge-high"
        poc_rows += (
            f"<tr>"
            f"<td><span class='badge {risk_cls}'>{_esc(poc['type'])}</span></td>"
            f"<td><code>{_esc(poc['name'])}</code></td>"
            f"<td>{'⚠ Yes' if poc.get('has_filter') else '—'}</td>"
            f"<td style='font-size:11px'>{cmds_html}</td>"
            f"</tr>"
        )


    # ── certs ─────────────────────────────────────────────────────────────────
    cert_items = "\n".join(f"<li><code>{_esc(c)}</code></li>" for c in certs.get("embedded", []))
    cert_raw   = _esc(certs.get("apksigner", "apksigner not available")[:3000])

    # ── NSC ───────────────────────────────────────────────────────────────────
    nsc_clear    = "⚠ YES — cleartext HTTP permitted" if nsc.get("cleartext") else "✓ Not found"
    nsc_user     = "⚠ YES — user cert store trusted (Burp-ready!)" if nsc.get("user_certs") else "✓ Not found"
    nsc_raw      = _esc(nsc.get("raw", "network_security_config.xml not found"))

    sdk_notice = (
        f'<div class="alert alert-blue">SDK findings filtered. '
        f'{len(sdk_secrets)} secret(s) and {len(sdk_apis)} API finding(s) in third-party code '
        f'are hidden by default — run with <code>--include-sdk</code> to see them.</div>'
        if sdk_filtered else
        '<div class="alert alert-orange">SDK findings included. '
        'Expect higher noise — focus on <code>com/&lt;apppackage&gt;/</code> paths.</div>'
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>APK Hunter Report — {_esc(apk_name)}</title>
<style>
:root{{
  --bg:#0d1117;--bg2:#161b22;--bg3:#21262d;
  --bd:#30363d;--bd2:#444c56;
  --tx:#e6edf3;--tx2:#8b949e;
  --red:#e53935;--ora:#f57c00;--yel:#f9a825;
  --grn:#43a047;--blu:#1e88e5;--acc:#e53935;
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--tx);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px;line-height:1.6}}
a{{color:var(--blu);text-decoration:none}}a:hover{{text-decoration:underline}}
code{{font-family:"SFMono-Regular",Consolas,monospace;font-size:12px;background:var(--bg3);padding:1px 5px;border-radius:4px}}
.filepath{{color:#8b949e}}.match{{color:#ffa657;word-break:break-all}}

/* layout */
.sidebar{{position:fixed;left:0;top:0;height:100vh;width:220px;background:var(--bg2);border-right:1px solid var(--bd);overflow-y:auto;z-index:100}}
.sidebar-logo{{padding:20px 16px 12px;border-bottom:1px solid var(--bd)}}
.sidebar-logo h1{{font-size:15px;font-weight:600;color:var(--acc)}}
.sidebar-logo p{{font-size:11px;color:var(--tx2);margin-top:2px;word-break:break-all}}
.sidebar nav a{{display:flex;align-items:center;justify-content:space-between;padding:8px 16px;color:var(--tx2);font-size:13px;border-left:2px solid transparent;transition:all .15s}}
.sidebar nav a:hover,.sidebar nav a.active{{color:var(--tx);background:var(--bg3);border-left-color:var(--acc);text-decoration:none}}
.sidebar nav a .cnt{{font-size:11px;background:var(--bg3);padding:1px 6px;border-radius:10px}}
.sidebar nav a.active .cnt{{background:var(--bg)}}
.nav-section{{padding:12px 16px 4px;font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:var(--tx2)}}
.main{{margin-left:220px;padding:32px;max-width:1100px}}

/* stat grid */
.stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:28px}}
.stat-card{{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:16px}}
.stat-card .val{{font-size:28px;font-weight:700;line-height:1}}
.stat-card .lbl{{font-size:12px;color:var(--tx2);margin-top:4px}}
.crit .val{{color:var(--red)}}.high_ .val{{color:var(--ora)}}.med_ .val{{color:var(--yel)}}.blu_ .val{{color:var(--blu)}}

/* section */
.section{{margin-bottom:40px;scroll-margin-top:24px}}
.section-title{{font-size:16px;font-weight:600;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--bd);display:flex;align-items:center;gap:8px}}

/* table */
.table-wrap{{overflow-x:auto;border-radius:8px;border:1px solid var(--bd)}}
table{{width:100%;border-collapse:collapse}}
th{{background:var(--bg3);color:var(--tx2);font-size:11px;text-transform:uppercase;letter-spacing:.06em;padding:10px 12px;text-align:left;font-weight:500}}
td{{padding:9px 12px;border-top:1px solid var(--bd);vertical-align:top;font-size:13px}}
tr:hover td{{background:var(--bg3)}}
.empty{{padding:20px;color:var(--tx2);font-size:13px;text-align:center;background:var(--bg2)}}

/* badge */
.badge{{display:inline-block;font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;color:#fff;white-space:nowrap}}
.sdk-tag{{font-size:10px;padding:1px 5px;border-radius:3px;background:var(--bg3);color:var(--tx2);margin-left:4px;border:1px solid var(--bd)}}

/* list */
.plain-list{{list-style:none;background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:0;max-height:320px;overflow-y:auto}}
.plain-list li{{padding:6px 14px;border-bottom:1px solid var(--bd);font-size:12px}}
.plain-list li:last-child{{border-bottom:none}}

/* info box */
.info-box{{background:var(--bg2);border:1px solid var(--bd);border-radius:8px;padding:16px}}
.info-box table{{border:none}}
.info-box td{{border-top:1px solid var(--bd);padding:6px 8px}}
.info-box tr:first-child td{{border-top:none}}
.info-box td:first-child{{color:var(--tx2);width:180px;font-size:12px}}
.perm-danger{{font-size:10px;background:#e5393520;color:var(--red);padding:1px 6px;border-radius:3px;margin-left:6px}}

/* alerts */
.alert{{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:12px}}
.alert-red{{background:#e5393520;border:1px solid #e5393540;color:#ff8a80}}
.alert-orange{{background:#f57c0020;border:1px solid #f57c0040;color:#ffcc80}}
.alert-green{{background:#43a04720;border:1px solid #43a04740;color:#a5d6a7}}
.alert-blue{{background:#1e88e520;border:1px solid #1e88e540;color:#90caf9}}

/* tabs */
.tab-bar{{display:flex;border-bottom:1px solid var(--bd);margin-bottom:16px}}
.tab-btn{{padding:8px 16px;font-size:13px;background:none;border:none;border-bottom:2px solid transparent;color:var(--tx2);cursor:pointer;margin-bottom:-1px}}
.tab-btn.active{{color:var(--tx);border-bottom-color:var(--acc)}}
.tab-pane{{display:none}}.tab-pane.active{{display:block}}

/* search */
.search-bar{{margin-bottom:12px}}
.search-bar input{{width:100%;padding:8px 12px;background:var(--bg3);border:1px solid var(--bd);border-radius:6px;color:var(--tx);font-size:13px;outline:none}}
.search-bar input:focus{{border-color:var(--acc)}}

/* pre */
pre{{background:var(--bg3);border:1px solid var(--bd);border-radius:8px;padding:14px;font-size:11px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:var(--tx2)}}

@media(max-width:768px){{.sidebar{{display:none}}.main{{margin-left:0;padding:16px}}}}
</style>
</head>
<body>

<nav class="sidebar">
  <div class="sidebar-logo">
    <h1>🔍 APK Hunter </h1>
    <p>{_esc(apk_name)}</p>
    <p style="margin-top:4px;font-size:10px">{_esc(timestamp[:19].replace("T"," "))}</p>
  </div>
  <nav>
    <div class="nav-section">overview</div>
    <a href="#summary">📊 Summary</a>
    <a href="#manifest">📄 Manifest</a>
    <div class="nav-section">findings</div>
    <a href="#secrets">🔑 Secrets <span class="cnt">{len(app_secrets)}</span></a>
    <a href="#apis">⚠️ Dangerous APIs <span class="cnt">{len(app_apis)}</span></a>
    <div class="nav-section">recon</div>
    <a href="#urls">🌐 URLs <span class="cnt">{len(urls)}</span></a>
    <a href="#certs">🔐 Certificates</a>
    <a href="#network">📡 Network Config</a>
    <a href="#native">🦾 Native Libs</a>
    <a href="#firebase">🔥 Firebase <span class="cnt">{len(firebase)}</span></a>
    <a href="#poc">🎯 PoC Intents <span class="cnt">{len(pocs)}</span></a>
  </nav>
</nav>

<main class="main">

<!-- SUMMARY -->
<div class="section" id="summary">
  <div class="section-title">📊 Summary</div>
  <div class="stat-grid">
    <div class="stat-card crit"><div class="val">{crit_count}</div><div class="lbl">Critical</div></div>
    <div class="stat-card high_"><div class="val">{high_count}</div><div class="lbl">High</div></div>
    <div class="stat-card med_"><div class="val">{sum(1 for f in app_secrets+app_apis if f.get("severity")=="medium")}</div><div class="lbl">Medium</div></div>
    <div class="stat-card blu_"><div class="val">{total_app}</div><div class="lbl">App findings</div></div>
    <div class="stat-card blu_"><div class="val">{len(urls)}</div><div class="lbl">Endpoints</div></div>
    <div class="stat-card blu_"><div class="val">{len(manifest.get("exported_comps",[]))}</div><div class="lbl">Exported comps</div></div>
  </div>
  {sdk_notice}
  <div class="info-box">
    <table>
      <tr><td>Package</td><td><code>{_esc(manifest.get("package","?"))}</code></td></tr>
      <tr><td>Version</td><td><code>{_esc(manifest.get("version","?"))}</code></td></tr>
      <tr><td>APK file</td><td><code>{_esc(apk_name)}</code></td></tr>
      <tr><td>Report generated</td><td>{_esc(timestamp[:19].replace("T"," "))}</td></tr>
      <tr><td>SDK noise filter</td><td>{"On (default)" if sdk_filtered else "Off (--include-sdk)"}</td></tr>
    </table>
  </div>
</div>

<!-- MANIFEST -->
<div class="section" id="manifest">
  <div class="section-title">📄 AndroidManifest.xml</div>
  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab(this,'mf-findings')">Security Findings</button>
    <button class="tab-btn" onclick="switchTab(this,'mf-exported')">Exported Components ({len(manifest.get("exported_comps",[]))})</button>
    <button class="tab-btn" onclick="switchTab(this,'mf-perms')">Permissions ({len(manifest.get("permissions",[]))})</button>
  </div>
  <div class="tab-pane active" id="mf-findings">
    {"<div class='table-wrap'><table><thead><tr><th>Severity</th><th>Check</th><th>Description</th><th>Matches</th></tr></thead><tbody>"+mf_rows+"</tbody></table></div>" if mf_rows else "<div class='empty'>✓ No manifest security issues</div>"}
  </div>
  <div class="tab-pane" id="mf-exported">
    {"<div class='table-wrap'><table><thead><tr><th>Type</th><th>Component</th><th>Intent Filter</th></tr></thead><tbody>"+exp_rows+"</tbody></table></div>" if exp_rows else "<div class='empty'>No exported components</div>"}
  </div>
  <div class="tab-pane" id="mf-perms">
    <ul class="plain-list">{perms_html or "<li>No permissions declared</li>"}</ul>
  </div>
</div>

<!-- SECRETS -->
<div class="section" id="secrets">
  <div class="section-title">🔑 Secrets &amp; Credentials</div>
  {"<div class='alert alert-red'>⚠ "+str(sum(1 for f in app_secrets if f.get("severity")=="critical"))+" critical and "+str(sum(1 for f in app_secrets if f.get("severity")=="high"))+" high severity secrets found in app code</div>" if app_secrets else "<div class='alert alert-green'>✓ No secrets found in app code</div>"}
  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab(this,'sec-app')">App Code ({len(app_secrets)})</button>
    <button class="tab-btn" onclick="switchTab(this,'sec-sdk')">SDK / Third-party ({len(sdk_secrets)}) ↓ lower confidence</button>
  </div>
  <div class="tab-pane active" id="sec-app">
    <div class="search-bar"><input type="text" placeholder="filter..." oninput="filterTable(this,'sec-app-tbl')"></div>
    {"<div class='table-wrap'><table id='sec-app-tbl'><thead><tr><th>Severity</th><th>Type</th><th>File:Line</th><th>Match</th></tr></thead><tbody>"+secret_rows_app+"</tbody></table></div>" if secret_rows_app else "<div class='empty'>✓ No secrets in app code</div>"}
  </div>
  <div class="tab-pane" id="sec-sdk">
    <div class="search-bar"><input type="text" placeholder="filter..." oninput="filterTable(this,'sec-sdk-tbl')"></div>
    {"<div class='table-wrap'><table id='sec-sdk-tbl'><thead><tr><th>Severity</th><th>Type</th><th>File:Line</th><th>Match</th></tr></thead><tbody>"+secret_rows_sdk+"</tbody></table></div>" if secret_rows_sdk else "<div class='empty'>No SDK secrets found</div>"}
  </div>
</div>

<!-- DANGEROUS APIS -->
<div class="section" id="apis">
  <div class="section-title">⚠️ Dangerous API Calls</div>
  {"<div class='alert alert-orange'>"+str(sum(1 for f in app_apis if f.get("severity") in ("critical","high")))+" high-priority API patterns in app code</div>" if app_apis else ""}
  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab(this,'api-app')">App Code ({len(app_apis)})</button>
    <button class="tab-btn" onclick="switchTab(this,'api-sdk')">SDK / Third-party ({len(sdk_apis)}) ↓ lower confidence</button>
  </div>
  <div class="tab-pane active" id="api-app">
    <div class="search-bar"><input type="text" placeholder="filter..." oninput="filterTable(this,'api-app-tbl')"></div>
    {"<div class='table-wrap'><table id='api-app-tbl'><thead><tr><th>Severity</th><th>Pattern</th><th>File:Line</th><th>Context</th></tr></thead><tbody>"+api_rows_app+"</tbody></table></div>" if api_rows_app else "<div class='empty'>✓ No dangerous API patterns in app code</div>"}
  </div>
  <div class="tab-pane" id="api-sdk">
    <div class="search-bar"><input type="text" placeholder="filter..." oninput="filterTable(this,'api-sdk-tbl')"></div>
    {"<div class='table-wrap'><table id='api-sdk-tbl'><thead><tr><th>Severity</th><th>Pattern</th><th>File:Line</th><th>Context</th></tr></thead><tbody>"+api_rows_sdk+"</tbody></table></div>" if api_rows_sdk else "<div class='empty'>No SDK API findings</div>"}
  </div>
</div>

<!-- URLS -->
<div class="section" id="urls">
  <div class="section-title">🌐 Endpoints &amp; URLs ({len(urls)})</div>
  <div class="search-bar"><input type="text" placeholder="filter URLs..." oninput="filterList(this,'url-list')"></div>
  <ul class="plain-list" id="url-list">
    {url_items or "<li>No URLs found</li>"}
  </ul>
  {"<p style='margin-top:8px;font-size:12px;color:var(--tx2)'>Showing first 500 of "+str(len(urls))+" — see urls.txt for full list</p>" if len(urls)>500 else ""}
</div>

<!-- CERTS -->
<div class="section" id="certs">
  <div class="section-title">🔐 Certificate Analysis</div>
  {"<div class='alert alert-orange'>Embedded certificate/key files found</div>" if certs.get("embedded") else ""}
  <div class="tab-bar">
    <button class="tab-btn active" onclick="switchTab(this,'cert-sig')">APK Signer</button>
    <button class="tab-btn" onclick="switchTab(this,'cert-emb')">Embedded Files ({len(certs.get("embedded",[]))})</button>
  </div>
  <div class="tab-pane active" id="cert-sig"><pre>{cert_raw}</pre></div>
  <div class="tab-pane" id="cert-emb">
    {"<ul class='plain-list'>"+cert_items+"</ul>" if cert_items else "<div class='empty'>✓ No embedded cert/key files</div>"}
  </div>
</div>

<!-- NETWORK -->
<div class="section" id="network">
  <div class="section-title">📡 Network Security Config</div>
  {"<div class='alert alert-red'>network_security_config.xml not found — app may rely on manifest cleartext flag</div>" if not nsc.get("found") else ""}
  <div class="info-box" style="margin-bottom:16px">
    <table>
      <tr><td>Config file</td><td>{"✓ Found" if nsc.get("found") else "✗ Not found"}</td></tr>
      <tr><td>Cleartext HTTP</td><td style="color:{'var(--red)' if nsc.get('cleartext') else 'var(--grn)'}">{nsc_clear}</td></tr>
      <tr><td>User certs trusted</td><td style="color:{'var(--red)' if nsc.get('user_certs') else 'var(--grn)'}">{nsc_user}</td></tr>
    </table>
  </div>
  {"<pre>"+nsc_raw+"</pre>" if nsc.get("raw") else ""}
</div>

<!-- NATIVE -->
<div class="section" id="native">
  <div class="section-title">🦾 Native Library Strings</div>
  {"<div class='alert alert-orange'>"+str(len(native))+" suspicious strings in .so files</div>" if native else "<div class='alert alert-green'>✓ No suspicious strings in native libraries</div>"}
  {"<ul class='plain-list'>"+native_items+"</ul>" if native_items else ""}
</div>


<!-- FIREBASE -->
<div class="section" id="firebase">
  <div class="section-title">🔥 Firebase Security Rules</div>
  {f"<div class='alert alert-red'>⚠ {fb_vuln_count} Firebase database(s) open to unauthenticated read</div>" if fb_vuln_count else ""}
  {f"<div class='alert alert-green'>✓ All {len(firebase)} Firebase URL(s) tested — none open</div>" if firebase and not fb_vuln_count else ""}
  {"<div class='table-wrap'><table><thead><tr><th>URL</th><th>Status</th><th>Probe endpoint</th><th>Response</th></tr></thead><tbody>"+firebase_rows+"</tbody></table></div>" if firebase_rows else "<div class='empty'>No Firebase URLs found to test</div>"}
</div>

<!-- POC INTENTS -->
<div class="section" id="poc">
  <div class="section-title">🎯 PoC Intent Commands</div>
  {"<div class='alert alert-orange'>"+str(len(pocs))+" exported component(s) — run poc_intents.sh on a connected device</div>" if pocs else ""}
  <div class="search-bar"><input type="text" placeholder="filter components..." oninput="filterTable(this,'poc-tbl')"></div>
  {"<div class='table-wrap'><table id='poc-tbl'><thead><tr><th>Type</th><th>Component</th><th>Intent Filter</th><th>adb Commands</th></tr></thead><tbody>"+poc_rows+"</tbody></table></div>" if poc_rows else "<div class='empty'>No exported components found</div>"}
  {"<p style='margin-top:12px;font-size:12px;color:var(--tx2)'>Run all: <code>chmod +x poc_intents.sh &amp;&amp; ./poc_intents.sh</code></p>" if pocs else ""}
</div>

</main>

<script>
function switchTab(btn, paneId) {{
  const section = btn.closest('.section');
  section.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  section.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === paneId));
  btn.classList.add('active');
}}
function filterTable(input, tableId) {{
  const q = input.value.toLowerCase();
  const tbl = document.getElementById(tableId);
  if (!tbl) return;
  tbl.querySelectorAll('tbody tr').forEach(r => {{
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
function filterList(input, listId) {{
  const q = input.value.toLowerCase();
  document.getElementById(listId).querySelectorAll('li').forEach(li => {{
    li.style.display = li.textContent.toLowerCase().includes(q) ? '' : 'none';
  }});
}}
const sections = document.querySelectorAll('.section');
const navLinks = document.querySelectorAll('.sidebar nav a');
window.addEventListener('scroll', () => {{
  let cur = '';
  sections.forEach(s => {{ if (window.scrollY >= s.offsetTop - 60) cur = s.id; }});
  navLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + cur));
}}, {{passive: true}});
</script>
</body>
</html>"""
    return html
