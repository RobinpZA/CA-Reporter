function Show-CAReporterGUI {
    <#
    .SYNOPSIS
        Launches a browser-based GUI for configuring and running CA What-If reports.
    .DESCRIPTION
        Starts a local HTTP server on localhost and opens the default browser to a
        single-page web application that guides the user through:
          1. Signing in to Microsoft Graph
          2. Configuring the What-If analysis parameters
          3. Running the analysis with live progress updates
          4. Viewing and exporting the generated HTML report

        Required Graph permissions: Policy.Read.All, Directory.Read.All, Application.Read.All
    .PARAMETER Port
        Port number for the local web server. Default: 8731.
    .EXAMPLE
        Show-CAReporterGUI
    .EXAMPLE
        Show-CAReporterGUI -Port 9000
    #>
    [CmdletBinding()]
    param(
        [int]$Port = 8731
    )

    # ── Module path (needed to import module inside runspaces) ────────────────
    $moduleBase = $MyInvocation.MyCommand.Module.ModuleBase
    $modulePsd1 = Join-Path $moduleBase 'CAReporter.psd1'

    # ── App list JSON for SPA ─────────────────────────────────────────────────
    $appItems    = @($script:AppCompletions.GetEnumerator() | ForEach-Object {
        [PSCustomObject]@{ name = $_.Key; id = $_.Value }
    })
    $appListJson = ConvertTo-Json -InputObject $appItems -Compress

    # ── Thread-safe shared state ──────────────────────────────────────────────
    $state = [hashtable]::Synchronized(@{
        Status     = 'idle'   # idle | auth-pending | connecting | connected | running | complete | error
        Account    = ''
        TenantId   = ''
        Progress   = 0
        Logs       = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        Results    = $null    # summary hashtable for result cards
        ReportHtml = ''       # generated report HTML
        Error      = ''
    })

    # Accumulated log buffer (append-only, allows polling by index)
    $allLogs   = [System.Collections.Generic.List[string]]::new()
    $state['RunStart']  = [datetime]::MinValue
    $state['LastHbeat'] = [datetime]::MinValue

    # ── SPA HTML ──────────────────────────────────────────────────────────────
    # CSS/JS contain no bare $ so no PS interpolation conflicts exist here.
    $spaHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CA Reporter</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700&display=swap');
:root{
  --bg:#050d1a;--bg2:#091524;--bg3:#0c1e35;--bg4:#122540;
  --txt:#ddeeff;--txt2:#6b95bb;--txt3:#2f4d66;--bdr:#162d4a;
  --blue:#00aaff;--green:#00e676;--orange:#ffa726;--red:#ff3366;--purple:#b24fff;--cyan:#00e5ff;
  --gb:rgba(0,170,255,.25);--gg:rgba(0,230,118,.2);--gr:rgba(255,51,102,.25);
  --ff:'Sora',-apple-system,sans-serif;--fm:'JetBrains Mono',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ff);background-color:var(--bg);background-image:radial-gradient(ellipse 70% 50% at 15% 25%,rgba(0,80,180,.1) 0%,transparent 60%),radial-gradient(ellipse 50% 40% at 85% 75%,rgba(0,30,100,.07) 0%,transparent 60%),radial-gradient(circle,#162d4a 1px,transparent 1px);background-size:100% 100%,100% 100%,30px 30px;color:var(--txt);min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:32px 20px 60px}
.topbar{width:100%;max-width:880px;display:flex;align-items:center;gap:12px;margin-bottom:28px}
.tlogo{width:36px;height:36px;background:linear-gradient(135deg,var(--blue),var(--cyan));border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.ttitle{font-size:17px;font-weight:800;letter-spacing:-.3px}.tsub{font-size:11px;color:var(--txt2);margin-top:1px}
.btn-close{margin-left:10px;display:inline-flex;align-items:center;gap:6px;background:transparent;color:var(--txt3);font-family:var(--ff);font-size:11px;font-weight:600;padding:6px 12px;border-radius:8px;border:1px solid var(--bdr);cursor:pointer;transition:all .2s;flex-shrink:0}
.btn-close:hover{border-color:var(--red);color:var(--red);background:rgba(255,51,102,.07)}
.status-chip{margin-left:auto;display:inline-flex;align-items:center;gap:6px;font-family:var(--fm);font-size:10px;padding:5px 12px;border-radius:20px;border:1px solid;background:rgba(0,0,0,.2);white-space:nowrap}
.dot{width:6px;height:6px;border-radius:50%}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.3}}
.ch-idle{border-color:var(--bdr);color:var(--txt3)}.ch-idle .dot{background:var(--txt3)}
.ch-connecting{border-color:var(--orange);color:var(--orange)}.ch-connecting .dot{background:var(--orange);animation:blink 1.2s ease-in-out infinite}
.ch-connected{border-color:var(--green);color:var(--green)}.ch-connected .dot{background:var(--green)}
.ch-running{border-color:var(--blue);color:var(--blue)}.ch-running .dot{background:var(--blue);animation:blink 1s ease-in-out infinite}
.ch-complete{border-color:var(--cyan);color:var(--cyan)}.ch-complete .dot{background:var(--cyan)}
.ch-error{border-color:var(--red);color:var(--red)}.ch-error .dot{background:var(--red)}
.card{width:100%;max-width:880px;background:var(--bg3);border:1px solid var(--bdr);border-radius:16px;overflow:hidden;position:relative}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,var(--cyan) 40%,var(--blue) 60%,transparent)}
.view{display:none;padding:40px}.view.active{display:block;animation:fadeUp .3s ease both}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
/* sign-in */
.si-wrap{text-align:center;max-width:420px;margin:0 auto;padding:16px 0}
.si-icon{width:72px;height:72px;margin:0 auto 24px;background:linear-gradient(135deg,var(--bg4),var(--bg2));border:1px solid var(--bdr);border-radius:20px;display:flex;align-items:center;justify-content:center;font-size:32px}
.si-wrap h1{font-size:26px;font-weight:800;margin-bottom:10px}
.si-wrap p{color:var(--txt2);font-size:13px;line-height:1.65;margin-bottom:32px}
.btn-signin{display:inline-flex;align-items:center;gap:10px;background:var(--blue);color:white;font-family:var(--ff);font-size:14px;font-weight:700;padding:14px 30px;border-radius:10px;border:none;cursor:pointer;transition:all .2s;box-shadow:0 0 24px var(--gb)}
.btn-signin:hover{transform:translateY(-2px);box-shadow:0 0 36px var(--gb)}.btn-signin:disabled{opacity:.45;cursor:not-allowed;transform:none}
.si-note{margin-top:20px;font-size:11px;color:var(--txt3);font-family:var(--fm)}
/* connecting */
.conn-wrap{text-align:center;padding:40px 0}
.spin{width:44px;height:44px;border-radius:50%;border:3px solid var(--bdr);border-top-color:var(--blue);animation:spin .8s linear infinite;margin:0 auto 24px}
@keyframes spin{to{transform:rotate(360deg)}}
.conn-title{font-size:18px;font-weight:700;margin-bottom:8px}.conn-sub{font-size:13px;color:var(--txt2);line-height:1.6}
/* configure */
.conn-banner{display:flex;align-items:center;gap:10px;padding:11px 16px;background:rgba(0,230,118,.06);border:1px solid rgba(0,230,118,.2);border-radius:9px;margin-bottom:28px;font-size:13px}
.section-lbl{font-family:var(--fm);font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.2px;color:var(--blue);margin-bottom:12px;display:flex;align-items:center;gap:8px}
.section-lbl::after{content:'';flex:1;height:1px;background:var(--bdr)}
.cfg-sec{margin-bottom:26px}
.app-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px}
.app-item{display:flex;align-items:center;gap:9px;padding:9px 12px;border-radius:8px;border:1px solid var(--bdr);background:var(--bg2);cursor:pointer;transition:all .15s;user-select:none;min-width:0}
.app-item:hover{border-color:rgba(0,170,255,.35);background:var(--bg4)}.app-item.sel{border-color:var(--blue);background:rgba(0,170,255,.09)}
.app-chk{width:15px;height:15px;border-radius:4px;border:1px solid var(--bdr);flex-shrink:0;display:flex;align-items:center;justify-content:center;transition:all .15s}
.app-item.sel .app-chk{background:var(--blue);border-color:var(--blue)}.app-item.sel .app-chk::after{content:'\2713';font-size:9px;color:white}
.app-name{font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;min-width:0}
.form-row{display:grid;gap:14px;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));margin-bottom:14px}
.form-field{display:flex;flex-direction:column;gap:5px}
.form-label{font-family:var(--fm);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--txt2)}
.form-select,.form-input{background:var(--bg2);border:1px solid var(--bdr);border-radius:7px;color:var(--txt);padding:8px 12px;font-family:var(--ff);font-size:12px;transition:border-color .2s,box-shadow .2s;-webkit-appearance:none}
.form-select{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='10' viewBox='0 0 10 10'%3E%3Cpath fill='%236b95bb' d='M5 7L0 2h10z'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
.form-select:focus,.form-input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,170,255,.18)}
.toggle-row{display:flex;flex-wrap:wrap;gap:8px}
.toggle-item{display:inline-flex;align-items:center;gap:8px;padding:7px 14px;border-radius:7px;border:1px solid var(--bdr);background:var(--bg2);cursor:pointer;font-size:12px;font-weight:500;transition:all .15s;user-select:none}
.toggle-item:hover{border-color:rgba(0,170,255,.3)}.toggle-item.on{border-color:var(--blue);background:rgba(0,170,255,.09);color:var(--blue)}
.mode-tabs{display:flex;border-radius:8px;overflow:hidden;border:1px solid var(--bdr);margin-bottom:14px}
.mode-tab{flex:1;padding:9px;text-align:center;font-size:12px;font-weight:600;cursor:pointer;background:var(--bg2);border:none;color:var(--txt2);transition:all .15s}.mode-tab.active{background:rgba(0,170,255,.12);color:var(--blue)}
.run-wrap{display:flex;align-items:center;gap:12px;margin-top:8px;padding-top:22px;border-top:1px solid var(--bdr);flex-wrap:wrap}
.btn-run{display:inline-flex;align-items:center;gap:8px;background:var(--blue);color:white;font-family:var(--ff);font-size:14px;font-weight:700;padding:13px 28px;border-radius:10px;border:none;cursor:pointer;transition:all .2s;box-shadow:0 0 20px var(--gb);letter-spacing:-.2px}
.btn-run:hover{transform:translateY(-1px);box-shadow:0 0 30px var(--gb)}.btn-run:disabled{opacity:.4;cursor:not-allowed;transform:none}
.btn-ghost{background:transparent;color:var(--txt2);font-family:var(--ff);font-size:12px;font-weight:500;padding:12px 18px;border-radius:10px;border:1px solid var(--bdr);cursor:pointer;transition:all .15s}
.btn-ghost:hover{border-color:var(--txt2);color:var(--txt)}.sel-count{font-size:11px;color:var(--txt3);font-family:var(--fm);margin-left:auto}
/* running */
.run-hdr{display:flex;align-items:center;gap:16px;margin-bottom:22px}
.run-title{font-size:19px;font-weight:700}.run-sub{font-size:12px;color:var(--txt2);margin-top:2px}
.prog-wrap{background:var(--bg2);border:1px solid var(--bdr);border-radius:6px;overflow:hidden;height:5px;margin-bottom:20px}
.prog-fill{height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:6px;transition:width .6s ease;box-shadow:0 0 8px var(--gb)}
.log-panel{background:var(--bg);border:1px solid var(--bdr);border-radius:10px;padding:14px 16px;height:280px;overflow-y:auto;font-family:var(--fm);font-size:11.5px;line-height:2}
.ll{color:var(--txt2)}.ll.ok{color:var(--green)}.ll.info{color:var(--blue)}.ll.warn{color:var(--orange)}.ll.err{color:var(--red)}
/* complete */
.cmp-hdr{text-align:center;padding:8px 0 28px}
.cmp-check{width:64px;height:64px;margin:0 auto 20px;background:rgba(0,230,118,.1);border:2px solid var(--green);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;color:var(--green);box-shadow:0 0 24px var(--gg)}
.cmp-title{font-size:22px;font-weight:800;margin-bottom:6px}.cmp-sub{font-size:13px;color:var(--txt2)}
.result-cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:12px;margin-bottom:28px}
.rc{background:var(--bg2);border:1px solid var(--bdr);border-radius:10px;padding:18px 14px;text-align:center}
.rv{font-family:var(--fm);font-size:30px;font-weight:700;line-height:1}.rl{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.8px;color:var(--txt2);margin-top:6px}
.rv-blue{color:var(--blue);text-shadow:0 0 20px var(--gb)}.rv-green{color:var(--green);text-shadow:0 0 20px var(--gg)}.rv-red{color:var(--red);text-shadow:0 0 20px var(--gr)}.rv-orange{color:var(--orange)}.rv-purple{color:var(--purple)}
.act-row{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.btn-primary{display:inline-flex;align-items:center;gap:8px;background:var(--blue);color:white;font-family:var(--ff);font-size:14px;font-weight:600;padding:12px 22px;border-radius:10px;border:none;cursor:pointer;transition:all .2s;box-shadow:0 0 18px var(--gb);text-decoration:none}
.btn-primary:hover{transform:translateY(-1px);filter:brightness(1.1)}
.btn-outline{display:inline-flex;align-items:center;gap:8px;background:transparent;color:var(--txt2);font-family:var(--ff);font-size:13px;font-weight:500;padding:12px 18px;border-radius:10px;border:1px solid var(--bdr);cursor:pointer;transition:all .15s;text-decoration:none}
.btn-outline:hover{border-color:var(--txt2);color:var(--txt)}
/* error */
.err-icon{font-size:40px;text-align:center;margin-bottom:16px}
.err-box{background:rgba(255,51,102,.08);border:1px solid rgba(255,51,102,.3);border-radius:8px;padding:16px;font-family:var(--fm);font-size:11px;color:var(--red);word-break:break-all;white-space:pre-wrap;max-height:220px;overflow-y:auto}
::-webkit-scrollbar{width:5px;height:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--bdr);border-radius:3px}
</style>
</head>
<body>
<div class="topbar">
  <div class="tlogo">&#x1F6E1;</div>
  <div>
    <div class="ttitle">CA Reporter</div>
    <div class="tsub">Conditional Access What-If Analysis</div>
  </div>
  <span id="chip" class="status-chip ch-idle"><span class="dot"></span><span id="chipTxt">Not Connected</span></span>
  <button class="btn-close" onclick="doClose()" title="Stop the CA Reporter server and close this session">&#x2715; Close</button>
</div>

<div class="card">

  <!-- SIGN IN -->
  <div id="v-signin" class="view active">
    <div class="si-wrap">
      <div class="si-icon">&#x1F512;</div>
      <h1>Sign In to Get Started</h1>
      <p>Connect to your Microsoft 365 tenant via Microsoft Graph to begin the Conditional Access What-If analysis.</p>
      <button class="btn-signin" id="btnSignin" onclick="doSignIn()">
        <svg width="18" height="18" viewBox="0 0 22 22">
          <rect width="10" height="10" fill="#f25022"/><rect x="12" width="10" height="10" fill="#7fba00"/>
          <rect y="12" width="10" height="10" fill="#00a4ef"/><rect x="12" y="12" width="10" height="10" fill="#ffb900"/>
        </svg>
        Sign In with Microsoft
      </button>
      <div class="si-note">Requires: Policy.Read.All &middot; Directory.Read.All &middot; Application.Read.All</div>
    </div>
  </div>

  <!-- CONNECTING -->
  <div id="v-connecting" class="view">
    <div class="conn-wrap">
      <div class="spin"></div>
      <div class="conn-title">Waiting for Authentication&hellip;</div>
      <div class="conn-sub">A Microsoft sign-in window has opened.<br>Complete sign-in there, then return here.</div>
    </div>
  </div>

  <!-- CONFIGURE -->
  <div id="v-configure" class="view">
    <div class="conn-banner">
      <span style="color:var(--green);font-size:15px">&#10003;</span>
      <span style="color:var(--green);font-weight:700">Connected</span>
      <span id="accTxt" style="color:var(--txt2);font-family:var(--fm);font-size:11px"></span>
    </div>

    <div class="cfg-sec">
      <div class="section-lbl">Applications</div>
      <div class="app-grid" id="appGrid"></div>
    </div>

    <div class="cfg-sec">
      <div class="section-lbl">Sign-In Conditions</div>
      <div class="form-row">
        <div class="form-field"><label class="form-label">Client App</label>
          <select class="form-select" id="clientApp">
            <option value="browser">browser</option>
            <option value="mobileAppsAndDesktopClients">mobileAppsAndDesktopClients</option>
            <option value="exchangeActiveSync">exchangeActiveSync</option>
            <option value="easSupported">easSupported</option>
            <option value="other">other</option>
          </select></div>
        <div class="form-field"><label class="form-label">Device Platform</label>
          <select class="form-select" id="platform">
            <option value="">(Any)</option>
            <option value="android">android</option>
            <option value="iOS">iOS</option>
            <option value="windows">windows</option>
            <option value="windowsPhone">windowsPhone</option>
            <option value="macOS">macOS</option>
            <option value="linux">linux</option>
          </select></div>
        <div class="form-field"><label class="form-label">Sign-In Risk</label>
          <select class="form-select" id="signinRisk">
            <option value="none">none</option><option value="low">low</option>
            <option value="medium">medium</option><option value="high">high</option>
          </select></div>
        <div class="form-field"><label class="form-label">User Risk</label>
          <select class="form-select" id="userRisk">
            <option value="none">none</option><option value="low">low</option>
            <option value="medium">medium</option><option value="high">high</option>
          </select></div>
        <div class="form-field"><label class="form-label">Country (ISO-2)</label>
          <input class="form-input" id="country" maxlength="2" placeholder="e.g. US"></div>
        <div class="form-field"><label class="form-label">IP Address</label>
          <input class="form-input" id="ipAddr" placeholder="e.g. 203.0.113.1"></div>
      </div>
    </div>

    <div class="cfg-sec">
      <div class="section-lbl">User Options</div>
      <div class="form-row" style="grid-template-columns:160px 1fr">
        <div class="form-field"><label class="form-label">Max Users (0 = all)</label>
          <input class="form-input" id="maxUsers" type="number" value="0" min="0"></div>
        <div class="form-field">
          <label class="form-label">&nbsp;</label>
          <div class="toggle-row">
            <label class="toggle-item" id="tGuests"  onclick="syncToggle(this)"><input type="checkbox" id="cbGuests">   Include Guests</label>
            <label class="toggle-item" id="tExclDis" onclick="syncToggle(this)"><input type="checkbox" id="cbExclDis">  Exclude Disabled</label>
            <label class="toggle-item" id="tRptOnly" onclick="syncToggle(this)"><input type="checkbox" id="cbRptOnly">  Include Report-Only</label>
            <label class="toggle-item" id="tInclDis" onclick="syncToggle(this)"><input type="checkbox" id="cbInclDis">  Include Disabled Policies</label>
          </div>
        </div>
      </div>
    </div>

    <div class="cfg-sec">
      <div class="section-lbl">Analysis Mode</div>
      <div class="mode-tabs">
        <button class="mode-tab active" id="modeStd"  onclick="setMode('standard')">Standard What-If</button>
        <button class="mode-tab"        id="modeComp" onclick="setMode('comprehensive')">Comprehensive Gap Analysis</button>
      </div>
      <div id="compPanel" style="display:none">
        <div class="form-row">
          <div class="form-field"><label class="form-label">Scenario Profile</label>
            <select class="form-select" id="scenProfile">
              <option value="Quick">Quick &mdash; 1 scenario (fast)</option>
              <option value="Standard" selected>Standard &mdash; 18 scenarios (recommended)</option>
              <option value="Thorough">Thorough &mdash; 42 scenarios (most complete)</option>
            </select></div>
          <div class="form-field"><label class="form-label">Extra Countries (comma-sep)</label>
            <input class="form-input" id="compCountries" placeholder="e.g. CN, RU"></div>
          <div class="form-field"><label class="form-label">Extra IPs (comma-sep)</label>
            <input class="form-input" id="compIps" placeholder="e.g. 1.2.3.4, 5.6.7.8"></div>
        </div>
      </div>
    </div>

    <div class="run-wrap">
      <button class="btn-run" id="btnRun" onclick="doRun()">&#x25B6; Run Analysis</button>
      <button class="btn-ghost" onclick="doSignOut()">Sign Out</button>
      <span class="sel-count" id="selCount">0 apps selected</span>
    </div>
  </div>

  <!-- RUNNING -->
  <div id="v-running" class="view">
    <div class="run-hdr">
      <div class="spin"></div>
      <div>
        <div class="run-title">Running Analysis&hellip;</div>
        <div class="run-sub">Evaluating your Conditional Access policies. This may take a few minutes.</div>
      </div>
    </div>
    <div class="prog-wrap"><div class="prog-fill" id="progBar" style="width:0%"></div></div>
    <div class="log-panel" id="logPanel"></div>
  </div>

  <!-- COMPLETE -->
  <div id="v-complete" class="view">
    <div class="cmp-hdr">
      <div class="cmp-check">&#x2713;</div>
      <div class="cmp-title">Analysis Complete</div>
      <div class="cmp-sub">Your Conditional Access What-If report is ready.</div>
    </div>
    <div class="result-cards" id="resultCards"></div>
    <div class="act-row">
      <a class="btn-primary" href="/report" target="_blank">&#x1F4C4; View Report</a>
      <a class="btn-outline" href="/export" download="CA-WhatIf-Report.html">&#x2B07; Export HTML</a>
      <button class="btn-outline" onclick="doRunAgain()">&#x21BA; Run Again</button>
    </div>
  </div>

  <!-- ERROR -->
  <div id="v-error" class="view">
    <div class="err-icon">&#x26A0;&#xFE0F;</div>
    <div style="text-align:center;margin-bottom:20px">
      <div style="font-size:20px;font-weight:700;margin-bottom:8px">Something went wrong</div>
      <div style="font-size:13px;color:var(--txt2)">The analysis encountered an error.</div>
    </div>
    <div class="err-box" id="errBox"></div>
    <div style="text-align:center;margin-top:20px">
      <button class="btn-outline" onclick="doRunAgain()">&#x21BA; Try Again</button>
    </div>
  </div>

</div><!-- /card -->

<script>
var APPS = __APPS__;
var mode = 'standard';
var logSeq = 0;
var poll = null;

function init() {
  var grid = document.getElementById('appGrid');
  APPS.forEach(function(a) {
    var el = document.createElement('div');
    el.className = 'app-item';
    el.dataset.name = a.name;
    el.title = a.name;
    el.innerHTML = '<div class="app-chk"></div><div class="app-name">' + a.name + '</div>';
    if (a.name === 'Office365') el.classList.add('sel');
    el.addEventListener('click', function() { el.classList.toggle('sel'); updCount(); });
    grid.appendChild(el);
  });
  updCount();
  checkStatus();
}

function updCount() {
  var n = document.querySelectorAll('.app-item.sel').length;
  document.getElementById('selCount').textContent = n + ' app' + (n === 1 ? '' : 's') + ' selected';
}

function showView(v) {
  document.querySelectorAll('.view').forEach(function(x) { x.classList.remove('active'); });
  document.getElementById('v-' + v).classList.add('active');
}

function setChip(cls, txt) {
  document.getElementById('chip').className = 'status-chip ' + cls;
  document.getElementById('chipTxt').textContent = txt;
}

function syncToggle(lbl) {
  setTimeout(function() {
    var cb = lbl.querySelector('input[type=checkbox]');
    lbl.classList.toggle('on', cb.checked);
  }, 0);
}

function setMode(m) {
  mode = m;
  document.getElementById('modeStd').classList.toggle('active', m === 'standard');
  document.getElementById('modeComp').classList.toggle('active', m === 'comprehensive');
  document.getElementById('compPanel').style.display = m === 'comprehensive' ? 'block' : 'none';
}

function doSignIn() {
  document.getElementById('btnSignin').disabled = true;
  setChip('ch-connecting', 'Connecting...');
  showView('connecting');
  fetch('/api/connect', { method: 'POST' }).catch(function() {});
  startStatusPoll();
}

function doSignOut() {
  stopPoll();
  fetch('/api/disconnect', { method: 'POST' }).catch(function() {});
  setChip('ch-idle', 'Not Connected');
  document.getElementById('btnSignin').disabled = false;
  showView('signin');
}

function doRun() {
  var apps = Array.from(document.querySelectorAll('.app-item.sel')).map(function(e) { return e.dataset.name; });
  if (!apps.length) { alert('Please select at least one application.'); return; }
  var p = {
    applications:       apps,
    clientAppType:      document.getElementById('clientApp').value,
    platform:           document.getElementById('platform').value,
    signinRisk:         document.getElementById('signinRisk').value,
    userRisk:           document.getElementById('userRisk').value,
    country:            document.getElementById('country').value.trim().toUpperCase(),
    ipAddress:          document.getElementById('ipAddr').value.trim(),
    maxUsers:           parseInt(document.getElementById('maxUsers').value) || 0,
    includeGuests:      document.getElementById('cbGuests').checked,
    excludeDisabled:    document.getElementById('cbExclDis').checked,
    includeReportOnly:  document.getElementById('cbRptOnly').checked,
    includeDisabledPol: document.getElementById('cbInclDis').checked,
    comprehensive:      mode === 'comprehensive',
    scenarioProfile:    document.getElementById('scenProfile').value,
    compCountries:      document.getElementById('compCountries').value.trim(),
    compIps:            document.getElementById('compIps').value.trim()
  };
  document.getElementById('logPanel').innerHTML = '';
  logSeq = 0;
  document.getElementById('progBar').style.width = '0%';
  showView('running');
  setChip('ch-running', 'Running...');
  fetch('/api/run', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(p) }).catch(function() {});
  startProgressPoll();
}

function doRunAgain() { stopPoll(); logSeq = 0; showView('configure'); setChip('ch-connected', 'Connected'); }

function doClose() {
  if (!confirm('Stop the CA Reporter server and close this session?')) return;
  stopPoll();
  fetch('/stop', { method: 'POST' }).catch(function() {}).finally(function() {
    document.body.innerHTML = '<div style="display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;font-family:var(--ff);color:var(--txt2);gap:12px"><div style="font-size:32px">&#x2715;</div><div style="font-size:16px;font-weight:600;color:var(--txt)">CA Reporter stopped</div><div style="font-size:13px">You can close this tab.</div></div>';
  });
}

function startStatusPoll()   { stopPoll(); poll = setInterval(checkStatus,   1500); }
function startProgressPoll() { stopPoll(); poll = setInterval(checkProgress, 1800); }
function stopPoll() { if (poll) { clearInterval(poll); poll = null; } }

function checkStatus() {
  fetch('/api/status').then(function(r) { return r.json(); }).then(function(s) {
    if (s.status === 'connected') {
      stopPoll();
      document.getElementById('accTxt').textContent = s.account;
      setChip('ch-connected', 'Connected');
      showView('configure');
    } else if (s.status === 'error') {
      stopPoll(); setChip('ch-error', 'Error');
      document.getElementById('errBox').textContent = s.error;
      showView('error');
    }
  }).catch(function() {});
}

function checkProgress() {
  fetch('/api/progress?seq=' + logSeq).then(function(r) { return r.json(); }).then(function(s) {
    var panel = document.getElementById('logPanel');
    (s.logs || []).forEach(function(line) {
      var d = document.createElement('div');
      var c = 'll';
      if (line.indexOf('[+]') === 0 || line.indexOf('[v]') === 0 || line.indexOf('✓') >= 0) c += ' ok';
      else if (line.indexOf('[!]') === 0 || line.toLowerCase().indexOf('warning') >= 0)       c += ' warn';
      else if (line.indexOf('[x]') === 0 || line.indexOf('✗') >= 0 || line.toLowerCase().indexOf('error') >= 0) c += ' err';
      else if (line.indexOf('[•]') >= 0 || line.indexOf('[*]') >= 0 || line.indexOf('[i]') >= 0) c += ' info';
      d.className = c; d.textContent = line; panel.appendChild(d); logSeq++;
    });
    if (s.logs && s.logs.length) panel.scrollTop = panel.scrollHeight;
    if (s.progress !== undefined) document.getElementById('progBar').style.width = s.progress + '%';
    if (s.status === 'complete') {
      stopPoll(); setChip('ch-complete', 'Complete'); showComplete(s.summary);
    } else if (s.status === 'error') {
      stopPoll(); setChip('ch-error', 'Error');
      document.getElementById('errBox').textContent = s.error || 'Unknown error';
      showView('error');
    }
  }).catch(function() {});
}

function showComplete(summary) {
  var cards = document.getElementById('resultCards');
  if (summary) {
    cards.innerHTML =
      '<div class="rc"><div class="rv rv-blue">'   + (summary.users      || 0) + '</div><div class="rl">Users Evaluated</div></div>' +
      '<div class="rc"><div class="rv rv-purple">' + (summary.policies   || 0) + '</div><div class="rl">CA Policies</div></div>' +
      '<div class="rc"><div class="rv rv-green">'  + (summary.mfaPct     || 0) + '%</div><div class="rl">MFA Coverage</div></div>' +
      '<div class="rc"><div class="rv rv-red">'    + (summary.blockedPct || 0) + '%</div><div class="rl">Blocked</div></div>' +
      '<div class="rc"><div class="rv rv-orange">' + (summary.noPolicies || 0) + '</div><div class="rl">No CA Policies</div></div>';
  }
  showView('complete');
}

init();
</script>
</body>
</html>
"@

    # Inject app list JSON into SPA placeholder
    $spaHtml = $spaHtml.Replace('__APPS__', $appListJson)

    # ── Start HTTP listener ───────────────────────────────────────────────────
    $listener = [System.Net.HttpListener]::new()
    $baseUrl   = "http://localhost:$Port/"
    $listener.Prefixes.Add($baseUrl)

    try { $listener.Start() }
    catch {
        Write-Error "Failed to start HTTP listener on port $Port. Try: Show-CAReporterGUI -Port 9000"
        return
    }

    Write-Host ''
    Write-Host '  CA Reporter Web GUI' -ForegroundColor Cyan
    Write-Host '  ─────────────────────────────────' -ForegroundColor DarkGray
    Write-Host "  URL  : $baseUrl" -ForegroundColor Cyan
    Write-Host '  Stop : Ctrl+C in this window' -ForegroundColor DarkGray
    Write-Host ''

    Start-Process $baseUrl

    # ── Inner helpers ─────────────────────────────────────────────────────────

    function Send-PlainResponse {
        param($ctx, [string]$body, [string]$ct = 'text/html', [int]$code = 200)
        $ctx.Response.StatusCode  = $code
        $ctx.Response.ContentType = "$ct; charset=utf-8"
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($body)
        $ctx.Response.ContentLength64 = $bytes.Length
        $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $ctx.Response.OutputStream.Close()
    }

    function Send-Json {
        param($ctx, $obj, [int]$code = 200)
        Send-PlainResponse $ctx ($obj | ConvertTo-Json -Depth 5 -Compress) 'application/json' $code
    }

    function Drain-Logs {
        param([int]$since)
        $item = $null
        while ($state.Logs.TryDequeue([ref]$item)) { $allLogs.Add($item); $item = $null }
        return @($allLogs | Select-Object -Skip $since)
    }

    # ── Analysis runspace (calls Get-CAWhatIfReport in background) ────────────
    function Start-AnalysisRunspace {
        param($webParams)

        if ($state.Status -eq 'running') { return }

        $state.Status     = 'running'
        $state.Progress   = 0
        $state.Results    = $null
        $state.ReportHtml = ''
        $state.Error      = ''
        $item = $null
        while ($state.Logs.TryDequeue([ref]$item)) { $item = $null }
        $allLogs.Clear()

        # Map browser params → Get-CAWhatIfReport params
        $runParams = @{
            Applications    = @($webParams.applications)
            ClientAppType   = $webParams.clientAppType
            SignInRiskLevel = $webParams.signinRisk
            UserRiskLevel   = $webParams.userRisk
            SkipConnection  = $true
        }
        if ($webParams.platform)           { $runParams['DevicePlatform']        = $webParams.platform }
        if ($webParams.country)            { $runParams['Country']               = $webParams.country }
        if ($webParams.ipAddress)          { $runParams['IpAddress']             = $webParams.ipAddress }
        if ([int]$webParams.maxUsers -gt 0){ $runParams['MaxUsers']              = [int]$webParams.maxUsers }
        if ($webParams.includeGuests)      { $runParams['IncludeGuests']         = $true }
        if ($webParams.excludeDisabled)    { $runParams['ExcludeDisabledUsers']  = $true }
        if ($webParams.includeReportOnly)  { $runParams['IncludeReportOnly']     = $true }
        if ($webParams.includeDisabledPol) { $runParams['IncludeDisabled']       = $true }
        if ($webParams.comprehensive) {
            $runParams['Comprehensive']   = $true
            $runParams['ScenarioProfile'] = $webParams.scenarioProfile
            if ($webParams.compCountries) {
                $runParams['ComprehensiveCountries'] = @(
                    $webParams.compCountries -split '\s*,\s*' | Where-Object { $_ }
                )
            }
            if ($webParams.compIps) {
                $runParams['ComprehensiveIpAddresses'] = @(
                    $webParams.compIps -split '\s*,\s*' | Where-Object { $_ }
                )
            }
        }

        $rs = [RunspaceFactory]::CreateRunspace()
        $rs.ApartmentState = 'MTA'
        $rs.ThreadOptions  = 'ReuseThread'
        $rs.Open()
        $rs.SessionStateProxy.SetVariable('state',      $state)
        $rs.SessionStateProxy.SetVariable('modulePsd1', $modulePsd1)
        $rs.SessionStateProxy.SetVariable('runParams',  $runParams)

        $ps = [PowerShell]::Create()
        $ps.Runspace = $rs
        [void]$ps.AddScript({
            function Log { param([string]$m) $state.Logs.Enqueue($m) }
            try {
                Import-Module $modulePsd1 -Force -ErrorAction Stop

                Log '[•] Verifying Microsoft Graph connection...'
                $ctx = Get-MgContext
                if (-not $ctx) { throw 'Not connected to Microsoft Graph. Please sign in first.' }
                Log "[+] Connected as $($ctx.Account)"
                $state.Progress = 8

                try {
                    $org = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization?$select=displayName' -ErrorAction Stop
                    $tenantDisplayName = $org.value[0].displayName
                    Log "[•] Tenant: $tenantDisplayName"
                } catch { }

                $tempPath = [System.IO.Path]::ChangeExtension([System.IO.Path]::GetTempFileName(), '.html')
                $runParams['OutputPath'] = $tempPath

                if ($runParams.ContainsKey('Comprehensive')) {
                    Log "[•] Starting Comprehensive Gap Analysis (profile: $($runParams['ScenarioProfile']))..."
                } else {
                    Log "[•] Starting What-If analysis for: $($runParams['Applications'] -join ', ')"
                }
                $state.Progress = 15

                $result = Get-CAWhatIfReport @runParams

                Log '[+] Analysis complete'
                $state.Progress = 88

                Log '[•] Loading report into memory...'
                if (Test-Path $tempPath) {
                    $state.ReportHtml = [System.IO.File]::ReadAllText($tempPath, [System.Text.Encoding]::UTF8)
                    Remove-Item $tempPath -Force -ErrorAction SilentlyContinue
                    Log "[+] Report ready ($([math]::Round($state.ReportHtml.Length / 1KB, 0)) KB)"
                } else {
                    Log '[!] Warning: report file was not created at expected path'
                }
                $state.Progress = 95

                # Build summary for result cards
                $summary = @{ users = 0; policies = 0; mfaPct = 0.0; blockedPct = 0.0; noPolicies = 0 }
                if ($result.Analysis) {
                    $allRes       = @($result.Analysis.Results)
                    $enabledIds   = @($result.Policies | Where-Object { $_.state -eq 'enabled' }).id
                    $enforced     = @($allRes | Where-Object { $_.PolicyApplies -and $_.PolicyId -in $enabledIds })
                    $n            = @($result.Users).Count
                    $mfaCount     = @($enforced | Where-Object { $_.RequiresMfa }  | Select-Object -ExpandProperty UserId -Unique).Count
                    $blockCount   = @($enforced | Where-Object { $_.IsBlocking }   | Select-Object -ExpandProperty UserId -Unique).Count
                    $coveredCount = @($enforced | Select-Object -ExpandProperty UserId -Unique).Count
                    $summary.users      = $n
                    $summary.policies   = $result.Policies.Count
                    $summary.mfaPct     = if ($n -gt 0) { [math]::Round($mfaCount   / $n * 100, 1) } else { 0 }
                    $summary.blockedPct = if ($n -gt 0) { [math]::Round($blockCount / $n * 100, 1) } else { 0 }
                    $summary.noPolicies = [math]::Max(0, $n - $coveredCount)
                } elseif ($result.Users -and $result.Policies) {
                    $summary.users    = @($result.Users).Count
                    $summary.policies = $result.Policies.Count
                    if ($result.Report.GapUsers -ne $null) { $summary.noPolicies = $result.Report.GapUsers }
                }

                $state.Results  = $summary
                $state.Progress = 100
                $state.Status   = 'complete'
            }
            catch {
                $state.Error  = $_.ToString()
                $state.Status = 'error'
                $state.Logs.Enqueue("[x] Error: $_")
            }
        })
        [void]$ps.BeginInvoke()

        $state.RunStart  = [datetime]::Now
        $state.LastHbeat = [datetime]::MinValue
    }

    # ── Main request loop ─────────────────────────────────────────────────────
    $asyncCtx = $listener.BeginGetContext($null, $null)

    try {
        while ($listener.IsListening) {

            # Auth is performed on the main thread so WAM can open its sign-in window.
            # HTTP requests queue at the OS level during auth and are processed once we return.
            if ($state.Status -eq 'auth-pending') {
                $state.Status = 'connecting'
                try {
                    Connect-MgGraph -Scopes @('Policy.Read.All','Directory.Read.All','Application.Read.All') `
                        -NoWelcome -ErrorAction Stop
                    $ctx = Get-MgContext
                    if (-not $ctx) { throw 'Authentication context is null after Connect-MgGraph.' }
                    $state.Account  = $ctx.Account
                    $state.TenantId = $ctx.TenantId
                    $state.Status   = 'connected'
                }
                catch {
                    $state.Error  = $_.ToString()
                    $state.Status = 'error'
                }
                continue
            }

            # Emit a heartbeat log line every 7 s while analysis is running
            if ($state.Status -eq 'running') {
                $now = [datetime]::Now
                if (($now - $state.LastHbeat).TotalSeconds -ge 7) {
                    $elapsed = [long]($now - $state.RunStart).TotalSeconds
                    $state.Logs.Enqueue("[i] Analysis in progress... (${elapsed}s elapsed)")
                    $state.LastHbeat = $now
                }
            }

            if (-not $asyncCtx.AsyncWaitHandle.WaitOne(100)) { continue }

            $reqCtx = $listener.EndGetContext($asyncCtx)
            $req    = $reqCtx.Request
            $path   = $req.Url.AbsolutePath

            try {
                switch -Regex ($path) {

                    '^/$' { Send-PlainResponse $reqCtx $spaHtml 'text/html' }

                    '^/favicon\.ico$' {
                        $reqCtx.Response.StatusCode = 204
                        $reqCtx.Response.OutputStream.Close()
                    }

                    '^/api/status$' {
                        Send-Json $reqCtx @{
                            status   = $state.Status
                            account  = $state.Account
                            tenantId = $state.TenantId
                            error    = $state.Error
                        }
                    }

                    '^/api/connect$' {
                        if ($state.Status -notin @('auth-pending','connecting','connected')) {
                            $state.Status = 'auth-pending'
                            $state.Error  = ''
                        }
                        Send-Json $reqCtx @{ ok = $true }
                    }

                    '^/api/disconnect$' {
                        try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
                        $state.Status  = 'idle'
                        $state.Account = ''
                        Send-Json $reqCtx @{ ok = $true }
                    }

                    '^/api/run$' {
                        $bodyText  = (New-Object System.IO.StreamReader $req.InputStream).ReadToEnd()
                        $webParams = $bodyText | ConvertFrom-Json
                        Start-AnalysisRunspace $webParams
                        Send-Json $reqCtx @{ ok = $true }
                    }

                    '^/api/progress$' {
                        $seq = 0
                        if ($req.QueryString['seq']) { $seq = [int]$req.QueryString['seq'] }
                        $newLogs = Drain-Logs $seq
                        Send-Json $reqCtx @{
                            status   = $state.Status
                            progress = $state.Progress
                            logs     = @($newLogs)
                            error    = $state.Error
                            summary  = $state.Results
                        }
                    }

                    '^/report$' {
                        if ($state.ReportHtml) {
                            Send-PlainResponse $reqCtx $state.ReportHtml 'text/html'
                        } else {
                            Send-PlainResponse $reqCtx '<html><body style="background:#050d1a;color:#ddeeff;font-family:sans-serif;padding:60px;text-align:center"><h2>No report available yet.</h2><p style="color:#6b95bb;margin-top:12px">Run an analysis first.</p></body></html>'
                        }
                    }

                    '^/export$' {
                        if ($state.ReportHtml) {
                            $reqCtx.Response.StatusCode  = 200
                            $reqCtx.Response.ContentType = 'text/html; charset=utf-8'
                            $reqCtx.Response.AddHeader('Content-Disposition', 'attachment; filename="CA-WhatIf-Report.html"')
                            $bytes = [System.Text.Encoding]::UTF8.GetBytes($state.ReportHtml)
                            $reqCtx.Response.ContentLength64 = $bytes.Length
                            $reqCtx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
                            $reqCtx.Response.OutputStream.Close()
                        } else {
                            Send-Json $reqCtx @{ error = 'No report available' } 404
                        }
                    }

                    '^/stop$' {
                        Send-PlainResponse $reqCtx '<html><body style="background:#050d1a;color:#ddeeff;font-family:sans-serif;padding:60px;text-align:center"><h2>CA Reporter stopped.</h2><p style="color:#6b95bb;margin-top:12px">You can close this tab.</p></body></html>'
                        $listener.Stop()
                        break
                    }

                    default { Send-Json $reqCtx @{ error = 'Not Found' } 404 }
                }
            }
            catch {
                Write-Verbose "[CAReporter] Request handler error: $_"
                try { Send-Json $reqCtx @{ error = 'Internal server error' } 500 } catch { }
            }

            if ($listener.IsListening) {
                $asyncCtx = $listener.BeginGetContext($null, $null)
            }
        }
    }
    finally {
        if ($listener.IsListening) { $listener.Stop() }
        $listener.Close()
        Write-Host '[CAReporter] Web GUI stopped.' -ForegroundColor DarkGray
    }
}
