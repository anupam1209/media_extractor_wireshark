#!/usr/bin/env python3
"""
webapp — zero-dependency web UI for the PCAP RTP media extractor.

Stdlib only (http.server). Reuses the verified engine in mediax.py.
Run:  python3 webapp.py   then open  http://127.0.0.1:8000

Flow:  upload PCAP  ->  auto-detected streams table  ->  Extract (per stream)  ->  download/preview WAV
"""
import base64
import hmac
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import mediax

HOST, PORT = "127.0.0.1", 8000
WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_work")
UPLOADS = os.path.join(WORK, "uploads")
OUTPUTS = os.path.join(WORK, "outputs")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)

# ---- debug logs (only ever created when the server is started with --debug) -- #
# Lives under _work/, which .gitignore already excludes, so logs can never be
# committed. The folder is created lazily -- a normal run leaves no trace of it.
LOGS = os.path.join(WORK, "logs")
LOG_PREFIX, LOG_SUFFIX = "webapp-", ".log"   # prune only touches files we created
LOG_RETENTION_DAYS = 7                       # delete logs older than this
LOG_KEEP_MAX = 50                            # ...and keep at most this many, newest first

UPLOAD_REGISTRY = {}   # token -> {"path":..., "name":...}
OUTPUT_REGISTRY = {}   # token -> path
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_UPLOAD = 500 * 1024 * 1024  # 500 MB cap

# ---- live "Stream to phone" sessions (ffmpeg -> MPEG-TS over UDP -> VLC) ----- #
# Each Start spawns an ffmpeg that pushes the already-extracted file to the phone's
# IP:port as MPEG-TS/UDP (the container carries codec info, so VLC needs no SDP).
# Only usable when this server and the phone share a LAN -- see _valid_target().
STREAM_REGISTRY = {}   # session -> {"proc","ip","port","path","cmd","err_path","stopped"}
STREAM_LOCK = threading.Lock()
DEFAULT_STREAM_PORT = 1234
UDP_PKT_SIZE = 1316    # 7 x 188-byte TS packets: stays under a 1500-byte MTU


def lan_ip():
    """Best-effort primary LAN IPv4 of this machine (for the setup hint shown to the
    user). Opens a throwaway UDP socket toward a public address -- no packet is sent,
    it just makes the OS pick the outbound interface -- and reads back its local IP."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def valid_target(ip):
    """Validate the phone's IP and return it normalised, or raise ValueError.

    Restricted to private / loopback / link-local IPv4 on purpose: this feature only
    works when the phone is on the same LAN as this PC, and the restriction also keeps
    the server from being coaxed into firing UDP at arbitrary internet hosts."""
    try:
        a = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise ValueError(f"'{ip}' is not a valid IP address")
    if a.version != 4:
        raise ValueError("please enter an IPv4 address (e.g. 192.168.1.57)")
    if not (a.is_private or a.is_loopback or a.is_link_local):
        raise ValueError("target must be a private/LAN address on the same Wi-Fi "
                         "(e.g. 192.168.x.x or 10.x.x.x)")
    return str(a)


def stream_cmd(path, ip, port):
    """ffmpeg command that real-time streams `path` to ip:port as MPEG-TS/UDP.
    Video (.mp4/.h264/.h265) is copied as-is (no re-encode); audio (.wav) is
    encoded to AAC because raw PCM does not ride in MPEG-TS."""
    url = f"udp://{ip}:{port}?pkt_size={UDP_PKT_SIZE}"
    cmd = [mediax.FFMPEG, "-hide_banner", "-loglevel", "warning", "-nostdin",
           "-re", "-i", path]
    if path.lower().endswith((".mp4", ".mkv", ".h264", ".264", ".h265", ".hevc")):
        cmd += ["-c", "copy"]
    else:                                    # wav / raw PCM audio -> AAC for TS
        cmd += ["-c:a", "aac", "-b:a", "64k"]
    cmd += ["-f", "mpegts", url]
    return cmd


def prune_logs():
    """Delete stale debug logs: first anything older than LOG_RETENTION_DAYS, then the
    oldest files beyond LOG_KEEP_MAX. Only files this app created (webapp-*.log in
    _work/logs/) are ever considered -- nothing else in the folder is touched."""
    if not os.path.isdir(LOGS):
        return 0
    cutoff = time.time() - LOG_RETENTION_DAYS * 86400
    removed, keep = 0, []
    for name in os.listdir(LOGS):
        if not (name.startswith(LOG_PREFIX) and name.endswith(LOG_SUFFIX)):
            continue
        path = os.path.join(LOGS, name)
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            continue
        if mtime < cutoff:
            try:
                os.remove(path)
                removed += 1
            except OSError:
                pass
        else:
            keep.append((mtime, path))
    keep.sort()                                     # oldest first
    for _, path in keep[:max(0, len(keep) - LOG_KEEP_MAX)]:
        try:
            os.remove(path)
            removed += 1
        except OSError:
            pass
    return removed


def open_log():
    """Create _work/logs/ and open this run's log file. Called only for --debug."""
    os.makedirs(LOGS, exist_ok=True)
    name = f"{LOG_PREFIX}{datetime.now():%Y%m%d-%H%M%S}-{os.getpid()}{LOG_SUFFIX}"
    path = os.path.join(LOGS, name)
    return path, open(path, "a", encoding="utf-8", buffering=1)


PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PCAP RTP Media Extractor</title>
<!-- Inter is loaded only as a graceful web substitute for SF Pro on non-Apple devices;
     if offline it simply falls back to the native system stack below. No JS libraries. -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{
    --font:"SF Pro Display","SF Pro Text",-apple-system,BlinkMacSystemFont,"Inter","Helvetica Neue",Helvetica,Arial,sans-serif;
    --bg:#fbfbfd; --surface:#ffffff; --ink:#1d1d1f; --ink2:#6e6e73;
    --hair:#d2d2d7; --blue:#0071e3; --blue-h:#0077ed;
    --ease:cubic-bezier(.25,.1,.25,1); --max:1200px;
  }
  *{box-sizing:border-box;}
  html{scroll-behavior:smooth;}
  body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--font);
       font-weight:400;line-height:1.47;-webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;}
  a{color:var(--blue);text-decoration:none;}
  a:hover{text-decoration:underline;}

  /* frosted sticky nav */
  .nav{position:sticky;top:0;z-index:100;background:rgba(251,251,253,.72);
       backdrop-filter:saturate(180%) blur(20px);-webkit-backdrop-filter:saturate(180%) blur(20px);
       border-bottom:1px solid rgba(0,0,0,.08);}
  .nav-inner{max-width:var(--max);margin:0 auto;padding:0 22px;height:48px;display:flex;align-items:center;gap:.7rem;}
  .brand{font-size:17px;font-weight:600;letter-spacing:-.01em;}
  .nav-tag{font-size:12px;color:var(--ink2);letter-spacing:.02em;border:1px solid var(--hair);border-radius:980px;padding:1px 9px;}

  main{max-width:var(--max);margin:0 auto;padding:0 22px;}

  /* hero */
  .hero{position:relative;text-align:center;padding:96px 0 56px;overflow:hidden;}
  .hero-bg{position:absolute;inset:-25% -10% 0;z-index:-1;pointer-events:none;will-change:transform;
           background:radial-gradient(58% 48% at 50% 0%, rgba(0,113,227,.12), transparent 70%);}
  h1{font-size:clamp(32px,6vw,80px);line-height:1.05;font-weight:700;letter-spacing:-.03em;
     margin:0 auto;max-width:min(16ch,100%);overflow-wrap:break-word;}
  .sub{font-size:clamp(17px,2.4vw,26px);line-height:1.4;font-weight:400;color:var(--ink2);
       margin:.7em auto 0;max-width:min(40ch,100%);letter-spacing:-.01em;overflow-wrap:break-word;}

  /* upload */
  .upload{margin-top:36px;display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:center;}
  input[type=file]{font:inherit;color:var(--ink2);max-width:100%;}
  input[type=file]::file-selector-button{font:inherit;font-weight:500;cursor:pointer;margin-right:12px;
       padding:9px 18px;border-radius:980px;border:1px solid var(--hair);background:var(--surface);color:var(--ink);
       transition:background .3s var(--ease),border-color .3s var(--ease);}
  input[type=file]::file-selector-button:hover{background:#f5f5f7;border-color:#c7c7cc;}
  .btn{font:inherit;font-weight:500;cursor:pointer;padding:10px 22px;border-radius:980px;border:0;
       background:var(--blue);color:#fff;letter-spacing:-.01em;
       transition:transform .3s var(--ease),background .3s var(--ease),opacity .3s var(--ease);}
  .btn:hover{background:var(--blue-h);transform:scale(1.03);}
  .btn:active{transform:scale(.98);}
  .btn:disabled{background:#b9b9be;cursor:not-allowed;transform:none;}
  #status{display:block;width:100%;margin-top:10px;color:var(--ink2);font-size:14px;}

  /* results */
  .results{margin:28px 0 100px;}
  .results-head{display:flex;flex-wrap:wrap;gap:14px;align-items:center;justify-content:space-between;margin-bottom:18px;}
  .results-head h2{font-size:clamp(26px,3.4vw,40px);font-weight:600;letter-spacing:-.02em;margin:0;}
  .timing-toggle{display:flex;gap:4px;background:#f0f0f3;border-radius:980px;padding:4px;}
  .timing{font-size:13px;color:var(--ink2);cursor:pointer;padding:6px 14px;border-radius:980px;transition:all .3s var(--ease);}
  .timing input{position:absolute;opacity:0;pointer-events:none;}
  .timing:has(input:checked){background:var(--surface);color:var(--ink);box-shadow:0 1px 3px rgba(0,0,0,.08);}

  .card{background:var(--surface);border-radius:18px;border:1px solid rgba(0,0,0,.06);overflow:hidden;}
  .table-wrap{overflow-x:auto;}
  table{border-collapse:collapse;width:100%;font-size:14px;font-variant-numeric:tabular-nums;}
  th,td{text-align:left;padding:14px 18px;border-bottom:1px solid #f0f0f2;white-space:nowrap;}
  thead th{font-size:11px;font-weight:600;color:var(--ink2);letter-spacing:.04em;text-transform:uppercase;background:#fafafc;}
  tbody tr{transition:background .25s var(--ease);}
  tbody tr:last-child td{border-bottom:0;}
  tbody tr:hover{background:#f7f7f9;}
  .pill{font-size:12px;font-weight:500;padding:3px 11px;border-radius:980px;background:#f0f0f3;color:var(--ink);}
  .muted{color:var(--ink2);}
  .warn{color:#bf4800;}
  .ok{color:#1d8a4e;}

  /* Apple-style black pill for the in-table Extract action */
  .btn-extract{font-family:inherit;font-size:14px;font-weight:500;letter-spacing:-.01em;
    color:#fff;background:#1d1d1f;border:0;border-radius:980px;padding:9px 22px;
    cursor:pointer;transition:all .2s ease;}
  .btn-extract:hover{background:#424245;}
  .btn-extract:active{transform:scale(.97);}
  .btn-extract:focus{outline:none;}
  .btn-extract:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(0,0,0,.18);}
  .btn-extract:disabled{opacity:.5;cursor:default;}

  th.out-col,td.out{min-width:360px;}
  td.out{white-space:normal;}
  td.out audio,td.out video{display:block;margin-top:.5rem;border-radius:10px;}
  td.out audio{width:340px;height:38px;}
  td.out video{width:340px;max-width:100%;}

  /* scroll-reveal */
  .reveal{opacity:0;transform:translateY(30px);transition:opacity .8s var(--ease),transform .8s var(--ease);}
  .reveal.in{opacity:1;transform:none;}

  @media (max-width:600px){
    .hero{padding:60px 0 36px;}
    th,td{padding:12px 14px;}
    .results-head{align-items:flex-start;}
  }
  @media (prefers-reduced-motion: reduce){
    html{scroll-behavior:auto;}
    .reveal{opacity:1 !important;transform:none !important;transition:none !important;}
    .btn:hover{transform:none;}
    .hero-bg{transform:none !important;}
  }

  /* "Stream to phone" button in the Output cell */
  .btn-stream{font-family:inherit;font-size:13px;font-weight:500;letter-spacing:-.01em;
    color:var(--blue);background:transparent;border:1px solid var(--hair);border-radius:980px;
    padding:6px 14px;margin-top:.55rem;cursor:pointer;display:inline-flex;align-items:center;gap:.35em;
    transition:background .2s var(--ease),border-color .2s var(--ease);}
  .btn-stream:hover{background:#f0f6ff;border-color:var(--blue);}

  /* guided "Stream to phone" modal */
  .modal-overlay{position:fixed;inset:0;z-index:200;display:flex;align-items:center;justify-content:center;
    padding:20px;background:rgba(0,0,0,.32);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);}
  .modal-overlay[hidden]{display:none;}
  .modal{position:relative;width:min(520px,100%);max-height:90vh;overflow-y:auto;background:var(--surface);
    border-radius:20px;border:1px solid rgba(0,0,0,.08);box-shadow:0 24px 70px rgba(0,0,0,.28);padding:30px 30px 26px;}
  .modal-x{position:absolute;top:16px;right:18px;border:0;background:transparent;color:var(--ink2);
    font-size:26px;line-height:1;cursor:pointer;padding:2px 6px;border-radius:8px;transition:color .2s,background .2s;}
  .modal-x:hover{color:var(--ink);background:#f0f0f3;}
  .modal-title{font-size:22px;font-weight:600;letter-spacing:-.02em;margin:0 40px 2px 0;}
  .modal-file{font-size:12.5px;margin:0 0 18px;word-break:break-all;}
  .step-badge{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;color:var(--blue);
    margin-bottom:12px;}
  .note{background:#fff8ee;border:1px solid #f0d9b5;color:#6b4e16;border-radius:12px;
    padding:11px 14px;font-size:12.5px;line-height:1.5;margin:0 0 16px;}
  .note b{color:#5a3d0a;}
  .checklist{list-style:none;padding:0;margin:0 0 14px;}
  .checklist li{position:relative;padding:9px 0 9px 26px;font-size:14px;border-bottom:1px solid #f0f0f2;}
  .checklist li:last-child{border-bottom:0;}
  .checklist li::before{content:"";position:absolute;left:2px;top:14px;width:7px;height:7px;border-radius:50%;
    background:var(--blue);}
  .hint{font-size:12.5px;color:var(--ink2);margin-top:3px;}
  .hint b, .hint code{color:var(--ink);}
  .state-ok{color:var(--ok,#1d8a4e);font-weight:600;}
  .state-bad{color:#c0392b;font-weight:600;}
  .confirm{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--ink2);margin:6px 0 4px;cursor:pointer;}
  .confirm input{width:16px;height:16px;}
  .vlc-steps{margin:0 0 14px;padding-left:20px;font-size:14px;}
  .vlc-steps li{margin:8px 0;}
  .field-row{display:flex;gap:14px;flex-wrap:wrap;margin:10px 0 4px;}
  .field-row label{display:flex;flex-direction:column;gap:5px;font-size:12.5px;color:var(--ink2);font-weight:500;}
  .field-row input{font:inherit;font-size:15px;color:var(--ink);padding:9px 12px;border:1px solid var(--hair);
    border-radius:10px;background:var(--surface);}
  .field-row input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(0,113,227,.15);}
  .field-row input#phoneIp{width:190px;}
  .field-row input#phonePort{width:96px;}
  code, .codeblock{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;}
  .codeblock{display:block;background:#f5f5f7;border:1px solid var(--hair);border-radius:10px;padding:10px 12px;
    font-size:13px;color:var(--ink);margin:6px 0;word-break:break-all;user-select:all;cursor:pointer;}
  .codeblock:hover{border-color:var(--blue);}
  .err{color:#c0392b;font-size:13px;min-height:1.2em;margin-top:6px;}
  .stream-status{font-size:13.5px;margin:12px 0 4px;min-height:1.2em;}
  .stream-status .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:7px;vertical-align:middle;}
  .stream-status.live .dot{background:#1d8a4e;animation:pulse 1.4s var(--ease) infinite;}
  .stream-status.done .dot{background:var(--ink2);}
  .stream-status.err .dot{background:#c0392b;}
  @keyframes pulse{0%,100%{opacity:1;}50%{opacity:.3;}}
  .step-actions{display:flex;gap:10px;justify-content:flex-end;margin-top:18px;flex-wrap:wrap;}
  .btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--hair);}
  .btn.ghost:hover{background:#f5f5f7;}
  .btn.danger{background:#c0392b;}
  .btn.danger:hover{background:#d0432f;}
  .cmd-details{margin-top:14px;font-size:12px;color:var(--ink2);}
  .cmd-details summary{cursor:pointer;}
  .cmd-details code{display:block;margin-top:8px;background:#f5f5f7;border:1px solid var(--hair);border-radius:8px;
    padding:8px 10px;font-size:11.5px;color:var(--ink);word-break:break-all;white-space:pre-wrap;}
  @media (prefers-reduced-motion: reduce){ .stream-status.live .dot{animation:none;} }
</style></head>
<body>
  <nav class="nav">
    <div class="nav-inner">
      <span class="brand">PCAP RTP Media Extractor</span>
      <span class="nav-tag">RTP &middot; PCAP</span>
    </div>
  </nav>

  <main>
    <section class="hero">
      <div class="hero-bg" id="heroBg"></div>
      <h1 class="reveal">PCAP RTP Media Extractor</h1>
      <p class="sub reveal">Upload a capture &rarr; streams are auto-detected &rarr; extract &amp; download audio.</p>
      <div class="upload reveal">
        <input type="file" id="file" accept=".pcap,.pcapng,.cap">
        <button id="up" class="btn">Upload &amp; detect</button>
        <span id="status"></span>
      </div>
    </section>

    <section class="results" id="result" style="display:none">
      <div class="results-head reveal">
        <h2>Detected streams</h2>
        <div class="timing-toggle">
          <label class="timing"><input type="radio" name="timing" value="accurate" checked> Real timing (silence in gaps)</label>
          <label class="timing"><input type="radio" name="timing" value="compact"> Compact (speech only)</label>
        </div>
      </div>
      <div class="card reveal">
        <div class="table-wrap">
        <table id="tbl"><thead><tr>
          <th>Source</th><th>Destination</th><th>SSRC</th><th>Codec</th>
          <th>Pkts</th><th>Start (IST)</th><th>Dur (s)</th><th>Action</th><th class="out-col">Output</th>
        </tr></thead><tbody></tbody></table>
        </div>
      </div>
    </section>
  </main>

  <!-- guided "Stream to phone" flow (opens after a stream is extracted) -->
  <div class="modal-overlay" id="phoneModal" hidden>
    <div class="modal" role="dialog" aria-modal="true" aria-labelledby="phoneTitle">
      <button class="modal-x" id="phoneClose" aria-label="Close">&times;</button>
      <h3 class="modal-title" id="phoneTitle">Stream to phone</h3>
      <p class="modal-file muted" id="phoneFile"></p>

      <!-- Step 1: prerequisites -->
      <div class="step" data-step="1">
        <div class="step-badge">Step 1 of 3 &middot; Check your setup</div>
        <div class="note">&#9888;&#65039; This pushes the video straight to your phone over the local network, so it only
          works when this extractor is running on a <b>PC on the same Wi-Fi as the phone</b>. It will <b>not</b> work
          from a remote / cloud-hosted instance.</div>
        <ul class="checklist">
          <li>This PC and your phone are on the <b>same Wi-Fi network</b>.
            <div class="hint" id="pcIpHint">Your PC's IP: <b>&hellip;</b></div></li>
          <li>The Wi-Fi allows device-to-device traffic
            <span class="hint">(some &ldquo;guest&rdquo; networks block it &mdash; AP/client isolation).</span></li>
          <li><b>VLC</b> is installed on the phone (App Store / Play Store).</li>
          <li>Streaming tool on this PC (ffmpeg): <span id="ffmpegState">checking&hellip;</span></li>
        </ul>
        <label class="confirm"><input type="checkbox" id="prereqOk"> I've confirmed the above</label>
        <div class="step-actions"><button class="btn" id="toStep2" disabled>Next</button></div>
      </div>

      <!-- Step 2: phone IP -->
      <div class="step" data-step="2" hidden>
        <div class="step-badge">Step 2 of 3 &middot; Your phone's IP address</div>
        <p style="font-size:14px;margin:0 0 4px;">On the phone open
          <b>Settings &rarr; Wi-Fi &rarr; (your network) &rarr; IP address</b> and type it below.</p>
        <div class="field-row">
          <label>Phone IP<input type="text" id="phoneIp" placeholder="192.168.1.57" inputmode="decimal" autocomplete="off"></label>
          <label>Port<input type="number" id="phonePort" value="1234" min="1" max="65535"></label>
        </div>
        <div class="hint" id="subnetHint"></div>
        <div class="err" id="ipErr"></div>
        <div class="step-actions">
          <button class="btn ghost" data-back="1">Back</button>
          <button class="btn" id="toStep3">Next</button>
        </div>
      </div>

      <!-- Step 3: start streaming -->
      <div class="step" data-step="3" hidden>
        <div class="step-badge">Step 3 of 3 &middot; Start the stream</div>
        <ol class="vlc-steps">
          <li>Open <b>VLC</b> on the phone &rarr; <b>New Stream</b> (Network Stream).</li>
          <li>Enter this address and press play &mdash; VLC will wait for the video:
            <code class="codeblock" id="vlcUrl" title="tap to select">udp://@:1234</code></li>
          <li>Then press <b>Start streaming</b> below.</li>
        </ol>
        <div class="stream-status" id="streamStatus"></div>
        <div class="step-actions">
          <button class="btn ghost" data-back="2">Back</button>
          <button class="btn" id="startStream">Start streaming</button>
          <button class="btn danger" id="stopStream" hidden>Stop</button>
        </div>
        <details class="cmd-details"><summary>Show the command running on this PC</summary><code id="cmdText"></code></details>
      </div>
    </div>
  </div>

<script>
let FILE_ID = null;
const $ = s => document.querySelector(s);
const REDUCE = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/* Scroll-triggered reveals via the native IntersectionObserver — no animation libraries.
   Elements with class "reveal" fade in and rise as they enter the viewport. */
const io = (!REDUCE && 'IntersectionObserver' in window)
  ? new IntersectionObserver((entries, obs) => {
      for (const e of entries) if (e.isIntersecting) { e.target.classList.add('in'); obs.unobserve(e.target); }
    }, { threshold: 0.12, rootMargin: '0px 0px -8% 0px' })
  : null;
function observeReveals() {
  document.querySelectorAll('.reveal:not(.in)').forEach(el => io ? io.observe(el) : el.classList.add('in'));
}

/* Subtle hero parallax, throttled to a single rAF per frame. */
const heroBg = $('#heroBg');
if (heroBg && !REDUCE) {
  let ticking = false;
  addEventListener('scroll', () => {
    if (ticking) return; ticking = true;
    requestAnimationFrame(() => { heroBg.style.transform = 'translateY(' + (scrollY * 0.3) + 'px)'; ticking = false; });
  }, { passive: true });
}

$('#up').onclick = async () => {
  const f = $('#file').files[0];
  if (!f) { $('#status').textContent = 'pick a file first'; return; }
  $('#status').textContent = 'uploading & detecting (large captures take a moment)...';
  $('#up').disabled = true;
  try {
    const r = await fetch('/api/upload?name=' + encodeURIComponent(f.name), {method:'POST', body:f});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'upload failed');
    FILE_ID = d.file_id;
    $('#result').style.display = '';
    renderStreams(d.streams);
    $('#status').textContent = d.streams.length + ' stream(s) found';
    observeReveals();
  } catch (e) { $('#status').textContent = 'error: ' + e.message; }
  $('#up').disabled = false;
};

function renderStreams(streams) {
  const tb = $('#tbl tbody'); tb.innerHTML = '';
  streams.forEach((s, i) => {
    const tr = document.createElement('tr');
    tr.classList.add('reveal');
    tr.style.transitionDelay = Math.min(i * 0.04, 0.4) + 's';   // gentle stagger
    const supported = ['AMR-NB','AMR-WB','G711u','G711a','H264','H265'].includes(s.codec);
    tr.innerHTML = `
      <td>${s.src_ip}:${s.src_port}</td>
      <td>${s.dst_ip}:${s.dst_port}</td>
      <td>${s.ssrc}</td>
      <td><span class="pill">${s.codec}</span></td>
      <td>${s.pkts}</td>
      <td title="ends ${s.end_time||'?'}">${s.start_time||'—'}</td>
      <td>${s.duration}</td>
      <td></td><td class="out muted">—</td>`;
    const act = tr.children[7], out = tr.children[8];
    if (supported) {
      const b = document.createElement('button');
      b.className = 'btn-extract';
      b.textContent = 'Extract';
      b.onclick = () => extract(s, b, out);
      act.appendChild(b);
    } else {
      act.innerHTML = '<span class="muted">unsupported</span>';
    }
    tb.appendChild(tr);
  });
  observeReveals();
}

async function extract(s, btn, out) {
  btn.disabled = true; const old = btn.textContent; btn.textContent = 'extracting...';
  out.classList.remove('muted'); out.textContent = '...';
  const timing = document.querySelector('input[name=timing]:checked').value;
  try {
    const r = await fetch('/api/extract', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({file_id: FILE_ID, stream: s, timing})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'extract failed');
    if (d.kind === 'video') {
      out.innerHTML = `<a href="${d.download}" download>download</a> `
        + `<span class="muted">(${d.frames} pkts, ${d.fps} fps)</span>`
        + `<video controls preload="none" src="${d.download}"></video>`;
    } else {
      out.innerHTML = `<a href="${d.download}" download>download</a> `
        + `<span class="muted">(${d.duration_s}s${d.gaps_filled_s?(', '+d.gaps_filled_s+'s silence'):''})</span>`
        + `<audio controls preload="none" src="${d.download}"></audio>`;
    }
    // "Stream to phone" — reuses the download token (…?f=<tok>) to push the file over UDP to VLC
    const tok = new URLSearchParams((d.download.split('?')[1] || '')).get('f');
    if (tok) {
      const label = `${s.src_ip}:${s.src_port} → ${s.dst_ip}:${s.dst_port} · ${s.codec}`;
      const sb = document.createElement('button');
      sb.className = 'btn-stream';
      sb.innerHTML = '&#128241; Stream to phone';   // 📱
      sb.onclick = () => openPhoneModal(tok, label);
      out.appendChild(sb);
    }
    // reveal the player even when the wide table is horizontally scrolled
    out.scrollIntoView({ behavior: REDUCE ? 'auto' : 'smooth', block: 'nearest', inline: 'end' });
  } catch (e) { out.innerHTML = '<span class="warn">'+e.message+'</span>'; }
  btn.disabled = false; btn.textContent = old;
}

/* ---------------- guided "Stream to phone" flow ---------------- */
const phoneModal = $('#phoneModal');
let STREAM_TOKEN = null;     // download token of the extracted file to stream
let STREAM_SESSION = null;   // active server-side ffmpeg session id
let STATUS_TIMER = null;
let PC_IP = null;

const subnetPrefix = ip => { const p = (ip||'').split('.'); return p.length === 4 ? p.slice(0,3).join('.') : ip; };
const validIpClient = ip => {
  const m = (ip||'').trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  return !!m && m.slice(1).every(o => +o >= 0 && +o <= 255);
};
function showStep(n){ phoneModal.querySelectorAll('.step').forEach(el => el.hidden = (el.dataset.step !== String(n))); }
function setStatus(cls, html){
  const el = $('#streamStatus');
  el.className = 'stream-status' + (cls ? ' ' + cls : '');
  el.innerHTML = (cls === 'live' || cls === 'done' || cls === 'err' ? '<span class="dot"></span>' : '') + html;
}
function stopPolling(){ if (STATUS_TIMER){ clearInterval(STATUS_TIMER); STATUS_TIMER = null; } }

async function openPhoneModal(token, label){
  STREAM_TOKEN = token;
  $('#phoneFile').textContent = label || '';
  $('#prereqOk').checked = false;
  $('#toStep2').disabled = true;
  $('#ipErr').textContent = '';
  $('#startStream').hidden = false; $('#startStream').disabled = false; $('#startStream').textContent = 'Start streaming';
  $('#stopStream').hidden = true;
  setStatus('', '');
  showStep(1);
  phoneModal.hidden = false;
  try {
    const d = await (await fetch('/api/netinfo')).json();
    PC_IP = d.lan_ip || null;
    $('#pcIpHint').innerHTML = PC_IP
      ? `Your PC's IP: <b>${PC_IP}</b> &mdash; the phone's IP should share the prefix <b>${subnetPrefix(PC_IP)}.x</b>`
      : `Your PC's IP: <b>unknown</b>`;
    const fs = $('#ffmpegState');
    if (d.ffmpeg){ fs.textContent = 'found ✓'; fs.className = 'state-ok'; }
    else { fs.textContent = 'not found ✗ — install ffmpeg on this PC'; fs.className = 'state-bad'; }
  } catch(e){ $('#pcIpHint').innerHTML = `Your PC's IP: <b>unknown</b>`; }
}

async function stopStream(silent){
  const session = STREAM_SESSION;
  STREAM_SESSION = null;
  stopPolling();
  if (session){
    try { await fetch('/api/stream/stop', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({session})}); } catch(e){}
  }
  if (!silent){
    $('#stopStream').hidden = true;
    $('#startStream').hidden = false; $('#startStream').disabled = false; $('#startStream').textContent = 'Stream again';
    setStatus('done', 'Stopped.');
  }
}
function closePhoneModal(){
  phoneModal.hidden = true;
  if (STREAM_SESSION) stopStream(true);   // never leave an orphaned ffmpeg running
  else stopPolling();
}

$('#phoneClose').onclick = closePhoneModal;
phoneModal.addEventListener('click', e => { if (e.target === phoneModal) closePhoneModal(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !phoneModal.hidden) closePhoneModal(); });

$('#prereqOk').onchange = e => { $('#toStep2').disabled = !e.target.checked; };
$('#toStep2').onclick = () => {
  showStep(2);
  const ipEl = $('#phoneIp');
  if (PC_IP) ipEl.placeholder = subnetPrefix(PC_IP) + '.57';
  $('#subnetHint').innerHTML = PC_IP ? `Tip: it should start with <b>${subnetPrefix(PC_IP)}.</b>` : '';
  ipEl.focus();
};
phoneModal.querySelectorAll('[data-back]').forEach(b => b.onclick = () => showStep(+b.dataset.back));
$('#toStep3').onclick = () => {
  const ip = $('#phoneIp').value.trim(), port = +$('#phonePort').value;
  if (!validIpClient(ip)){ $('#ipErr').textContent = 'Enter a valid IPv4 address, e.g. 192.168.1.57'; return; }
  if (!(port >= 1 && port <= 65535)){ $('#ipErr').textContent = 'Port must be between 1 and 65535'; return; }
  $('#ipErr').textContent = '';
  $('#vlcUrl').textContent = `udp://@:${port}`;
  showStep(3);
};
$('#vlcUrl').onclick = () => {
  const r = document.createRange(); r.selectNodeContents($('#vlcUrl'));
  const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
};

$('#startStream').onclick = async () => {
  const ip = $('#phoneIp').value.trim(), port = +$('#phonePort').value;
  $('#startStream').disabled = true;
  setStatus('', 'starting…');
  try {
    const r = await fetch('/api/stream/start', {method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({token: STREAM_TOKEN, ip, port})});
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'could not start');
    STREAM_SESSION = d.session;
    $('#cmdText').textContent = d.cmd || '';
    $('#startStream').hidden = true;
    $('#stopStream').hidden = false;
    setStatus('live', `Streaming to <b>${ip}:${port}</b> in real time &mdash; watch VLC on your phone.`);
    STATUS_TIMER = setInterval(pollStatus, 1500);
  } catch(e){ setStatus('err', e.message); $('#startStream').disabled = false; }
};
$('#stopStream').onclick = () => stopStream(false);

async function pollStatus(){
  if (!STREAM_SESSION){ stopPolling(); return; }
  try {
    const d = await (await fetch('/api/stream/status?session=' + STREAM_SESSION)).json();
    if (!d.running){
      stopPolling(); STREAM_SESSION = null;
      $('#stopStream').hidden = true;
      $('#startStream').hidden = false; $('#startStream').disabled = false; $('#startStream').textContent = 'Stream again';
      if (d.returncode === 0)
        setStatus('done', 'Finished &mdash; the whole clip was sent. Press “Stream again” to replay.');
      else
        setStatus('err', 'ffmpeg stopped' + (d.error ? ': ' + d.error : ` (exit code ${d.returncode})`));
    }
  } catch(e){ /* transient network hiccup; keep polling */ }
}

observeReveals();   // reveal the hero on first paint
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *a):
        """Silent by default; every request is logged once tracing is on
        (mediax --debug / MEDIAX_DEBUG=1 / mediax.set_debug(True))."""
        if mediax.tracing("web"):   # guard: skip the % formatting on every request
            mediax.trace("web", f"{self.address_string()} {fmt % a}")

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    # ---- optional HTTP Basic Auth (set MEDIAX_USER + MEDIAX_PASS to enable) - #
    def _authed(self):
        """Return True if the request may proceed. If MEDIAX_USER and MEDIAX_PASS
        are both set, require matching HTTP Basic credentials; otherwise the app
        stays open (convenient for local dev)."""
        user = os.environ.get("MEDIAX_USER")
        pw = os.environ.get("MEDIAX_PASS")
        if not user or not pw:            # no credentials configured -> open
            return True
        hdr = self.headers.get("Authorization", "")
        if hdr.startswith("Basic "):
            try:
                got = base64.b64decode(hdr[6:]).decode("utf-8", "replace")
            except Exception:
                got = ""
            u, _, p = got.partition(":")
            if (hmac.compare_digest(u.encode(), user.encode())
                    and hmac.compare_digest(p.encode(), pw.encode())):
                return True
        self._send(401, {"error": "authentication required"},
                   extra={"WWW-Authenticate": 'Basic realm="PCAP Media Extractor"'})
        return False

    # ---- GET: page + download -------------------------------------------- #
    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/healthz":   # unauthenticated so Render's health check passes
            return self._send(200, {"status": "ok"})
        if not self._authed():
            return
        if u.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if u.path == "/api/netinfo":
            return self._send(200, {"lan_ip": lan_ip(),
                                    "ffmpeg": shutil.which(mediax.FFMPEG) is not None,
                                    "default_port": DEFAULT_STREAM_PORT})
        if u.path == "/api/stream/status":
            return self._stream_status(parse_qs(u.query).get("session", [""])[0])
        if u.path == "/api/download":
            tok = parse_qs(u.query).get("f", [""])[0]
            path = OUTPUT_REGISTRY.get(tok)
            if not path or not os.path.exists(path):
                return self._send(404, {"error": "not found"})
            with open(path, "rb") as fh:
                data = fh.read()
            fn = os.path.basename(path)
            ctype = "video/mp4" if fn.endswith(".mp4") else "audio/wav"
            return self._send(200, data, ctype,
                              {"Content-Disposition": f'attachment; filename="{fn}"'})
        return self._send(404, {"error": "not found"})

    # ---- POST: upload + extract ------------------------------------------ #
    def do_POST(self):
        if not self._authed():
            return
        u = urlparse(self.path)
        try:
            if u.path == "/api/upload":
                return self._upload(u)
            if u.path == "/api/extract":
                return self._extract()
            if u.path == "/api/stream/start":
                return self._stream_start()
            if u.path == "/api/stream/stop":
                return self._stream_stop()
        except Exception as e:  # surface engine errors as JSON
            mediax.trace("web", f"ERROR on {u.path}: {type(e).__name__}: {e}")
            return self._send(400, {"error": str(e)})
        return self._send(404, {"error": "not found"})

    def _upload(self, u):
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0 or length > MAX_UPLOAD:
            return self._send(400, {"error": "missing or oversized upload"})
        name = parse_qs(u.query).get("name", ["capture.pcap"])[0]
        name = SAFE_NAME.sub("_", os.path.basename(name)) or "capture.pcap"
        token = uuid.uuid4().hex
        path = os.path.join(UPLOADS, f"{token}_{name}")
        remaining = length
        with open(path, "wb") as fh:
            while remaining > 0:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        UPLOAD_REGISTRY[token] = {"path": path, "name": name}
        if mediax.DEBUG:
            prune_logs()      # opportunistic cleanup so a long-lived server stays tidy
            mediax.trace("web", f"uploaded {name} ({length} bytes) -> {path}, "
                                f"detecting streams...")
        streams = mediax.detect_streams(path)
        return self._send(200, {"file_id": token, "streams": streams})

    def _extract(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        up = UPLOAD_REGISTRY.get(req.get("file_id"))
        if not up:
            return self._send(400, {"error": "unknown file_id (re-upload)"})
        s = req["stream"]
        timing = req.get("timing", "accurate")
        codec = s.get("codec")
        if codec not in mediax.SUPPORTED:
            return self._send(400, {"error": f"unsupported codec {codec}"})
        is_video = codec in mediax.VIDEO_CODECS
        ext = ".mp4" if is_video else ".wav"
        tag = "" if is_video else f"_{timing}"
        name = (f'{s["src_ip"]}_{s["src_port"]}-{s["dst_ip"]}_{s["dst_port"]}'
                f'_{s["ssrc"]}{tag}{ext}')
        name = SAFE_NAME.sub("_", name)
        out_path = os.path.join(OUTPUTS, name)
        mediax.trace("web", f'extract request: {s["src_ip"]}:{s["src_port"]}->'
                            f'{s["dst_ip"]}:{s["dst_port"]} {s["ssrc"]} '
                            f'codec={codec} timing={timing}')
        _, _, info = mediax.extract_stream(up["path"], s, out_path,
                                           codec=s["codec"], mode=s.get("mode"), timing=timing)
        tok = uuid.uuid4().hex
        OUTPUT_REGISTRY[tok] = out_path
        info["download"] = f"/api/download?f={tok}"
        return self._send(200, info)

    # ---- POST: live "Stream to phone" (ffmpeg -> MPEG-TS/UDP -> VLC) ------ #
    def _stream_start(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        path = OUTPUT_REGISTRY.get(req.get("token"))
        if not path or not os.path.exists(path):
            return self._send(400, {"error": "file not found — extract this stream again"})
        if not shutil.which(mediax.FFMPEG):
            return self._send(400, {"error": "ffmpeg not found on this PC"})
        try:
            ip = valid_target(str(req.get("ip", "")))
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        try:
            port = int(req.get("port", DEFAULT_STREAM_PORT))
        except (ValueError, TypeError):
            return self._send(400, {"error": "port must be a number"})
        if not (1 <= port <= 65535):
            return self._send(400, {"error": "port must be between 1 and 65535"})
        cmd = stream_cmd(path, ip, port)
        err_fh = tempfile.NamedTemporaryFile(prefix="mediax-stream-", suffix=".log", delete=False)
        try:
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.DEVNULL, stderr=err_fh)
        except OSError as e:
            err_fh.close()
            return self._send(400, {"error": f"could not start ffmpeg: {e}"})
        finally:
            err_fh.close()   # ffmpeg has its own dup'd handle; we reopen the path to read errors later
        session = uuid.uuid4().hex
        with STREAM_LOCK:
            STREAM_REGISTRY[session] = {"proc": proc, "ip": ip, "port": port, "path": path,
                                        "cmd": " ".join(cmd), "err_path": err_fh.name, "stopped": False}
        mediax.trace("web", f"stream start {session[:8]} -> {ip}:{port} ({os.path.basename(path)})")
        return self._send(200, {"session": session, "vlc_url": f"udp://@:{port}",
                                "target": f"{ip}:{port}", "cmd": " ".join(cmd)})

    def _stream_stop(self):
        length = int(self.headers.get("Content-Length", 0))
        req = json.loads(self.rfile.read(length) or b"{}")
        info = self._end_stream(req.get("session", ""))
        return self._send(200, {"stopped": bool(info)})

    def _stream_status(self, session):
        info = STREAM_REGISTRY.get(session)
        if not info:
            return self._send(404, {"error": "unknown session", "running": False})
        rc = info["proc"].poll()
        if rc is None:
            return self._send(200, {"running": True, "returncode": None})
        # process ended on its own -> report, capture any error, then retire the session
        resp = {"running": False, "returncode": rc}
        if rc != 0 and not info["stopped"]:
            resp["error"] = self._stream_err_tail(info)
        self._end_stream(session)
        return self._send(200, resp)

    @staticmethod
    def _stream_err_tail(info, limit=300):
        """Last chunk of ffmpeg's stderr, for surfacing why a stream died."""
        try:
            with open(info["err_path"], "r", encoding="utf-8", errors="replace") as fh:
                txt = fh.read().strip().replace("\n", " ")
            return txt[-limit:] if txt else None
        except OSError:
            return None

    @staticmethod
    def _end_stream(session):
        """Terminate an ffmpeg session (if still running), drop it from the registry,
        and delete its stderr log. Safe to call on an already-finished session."""
        with STREAM_LOCK:
            info = STREAM_REGISTRY.pop(session, None)
        if not info:
            return None
        info["stopped"] = True
        proc = info["proc"]
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.remove(info["err_path"])
        except OSError:
            pass
        return info


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Web UI for the PCAP RTP media extractor")
    ap.add_argument("--host", default=os.environ.get("MEDIAX_HOST", HOST),
                    help="bind address (use 0.0.0.0 to expose on the VM)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("MEDIAX_PORT") or os.environ.get("PORT") or PORT),
                    help="listen port (honours $PORT, set by Render/Railway/Cloud Run/Fly)")
    ap.add_argument("--debug", action="store_true",
                    help="log every request and trace the extraction pipeline "
                         "(same tracing as mediax.py --debug)")
    ap.add_argument("--debug-tags", metavar="TAGS",
                    help="limit --debug to these comma-separated mediax trace tags")
    args = ap.parse_args()
    log_fh = None
    if args.debug:
        mediax.set_debug(True, args.debug_tags.split(",") if args.debug_tags else None)
        dropped = prune_logs()                      # clear stale logs before opening a new one
        log_path, log_fh = open_log()
        mediax.set_trace_sink(log_fh)
        print(f"debug tracing -> {log_path}")
        print(f"  (logs kept {LOG_RETENTION_DAYS} days / {LOG_KEEP_MAX} files"
              f"{f'; pruned {dropped} stale' if dropped else ''})")
        mediax.trace("web", f"server starting on {args.host}:{args.port} "
                            f"(pid {os.getpid()})")
    print(f"PCAP RTP Media Extractor  ->  http://{args.host}:{args.port}")
    try:
        ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        mediax.trace("web", "server stopped")
    finally:
        for session in list(STREAM_REGISTRY):   # kill any live phone streams on shutdown
            Handler._end_stream(session)
        if log_fh:
            mediax.set_trace_sink(None)
            log_fh.close()
