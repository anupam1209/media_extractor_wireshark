#!/usr/bin/env python3
"""
webapp — zero-dependency web UI for the PCAP RTP media extractor.

Stdlib only (http.server). Reuses the verified engine in mediax.py.
Run:  python3 webapp.py   then open  http://127.0.0.1:8000

Flow:  upload PCAP  ->  auto-detected streams table  ->  Extract (per stream)  ->  download/preview WAV
"""
import base64
import hmac
import json
import os
import re
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import mediax

HOST, PORT = "127.0.0.1", 8000
WORK = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_work")
UPLOADS = os.path.join(WORK, "uploads")
OUTPUTS = os.path.join(WORK, "outputs")
os.makedirs(UPLOADS, exist_ok=True)
os.makedirs(OUTPUTS, exist_ok=True)

UPLOAD_REGISTRY = {}   # token -> {"path":..., "name":...}
OUTPUT_REGISTRY = {}   # token -> path
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]")
MAX_UPLOAD = 500 * 1024 * 1024  # 500 MB cap

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
    // reveal the player even when the wide table is horizontally scrolled
    out.scrollIntoView({ behavior: REDUCE ? 'auto' : 'smooth', block: 'nearest', inline: 'end' });
  } catch (e) { out.innerHTML = '<span class="warn">'+e.message+'</span>'; }
  btn.disabled = false; btn.textContent = old;
}

observeReveals();   // reveal the hero on first paint
</script>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # quieter logs
        pass

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
        if not self._authed():
            return
        u = urlparse(self.path)
        if u.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
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
        except Exception as e:  # surface engine errors as JSON
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
        _, _, info = mediax.extract_stream(up["path"], s, out_path,
                                           codec=s["codec"], mode=s.get("mode"), timing=timing)
        tok = uuid.uuid4().hex
        OUTPUT_REGISTRY[tok] = out_path
        info["download"] = f"/api/download?f={tok}"
        return self._send(200, info)


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Web UI for the PCAP RTP media extractor")
    ap.add_argument("--host", default=os.environ.get("MEDIAX_HOST", HOST),
                    help="bind address (use 0.0.0.0 to expose on the VM)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("MEDIAX_PORT") or os.environ.get("PORT") or PORT),
                    help="listen port (honours $PORT, set by Render/Railway/Cloud Run/Fly)")
    args = ap.parse_args()
    print(f"PCAP RTP Media Extractor  ->  http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
