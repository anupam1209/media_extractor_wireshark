#!/usr/bin/env python3
"""
webapp — zero-dependency web UI for the PCAP RTP media extractor.

Stdlib only (http.server). Reuses the verified engine in mediax.py.
Run:  python3 webapp.py   then open  http://127.0.0.1:8000

Flow:  upload PCAP  ->  auto-detected streams table  ->  Extract (per stream)  ->  download/preview WAV
"""
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
<html><head><meta charset="utf-8"><title>PCAP RTP Media Extractor</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0; padding: 2rem; max-width: 1100px; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .sub { opacity: .7; margin-bottom: 1.5rem; }
  .card { border: 1px solid #8884; border-radius: 10px; padding: 1rem 1.25rem; margin-bottom: 1.25rem; }
  table { border-collapse: collapse; width: 100%; font-size: 14px; }
  th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid #8883; white-space: nowrap; }
  th { font-weight: 600; opacity: .75; }
  tr:hover td { background: #8881; }
  button { font: inherit; padding: .35rem .8rem; border-radius: 7px; border: 1px solid #8886;
           background: #2b6cb0; color: #fff; cursor: pointer; }
  button:disabled { background: #8884; color: #8888; cursor: not-allowed; }
  .pill { font-size: 12px; padding: .1rem .5rem; border-radius: 999px; background: #8882; }
  .ok { color: #2f855a; } .warn { color: #b7791f; }
  input[type=file] { font: inherit; }
  label.timing { margin-right: 1rem; opacity:.85; }
  audio { height: 32px; vertical-align: middle; }
  .muted { opacity:.6; }
  #status { margin-left: .75rem; opacity:.8; }
</style></head>
<body>
  <h1>PCAP RTP Media Extractor</h1>
  <div class="sub">Upload a capture &rarr; streams are auto-detected &rarr; extract & download audio.</div>

  <div class="card">
    <input type="file" id="file" accept=".pcap,.pcapng,.cap">
    <button id="up">Upload &amp; detect</button>
    <span id="status"></span>
  </div>

  <div class="card" id="result" style="display:none">
    <div style="margin-bottom:.75rem">
      <strong>Detected streams</strong> &nbsp;
      <label class="timing"><input type="radio" name="timing" value="accurate" checked> Real timing (silence in gaps)</label>
      <label class="timing"><input type="radio" name="timing" value="compact"> Compact (speech only)</label>
    </div>
    <table id="tbl"><thead><tr>
      <th>Source</th><th>Destination</th><th>SSRC</th><th>Codec</th>
      <th>Pkts</th><th>Dur (s)</th><th>Action</th><th>Output</th>
    </tr></thead><tbody></tbody></table>
  </div>

<script>
let FILE_ID = null;
const $ = s => document.querySelector(s);

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
    renderStreams(d.streams);
    $('#status').textContent = d.streams.length + ' stream(s) found';
    $('#result').style.display = '';
  } catch (e) { $('#status').textContent = 'error: ' + e.message; }
  $('#up').disabled = false;
};

function renderStreams(streams) {
  const tb = $('#tbl tbody'); tb.innerHTML = '';
  for (const s of streams) {
    const tr = document.createElement('tr');
    const supported = ['AMR-NB','AMR-WB','G711u','G711a'].includes(s.codec);
    tr.innerHTML = `
      <td>${s.src_ip}:${s.src_port}</td>
      <td>${s.dst_ip}:${s.dst_port}</td>
      <td>${s.ssrc}</td>
      <td><span class="pill">${s.codec}</span></td>
      <td>${s.pkts}</td>
      <td>${s.duration}</td>
      <td></td><td class="out muted">—</td>`;
    const act = tr.children[6], out = tr.children[7];
    if (supported) {
      const b = document.createElement('button');
      b.textContent = 'Extract';
      b.onclick = () => extract(s, b, out);
      act.appendChild(b);
    } else {
      act.innerHTML = '<span class="muted">unsupported</span>';
    }
    tb.appendChild(tr);
  }
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
    out.innerHTML = `<a href="${d.download}" download>download</a> `
      + `<span class="muted">(${d.duration_s}s${d.gaps_filled_s?(', '+d.gaps_filled_s+'s silence'):''})</span><br>`
      + `<audio controls preload="none" src="${d.download}"></audio>`;
  } catch (e) { out.innerHTML = '<span class="warn">'+e.message+'</span>'; }
  btn.disabled = false; btn.textContent = old;
}
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

    # ---- GET: page + download -------------------------------------------- #
    def do_GET(self):
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
            return self._send(200, data, "audio/wav",
                              {"Content-Disposition": f'attachment; filename="{fn}"'})
        return self._send(404, {"error": "not found"})

    # ---- POST: upload + extract ------------------------------------------ #
    def do_POST(self):
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
        if s.get("codec") not in mediax.SUPPORTED:
            return self._send(400, {"error": f"unsupported codec {s.get('codec')}"})
        name = (f'{s["src_ip"]}_{s["src_port"]}-{s["dst_ip"]}_{s["dst_port"]}'
                f'_{s["ssrc"]}_{timing}.wav')
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
    ap.add_argument("--port", type=int, default=int(os.environ.get("MEDIAX_PORT", PORT)))
    args = ap.parse_args()
    print(f"PCAP RTP Media Extractor  ->  http://{args.host}:{args.port}")
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()
