#!/usr/bin/env python3
"""
mediax — PCAP RTP media extractor (audio + video).

Commands:
  detect      : auto-detect every RTP stream + guess codec (no manual config)
  extract     : extract one stream (audio -> WAV, video -> MP4), auto-codec or override
  extract-all : extract every supported media stream from a PCAP to a folder
  validate    : compare a WAV against a reference (.avi/.wav/.amr), drift-tolerant

Video note:
  H.264/H.265 streams are detected (90kHz clock / large payloads / NAL fingerprint), then
  depacketized in pure Python (RFC 6184 / 7798) into an Annex-B elementary stream and remuxed
  to MP4 with ffmpeg (-c copy, no re-encode). Video extraction is implemented to spec but has
  not yet been validated against a real video capture.

Codec handling:
  - Codec is inferred from RTP clock-rate (timestamp delta) + payload size, since these
    captures carry no SDP. 20ms@8kHz (delta 160) + ~small frames => AMR-NB; delta 320 => AMR-WB.
    Static payload types (0=PCMU, 8=PCMA, ...) are mapped directly.
  - AMR is depayloaded in pure Python (RFC 4867) because GStreamer >=1.28 rtpamrdepay only
    accepts octet-align=1, while these streams are bandwidth-efficient (octet-align=0).
    The rebuilt .amr is decoded with GStreamer amrnbdec/amrwbdec (opencore) or ffmpeg.
"""
import argparse
import array
import json
import math
import os
import re
import subprocess
import tempfile
import wave
from collections import Counter

TSHARK = "tshark"
FFMPEG = "ffmpeg"

# Speech bits per AMR frame type index (0 => SID/NO_DATA/reserved: no speech octets here).
AMR_NB_BITS = [95, 103, 118, 134, 148, 159, 204, 244, 39, 0, 0, 0, 0, 0, 0, 0]
AMR_WB_BITS = [132, 177, 253, 285, 317, 365, 397, 461, 477, 40, 0, 0, 0, 0, 0, 0]

STATIC_PT = {0: "G711u", 3: "GSM", 8: "G711a", 9: "G722", 18: "G729"}
AUDIO_CODECS = {"AMR-NB", "AMR-WB", "G711u", "G711a"}
VIDEO_CODECS = {"H264", "H265"}          # depacketize + remux supported (VP8 = detect-only)
SUPPORTED = AUDIO_CODECS | VIDEO_CODECS
START_CODE = b"\x00\x00\x00\x01"         # Annex-B NAL unit separator


# --------------------------------------------------------------------------- #
# Detection (single tshark pass, aggregated per stream)
# --------------------------------------------------------------------------- #
def detect_streams(pcap):
    """Return one dict per RTP stream with topology, packet count, modal payload size,
    modal timestamp delta, duration, and a codec guess. Robust to multi-word payload names."""
    out = subprocess.run(
        [TSHARK, "-r", pcap, "-o", "rtp.heuristic_rtp:TRUE", "-Y", "rtp", "-T", "fields",
         "-e", "ip.src", "-e", "udp.srcport", "-e", "ip.dst", "-e", "udp.dstport",
         "-e", "rtp.ssrc", "-e", "rtp.p_type", "-e", "rtp.timestamp",
         "-e", "rtp.payload", "-e", "frame.time_relative"],
        capture_output=True, text=True,
    ).stdout
    agg = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) < 9 or not f[1] or not f[3] or not f[4]:
            continue
        # tunneled/fragmented packets can yield comma-joined fields; take the first value
        f = [c.split(",")[0] for c in f]
        try:
            sip, sport, dip, dport = f[0], int(f[1]), f[2], int(f[3])
            ssrc = int(f[4], 0)
            pt = int(f[5]) if f[5] else -1
            ts = int(f[6]) if f[6] else None
            size = len(f[7].replace(":", "")) // 2 if f[7] else 0
            t = float(f[8]) if f[8] else 0.0
        except ValueError:
            continue
        key = (sip, sport, dip, dport, ssrc)
        d = agg.get(key)
        if d is None:
            d = agg[key] = {"pt": pt, "pkts": 0, "sizes": Counter(),
                            "deltas": Counter(), "last_ts": None, "t0": t, "t1": t,
                            "max_size": 0, "same_ts": 0, "sample": None}
        d["pkts"] += 1
        if size:
            d["sizes"][size] += 1
            if size > d["max_size"]:
                d["max_size"] = size
        if f[7] and d["sample"] is None:
            d["sample"] = f[7].replace(":", "")  # hex of first payload (for video fingerprint)
        if ts is not None and d["last_ts"] is not None:
            delta = ts - d["last_ts"]
            if delta == 0:
                d["same_ts"] += 1                 # multiple packets per frame => likely video
            elif 0 < delta < 4000:
                d["deltas"][delta] += 1
        if ts is not None:
            d["last_ts"] = ts
        d["t1"] = t

    streams = []
    for (sip, sport, dip, dport, ssrc), d in agg.items():
        s = {
            "src_ip": sip, "src_port": sport, "dst_ip": dip, "dst_port": dport,
            "ssrc": f"0x{ssrc:08X}", "pt": d["pt"], "pkts": d["pkts"],
            "mode_size": d["sizes"].most_common(1)[0][0] if d["sizes"] else None,
            "max_size": d["max_size"], "same_ts": d["same_ts"],
            "ts_delta": d["deltas"].most_common(1)[0][0] if d["deltas"] else None,
            "duration": round(d["t1"] - d["t0"], 2),
        }
        s["codec"], s["wideband"], s["mode"] = classify(s, d["sample"])
        streams.append(s)
    streams.sort(key=lambda x: -x["pkts"])
    return streams


def classify(s, sample=None):
    """Return (codec, wideband, amr_mode). Static PT map, then audio (clock-rate/size), then video."""
    pt = s.get("pt", -1)
    if pt in STATIC_PT:
        return STATIC_PT[pt], False, None
    delta, size = s.get("ts_delta"), s.get("mode_size")
    if delta == 160 or size == 32:
        return "AMR-NB", False, "be"
    if delta == 320 or size in (60, 61):
        return "AMR-WB", True, "be"
    # video: large/variable payloads or multiple packets sharing one RTP timestamp (a frame)
    if (s.get("max_size", 0) or 0) > 200 or (s.get("same_ts", 0) or 0) > 0:
        return fingerprint_video(sample), False, None
    return f"PT{pt}", False, "be"  # unknown / unsupported


def fingerprint_video(sample):
    """Best-effort video codec from the first RTP payload's NAL header.
    H.264 (RFC 6184): 1-byte NAL header, type = b0 & 0x1F.
    H.265 (RFC 7798): 2-byte NAL header, type = (b0 >> 1) & 0x3F."""
    if not sample:
        return "video"
    try:
        b = bytes.fromhex(sample)
    except ValueError:
        return "video"
    if not b or (b[0] & 0x80):  # forbidden_zero_bit must be 0 for a real NAL
        return "video"
    t264 = b[0] & 0x1F
    t265 = (b[0] >> 1) & 0x3F
    if t265 in (48, 49, 50):                 # H.265 AP / FU / PACI (distinctive)
        return "H265"
    if t264 in (24, 28, 29):                 # H.264 STAP-A / FU-A / FU-B (distinctive)
        return "H264"
    if t265 in (32, 33, 34, 19, 20, 21):     # H.265 VPS/SPS/PPS/IDR
        return "H265"
    if t264 in (1, 5, 6, 7, 8):              # H.264 slice/IDR/SEI/SPS/PPS
        return "H264"
    return "video"


# --------------------------------------------------------------------------- #
# RTP AMR -> AMR storage (RFC 4867)
# --------------------------------------------------------------------------- #
class BitReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def _bit(self):
        b = self.data[self.pos >> 3]
        bit = (b >> (7 - (self.pos & 7))) & 1
        self.pos += 1
        return bit

    def read(self, n):
        v = 0
        for _ in range(n):
            v = (v << 1) | self._bit()
        return v

    def read_bytes_msb(self, nbits):
        out = bytearray()
        cur = cnt = 0
        for _ in range(nbits):
            cur = (cur << 1) | self._bit()
            cnt += 1
            if cnt == 8:
                out.append(cur)
                cur = cnt = 0
        if cnt:
            out.append(cur << (8 - cnt))
        return bytes(out)


def depacketize_be(payload, wideband=False):
    """Bandwidth-efficient (octet-align=0) RTP AMR -> concatenated AMR storage frames."""
    sizes = AMR_WB_BITS if wideband else AMR_NB_BITS
    br = BitReader(payload)
    br.read(4)  # CMR
    tocs = []
    while True:
        f = br.read(1)
        ft = br.read(4)
        q = br.read(1)
        tocs.append((ft, q))
        if f == 0:
            break
    frames = bytearray()
    for ft, q in tocs:
        nbits = sizes[ft] if ft < len(sizes) else 0
        frames.append((ft << 3) | (q << 2))
        if nbits:
            frames += br.read_bytes_msb(nbits)
    return bytes(frames)


def depacketize_oa(payload, wideband=False):
    """Octet-aligned (octet-align=1) RTP AMR -> concatenated AMR storage frames."""
    sizes = AMR_WB_BITS if wideband else AMR_NB_BITS
    i, tocs = 1, []  # byte 0 = CMR
    while True:
        toc = payload[i]; i += 1
        f = (toc >> 7) & 1
        ft = (toc >> 3) & 0xF
        q = (toc >> 2) & 1
        tocs.append((ft, q))
        if f == 0:
            break
    frames = bytearray()
    for ft, q in tocs:
        nbits = sizes[ft] if ft < len(sizes) else 0
        nbytes = (nbits + 7) // 8
        frames.append((ft << 3) | (q << 2))
        frames += payload[i:i + nbytes]; i += nbytes
    return bytes(frames)


# --------------------------------------------------------------------------- #
# Payload extraction + decode
# --------------------------------------------------------------------------- #
def get_rtp_payloads_ts(pcap, s):
    """[(timestamp, payload)] for one stream (by 5-tuple + SSRC), ordered by sequence number."""
    flt = (f'ip.src=={s["src_ip"]} && udp.srcport=={s["src_port"]} && '
           f'ip.dst=={s["dst_ip"]} && udp.dstport=={s["dst_port"]} && '
           f'rtp.ssrc=={s["ssrc"]} && rtp')
    out = subprocess.run(
        [TSHARK, "-r", pcap, "-o", "rtp.heuristic_rtp:TRUE", "-Y", flt,
         "-T", "fields", "-e", "rtp.seq", "-e", "rtp.timestamp", "-e", "rtp.payload"],
        capture_output=True, text=True,
    ).stdout
    rows = []
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) < 3 or not p[2]:
            continue
        rows.append((int(p[0]), int(p[1]), bytes.fromhex(p[2].replace(":", ""))))
    rows.sort(key=lambda r: r[0])  # by sequence number
    return [(ts, pl) for _, ts, pl in rows]


def get_rtp_payloads(pcap, s):
    """RTP payloads for one stream, ordered by sequence number."""
    return [pl for _, pl in get_rtp_payloads_ts(pcap, s)]


def _unwrap_ts(ts_list):
    """Undo 32-bit RTP timestamp wraparound."""
    out, off, prev = [], 0, None
    for t in ts_list:
        if prev is not None and t < prev - (1 << 31):
            off += 1 << 32
        out.append(t + off)
        prev = t
    return out


def reconstruct_timed(samples, frame_counts, ts_list):
    """Place each frame's decoded samples at its RTP-timestamp offset, filling DTX gaps with
    silence. RTP audio timestamps are in sample units, so (ts - ts0) is the sample offset."""
    ts = _unwrap_ts(ts_list)
    ts0 = ts[0]
    total = (ts[-1] - ts0) + frame_counts[-1]
    buf = array.array("h", bytes(2 * total))  # zero-filled (silence)
    pos = 0
    for fc, t in zip(frame_counts, ts):
        chunk = samples[pos:pos + fc]
        pos += fc
        off = max(0, t - ts0)
        end = min(off + len(chunk), total)
        if end > off:
            buf[off:end] = chunk[:end - off]
    return buf


def write_wav(path, samples, sr):
    w = wave.open(path, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(sr)
    w.writeframes(samples.tobytes())
    w.close()


def _gst_has(element):
    try:
        return subprocess.run(["gst-inspect-1.0", element], capture_output=True).returncode == 0
    except FileNotFoundError:
        return False


def decode_amr(amr_path, out_wav, wideband):
    """Decode AMR storage to WAV; prefer GStreamer opencore decoder, fall back to ffmpeg."""
    dec = "amrwbdec" if wideband else "amrnbdec"
    rate = 16000 if wideband else 8000
    if _gst_has(dec):
        pipe = (f"filesrc location={amr_path} ! amrparse ! {dec} ! "
                f"audioconvert ! audioresample ! wavenc ! filesink location={out_wav}")
        r = subprocess.run(["gst-launch-1.0", "-e", *pipe.split()], capture_output=True)
        if r.returncode == 0 and os.path.exists(out_wav) and os.path.getsize(out_wav) > 44:
            return "gstreamer:" + dec
    subprocess.run([FFMPEG, "-y", "-v", "error", "-i", amr_path,
                    "-ar", str(rate), "-ac", "1", out_wav], check=True)
    return "ffmpeg:native"


# --------------------------------------------------------------------------- #
# RTP video -> Annex-B elementary stream (RFC 6184 / RFC 7798)
# --------------------------------------------------------------------------- #
def depacketize_h264(payloads):
    """H.264 RTP payloads -> Annex-B byte stream (single NAL / STAP-A / FU-A / FU-B)."""
    out = bytearray()
    for p in payloads:
        if not p:
            continue
        t = p[0] & 0x1F
        if 1 <= t <= 23:                          # single NAL unit
            out += START_CODE + p
        elif t == 24:                             # STAP-A aggregation
            i = 1
            while i + 2 <= len(p):
                sz = (p[i] << 8) | p[i + 1]
                i += 2
                out += START_CODE + p[i:i + sz]
                i += sz
        elif t in (28, 29):                       # FU-A / FU-B (fragmentation)
            if len(p) < 2:
                continue
            offset = 4 if t == 29 else 2          # FU-B carries a 2-byte DON
            if p[1] & 0x80:                       # start fragment -> rebuild NAL header
                nal = (p[0] & 0xE0) | (p[1] & 0x1F)
                out += START_CODE + bytes([nal]) + p[offset:]
            else:
                out += p[offset:]
        # STAP-B(25)/MTAP(26,27)/reserved -> skip
    return bytes(out)


def depacketize_h265(payloads):
    """H.265 RTP payloads -> Annex-B byte stream (single NAL / AP / FU)."""
    out = bytearray()
    for p in payloads:
        if len(p) < 2:
            continue
        t = (p[0] >> 1) & 0x3F
        if t <= 47:                               # single NAL unit
            out += START_CODE + p
        elif t == 48:                             # AP aggregation
            i = 2
            while i + 2 <= len(p):
                sz = (p[i] << 8) | p[i + 1]
                i += 2
                out += START_CODE + p[i:i + sz]
                i += sz
        elif t == 49:                             # FU (fragmentation)
            if len(p) < 3:
                continue
            if p[2] & 0x80:                        # start fragment -> rebuild 2-byte NAL header
                h0 = (p[0] & 0x81) | ((p[2] & 0x3F) << 1)
                out += START_CODE + bytes([h0, p[1]]) + p[3:]
            else:
                out += p[3:]
        # PACI(50)/reserved -> skip
    return bytes(out)


def _video_fps(ts_list):
    """Frame rate from the 90 kHz RTP timestamps (frame = a distinct timestamp)."""
    ts = _unwrap_ts(ts_list)
    deltas = []
    prev = ts[0]
    for t in ts[1:]:
        if t > prev:
            deltas.append(t - prev)
            prev = t
    if not deltas:
        return 25.0
    deltas.sort()
    d = deltas[len(deltas) // 2]  # median inter-frame timestamp delta
    return round(90000 / d, 2) if d > 0 else 25.0


def extract_video(pcap, s, out_path, codec):
    """Depacketize a video stream to Annex-B, then remux to MP4 (no re-encode)."""
    rows = get_rtp_payloads_ts(pcap, s)
    if not rows:
        raise SystemExit("no RTP payloads matched the stream")
    payloads = [p for _, p in rows]
    fps = _video_fps([t for t, _ in rows])
    if codec == "H264":
        es, demux, suffix = depacketize_h264(payloads), "h264", ".h264"
    elif codec == "H265":
        es, demux, suffix = depacketize_h265(payloads), "hevc", ".h265"
    else:
        raise SystemExit(f"video codec '{codec}' is detect-only (extraction not implemented)")
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tf:
        tf.write(es)
        raw_path = tf.name
    subprocess.run([FFMPEG, "-y", "-v", "error", "-r", str(fps),
                    "-f", demux, "-i", raw_path, "-c", "copy", out_path], check=True)
    os.unlink(raw_path)
    info = {"frames": len(payloads), "decoder": "ffmpeg:remux", "kind": "video",
            "container": "mp4", "fps": fps,
            "note": "validated pixel-exact on synthetic H.264; confirm against a real capture"}
    return len(payloads), "ffmpeg:remux", info


def extract_stream(pcap, s, out_path, codec=None, mode=None, timing="accurate"):
    """Extract one stream. Audio -> WAV (RTP-timestamp accurate by default); video -> MP4.
    Auto-classifies if codec is None. Returns (frames, decoder, info-dict).
    """
    if codec is None:
        codec = s.get("codec") or classify(s)[0]
    mode = mode or s.get("mode") or "be"
    wideband = codec == "AMR-WB"

    if codec in VIDEO_CODECS:
        return extract_video(pcap, s, out_path, codec)
    if codec not in AUDIO_CODECS:
        raise SystemExit(f"unsupported codec '{codec}' for this stream (override with --codec)")

    out_wav = out_path
    rows = get_rtp_payloads_ts(pcap, s)
    if not rows:
        raise SystemExit("no RTP payloads matched the stream")
    ts_list = [t for t, _ in rows]
    payloads = [p for _, p in rows]
    rate = 16000 if wideband else 8000

    # 1) decode received frames to a concatenated PCM stream + per-frame sample counts
    tmp_wav = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
    if codec in ("G711u", "G711a"):
        fmt = "mulaw" if codec == "G711u" else "alaw"
        with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as tf:
            tf.write(b"".join(payloads))
            raw_path = tf.name
        subprocess.run([FFMPEG, "-y", "-v", "error", "-f", fmt, "-ar", "8000",
                        "-ac", "1", "-i", raw_path, tmp_wav], check=True)
        os.unlink(raw_path)
        decoder = "ffmpeg:" + fmt
        frame_counts = [len(p) for p in payloads]
    else:
        depay = depacketize_oa if mode == "oa" else depacketize_be
        body = bytearray(b"#!AMR-WB\n" if wideband else b"#!AMR\n")
        for p in payloads:
            body += depay(p, wideband)
        with tempfile.NamedTemporaryFile(suffix=".amr", delete=False) as tf:
            tf.write(body)
            amr_path = tf.name
        decoder = decode_amr(amr_path, tmp_wav, wideband)
        os.unlink(amr_path)
        fs = 320 if wideband else 160
        frame_counts = [fs] * len(payloads)

    sr, samples = load_samples(tmp_wav)
    os.unlink(tmp_wav)

    # 2) place on the real timeline (or concatenate)
    info = {"frames": len(payloads), "decoder": decoder, "timing": timing}
    expected = sum(frame_counts)
    if timing == "accurate" and len(samples) == expected:
        buf = reconstruct_timed(samples, frame_counts, ts_list)
        info["gaps_filled_s"] = round((len(buf) - expected) / sr, 2)
    else:
        if timing == "accurate" and len(samples) != expected:
            info["timing"] = "compact (fallback: decoder sample count mismatch)"
        buf = samples
    write_wav(out_wav, buf, sr)
    info["duration_s"] = round(len(buf) / sr, 2)
    return len(payloads), decoder, info


def extract_all(pcap, out_dir, min_pkts=20, timing="accurate"):
    """Extract every supported media stream (audio->WAV, video->MP4) into out_dir."""
    os.makedirs(out_dir, exist_ok=True)
    results = []
    for s in detect_streams(pcap):
        rec = {"src": f'{s["src_ip"]}:{s["src_port"]}', "dst": f'{s["dst_ip"]}:{s["dst_port"]}',
               "ssrc": s["ssrc"], "pt": s["pt"], "pkts": s["pkts"], "codec": s["codec"]}
        if s["codec"] not in SUPPORTED:
            rec["status"] = "skipped (unsupported)"
        elif s["pkts"] < min_pkts:
            rec["status"] = f"skipped (<{min_pkts} pkts)"
        else:
            ext = ".mp4" if s["codec"] in VIDEO_CODECS else ".wav"
            name = f'{s["src_ip"]}_{s["src_port"]}-{s["dst_ip"]}_{s["dst_port"]}_{s["ssrc"]}{ext}'
            out = os.path.join(out_dir, name)
            n, dec, info = extract_stream(pcap, s, out, codec=s["codec"],
                                          mode=s["mode"], timing=timing)
            rec.update(status="ok", file=out, **info)
        results.append(rec)
    return results


# --------------------------------------------------------------------------- #
# Validation (drift-tolerant)
# --------------------------------------------------------------------------- #
def to_canonical_wav(path, rate):
    tmp = tempfile.NamedTemporaryFile(suffix=".wav", delete=False).name
    subprocess.run([FFMPEG, "-y", "-v", "error", "-i", path, "-ar", str(rate),
                    "-ac", "1", "-f", "wav", tmp], check=True)
    return tmp


def load_samples(wav_path):
    w = wave.open(wav_path, "rb")
    a = array.array("h")
    a.frombytes(w.readframes(w.getnframes()))
    return w.getframerate(), a


def _norm_seg(x, s, n):
    m = sum(x[s:s + n]) / n
    d = [v - m for v in x[s:s + n]]
    nn = math.sqrt(sum(v * v for v in d)) or 1.0
    return d, nn


def validate(out_wav, ref_path, rate=8000):
    """Per-window sample-level correlation with local lag tracking (tolerates timing drift)."""
    ref_wav = to_canonical_wav(ref_path, rate)
    sr1, a = load_samples(out_wav)
    sr2, b = load_samples(ref_wav)
    os.unlink(ref_wav)

    win = int(rate * 0.3)
    hop = rate
    gate = 150
    peaks, cur_lag, i = [], 0, 0
    while i + win < len(a):
        A, nA = _norm_seg(a, i, win)
        if nA / math.sqrt(win) < gate:
            i += hop
            continue
        best, bl = -1.0, cur_lag
        for lag in range(cur_lag - 300, cur_lag + 301):
            j = i + lag
            if j < 0 or j + win > len(b):
                continue
            B, nB = _norm_seg(b, j, win)
            c = sum(A[k] * B[k] for k in range(win)) / (nA * nB)
            if c > best:
                best, bl = c, lag
        peaks.append(best)
        cur_lag = bl
        i += hop

    peaks.sort()
    score = peaks[len(peaks) // 2] if peaks else 0.0
    return {
        "out_dur": round(len(a) / sr1, 3), "ref_dur": round(len(b) / sr2, 3),
        "corr_local_median": round(score, 4), "active_windows": len(peaks),
        "drift_samples": cur_lag, "verdict": "PASS" if score >= 0.9 else "FAIL",
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _find_stream(streams, sport, dport, src=None, dst=None):
    for s in streams:
        if s["src_port"] == sport and s["dst_port"] == dport \
                and (src is None or s["src_ip"] == src) and (dst is None or s["dst_ip"] == dst):
            return s
    return None


def main():
    ap = argparse.ArgumentParser(description="PCAP RTP media extractor (audio + video)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("detect", help="list RTP streams with codec guess")
    d.add_argument("pcap")
    d.add_argument("--json", action="store_true")

    e = sub.add_parser("extract", help="extract one stream (audio->WAV, video->MP4)")
    e.add_argument("pcap")
    e.add_argument("--src"); e.add_argument("--sport", type=int, required=True)
    e.add_argument("--dst"); e.add_argument("--dport", type=int, required=True)
    e.add_argument("--codec", choices=sorted(SUPPORTED), help="override auto-detected codec")
    e.add_argument("--mode", choices=["be", "oa"], help="AMR framing override")
    e.add_argument("--timing", choices=["accurate", "compact"], default="accurate",
                   help="accurate: silence fills DTX gaps (default); compact: frames back-to-back")
    e.add_argument("-o", "--out", required=True)
    e.add_argument("--validate-against")

    a = sub.add_parser("extract-all", help="extract every supported media stream to a folder")
    a.add_argument("pcap")
    a.add_argument("-o", "--out-dir", required=True)
    a.add_argument("--timing", choices=["accurate", "compact"], default="accurate")

    v = sub.add_parser("validate", help="compare a WAV against a reference")
    v.add_argument("wav"); v.add_argument("reference")
    v.add_argument("--rate", type=int, default=8000)

    args = ap.parse_args()

    if args.cmd == "detect":
        streams = detect_streams(args.pcap)
        if args.json:
            print(json.dumps(streams, indent=2))
        else:
            print(f"{'src':>22} {'dst':>22} {'ssrc':>11} {'pt':>4} {'pkts':>6} "
                  f"{'sz':>3} {'dur':>6}  codec")
            for s in streams:
                print(f'{s["src_ip"]+":"+str(s["src_port"]):>22} '
                      f'{s["dst_ip"]+":"+str(s["dst_port"]):>22} {s["ssrc"]:>11} '
                      f'{s["pt"]:>4} {s["pkts"]:>6} {str(s["mode_size"]):>3} '
                      f'{s["duration"]:>6}  {s["codec"]}')
        return

    if args.cmd == "extract":
        streams = detect_streams(args.pcap)
        s = _find_stream(streams, args.sport, args.dport, args.src, args.dst)
        if not s:
            raise SystemExit(f"no stream {args.sport}->{args.dport} found")
        n, dec, info = extract_stream(args.pcap, s, args.out, codec=args.codec,
                                      mode=args.mode, timing=args.timing)
        print(f"extracted {n} frames -> {args.out}  (codec: {args.codec or s['codec']})")
        print("info:", json.dumps(info))
        if args.validate_against:
            rate = 16000 if (args.codec or s["codec"]) == "AMR-WB" else 8000
            print("validation:", json.dumps(validate(args.out, args.validate_against, rate)))
        return

    if args.cmd == "extract-all":
        for rec in extract_all(args.pcap, args.out_dir, timing=args.timing):
            print(json.dumps(rec))
        return

    if args.cmd == "validate":
        print(json.dumps(validate(args.wav, args.reference, args.rate)))
        return


if __name__ == "__main__":
    main()
