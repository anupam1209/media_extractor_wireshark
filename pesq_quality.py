#!/usr/bin/env python3
"""
pesq_quality — optional, self-contained speech-quality (ITU-T P.862 / PESQ) add-on.

This module is deliberately isolated from the core extractor:

  * It is imported lazily by webapp.py; removing this one file (and the small,
    clearly-marked PESQ block in webapp.py) takes the feature away cleanly and
    leaves every existing extractor flow untouched.
  * It depends on numpy + the `pesq` pip package (plus ffmpeg/ffprobe, which the
    app already requires). Those extras are NOT needed by the rest of the app --
    if they are missing the core stays fully usable and this feature simply
    reports that it is unavailable (see deps_status()).

What it does: given a clean *reference* speech file and one *degraded* test file,
it converts both to the mono / 8 kHz (narrowband) or 16 kHz (wideband) signal
PESQ expects, trims them to a common length, and returns a PESQ MOS-LQO score --
reporting audio problems as warnings/errors rather than raising.

PESQ is an *intrusive, speech-only* metric: it needs the original reference and
assumes the two signals are time-aligned. Scores on music / non-speech, or on
badly misaligned clips, are not meaningful.
"""
import json
import os
import subprocess
import tempfile
import wave

import mediax   # reuse the engine's ffmpeg-based mono/resample + stdlib WAV loader

FFPROBE = "ffprobe"

# PESQ operates at exactly these rates; "wb" (wideband, 16 kHz) is the default.
MODES = {"wb": 16000, "nb": 8000}
DEFAULT_MODE = "wb"
MODE_LABEL = {"wb": "Wideband (16 kHz)", "nb": "Narrowband (8 kHz)"}

# Accepted upload extensions (ffprobe still has the final say on the contents).
AUDIO_EXTS = {".wav", ".wave", ".mp3", ".m4a", ".aac", ".ogg", ".oga", ".opus",
              ".flac", ".amr", ".awb", ".wma", ".caf", ".aif", ".aiff", ".au"}
MAX_PESQ_UPLOAD = 100 * 1024 * 1024   # 100 MB per file -- generous for speech clips

# Length-mismatch warning: flag only differences that are both absolutely and
# relatively large, so trivially-trimmed clips don't spam warnings.
_MISMATCH_ABS_S = 0.5
_MISMATCH_FRAC = 0.10
_MIN_USABLE_S = 0.5    # below this much overlapping audio PESQ is unreliable


# --------------------------------------------------------------------------- #
# optional dependency loading (numpy + pesq) -- kept lazy so importing this
# module never fails and never pulls numpy into the stdlib-only core.
# --------------------------------------------------------------------------- #
_np = None
_pesq_fn = None
_import_error = None


def _load_deps():
    """Import numpy + pesq once, caching the result. Returns True on success,
    False if the extras are not installed (reason stashed in _import_error)."""
    global _np, _pesq_fn, _import_error
    if _np is not None:
        return True
    if _import_error is not None:
        return False
    try:
        import numpy as np
        from pesq import pesq as pesq_fn
        _np, _pesq_fn = np, pesq_fn
        return True
    except Exception as e:   # ImportError, or numpy/pesq ABI mismatch
        _import_error = e
        return False


def deps_status():
    """(available: bool, message: str) -- used by the UI to show whether the
    PESQ extras are installed, and how to install them if not."""
    if _load_deps():
        return True, "PESQ engine ready."
    return False, (
        "Speech-quality scoring needs two extra Python packages that the rest of "
        "this app does not: numpy and pesq. Install them with:\n"
        "    pip install numpy pesq\n"
        "The 'pesq' package builds a small C extension, so a C compiler may be "
        "required (see the README). "
        f"[import error: {type(_import_error).__name__}: {_import_error}]"
    )


# --------------------------------------------------------------------------- #
# input validation -- audio only; reject video and non-audio clearly.
# --------------------------------------------------------------------------- #
def _ffprobe_kinds(path):
    """Return (has_real_video, has_audio) for `path` via ffprobe.

    'Real' video excludes attached cover art (e.g. an album-art JPEG inside an
    MP3 is reported by ffprobe as a video stream with disposition attached_pic;
    that must not cause an audio file to be rejected)."""
    try:
        r = subprocess.run(
            [FFPROBE, "-v", "error", "-show_entries",
             "stream=codec_type:stream_disposition=attached_pic",
             "-of", "json", path],
            capture_output=True, text=True)
    except FileNotFoundError:
        raise ValueError("ffprobe not found on this PC (install ffmpeg to use PESQ).")
    if r.returncode != 0:
        tail = [ln for ln in (r.stderr or "").splitlines() if ln.strip()]
        raise ValueError("could not read this file as media"
                         + (f" ({tail[-1].strip()})" if tail else ""))
    try:
        streams = json.loads(r.stdout or "{}").get("streams", [])
    except json.JSONDecodeError:
        raise ValueError("could not parse this file's media info")
    has_video = any(
        s.get("codec_type") == "video"
        and not (s.get("disposition") or {}).get("attached_pic")
        for s in streams)
    has_audio = any(s.get("codec_type") == "audio" for s in streams)
    return has_video, has_audio


def validate_audio(path, name=None):
    """Raise ValueError if `path` is not usable mono-isable audio. The feature is
    audio-only: video files and non-audio uploads are rejected with a clear
    message. `name` is the user-facing filename (path may be a temp file)."""
    label = name or os.path.basename(path)
    ext = os.path.splitext(name or path)[1].lower()
    if ext and ext not in AUDIO_EXTS:
        raise ValueError(
            f"{label}: '{ext or 'no extension'}' is not an accepted audio type. "
            f"Upload an audio file such as .wav, .mp3, .m4a, .flac or .amr.")
    has_video, has_audio = _ffprobe_kinds(path)
    if has_video:
        raise ValueError(
            f"{label}: this looks like a video file. Speech-quality scoring is "
            f"audio-only — upload the extracted audio instead.")
    if not has_audio:
        raise ValueError(f"{label}: no audio stream found in this file.")


# --------------------------------------------------------------------------- #
# scoring
# --------------------------------------------------------------------------- #
def _load_mono(path, rate):
    """Decode `path` to a mono int16 numpy array at `rate` Hz, reusing the
    engine's ffmpeg conversion and stdlib WAV loader. Temp WAV is cleaned up."""
    wav = mediax.to_canonical_wav(path, rate)      # ffmpeg -> mono WAV @ rate
    try:
        _, samples = mediax.load_samples(wav)      # (rate, array('h'))
    finally:
        try:
            os.unlink(wav)
        except OSError:
            pass
    return _np.array(samples, dtype=_np.int16)


def _pretty_pesq_error(e):
    """Turn a raw pesq exception into a human-readable, per-file reason."""
    name = type(e).__name__
    msg = (str(e) or "").strip()
    low = (name + " " + msg).lower()
    if "noutterance" in low or "no utterance" in low:
        return ("PESQ found no speech (the audio may be silent, too short, or not "
                "speech — remember PESQ only measures speech).")
    if "too short" in low or "buffertooshort" in low:
        return "the overlapping audio is too short for PESQ."
    if "sample rate" in low or "fs" in low and "support" in low:
        return "unsupported sample rate for this PESQ mode."
    return f"PESQ error: {msg or name}"


def score_one(ref_path, deg_path, mode=DEFAULT_MODE):
    """Score one degraded file against the reference. Returns a dict with:
       score (float or None), mode, ref_dur, deg_dur, duration (overlap used),
       warnings (list[str]), error (str or None).
    Never raises for ordinary audio problems -- they come back in `error`."""
    if mode not in MODES:
        mode = DEFAULT_MODE
    rate = MODES[mode]
    result = {"score": None, "mode": mode, "ref_dur": None, "deg_dur": None,
              "duration": None, "warnings": [], "error": None}
    if not _load_deps():                    # safe when called on its own
        result["error"] = deps_status()[1]
        return result

    ref = _load_mono(ref_path, rate)
    deg = _load_mono(deg_path, rate)
    ref_dur, deg_dur = len(ref) / rate, len(deg) / rate
    result["ref_dur"], result["deg_dur"] = round(ref_dur, 2), round(deg_dur, 2)

    if len(ref) == 0 or len(deg) == 0:
        result["error"] = "no audio samples after decoding."
        return result

    # PESQ assumes time-aligned signals; we trim both to the shorter length.
    diff = abs(ref_dur - deg_dur)
    if diff > _MISMATCH_ABS_S and diff > _MISMATCH_FRAC * max(ref_dur, deg_dur):
        result["warnings"].append(
            f"duration differs by {diff:.1f}s (reference {ref_dur:.1f}s vs "
            f"this file {deg_dur:.1f}s); PESQ assumes the signals are time-aligned, "
            f"so this score may be unreliable.")

    n = min(len(ref), len(deg))
    ref, deg = ref[:n], deg[:n]
    overlap = n / rate
    result["duration"] = round(overlap, 2)
    if overlap < _MIN_USABLE_S:
        result["warnings"].append(
            f"only {overlap:.2f}s of overlapping audio — too short for a reliable score.")

    if int(_np.abs(ref).max()) == 0 or int(_np.abs(deg).max()) == 0:
        result["error"] = "one of the signals is completely silent."
        return result

    try:
        result["score"] = round(float(_pesq_fn(rate, ref, deg, mode)), 3)
    except Exception as e:
        result["error"] = _pretty_pesq_error(e)
    return result


def run_single(ref_path, deg_name, deg_path, mode=DEFAULT_MODE):
    """Score one degraded file against one reference.

    Returns a single result dict (see score_one) plus a 'name' key. Ordinary
    audio problems (silence, no speech, decode failure) come back in the dict's
    'error'/'warnings' instead of raising. Raises RuntimeError only when the
    PESQ extras aren't installed."""
    ok, msg = deps_status()
    if not ok:
        raise RuntimeError(msg)
    if mode not in MODES:
        mode = DEFAULT_MODE
    try:
        result = score_one(ref_path, deg_path, mode)
    except Exception as e:       # unexpected (e.g. ffmpeg conversion failure)
        result = {"score": None, "mode": mode, "ref_dur": None, "deg_dur": None,
                  "duration": None, "warnings": [], "error": f"{type(e).__name__}: {e}"}
    result["name"] = deg_name
    return result


# --------------------------------------------------------------------------- #
# tiny CLI for ad-hoc checks:  python3 pesq_quality.py ref.wav deg.wav [wb|nb]
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import sys
    ok, msg = deps_status()
    if not ok:
        print(msg)
        sys.exit(2)
    if len(sys.argv) < 3:
        print("usage: python3 pesq_quality.py <reference> <degraded> [wb|nb]")
        sys.exit(1)
    ref, deg = sys.argv[1], sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else DEFAULT_MODE
    for p, role in ((ref, "reference"), (deg, "degraded")):
        try:
            validate_audio(p)
        except ValueError as e:
            print(f"{role}: {e}")
            sys.exit(1)
    res = score_one(ref, deg, mode)
    print(f"mode     : {MODE_LABEL.get(res['mode'], res['mode'])}")
    print(f"ref/deg  : {res['ref_dur']}s / {res['deg_dur']}s  (scored {res['duration']}s)")
    for w in res["warnings"]:
        print(f"warning  : {w}")
    if res["error"]:
        print(f"error    : {res['error']}")
        sys.exit(1)
    print(f"PESQ     : {res['score']}")
