#!/usr/bin/env python3
"""
Brief tests for the PESQ speech-quality logic (pesq_quality.py).

Two behavioural checks:
  1. A file scored against *itself* returns a high PESQ score.
  2. A *noisy copy* of that file scores lower than the identical case.

These require the optional extras (numpy + pesq) and ffmpeg. If the extras are
not installed, or no speech sample is available, the tests SKIP cleanly rather
than fail -- the core app has no such dependency.

Run directly:
    python3 test_pesq_quality.py
...or under pytest:
    pytest test_pesq_quality.py

Reference sample resolution order:
  1. $PESQ_TEST_WAV
  2. the first _work/outputs/*.wav (real extracted speech, if present)
"""
import glob
import os
import sys
import tempfile
import wave

import pesq_quality

MODE = "wb"
RATE = pesq_quality.MODES[MODE]


# --- pytest-style skip that also works when run as a plain script ---------- #
class _Skip(Exception):
    pass


def _skip(msg):
    try:
        import pytest
        pytest.skip(msg)
    except ImportError:
        raise _Skip(msg)


def _deps_or_skip():
    ok, msg = pesq_quality.deps_status()
    if not ok:
        _skip("PESQ extras not installed: " + msg.splitlines()[0])


def _find_reference():
    env = os.environ.get("PESQ_TEST_WAV")
    if env and os.path.exists(env):
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    wavs = sorted(glob.glob(os.path.join(here, "_work", "outputs", "*.wav")))
    return wavs[0] if wavs else None


def _write_wav_int16(samples, rate):
    path = tempfile.NamedTemporaryFile(prefix="pesq-test-", suffix=".wav", delete=False).name
    w = wave.open(path, "wb")
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    w.writeframes(samples.tobytes())
    w.close()
    return path


def _make_noisy(ref_path, snr_db=8):
    """A noisy copy of the reference at the given SNR (returns a temp wav path)."""
    import numpy as np
    x = pesq_quality._load_mono(ref_path, RATE).astype(np.float64)
    sig_p = float(np.mean(x ** 2)) + 1e-9
    noise_p = sig_p / (10 ** (snr_db / 10.0))
    rng = np.random.default_rng(0)
    noisy = x + rng.normal(0.0, noise_p ** 0.5, size=x.shape)
    noisy = np.clip(noisy, -32768, 32767).astype(np.int16)
    return _write_wav_int16(noisy, RATE)


def test_identical_high_score():
    _deps_or_skip()
    ref = _find_reference()
    if not ref:
        _skip("no speech sample found (set $PESQ_TEST_WAV or add _work/outputs/*.wav)")
    res = pesq_quality.score_one(ref, ref, MODE)
    assert res["error"] is None, res["error"]
    assert res["score"] is not None
    # identical signals score near the wideband ceiling (~4.5); allow margin
    assert res["score"] >= 4.0, f"identical score too low: {res['score']}"
    print(f"identical: {res['score']}")


def test_noisy_scores_lower():
    _deps_or_skip()
    ref = _find_reference()
    if not ref:
        _skip("no speech sample found (set $PESQ_TEST_WAV or add _work/outputs/*.wav)")
    ident = pesq_quality.score_one(ref, ref, MODE)
    noisy_path = _make_noisy(ref)
    try:
        noisy = pesq_quality.score_one(ref, noisy_path, MODE)
    finally:
        os.unlink(noisy_path)
    assert noisy["error"] is None, noisy["error"]
    assert noisy["score"] is not None
    assert noisy["score"] < ident["score"], (
        f"noisy ({noisy['score']}) should score below identical ({ident['score']})")
    print(f"identical: {ident['score']}  noisy: {noisy['score']}")


if __name__ == "__main__":
    failed = 0
    for fn in (test_identical_high_score, test_noisy_scores_lower):
        try:
            fn()
            print(f"PASS  {fn.__name__}")
        except _Skip as e:
            print(f"SKIP  {fn.__name__}: {e}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL  {fn.__name__}: {e}")
    sys.exit(1 if failed else 0)
