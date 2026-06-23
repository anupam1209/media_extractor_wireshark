# PCAP RTP Media Extractor

Extract **audio and video** from RTP streams in a packet capture (`.pcap` / `.pcapng`),
**automatically**.

Point it at a capture and it finds every RTP stream, figures out the codec on its own (no
manual IP/port/codec configuration), and gives you a downloadable file for each one — `.wav`
for audio, `.mp4` for video. It works through a simple **web page** or a **command line**, and
it runs anywhere Python does — no build step and no Python packages to install.

It was built to investigate conference "mute" issues, so by default it reconstructs audio on
the **real timeline**: when a talker went silent (and the sender stopped transmitting), you
hear silence at exactly that point.

---

## Contents
- [What it can do](#what-it-can-do)
- [Requirements](#requirements)
- [Install the prerequisites](#install-the-prerequisites)
- [Quick start](#quick-start)
- [Web app](#web-app)
- [Command line](#command-line)
- [Output files](#output-files)
- [Timing modes: real vs compact](#timing-modes-real-vs-compact)
- [Supported codecs](#supported-codecs)
- [Validating against known-good files](#validating-against-known-good-files)
- [How it works](#how-it-works)
- [Troubleshooting](#troubleshooting)
- [Limitations & roadmap](#limitations--roadmap)
- [Project files](#project-files)

---

## What it can do

- **Auto-detect** every RTP stream in a capture (source/destination, SSRC, packet count, duration).
- **Auto-identify the codec** with no manual config — audio (AMR-NB, AMR-WB, G.711 µ-law/A-law) and video (H.264, H.265).
- **Extract & decode** each stream: audio to `.wav`, video to `.mp4` (remuxed, no re-encode).
- **Preserve real timing** (audio) — silence is inserted where the audio actually dropped (great for mute analysis).
- **Web UI**: upload → see the streams → click to extract → download / play in the browser.
- **CLI**: scriptable for batch processing whole folders of captures.
- **Validate** audio output against a known-good reference file (correlation-based PASS/FAIL).

---

## Requirements

You need these command-line tools installed and on your `PATH`:

| Tool | Why | Required? |
|------|-----|-----------|
| **Python 3.8+** | runs the tool | yes |
| **tshark** (Wireshark CLI) | detects RTP streams and reads payloads | yes |
| **ffmpeg** | decodes G.711, converts/validates audio, AMR fallback | yes |
| **GStreamer** (`gst-launch-1.0` with `amrnbdec` / `amrwbdec`) | best-quality AMR decode | recommended |

No Python packages are required — the tool uses only the standard library.

> If GStreamer isn't available, AMR still decodes via ffmpeg's built-in decoder, but ffmpeg's
> native AMR decoder may skip comfort-noise (SID) frames. **For AMR captures, GStreamer is
> recommended.**

---

## Install the prerequisites

**macOS (Homebrew):**
```bash
brew install wireshark ffmpeg gstreamer
```

**Ubuntu / Debian:**
```bash
sudo apt update
sudo apt install -y tshark ffmpeg \
    gstreamer1.0-tools gstreamer1.0-plugins-good \
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly
```

**Verify everything is present:**
```bash
tshark --version | head -1
ffmpeg -version  | head -1
gst-launch-1.0 --version | head -1
gst-inspect-1.0 amrnbdec >/dev/null && echo "AMR decoder OK"
```

No installation of the tool itself is needed — just copy `mediax.py` and `webapp.py` into a
folder and run them.

---

## Quick start

```bash
# 1. See what's inside a capture
python3 mediax.py detect wiresharks/filtered_16152_to_15288.pcap

# 2a. Extract everything to a folder
python3 mediax.py extract-all wiresharks/filtered_16152_to_15288.pcap -o output/

# 2b. ...or start the web app and do it from the browser
python3 webapp.py        # then open http://127.0.0.1:8000
```

---

## Web app

Start the server:
```bash
python3 webapp.py
```
Then open **http://127.0.0.1:8000** in a browser.

1. **Choose a `.pcap`/`.pcapng` file** and click **Upload & detect**.
2. The detected streams appear in a table, each with its auto-identified codec.
3. Pick a timing mode (**Real timing** is the default — see [below](#timing-modes-real-vs-compact)).
4. Click **Extract** on any supported row, then **download** the `.wav` or play it inline.

**Running it on a remote machine / VM** (so you can reach it from your laptop's browser):
```bash
python3 webapp.py --host 0.0.0.0 --port 8000
# then browse to  http://<server-ip>:8000
```
You can also set `MEDIAX_HOST` / `MEDIAX_PORT` environment variables instead of flags.

Uploaded captures and extracted audio are stored under `./_work/` (`uploads/` and `outputs/`).
Maximum upload size is 500 MB.

> The web server is meant for trusted/internal use (no authentication). Don't expose it to the
> public internet as-is.

---

## Command line

`mediax.py` has four sub-commands.

### `detect` — list streams
```bash
python3 mediax.py detect <pcap> [--json]
```
Prints one row per RTP stream with source, destination, SSRC, payload type, packet count,
modal payload size, duration, and the guessed codec. Add `--json` for machine-readable output.

```
                   src                    dst        ssrc   pt   pkts  sz    dur  codec
      10.63.5.25:16152      10.44.139.5:15288  0x133FA82D  118   2200  32  41.83  AMR-NB
     10.44.139.5:15298      10.63.5.203:8100  0x82D8D370   98    217  61   6.18  AMR-WB
```

### `extract` — one stream to WAV
```bash
python3 mediax.py extract <pcap> --sport <src-port> --dport <dst-port> -o <out.wav> \
    [--src <src-ip>] [--dst <dst-ip>] \
    [--codec AMR-NB|AMR-WB|G711u|G711a] \
    [--mode be|oa] \
    [--timing accurate|compact] \
    [--validate-against <reference-file>]
```
- `--sport` / `--dport` are required; `--src` / `--dst` help disambiguate if ports repeat.
- `--codec` overrides auto-detection (rarely needed).
- `--mode` overrides AMR framing: `be` = bandwidth-efficient (default), `oa` = octet-aligned.
- `--timing` chooses real vs compact reconstruction (default `accurate`).
- `--validate-against` compares the result to a known-good file and prints PASS/FAIL.

Example:
```bash
python3 mediax.py extract wiresharks/filtered_16152_to_15288.pcap \
    --sport 16152 --dport 15288 -o call.wav \
    --validate-against AP_MUTE_ISSUE/filtered_16152_to_15288.avi
```

### `extract-all` — every audio stream to a folder
```bash
python3 mediax.py extract-all <pcap> -o <out-dir> [--timing accurate|compact]
```
Extracts every supported audio stream. Unsupported or tiny streams are skipped and reported.
Prints one JSON line per stream describing what it did.

**Batch a whole folder** (shell loop):
```bash
for f in wiresharks/*.pcap wiresharks/*.pcapng; do
    python3 mediax.py extract-all "$f" -o "output/$(basename "$f")/"
done
```

### `validate` — compare two audio files
```bash
python3 mediax.py validate <produced.wav> <reference-file> [--rate 8000]
```
Decodes both to PCM and reports a drift-tolerant correlation score and `PASS`/`FAIL`
(PASS when correlation ≥ 0.9). The reference can be `.wav`, `.avi`, `.amr`, or anything ffmpeg reads.

---

## Output files

- **Audio**: mono WAV, 16-bit PCM — 8 kHz for AMR-NB / G.711, 16 kHz for AMR-WB.
- **Video**: MP4 (H.264/H.265 stream copied in, not re-encoded), framerate from RTP timestamps.
- `extract` writes to the path you give with `-o` (use a `.mp4` path for a video stream).
- `extract-all` names each file:
  ```
  <src-ip>_<src-port>-<dst-ip>_<dst-port>_<ssrc>.wav
  ```
  e.g. `10.63.5.25_16152-10.44.139.5_15288_0x133FA82D.wav`
- Web-app outputs land in `./_work/outputs/`.

---

## Timing modes: real vs compact

When a talker is silent, many systems stop sending packets (this is called DTX / silence
suppression). There are two ways to rebuild such audio:

| Mode | Flag | Result | Use when |
|------|------|--------|----------|
| **Real timing** (default) | `--timing accurate` | Audio plays at true wall-clock time; silence fills the gaps where nothing was sent. | Investigating mutes / dropouts — you hear *when* audio stopped. |
| **Compact** | `--timing compact` | Received audio packed back-to-back, gaps removed. | You only care about the spoken content, not the timing. |

For a stream with silence gaps, *real timing* produces a longer file (e.g. 43.5 s) than
*compact* (e.g. 26.8 s). For a continuous stream with no gaps the two are identical.

Real timing anchors each frame to its **packet arrival time** (capture wall-clock), not the
RTP media timestamp. Conference mixers sometimes emit broken per-stream RTP timestamps within a
single SSRC — they reset backwards, run ahead of real time, or run behind it — which would
otherwise crash extraction or fabricate hours of bogus silence. Anchoring to arrival time keeps
the output faithful to the real capture length regardless, while still placing every frame in its
own slot so nothing is dropped.

---

## Supported codecs

**Audio** (output: `.wav`)

| Codec | RTP detection | Notes |
|-------|---------------|-------|
| **AMR-NB** | clock-rate 8 kHz / ~32-byte frames | bandwidth-efficient and octet-aligned both supported |
| **AMR-WB** | clock-rate 16 kHz / ~61-byte frames | |
| **G.711 µ-law (PCMU)** | static payload type 0 | |
| **G.711 A-law (PCMA)** | static payload type 8 | |

**Video** (output: `.mp4`, remuxed without re-encoding)

| Codec | RTP detection | Notes |
|-------|---------------|-------|
| **H.264 / AVC** | large/variable payloads + NAL fingerprint | single NAL, STAP-A, FU-A/FU-B handled |
| **H.265 / HEVC** | large/variable payloads + NAL fingerprint | single NAL, AP, FU handled |
| VP8 | large/variable payloads | **detected only** — extraction not implemented yet |

Codec is inferred from the RTP clock rate, payload size, and (for video) the NAL header in the
payload, because these captures carry no SDP signaling. If a stream is mis-identified, override
it with `--codec` (CLI). Video framerate is recovered from the RTP timestamps.

---

## Validating against known-good files

If you have previously decoded reference outputs (e.g. the `AP_MUTE_ISSUE/` folder pairs each
`.pcap` with a reference `.avi`), use `--validate-against` (or the `validate` command) to confirm
the extraction matches.

The comparison is **drift-tolerant**: it aligns the two signals locally, so small timing
differences don't cause false failures. A correlation near **1.0** means the audio content matches.

> Note: a reference made with a lossy decoder (one that drops comfort-noise/SID frames) can be
> *shorter* than a faithful extraction. In that case this tool's output is the more complete one,
> and a timing/duration difference is expected.

---

## How it works

1. **Detect** — `tshark` is run with heuristic RTP enabled. The RTP header and payload are parsed
   from the raw UDP bytes (`udp.payload`) rather than tshark's `rtp.payload` field, so results are
   identical across tshark versions and operating systems. Duplicate packets (same seq+timestamp,
   from capture mirrors/taps) are dropped. Packets are grouped per stream and summarized.
2. **Depacketize** — pure Python.
   - *Audio:* AMR is unpacked from RTP (per RFC 4867) and rebuilt into a standard `.amr` file
     (done in-tool because current GStreamer releases can't depacketize bandwidth-efficient AMR).
   - *Video:* H.264/H.265 NAL units are reassembled from RTP (RFC 6184 / 7798 — single NAL,
     aggregation, and fragmentation) into an Annex-B elementary stream.
3. **Decode / mux** — audio `.amr` is decoded by GStreamer's `amrnbdec`/`amrwbdec` (or ffmpeg),
   G.711 by ffmpeg; video is remuxed into MP4 with ffmpeg `-c copy` (no re-encode).
4. **Reconstruct** (audio) — decoded frames are placed on the real timeline using packet
   arrival time (robust to broken RTP media clocks), filling silence gaps (or concatenated, in
   compact mode), and written as WAV.

If any step fails, the tool reports the actual reason — the underlying `tshark`/`ffmpeg`/GStreamer
error message in the CLI, or a JSON `{"error": "..."}` in the web app — instead of failing
silently.

---

## Troubleshooting

**`detect` finds no streams.**
The capture may not contain RTP, or it uses a framing the heuristic can't recognize. Open it in
Wireshark and check `Telephony → RTP → RTP Streams`. Some merged/processed captures don't expose
standard RTP.

**A stream shows codec `PTxxx` (unknown) and can't be extracted.**
Auto-detection couldn't map that payload type. If you know the codec, force it:
`extract ... --codec AMR-NB`.

**Extracted AMR audio sounds like noise / is much shorter than expected.**
Usually an AMR framing mismatch — try `--mode oa` (octet-aligned) instead of the default
bandwidth-efficient.

**AMR decode warnings / dropped frames.**
ffmpeg's built-in AMR decoder is being used and it skips some frame types. Install GStreamer with
the AMR plugins (`gst-inspect-1.0 amrnbdec`) for clean decoding.

**Web app: "Address already in use".**
Another instance is already on that port. Use a different one: `python3 webapp.py --port 8001`.

**Large captures are slow.**
Detection and extraction read the whole file with `tshark`; multi-hundred-MB captures take time.
This is expected.

---

## Limitations & roadmap

- **H.264 video** is validated end-to-end (pixel-exact on synthetic streams, clean decode on a
  real capture). **H.265** uses the same code path but has not yet been field-tested against a
  real H.265 capture. **VP8** is detected but not yet extracted.
- Audio codec coverage is AMR-NB, AMR-WB, and G.711. Others can be added on request.
- The web server is single-purpose and unauthenticated — intended for local/trusted use.

---

## Project files

```
mediax.py     # the engine + CLI (detect / extract / extract-all / validate)
webapp.py     # zero-dependency web UI (imports mediax)
wiresharks/   # sample input captures (for testing)
AP_MUTE_ISSUE/# reference decoded outputs (.avi) + their source pcaps (for validation)
_work/        # created at runtime by the web app: uploads/ and outputs/
```
