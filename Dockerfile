# PCAP RTP Media Extractor — container image.
#
# The Python code (mediax.py / webapp.py) is stdlib-only, so there is no
# pip install step. What the engine DOES need are three native command-line
# tools it shells out to at runtime:
#   - tshark   (Wireshark CLI)  : reads the .pcap and finds RTP streams
#   - ffmpeg                     : muxes audio/video, G.711 + AMR fallback decode
#   - GStreamer                  : amrnbdec / amrwbdec (opencore) for AMR-NB/-WB
# This image bundles all three so the app is fully self-contained.

FROM python:3.12-slim

# Non-interactive apt so the wireshark/tshark debconf prompt can't hang the build.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        tshark \
        ffmpeg \
        gstreamer1.0-tools \
        gstreamer1.0-plugins-base \
        gstreamer1.0-plugins-good \
        gstreamer1.0-plugins-bad \
        gstreamer1.0-plugins-ugly \
        gstreamer1.0-libav \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY mediax.py webapp.py ./

# Fail the BUILD early if a required tool is missing (tshark/ffmpeg have no
# fallback). The GStreamer AMR decoders are only PREFERRED — mediax.py falls
# back to ffmpeg for AMR — so a missing one is a warning, not a build failure.
RUN tshark --version >/dev/null && ffmpeg -version >/dev/null \
    && echo "tshark + ffmpeg: OK" \
    && if gst-inspect-1.0 amrnbdec >/dev/null 2>&1 && gst-inspect-1.0 amrwbdec >/dev/null 2>&1; then \
           echo "GStreamer amrnbdec + amrwbdec: OK"; \
       else \
           echo "WARNING: GStreamer AMR decoders not found — AMR will use the ffmpeg fallback"; \
       fi

# Render / Railway / Cloud Run / Fly / HF Spaces all inject $PORT at runtime.
# webapp.py honours $PORT; we also pass it explicitly and bind 0.0.0.0 so the
# platform's router can reach the process (127.0.0.1 would be unreachable).
ENV PORT=8000
EXPOSE 8000
CMD ["sh", "-c", "python webapp.py --host 0.0.0.0 --port ${PORT:-8000}"]
