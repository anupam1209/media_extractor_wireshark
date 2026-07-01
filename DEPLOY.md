# Deploying the PCAP RTP Media Extractor

This app is **not** a static site — it is a long-running server that shells out
to native tools (`tshark`, `ffmpeg`, `GStreamer`). That rules out Netlify/Vercel
(static + short serverless functions only). It needs a **container host**.

The repo ships a `Dockerfile` that bundles everything, so it deploys unchanged to
Render, Railway, Fly.io, Hugging Face Spaces, Google Cloud Run, or any VPS.
These instructions cover **Render**.

---

## Deploy to Render (from GitHub)

1. **Push this repo to GitHub** (you already planned to do this):
   ```bash
   git add Dockerfile .dockerignore render.yaml DEPLOY.md webapp.py .gitignore
   git commit -m "Add Docker + Render deploy config"
   git push
   # (the oversized sample pcaps are now gitignored, so `git add .` is also safe)
   ```

2. **Create the service on Render** — two ways, pick one:

   - **Blueprint (one click, uses `render.yaml`):**
     Render dashboard → **New +** → **Blueprint** → connect this GitHub repo →
     **Apply**. Render reads `render.yaml`, builds the Dockerfile, and deploys.

   - **Manual web service:**
     **New +** → **Web Service** → connect the repo → set **Language/Runtime =
     Docker** (Render auto-detects the `Dockerfile`) → **Create Web Service**.

3. **Wait for the build** (~3–6 min the first time — it installs tshark, ffmpeg,
   and the GStreamer plugins). When it finishes you get a public URL like
   `https://pcap-media-extractor.onrender.com`. Open it and upload a `.pcap`.

That's it. Every later `git push` redeploys automatically (`autoDeploy: true`).

---

## Good to know (Render free tier)

- **Cold starts:** the free instance sleeps after ~15 min idle; the next request
  takes ~30–60 s to wake. Upgrade to a paid instance to keep it always-on.
- **Memory:** free = 512 MB RAM. Small/medium PCAPs are fine; a very large
  capture can OOM the process — bump `plan: free` → `plan: starter` in
  `render.yaml` (or the dashboard) if that happens.
- **Storage is ephemeral:** uploads and extracted files live under `_work/` and
  are wiped on restart/redeploy. That's fine — the browser downloads each
  extracted clip immediately; nothing needs to persist server-side.
- **It's public:** anyone with the URL can upload a pcap and trigger processing
  (which runs `tshark`/`ffmpeg` on your instance). If this isn't meant to be
  open, keep the URL private, or put it behind Render's access controls / add a
  simple auth check before exposing it widely.

---

## Test the container locally first (optional, needs Docker)

```bash
docker build -t pcap-extractor .
docker run --rm -p 8000:8000 pcap-extractor
# then open http://localhost:8000
```

The same image is what Render runs, so a clean local run = a clean deploy.
