#!/usr/bin/env python3
"""
Startup script:
1. Xvfb   — virtual display :99  (Playwright browser renders here)
2. x11vnc — VNC server on :5900  (reads the virtual display)
3. websockify + noVNC — web VNC proxy on :6080 (browser-accessible)
4. gunicorn — Flask app
"""
import os, subprocess, time, signal, sys

port = os.environ.get("PORT", "8080")

procs = []

def cleanup(sig=None, frame=None):
    for p in procs:
        try: p.terminate()
        except: pass
    sys.exit(0)

signal.signal(signal.SIGTERM, cleanup)
signal.signal(signal.SIGINT, cleanup)

# 1. Virtual framebuffer display
print("Starting Xvfb :99 ...", flush=True)
xvfb = subprocess.Popen([
    "Xvfb", ":99", "-screen", "0", "1280x900x24", "-ac", "+extension", "GLX"
])
procs.append(xvfb)
time.sleep(1.5)

# 2. VNC server (no password — protected by Vault login)
print("Starting x11vnc ...", flush=True)
vnc = subprocess.Popen([
    "x11vnc", "-display", ":99",
    "-nopw", "-listen", "localhost",
    "-forever", "-shared", "-quiet", "-noxdamage"
])
procs.append(vnc)
time.sleep(1)

# 3. noVNC websocket proxy
print("Starting noVNC on :6080 ...", flush=True)
novnc_web = "/usr/share/novnc"
novnc = subprocess.Popen([
    "websockify", "--web", novnc_web,
    "6080", "localhost:5900"
])
procs.append(novnc)
time.sleep(1)

# 4. Gunicorn — 1 worker so Playwright browser thread is shared across requests
print(f"Starting gunicorn on :{port} ...", flush=True)
gunicorn = subprocess.Popen([
    "gunicorn", "app:app",
    "--bind", f"0.0.0.0:{port}",
    "--workers", "1",
    "--worker-class", "gthread",
    "--threads", "4",
    "--timeout", "300",
    "--keep-alive", "5"
])
procs.append(gunicorn)
gunicorn.wait()
cleanup()