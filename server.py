#!/usr/bin/env python3
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

print("Starting Xvfb :99 ...", flush=True)
xvfb = subprocess.Popen(["Xvfb", ":99", "-screen", "0", "1280x900x24", "-ac"])
procs.append(xvfb)
time.sleep(1.5)

print("Starting x11vnc ...", flush=True)
vnc = subprocess.Popen([
    "x11vnc", "-display", ":99", "-nopw",
    "-listen", "localhost", "-forever", "-shared", "-quiet", "-noxdamage"
])
procs.append(vnc)
time.sleep(1)

print(f"Starting gunicorn on :{port} ...", flush=True)
# gthread worker supports WebSockets via flask-sock
gunicorn = subprocess.Popen([
    "gunicorn", "app:app",
    "--bind", f"0.0.0.0:{port}",
    "--workers", "1",
    "--worker-class", "gthread",
    "--threads", "8",
    "--timeout", "300",
    "--keep-alive", "30",
])
procs.append(gunicorn)
gunicorn.wait()
cleanup()