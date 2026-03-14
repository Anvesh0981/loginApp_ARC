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

# websockify bridges WebSocket -> VNC TCP on same port as Flask
# It serves noVNC static files AND handles WebSocket on port 6080
print("Starting websockify :6080 -> :5900 ...", flush=True)
ws = subprocess.Popen([
    "websockify",
    "--web", "/usr/share/novnc",
    "--heartbeat", "30",
    "6080", "localhost:5900"
])
procs.append(ws)
time.sleep(1)

# Flask on the main Railway port - uses gthread (no gevent needed)
print(f"Starting gunicorn on :{port} ...", flush=True)
gunicorn = subprocess.Popen([
    "gunicorn", "app:app",
    "--bind", f"0.0.0.0:{port}",
    "--workers", "1",
    "--worker-class", "gthread",
    "--threads", "8",
    "--timeout", "300",
])
procs.append(gunicorn)
gunicorn.wait()
cleanup()