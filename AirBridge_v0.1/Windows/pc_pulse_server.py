
import json
import os
import platform
import socket
import time
import uuid
from pathlib import Path
from datetime import datetime

from flask import Flask, jsonify, request, send_file
import psutil
import qrcode

PORT = 5050
BASE = Path(__file__).resolve().parent
PAIR_TOKEN = uuid.uuid4().hex[:16]

app = Flask(__name__)

def local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 80))
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        s.close()

def bytes_gb(n):
    return round(n / (1024 ** 3), 2)

def drive_info():
    drives = []
    seen = set()

    for part in psutil.disk_partitions(all=False):
        device = part.device
        if not device or device in seen:
            continue

        seen.add(device)

        # Prefer normal Windows drive letters.
        if os.name == "nt" and len(device) >= 2 and device[1] == ":":
            try:
                usage = psutil.disk_usage(device)
            except Exception:
                continue

            drives.append({
                "name": device.rstrip("\\"),
                "mountpoint": part.mountpoint,
                "total_gb": bytes_gb(usage.total),
                "used_gb": bytes_gb(usage.used),
                "free_gb": bytes_gb(usage.free),
                "percent": round(usage.percent, 1),
            })

    drives.sort(key=lambda d: d["name"])
    return drives

def uptime_seconds():
    return max(0, int(time.time() - psutil.boot_time()))

def cpu_name():
    name = platform.processor().strip()
    if name:
        return name
    return "CPU"

def gpu_hint():
    # v0.1 keeps this optional and lightweight.
    return None

def authorized():
    supplied = request.headers.get("X-PCPulse-Token", "")
    if supplied == PAIR_TOKEN:
        return True
    supplied = request.args.get("token", "")
    return supplied == PAIR_TOKEN

@app.after_request
def cors_headers(response):
    # Only local-device clients should know the token, but allow the app/web dashboard
    # to query from the LAN.
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, X-PCPulse-Token"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.route("/api/status")
def api_status():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401

    vm = psutil.virtual_memory()
    cpu_percent = psutil.cpu_percent(interval=0.15)

    data = {
        "ok": True,
        "timestamp": int(time.time()),
        "pc_name": socket.gethostname(),
        "os": f"{platform.system()} {platform.release()}",
        "cpu_name": cpu_name(),
        "cpu_percent": round(cpu_percent, 1),
        "ram": {
            "total_gb": bytes_gb(vm.total),
            "used_gb": bytes_gb(vm.used),
            "available_gb": bytes_gb(vm.available),
            "percent": round(vm.percent, 1),
        },
        "drives": drive_info(),
        "uptime_seconds": uptime_seconds(),
    }
    return jsonify(data)

@app.route("/api/ping")
def api_ping():
    if not authorized():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"ok": True, "server_time": int(time.time())})

@app.route("/")
def dashboard():
    if request.args.get("token", "") != PAIR_TOKEN:
        return "Invalid PC Pulse session", 403

    return f"""
<!doctype html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta charset="utf-8">
<title>PC Pulse</title>
<style>
:root {{
  color-scheme: dark;
  font-family: -apple-system, BlinkMacSystemFont, Segoe UI, sans-serif;
}}
body {{
  margin: 0; background: #0b0d12; color: #fff; padding: 18px;
}}
main {{ max-width: 720px; margin: auto; }}
h1 {{ font-size: 36px; margin-bottom: 4px; }}
.sub {{ color:#9da6b8; margin-top:0; }}
.grid {{
  display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:12px;
}}
.card {{
  background:#151923; border-radius:20px; padding:18px;
}}
.value {{ font-size:30px; font-weight:800; }}
.label {{ color:#8f98aa; font-size:13px; margin-top:4px; }}
.drive {{ margin-top:12px; }}
.bar {{ height:9px; background:#252b37; border-radius:999px; overflow:hidden; margin-top:8px; }}
.fill {{ height:100%; background:#fff; width:0; }}
.status {{ color:#7ff49b; font-weight:700; margin:14px 0; }}
@media(max-width:520px) {{ .grid {{ grid-template-columns:1fr; }} }}
</style>
</head>
<body>
<main>
<h1>PC Pulse</h1>
<p class="sub">Live Windows dashboard</p>
<div id="status" class="status">Connecting…</div>
<div class="grid">
  <div class="card"><div id="cpu" class="value">—</div><div class="label">CPU</div></div>
  <div class="card"><div id="ram" class="value">—</div><div class="label">RAM</div></div>
  <div class="card"><div id="uptime" class="value">—</div><div class="label">Uptime</div></div>
  <div class="card"><div id="pcname" class="value">—</div><div class="label">PC Name</div></div>
</div>
<div id="drives"></div>
</main>
<script>
const TOKEN={json.dumps(PAIR_TOKEN)};
function fmtUptime(s) {{
  const d=Math.floor(s/86400); s%=86400;
  const h=Math.floor(s/3600); s%=3600;
  const m=Math.floor(s/60);
  if(d) return `${{d}}d ${{h}}h`;
  if(h) return `${{h}}h ${{m}}m`;
  return `${{m}}m`;
}}
async function refresh() {{
  try {{
    const r=await fetch('/api/status?token='+encodeURIComponent(TOKEN),{{cache:'no-store'}});
    const d=await r.json();
    if(!d.ok) throw new Error('offline');
    document.getElementById('status').textContent='Connected ✓';
    document.getElementById('cpu').textContent=d.cpu_percent.toFixed(1)+'%';
    document.getElementById('ram').textContent=d.ram.percent.toFixed(1)+'%';
    document.getElementById('uptime').textContent=fmtUptime(d.uptime_seconds);
    document.getElementById('pcname').textContent=d.pc_name;
    const box=document.getElementById('drives');
    box.innerHTML='';
    for(const drive of d.drives) {{
      const el=document.createElement('div');
      el.className='card drive';
      el.innerHTML=`
        <div style="display:flex;justify-content:space-between;gap:12px">
          <strong>${{drive.name}}</strong>
          <span>${{drive.free_gb}} GB free</span>
        </div>
        <div class="bar"><div class="fill" style="width:${{drive.percent}}%"></div></div>
        <div class="label">${{drive.used_gb}} / ${{drive.total_gb}} GB used (${{drive.percent}}%)</div>`;
      box.appendChild(el);
    }}
  }} catch(e) {{
    document.getElementById('status').textContent='Disconnected';
  }}
}}
refresh();
setInterval(refresh,1500);
</script>
</body>
</html>
"""

def build_qr(ip):
    pair_url = f"http://{ip}:{PORT}/?token={PAIR_TOKEN}"
    qr = qrcode.QRCode(border=2)
    qr.add_data(pair_url)
    qr.make(fit=True)
    path = BASE / "PC_PULSE_QR.png"
    qr.make_image(fill_color="black", back_color="white").save(path)
    return pair_url, path

def main():
    ip = local_ip()
    pair_url, qr_path = build_qr(ip)

    print("=" * 64)
    print("                         PC Pulse v0.1")
    print("=" * 64)
    print()
    print("PC Name :", socket.gethostname())
    print("IP      :", ip)
    print("Port    :", PORT)
    print("Token   :", PAIR_TOKEN)
    print()
    print("Pair URL:")
    print(" ", pair_url)
    print()
    print("QR:")
    print(" ", qr_path)
    print()
    print("Keep this window OPEN while using the iPhone app.")
    print("If Windows Firewall asks, allow Python on PRIVATE networks.")
    print()

    try:
        os.startfile(str(qr_path))
    except Exception:
        pass

    app.run(host="0.0.0.0", port=PORT, threaded=True, debug=False)

if __name__ == "__main__":
    main()
