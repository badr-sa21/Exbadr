import asyncio
import os
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import ipaddress
import cv2
import numpy as np
import qrcode
from aiohttp import web
from aiortc import RTCPeerConnection, RTCSessionDescription
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

BASE = Path(__file__).resolve().parent
CERT_DIR = BASE / "cert"
CERT_DIR.mkdir(exist_ok=True)

HTTPS_PORT = 8443
HTTP_PORT = 8080

pcs = set()
LATEST_FRAME = None
LATEST_LOCK = threading.Lock()
RUNNING = True

STATS_LOCK = threading.Lock()
RX_FPS = 0.0
FRAME_COUNTER = 0
FPS_WINDOW_START = time.perf_counter()

def get_local_ip():
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

def load_or_create_ca():
    # Reuse v0.3 / v0.4 CA if user copies cert folder into v0.5.
    candidates = [
        ("AirCam_Local_CA_v03.key", "AirCam_Local_CA_v03.pem", "AirCam_Local_CA_v03.cer"),
        ("AirCam_Local_CA_v04.key", "AirCam_Local_CA_v04.pem", "AirCam_Local_CA_v04.cer"),
        ("AirCam_Local_CA_v05.key", "AirCam_Local_CA_v05.pem", "AirCam_Local_CA_v05.cer"),
    ]

    for key_name, pem_name, der_name in candidates:
        kp = CERT_DIR / key_name
        pp = CERT_DIR / pem_name
        dp = CERT_DIR / der_name
        if kp.exists() and pp.exists() and dp.exists():
            key = serialization.load_pem_private_key(kp.read_bytes(), password=None)
            cert = x509.load_pem_x509_certificate(pp.read_bytes())
            return key, cert, dp, cert.subject.rfc4514_string()

    key_p = CERT_DIR / "AirCam_Local_CA_v05.key"
    pem_p = CERT_DIR / "AirCam_Local_CA_v05.pem"
    der_p = CERT_DIR / "AirCam_Local_CA_v05.cer"

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AirCam Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, "AirCam Local CA v0.5"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    key_p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    pem_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    der_p.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    return key, cert, der_p, cert.subject.rfc4514_string()

def make_server_cert(ip, ca_key, ca_cert):
    key_path = CERT_DIR / f"server_{ip.replace('.', '_')}.key"
    cert_path = CERT_DIR / f"server_{ip.replace('.', '_')}.crt"

    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "SA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AirCam"),
        x509.NameAttribute(NameOID.COMMON_NAME, ip),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path

SETUP_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AirCam v0.5 Setup</title>
<style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}
body{margin:0;background:#090b0f;color:#fff;padding:20px}
main{max-width:600px;margin:auto}
.card{background:#151922;border-radius:24px;padding:24px}
h1{font-size:34px;margin-top:0}
p,li{color:#b7bfce;line-height:1.55}
a{display:block;background:#fff;color:#111;text-decoration:none;padding:16px;border-radius:15px;text-align:center;font-weight:800;margin:20px 0}
</style>
</head>
<body>
<main><div class="card">
<h1>AirCam v0.5 Gesture FX</h1>
<p>Hand gesture effects + WebRTC camera streaming.</p>
<a href="/certificate">Download AirCam Certificate</a>
<ol>
<li>Install the AirCam certificate.</li>
<li>Settings → General → About → Certificate Trust Settings.</li>
<li>Enable full trust for AirCam Local CA.</li>
<li>Then scan the Camera QR on the PC.</li>
</ol>
</div></main>
</body>
</html>"""

CAM_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>AirCam v0.5 Gesture FX</title>

<script src="https://cdn.jsdelivr.net/npm/@mediapipe/hands/hands.js"></script>

<style>
:root{color-scheme:dark;font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:#090b0f;color:#fff}
main{max-width:850px;margin:auto;padding:18px}
h1{font-size:38px;margin:8px 0 2px}
.sub{color:#aeb7c7;margin:0 0 15px}
.status{padding:13px 15px;border-radius:15px;background:#151922;margin:12px 0;font-size:14px}
.wrap{position:relative;width:100%;border-radius:22px;overflow:hidden;background:#050608}
canvas{width:100%;display:block;object-fit:contain;max-height:58vh}
video{display:none}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}
button,select,input{
 width:100%;min-height:50px;border:0;border-radius:15px;font-size:16px;padding:0 14px
}
button{font-weight:800;background:#fff;color:#111}
button.secondary{background:#1a1f2a;color:#fff}
label{display:block;color:#9fa8ba;font-size:13px;margin:14px 0 6px}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:12px 0}
.stat{background:#131720;border-radius:14px;padding:11px;text-align:center}
.stat b{display:block;font-size:17px}
.stat span{font-size:11px;color:#919bad}
.colorRow{display:grid;grid-template-columns:1fr 72px;gap:12px;align-items:center}
input[type=color]{padding:4px;height:50px}
.note{font-size:12px;color:#8f98aa;line-height:1.5}
@media(max-width:540px){.stats{grid-template-columns:1fr 1fr}}
</style>
</head>
<body>
<main>
<h1>AirCam Gesture FX</h1>
<p class="sub">Open hand = effect ON · Closed fist = effect OFF</p>

<div id="status" class="status">Choose an effect, then tap Start Camera.</div>

<div class="stats">
 <div class="stat"><b id="gesture">—</b><span>Gesture</span></div>
 <div class="stat"><b id="actualRes">—</b><span>Resolution</span></div>
 <div class="stat"><b id="actualFps">—</b><span>Camera FPS</span></div>
 <div class="stat"><b id="ping">—</b><span>Ping</span></div>
</div>

<div class="wrap">
  <video id="raw" autoplay playsinline muted></video>
  <canvas id="fx"></canvas>
</div>

<label>Effect</label>
<select id="effect">
 <option value="contour" selected>Contour / Terrain</option>
 <option value="ascii">ASCII</option>
 <option value="matrix">Matrix</option>
 <option value="none">None</option>
</select>

<label>Effect Color</label>
<div class="colorRow">
 <select id="presetColor">
  <option value="#00ff66">Matrix Green</option>
  <option value="#00b7ff">Cyan Blue</option>
  <option value="#9c5cff">Purple</option>
  <option value="#ff334f">Red</option>
  <option value="#ffffff">White</option>
 </select>
 <input id="customColor" type="color" value="#00ff66">
</div>

<label>Resolution</label>
<select id="resolution">
 <option value="720" selected>720p</option>
 <option value="1080">1080p</option>
</select>

<label>Target FPS</label>
<select id="fps">
 <option value="30" selected>30 FPS</option>
 <option value="60">60 FPS Experimental</option>
</select>

<div class="grid">
 <button id="start">Start Camera</button>
 <button id="flip" class="secondary">Flip Camera</button>
</div>
<div class="grid">
 <button id="toggleFx" class="secondary">Gesture Control: ON</button>
 <button id="stop" class="secondary">Stop</button>
</div>

<p class="note">
Tip: hold your hand clearly in front of the camera. Open palm activates the effect;
a closed fist hides it. Hand detection runs less often than the video frames so the
camera stays smoother.
</p>
</main>

<script>
const raw=document.getElementById('raw');
const canvas=document.getElementById('fx');
const ctx=canvas.getContext('2d',{willReadFrequently:true});
const statusEl=document.getElementById('status');
const gestureEl=document.getElementById('gesture');
const resEl=document.getElementById('actualRes');
const fpsEl=document.getElementById('actualFps');
const pingEl=document.getElementById('ping');

let cameraStream=null;
let outputStream=null;
let pc=null;
let dc=null;
let facing='user';
let rafId=null;
let hands=null;
let handBusy=false;
let lastHandRun=0;
let effectEnabled=false;
let gestureControl=true;
let lastGesture='NONE';
let openVotes=0;
let fistVotes=0;
let pingTimer=null;
let lastPingSent=0;

function status(t){statusEl.textContent=t}

function hexToRgb(hex){
 const h=hex.replace('#','');
 return {
  r:parseInt(h.substring(0,2),16),
  g:parseInt(h.substring(2,4),16),
  b:parseInt(h.substring(4,6),16)
 };
}

function currentColor(){
 return document.getElementById('customColor').value;
}

document.getElementById('presetColor').addEventListener('change',e=>{
 document.getElementById('customColor').value=e.target.value;
});

function stopAll(){
 if(rafId){cancelAnimationFrame(rafId);rafId=null}
 if(pingTimer){clearInterval(pingTimer);pingTimer=null}
 if(dc){try{dc.close()}catch(e){} dc=null}
 if(pc){try{pc.close()}catch(e){} pc=null}
 if(outputStream){outputStream.getTracks().forEach(t=>t.stop());outputStream=null}
 if(cameraStream){cameraStream.getTracks().forEach(t=>t.stop());cameraStream=null}
 raw.srcObject=null;
 gestureEl.textContent='—';
 pingEl.textContent='—';
}

function countExtendedFingers(lm){
 if(!lm || lm.length<21) return 0;
 const wrist=lm[0];
 const dist=(a,b)=>Math.hypot(a.x-b.x,a.y-b.y,a.z-b.z);

 // Finger is treated as extended when its tip is substantially farther
 // from wrist than the middle joint.
 const pairs=[
  [8,6],[12,10],[16,14],[20,18]
 ];
 let count=0;
 for(const [tip,pip] of pairs){
  if(dist(lm[tip],wrist) > dist(lm[pip],wrist)*1.12) count++;
 }

 // Thumb heuristic.
 if(dist(lm[4],wrist) > dist(lm[2],wrist)*1.18) count++;
 return count;
}

function updateGesture(lm){
 const fingers=countExtendedFingers(lm);
 let g='OTHER';
 if(fingers>=4) g='OPEN';
 else if(fingers<=1) g='FIST';

 if(g==='OPEN'){
  openVotes=Math.min(4,openVotes+1);
  fistVotes=Math.max(0,fistVotes-1);
 }else if(g==='FIST'){
  fistVotes=Math.min(4,fistVotes+1);
  openVotes=Math.max(0,openVotes-1);
 }else{
  openVotes=Math.max(0,openVotes-1);
  fistVotes=Math.max(0,fistVotes-1);
 }

 if(openVotes>=2){
  lastGesture='OPEN';
  if(gestureControl) effectEnabled=true;
 }
 if(fistVotes>=2){
  lastGesture='FIST';
  if(gestureControl) effectEnabled=false;
 }

 gestureEl.textContent=lastGesture==='OPEN'?'OPEN ✋':lastGesture==='FIST'?'FIST ✊':'—';
}

async function initHands(){
 if(typeof Hands==='undefined'){
  status('MediaPipe Hands failed to load. Check iPhone internet access.');
  return false;
 }

 hands=new Hands({
  locateFile:file=>`https://cdn.jsdelivr.net/npm/@mediapipe/hands/${file}`
 });

 hands.setOptions({
  maxNumHands:1,
  modelComplexity:0,
  minDetectionConfidence:0.6,
  minTrackingConfidence:0.55
 });

 hands.onResults(results=>{
  handBusy=false;
  if(results.multiHandLandmarks && results.multiHandLandmarks.length){
   updateGesture(results.multiHandLandmarks[0]);
  }else{
   gestureEl.textContent='—';
  }
 });
 return true;
}

function drawBase(){
 const w=canvas.width, h=canvas.height;
 ctx.save();
 if(facing==='user'){
  ctx.translate(w,0);
  ctx.scale(-1,1);
 }
 ctx.drawImage(raw,0,0,w,h);
 ctx.restore();
}

function applyContour(){
 const w=canvas.width,h=canvas.height;
 const image=ctx.getImageData(0,0,w,h);
 const d=image.data;
 const rgb=hexToRgb(currentColor());

 // Cheap edge/terrain detector on a downsampled grid.
 const step=2;
 const out=new Uint8ClampedArray(d.length);

 for(let y=step;y<h-step;y+=step){
  for(let x=step;x<w-step;x+=step){
   const i=(y*w+x)*4;
   const ir=(y*w+(x+step))*4;
   const id=((y+step)*w+x)*4;

   const lum=(idx)=>0.299*d[idx]+0.587*d[idx+1]+0.114*d[idx+2];
   const gx=Math.abs(lum(ir)-lum(i));
   const gy=Math.abs(lum(id)-lum(i));
   const edge=Math.min(255,(gx+gy)*2.2);

   if(edge>28){
    for(let yy=0;yy<step;yy++){
     for(let xx=0;xx<step;xx++){
      const oi=((y+yy)*w+(x+xx))*4;
      out[oi]=rgb.r;
      out[oi+1]=rgb.g;
      out[oi+2]=rgb.b;
      out[oi+3]=Math.min(255,80+edge);
     }
    }
   }
  }
 }

 // Darken camera slightly, then place colored contour map.
 ctx.fillStyle='rgba(0,0,0,0.48)';
 ctx.fillRect(0,0,w,h);
 ctx.putImageData(new ImageData(out,w,h),0,0);
}

function applyAscii(){
 const w=canvas.width,h=canvas.height;
 const sample=10;
 const chars=' .:-=+*#%@';
 const rgb=hexToRgb(currentColor());

 const temp=document.createElement('canvas');
 temp.width=Math.max(1,Math.floor(w/sample));
 temp.height=Math.max(1,Math.floor(h/sample));
 const tctx=temp.getContext('2d',{willReadFrequently:true});
 tctx.drawImage(canvas,0,0,temp.width,temp.height);
 const img=tctx.getImageData(0,0,temp.width,temp.height).data;

 ctx.fillStyle='rgba(0,0,0,0.82)';
 ctx.fillRect(0,0,w,h);
 ctx.font=`${sample}px ui-monospace, SFMono-Regular, Menlo, monospace`;
 ctx.textBaseline='top';
 ctx.fillStyle=`rgb(${rgb.r},${rgb.g},${rgb.b})`;

 for(let y=0;y<temp.height;y++){
  for(let x=0;x<temp.width;x++){
   const i=(y*temp.width+x)*4;
   const lum=(img[i]+img[i+1]+img[i+2])/3;
   const index=Math.max(0,Math.min(chars.length-1,Math.floor(lum/256*chars.length)));
   if(index>1) ctx.fillText(chars[index],x*sample,y*sample);
  }
 }
}

function applyMatrix(){
 const w=canvas.width,h=canvas.height;
 const sample=12;
 const rgb=hexToRgb(currentColor());

 const temp=document.createElement('canvas');
 temp.width=Math.max(1,Math.floor(w/sample));
 temp.height=Math.max(1,Math.floor(h/sample));
 const tctx=temp.getContext('2d',{willReadFrequently:true});
 tctx.drawImage(canvas,0,0,temp.width,temp.height);
 const img=tctx.getImageData(0,0,temp.width,temp.height).data;

 ctx.fillStyle='rgba(0,0,0,0.76)';
 ctx.fillRect(0,0,w,h);
 ctx.font=`bold ${sample}px ui-monospace, SFMono-Regular, monospace`;
 ctx.textBaseline='top';

 const symbols='01アイウエオカキクケコ';
 for(let y=0;y<temp.height;y++){
  for(let x=0;x<temp.width;x++){
   const i=(y*temp.width+x)*4;
   const lum=(img[i]+img[i+1]+img[i+2])/3;
   if(lum>70){
    const alpha=Math.min(1,0.18+lum/255*0.82);
    ctx.fillStyle=`rgba(${rgb.r},${rgb.g},${rgb.b},${alpha})`;
    const ch=symbols[(x*7+y*11)%symbols.length];
    ctx.fillText(ch,x*sample,y*sample);
   }
  }
 }
}

async function renderLoop(ts){
 if(raw.videoWidth && raw.videoHeight){
  const maxW=document.getElementById('resolution').value==='1080'?1280:960;
  const scale=Math.min(1,maxW/raw.videoWidth);
  const wantedW=Math.round(raw.videoWidth*scale);
  const wantedH=Math.round(raw.videoHeight*scale);

  if(canvas.width!==wantedW || canvas.height!==wantedH){
   canvas.width=wantedW;
   canvas.height=wantedH;
  }

  drawBase();

  const mode=document.getElementById('effect').value;
  if(effectEnabled && mode!=='none'){
   if(mode==='contour') applyContour();
   else if(mode==='ascii') applyAscii();
   else if(mode==='matrix') applyMatrix();
  }

  // Hand detection ~10 FPS, independent from video frame rate.
  if(hands && !handBusy && ts-lastHandRun>100){
   lastHandRun=ts;
   handBusy=true;
   hands.send({image:raw}).catch(()=>{
    handBusy=false;
   });
  }
 }
 rafId=requestAnimationFrame(renderLoop);
}

async function getCamera(){
 const r=document.getElementById('resolution').value;
 const f=Number(document.getElementById('fps').value);
 const width=r==='1080'?1920:1280;
 const height=r==='1080'?1080:720;

 return navigator.mediaDevices.getUserMedia({
  audio:false,
  video:{
   facingMode:{ideal:facing},
   width:{ideal:width},
   height:{ideal:height},
   frameRate:{ideal:f,max:f}
  }
 });
}

async function start(){
 stopAll();
 effectEnabled=false;
 lastGesture='NONE';
 openVotes=0;
 fistVotes=0;

 status('Starting camera + hand tracking…');

 try{
  if(!hands){
   const ok=await initHands();
   if(!ok)return;
  }

  cameraStream=await getCamera();
  raw.srcObject=cameraStream;
  await raw.play();

  const settings=cameraStream.getVideoTracks()[0].getSettings();
  resEl.textContent=(settings.width||'?')+'×'+(settings.height||'?');
  fpsEl.textContent=settings.frameRate?Math.round(settings.frameRate)+'':'?';

  rafId=requestAnimationFrame(renderLoop);

  // Wait for canvas to receive its first frame.
  await new Promise(r=>setTimeout(r,300));

  const targetFps=Number(document.getElementById('fps').value);
  if(!canvas.captureStream){
   throw new Error('Canvas captureStream is not supported by this Safari version.');
  }
  outputStream=canvas.captureStream(targetFps);
  const fxTrack=outputStream.getVideoTracks()[0];

  pc=new RTCPeerConnection({iceServers:[]});

  dc=pc.createDataChannel('aircam-stats');
  dc.onopen=()=>{
   pingTimer=setInterval(()=>{
    if(dc&&dc.readyState==='open'){
     lastPingSent=performance.now();
     dc.send('ping:'+lastPingSent);
    }
   },1000);
  };
  dc.onmessage=e=>{
   if(String(e.data).startsWith('pong:')){
    pingEl.textContent=Math.round(performance.now()-lastPingSent)+' ms';
   }
  };

  pc.addTrack(fxTrack,outputStream);

  pc.onconnectionstatechange=()=>{
   if(pc.connectionState==='connected') status('Connected ✓ Gesture FX streaming to PC');
   else if(['failed','disconnected','closed'].includes(pc.connectionState)){
    status('Connection to PC: '+pc.connectionState);
   }
  };

  const offer=await pc.createOffer();
  await pc.setLocalDescription(offer);

  await new Promise(resolve=>{
   if(pc.iceGatheringState==='complete') return resolve();
   const fn=()=>{
    if(pc.iceGatheringState==='complete'){
     pc.removeEventListener('icegatheringstatechange',fn);
     resolve();
    }
   };
   pc.addEventListener('icegatheringstatechange',fn);
  });

  const response=await fetch('/offer',{
   method:'POST',
   headers:{'Content-Type':'application/json'},
   body:JSON.stringify({
    sdp:pc.localDescription.sdp,
    type:pc.localDescription.type
   })
  });

  if(!response.ok) throw new Error('PC signaling failed');
  const answer=await response.json();
  await pc.setRemoteDescription(answer);

 }catch(e){
  status('Error: '+e.message);
 }
}

document.getElementById('start').addEventListener('click',start);

document.getElementById('flip').addEventListener('click',async()=>{
 facing=facing==='user'?'environment':'user';
 await start();
});

document.getElementById('toggleFx').addEventListener('click',()=>{
 gestureControl=!gestureControl;
 document.getElementById('toggleFx').textContent='Gesture Control: '+(gestureControl?'ON':'OFF');
 if(!gestureControl) effectEnabled=!effectEnabled;
});

document.getElementById('stop').addEventListener('click',()=>{
 stopAll();
 status('Stopped.');
});
</script>
</body>
</html>"""

async def receive_video(track):
    global LATEST_FRAME, RX_FPS, FRAME_COUNTER, FPS_WINDOW_START
    try:
        while RUNNING:
            frame = await track.recv()
            img = frame.to_ndarray(format="bgr24")

            with LATEST_LOCK:
                LATEST_FRAME = img

            now = time.perf_counter()
            with STATS_LOCK:
                FRAME_COUNTER += 1
                elapsed = now - FPS_WINDOW_START
                if elapsed >= 1.0:
                    RX_FPS = FRAME_COUNTER / elapsed
                    FRAME_COUNTER = 0
                    FPS_WINDOW_START = now
    except Exception:
        pass

async def offer(request):
    params = await request.json()
    remote_offer = RTCSessionDescription(sdp=params["sdp"], type=params["type"])

    pc = RTCPeerConnection()
    pcs.add(pc)

    @pc.on("connectionstatechange")
    async def on_state():
        if pc.connectionState in ("failed", "closed", "disconnected"):
            await pc.close()
            pcs.discard(pc)

    @pc.on("datachannel")
    def on_dc(channel):
        @channel.on("message")
        def on_message(message):
            if isinstance(message, str) and message.startswith("ping:"):
                channel.send("pong:" + message[5:])

    @pc.on("track")
    def on_track(track):
        if track.kind == "video":
            asyncio.create_task(receive_video(track))

    await pc.setRemoteDescription(remote_offer)
    answer = await pc.createAnswer()
    await pc.setLocalDescription(answer)

    return web.json_response({
        "sdp": pc.localDescription.sdp,
        "type": pc.localDescription.type,
    })

def fit_letterbox(frame, out_w, out_h):
    h, w = frame.shape[:2]
    if w <= 0 or h <= 0:
        return np.zeros((out_h, out_w, 3), dtype=np.uint8)

    scale = min(out_w / w, out_h / h)
    nw = max(1, int(round(w * scale)))
    nh = max(1, int(round(h * scale)))

    interp = cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR
    resized = cv2.resize(frame, (nw, nh), interpolation=interp)

    canvas = np.zeros((out_h, out_w, 3), dtype=np.uint8)
    x = (out_w - nw) // 2
    y = (out_h - nh) // 2
    canvas[y:y+nh, x:x+nw] = resized
    return canvas

def viewer_loop():
    global RUNNING
    name = "AirCam v0.5 Gesture FX"

    cv2.namedWindow(name, cv2.WINDOW_NORMAL)
    cv2.resizeWindow(name, 1280, 720)

    while RUNNING:
        with LATEST_LOCK:
            frame = None if LATEST_FRAME is None else LATEST_FRAME.copy()

        try:
            _, _, target_w, target_h = cv2.getWindowImageRect(name)
            target_w = max(640, target_w)
            target_h = max(360, target_h)
        except Exception:
            target_w, target_h = 1280, 720

        if frame is None:
            canvas = np.zeros((target_h, target_w, 3), dtype=np.uint8)
            cv2.putText(
                canvas,
                "Waiting for iPhone Gesture FX...",
                (max(30, target_w//2 - 300), target_h//2),
                cv2.FONT_HERSHEY_SIMPLEX,
                1.0,
                (230,230,230),
                2,
                cv2.LINE_AA,
            )
        else:
            canvas = fit_letterbox(frame, target_w, target_h)
            h, w = frame.shape[:2]
            with STATS_LOCK:
                fps = RX_FPS

            overlay = f"{w}x{h}   RX {fps:.1f} FPS   Gesture FX"
            cv2.rectangle(canvas, (14, 14), (500, 58), (0,0,0), -1)
            cv2.putText(
                canvas,
                overlay,
                (25, 44),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.72,
                (255,255,255),
                2,
                cv2.LINE_AA,
            )

        cv2.imshow(name, canvas)
        key = cv2.waitKey(1) & 0xFF

        if key in (27, ord("q")):
            RUNNING = False
            break

        try:
            if cv2.getWindowProperty(name, cv2.WND_PROP_VISIBLE) < 1:
                RUNNING = False
                break
        except Exception:
            pass

    cv2.destroyAllWindows()

async def main():
    global RUNNING

    ip = get_local_ip()
    ca_key, ca_cert, ca_der, ca_subject = load_or_create_ca()
    server_cert, server_key = make_server_cert(ip, ca_key, ca_cert)

    setup_url = f"http://{ip}:{HTTP_PORT}/"
    camera_url = f"https://{ip}:{HTTPS_PORT}/"

    setup_qr = BASE / "1_INSTALL_CERT_QR.png"
    camera_qr = BASE / "2_CAMERA_QR.png"

    qr = qrcode.QRCode(border=2)
    qr.add_data(setup_url)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(setup_qr)

    qr = qrcode.QRCode(border=2)
    qr.add_data(camera_url)
    qr.make(fit=True)
    qr.make_image(fill_color="black", back_color="white").save(camera_qr)

    async def setup_index(request):
        return web.Response(text=SETUP_HTML, content_type="text/html")

    async def certificate(request):
        return web.FileResponse(
            ca_der,
            headers={
                "Content-Type": "application/x-x509-ca-cert",
                "Content-Disposition": 'attachment; filename="AirCam_Local_CA.cer"',
            },
        )

    setup_app = web.Application()
    setup_app.router.add_get("/", setup_index)
    setup_app.router.add_get("/certificate", certificate)

    cam_app = web.Application()
    cam_app.router.add_get("/", lambda request: web.Response(text=CAM_HTML, content_type="text/html"))
    cam_app.router.add_post("/offer", offer)

    setup_runner = web.AppRunner(setup_app)
    cam_runner = web.AppRunner(cam_app)
    await setup_runner.setup()
    await cam_runner.setup()

    await web.TCPSite(setup_runner, "0.0.0.0", HTTP_PORT).start()

    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ssl_ctx.load_cert_chain(str(server_cert), str(server_key))
    await web.TCPSite(cam_runner, "0.0.0.0", HTTPS_PORT, ssl_context=ssl_ctx).start()

    print("=" * 74)
    print("                    AirCam v0.5 Gesture FX")
    print("=" * 74)
    print()
    print("PC IP:", ip)
    print("Certificate:", ca_subject)
    print()
    print("GESTURES:")
    print("  Open hand   -> Effect ON")
    print("  Closed fist -> Effect OFF")
    print()
    print("EFFECTS:")
    print("  Contour / Terrain")
    print("  ASCII")
    print("  Matrix")
    print()
    print("FIRST TIME ONLY (unless you reused cert folder):")
    print("  Scan:", setup_qr)
    print("  Install + FULL TRUST AirCam certificate")
    print()
    print("THEN:")
    print("  Scan:", camera_qr)
    print("  Camera URL:", camera_url)
    print()
    print("NOTE: MediaPipe Hands is loaded from jsDelivr,")
    print("so the iPhone needs internet access while loading the page.")
    print()
    print("Press Q / ESC in PC window to stop.")
    print()

    try:
        os.startfile(str(setup_qr))
    except Exception:
        pass

    viewer = threading.Thread(target=viewer_loop, daemon=True)
    viewer.start()

    try:
        while RUNNING:
            await asyncio.sleep(0.2)
    finally:
        RUNNING = False
        for pc in list(pcs):
            await pc.close()
        pcs.clear()
        await setup_runner.cleanup()
        await cam_runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())
