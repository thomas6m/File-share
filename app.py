#!/usr/bin/env python3
"""
Simple file share: upload + download only (no delete, no overwrite, no rename).
"""
import os
import sys
import hmac
import time
from pathlib import Path
from datetime import datetime
from flask import (Flask, request, redirect, url_for, flash,
                   send_from_directory, render_template_string, Response, abort)
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet

# =====================================================================
# CONFIG - tune these values here (environment variables, if set,
# override them, e.g. MAX_UPLOAD_MB=5000 in the systemd unit)
# =====================================================================
SHARE_DIR     = ""                 # where files are stored; "" = <current working dir>/fileshare
                                   # (created automatically if missing)
SECRETS_DIR   = ""                 # folder with .fernet.key and .password.enc (made by the
                                   # encryption script); "" = <current working dir>/.secrets
MAX_UPLOAD_MB = 2048               # max size of ONE upload request (all files in it combined), in MB
HOST          = "0.0.0.0"          # bind address
PORT          = 8080               # listen port
PROTECT_DOWNLOAD = True            # True  = browser login prompt (AUTH_USER + password) needed to
                                   #         view the file list and download
                                   # False = anyone who can reach the page can download
PROTECT_UPLOAD   = True            # True  = upload form asks for the password on every upload
                                   # False = anyone who can reach the page can upload
                                   # (both False = fully open; both use the password in SECRETS_DIR)
AUTH_USER     = "fileshare"        # username for the download login prompt
APP_TITLE     = "File share"       # name shown in the page header and browser tab
MAX_FAILED    = 5                  # wrong upload passwords allowed per client IP ...
LOCKOUT_SEC   = 300                # ... within this many seconds, then uploads are blocked
SHOW_HIDDEN   = False              # list files starting with "." ?
# =====================================================================

SHARE_DIR     = os.path.abspath(os.environ.get("SHARE_DIR") or SHARE_DIR or os.path.join(os.getcwd(), "fileshare"))
SECRETS_DIR   = Path(os.environ.get("SECRETS_DIR") or SECRETS_DIR or Path.cwd() / ".secrets")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", MAX_UPLOAD_MB))
HOST          = os.environ.get("HOST", HOST)
PORT          = int(os.environ.get("PORT", PORT))
USER          = os.environ.get("SHARE_USER", AUTH_USER)


def env_bool(name, default):
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


PROTECT_DOWNLOAD = env_bool("PROTECT_DOWNLOAD", PROTECT_DOWNLOAD)
PROTECT_UPLOAD   = env_bool("PROTECT_UPLOAD", PROTECT_UPLOAD)
MAX_MB        = MAX_UPLOAD_MB
SELF_NAME     = os.path.basename(os.path.abspath(__file__))  # never listed or served

KEY_FILE      = SECRETS_DIR / ".fernet.key"
PASSWORD_FILE = SECRETS_DIR / ".password.enc"


def load_password():
    """Decrypt the password stored by the encryption script. Exit if unusable
    so the app never starts silently unprotected."""
    try:
        fernet = Fernet(KEY_FILE.read_bytes())
        return fernet.decrypt(PASSWORD_FILE.read_bytes()).decode()
    except Exception as e:
        sys.exit(f"[FATAL] Cannot load password from {SECRETS_DIR}: "
                 f"{type(e).__name__}: {e}\n"
                 f"Run the encryption script first, or set PROTECT_DOWNLOAD and PROTECT_UPLOAD to False.")


PASSWORD = load_password() if (PROTECT_DOWNLOAD or PROTECT_UPLOAD) else None
if PROTECT_DOWNLOAD and not USER:
    sys.exit("[FATAL] PROTECT_DOWNLOAD is on but AUTH_USER is empty.")
print(f"[fileshare] download protected: {PROTECT_DOWNLOAD} | upload protected: {PROTECT_UPLOAD}",
      file=sys.stderr)

os.makedirs(SHARE_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))


# ---------- optional basic auth ----------
@app.before_request
def check_auth():
    if not PROTECT_DOWNLOAD:
        return
    a = request.authorization
    if not (a and hmac.compare_digest(a.username or "", USER)
            and hmac.compare_digest(a.password or "", PASSWORD)):
        return Response("Authentication required", 401,
                        {"WWW-Authenticate": 'Basic realm="fileshare"'})


# ---------- helpers ----------
_fails = {}   # ip -> [timestamps of recent failures] (per worker process)


def client_ip():
    return request.remote_addr or "unknown"


def locked_out(ip):
    now = time.time()
    recent = [t for t in _fails.get(ip, []) if now - t < LOCKOUT_SEC]
    _fails[ip] = recent
    return len(recent) >= MAX_FAILED


def password_ok(supplied):
    return hmac.compare_digest(supplied.encode(), PASSWORD.encode())


def human(n):
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def unique_path(name):
    """Never overwrite an existing file; add a timestamp suffix instead."""
    path = os.path.join(SHARE_DIR, name)
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(name)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    n = 0
    while True:
        suffix = f"_{stamp}" + (f"_{n}" if n else "")
        path = os.path.join(SHARE_DIR, f"{base}{suffix}{ext}")
        if not os.path.exists(path):
            return path
        n += 1


KINDS = {
    "archive": {"zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "iso", "img"},
    "image":   {"png", "jpg", "jpeg", "gif", "svg", "webp", "bmp", "tif", "tiff"},
    "doc":     {"pdf", "doc", "docx", "txt", "md", "rtf", "odt", "ppt", "pptx", "html"},
    "data":    {"csv", "json", "xlsx", "xls", "xml", "yaml", "yml", "sql", "db", "log"},
    "code":    {"py", "sh", "js", "ts", "go", "java", "c", "cpp", "rb", "pl", "conf",
                "ini", "toml", "service", "rpm", "deb"},
}


def file_kind(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    for kind, exts in KINDS.items():
        if ext in exts:
            return kind, ext.upper()[:4]
    return "other", (ext.upper()[:4] if ext else "FILE")


def list_files():
    out = []
    for e in os.scandir(SHARE_DIR):
        if e.is_file() and e.name != SELF_NAME and (SHOW_HIDDEN or not e.name.startswith(".")):
            st = e.stat()
            kind, ext = file_kind(e.name)
            out.append({"name": e.name, "size": human(st.st_size), "bytes": st.st_size,
                        "kind": kind, "ext": ext,
                        "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                        "ts": st.st_mtime})
    return sorted(out, key=lambda x: x["ts"], reverse=True)


# ---------- routes (GET list, POST upload, GET download; nothing else) ----------
PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='8' fill='%230B6E69'/%3E%3Cpath d='M8 19v4h16v-4M16 9v10M11.5 14.5L16 9l4.5 5.5' fill='none' stroke='white' stroke-width='2.2' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
  :root{
    --bg:#EDF1F4; --panel:#FFFFFF; --soft:#F5F7F9; --ink:#15212B; --mut:#586979; --line:#D6DDE3;
    --acc:#0B6E69; --acc-ink:#FFFFFF; --acc-soft:#DCEEEB;
    --bad:#A32A24; --bad-bg:#FBEDEC; --ok:#0B6E69; --ok-bg:#E3F2EF;
    --b-l:92%; --b-c:30%; --b-s:60%;
  }
  @media (prefers-color-scheme:dark){
    :root{
      --bg:#0D1319; --panel:#141C24; --soft:#1A242E; --ink:#E4EAF0; --mut:#92A2B1; --line:#27323D;
      --acc:#3CC5B8; --acc-ink:#06201D; --acc-soft:#12332F;
      --bad:#FF9C94; --bad-bg:#3A1917; --ok:#3CC5B8; --ok-bg:#12332F;
      --b-l:22%; --b-c:78%; --b-s:35%;
    }
  }
  *{box-sizing:border-box}
  html{-webkit-text-size-adjust:100%}
  body{margin:0;background:var(--bg);color:var(--ink);
       font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif}
  .wrap{max-width:1080px;margin:0 auto;padding:0 20px}
  :focus-visible{outline:2px solid var(--acc);outline-offset:2px}
  button,input{font:inherit;color:inherit}
  .num{font-variant-numeric:tabular-nums}

  /* header */
  .top{background:var(--panel);border-bottom:1px solid var(--line)}
  .top .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:16px;padding-bottom:16px;flex-wrap:wrap}
  .brand{display:flex;align-items:center;gap:12px}
  .logo{width:36px;height:36px;border-radius:9px;background:var(--acc);display:grid;place-items:center;flex:none}
  .logo svg{width:20px;height:20px;stroke:var(--acc-ink)}
  h1{margin:0;font-size:19px;line-height:1.2;font-weight:650;letter-spacing:-.01em}
  .brand p{margin:2px 0 0;font-size:13px;color:var(--mut)}
  .lock{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--mut);
        border:1px solid var(--line);border-radius:999px;padding:5px 12px 5px 10px;background:var(--soft)}
  .lock svg{width:14px;height:14px;stroke:currentColor}

  /* layout */
  .grid{display:grid;grid-template-columns:344px minmax(0,1fr);gap:20px;align-items:start;margin:24px auto 48px}
  @media (max-width:880px){.grid{grid-template-columns:1fr}}
  .panel{background:var(--panel);border:1px solid var(--line);border-radius:10px}
  .upload{position:sticky;top:20px}
  @media (max-width:880px){.upload{position:static}}
  .phead{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;
         padding:14px 18px;border-bottom:1px solid var(--line)}
  h2{margin:0;font-size:15px;font-weight:650}
  .pbody{padding:18px}
  .sub{font-size:13px;color:var(--mut)}

  /* drop zone: it is also the progress bar */
  .zone{position:relative;overflow:hidden;width:100%;min-height:156px;padding:20px;cursor:pointer;
        display:grid;place-items:center;text-align:center;
        background:var(--soft);border:1.5px dashed var(--line);border-radius:8px;transition:border-color .15s,background .15s}
  .zone:hover,.zone.over{border-color:var(--acc);background:var(--acc-soft)}
  .zone[disabled]{cursor:default}
  .zone .fill{position:absolute;inset:0 auto 0 0;width:0;background:var(--acc-soft);transition:width .25s linear}
  .zone.busy{border-style:solid;border-color:var(--acc)}
  .zone .in{position:relative;display:grid;gap:4px;justify-items:center}
  .zone svg{width:28px;height:28px;stroke:var(--acc);margin-bottom:4px}
  .zone strong{font-weight:650}
  .zone .big{font-size:26px;font-weight:650;letter-spacing:-.02em}

  .qhead{display:flex;justify-content:space-between;align-items:baseline;margin:16px 0 6px}
  .link{background:none;border:0;padding:0;color:var(--acc);cursor:pointer;font-size:13px;text-decoration:underline;text-underline-offset:2px}
  ul.queue{list-style:none;margin:0;padding:0;max-height:176px;overflow:auto;border:1px solid var(--line);border-radius:8px}
  ul.queue li{display:flex;align-items:center;gap:10px;padding:7px 8px 7px 12px;border-bottom:1px solid var(--line);font-size:13.5px}
  ul.queue li:last-child{border-bottom:0}
  ul.queue .n{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  ul.queue .s{color:var(--mut);white-space:nowrap}
  .x{width:26px;height:26px;border-radius:6px;border:0;background:none;color:var(--mut);cursor:pointer;font-size:18px;line-height:1}
  .x:hover{background:var(--soft);color:var(--ink)}

  label.f{display:block;margin:16px 0 6px;font-size:13px;font-weight:600}
  .pw{position:relative}
  .pw input{width:100%;height:40px;padding:0 64px 0 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
  .pw input:focus-visible{outline-offset:0}
  .pw button{position:absolute;right:6px;top:6px;height:28px;padding:0 10px;border:0;border-radius:6px;background:var(--soft);color:var(--mut);cursor:pointer;font-size:13px}
  .btn{width:100%;height:42px;margin-top:16px;border:0;border-radius:8px;background:var(--acc);color:var(--acc-ink);font-weight:650;cursor:pointer}
  .btn:hover:not(:disabled){filter:brightness(1.07)}
  .btn:disabled{opacity:.45;cursor:not-allowed}
  .rule{margin:16px 0 0;font-size:12.5px;color:var(--mut)}

  .note{margin:0 0 12px;padding:9px 12px;border-radius:8px;font-size:13.5px;border:1px solid transparent}
  .note.err{background:var(--bad-bg);color:var(--bad);border-color:var(--bad)}
  .note.ok{background:var(--ok-bg);color:var(--ok);border-color:var(--ok)}
  .note[hidden]{display:none}
  .pbody .note{margin:14px 0 0}

  /* file list */
  .tools{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .search{position:relative}
  .search svg{position:absolute;left:10px;top:50%;margin-top:-8px;width:16px;height:16px;stroke:var(--mut);pointer-events:none}
  .search input{height:36px;width:230px;max-width:100%;padding:0 12px 0 32px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
  .search input:focus-visible{outline-offset:0}
  .listwrap{padding:0}
  .flash{padding:14px 18px 0}
  .scroll{overflow-x:auto}
  table{width:100%;border-collapse:collapse}
  th,td{padding:11px 12px;text-align:left;border-bottom:1px solid var(--line);vertical-align:middle}
  tbody tr:last-child td{border-bottom:0}
  th:first-child,td:first-child{padding-left:18px}
  th:last-child,td:last-child{padding-right:18px}
  th{font-weight:600;font-size:13px;color:var(--mut);background:var(--soft);white-space:nowrap}
  th button{background:none;border:0;padding:0;font:inherit;color:inherit;cursor:pointer;display:inline-flex;align-items:center;gap:5px}
  th button:hover{color:var(--ink)}
  th button::after{content:"";width:0;height:0;border:4px solid transparent;opacity:0}
  th[aria-sort="ascending"] button::after{border-bottom:5px solid currentColor;border-top:0;opacity:1}
  th[aria-sort="descending"] button::after{border-top:5px solid currentColor;border-bottom:0;opacity:1}
  td.r,th.r{text-align:right}
  tbody tr:hover{background:var(--soft)}
  .file{display:flex;align-items:center;gap:12px;min-width:0}
  .badge{flex:none;width:38px;height:38px;border-radius:8px;display:grid;place-items:center;
         font-size:10.5px;font-weight:700;letter-spacing:.02em;
         background:hsl(var(--h,215) var(--b-s) var(--b-l));color:hsl(var(--h,215) 55% var(--b-c))}
  .badge[data-k="archive"]{--h:34}.badge[data-k="image"]{--h:285}.badge[data-k="doc"]{--h:212}
  .badge[data-k="data"]{--h:148}.badge[data-k="code"]{--h:186}.badge[data-k="other"]{--h:215;--b-s:12%}
  .fname{overflow-wrap:anywhere;font-weight:550}
  .dl{display:inline-flex;align-items:center;gap:6px;height:32px;padding:0 12px;border:1px solid var(--line);border-radius:8px;
      color:var(--ink);text-decoration:none;font-size:13.5px;font-weight:550;background:var(--panel);white-space:nowrap}
  .dl:hover{border-color:var(--acc);color:var(--acc)}
  .dl svg{width:15px;height:15px;stroke:currentColor}
  .empty td{padding:44px 18px;text-align:center;color:var(--mut)}
  @media (max-width:640px){.hide-sm{display:none}.search input{width:100%}.search{flex:1}}
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head>
<body>
<header class="top"><div class="wrap">
  <div class="brand">
    <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15v4h16v-4M12 5v10M7.5 9.5L12 5l4.5 4.5"/></svg></div>
    <div><h1>{{ title }}</h1><p>Move files between your desktop and this server</p></div>
  </div>
  <div class="lock" title="Files can be added and downloaded. They can't be deleted or overwritten.">
    <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
    Read-only: upload and download
  </div>
</div></header>

<main class="wrap grid">
  <section class="panel upload" aria-labelledby="uh">
    <div class="phead"><h2 id="uh">Upload files</h2><span class="sub">Up to {{ max_mb }} MB per upload</span></div>
    <div class="pbody">
      <button type="button" id="zone" class="zone" aria-describedby="zhint">
        <span class="fill" id="fill"></span>
        <span class="in" id="zin">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 15v4h16v-4M12 5v10M7.5 9.5L12 5l4.5 4.5"/></svg>
          <strong>Drop files here</strong>
          <span class="sub" id="zhint">or click to choose from your computer</span>
        </span>
      </button>
      <input id="file" type="file" multiple hidden>

      <div id="qwrap" hidden>
        <div class="qhead"><span class="sub num" id="qsum"></span><button type="button" class="link" id="qclear">Clear all</button></div>
        <ul class="queue" id="queue"></ul>
      </div>

      {% if need_pw %}
      <label class="f" for="pw">Upload password</label>
      <div class="pw">
        <input id="pw" type="password" autocomplete="off" spellcheck="false">
        <button type="button" id="pwt" aria-pressed="false">Show</button>
      </div>
      {% endif %}

      <div id="err" class="note err" role="alert" hidden></div>
      <button type="button" class="btn" id="go" disabled>Upload files</button>
      <p class="rule">Uploaded files can’t be deleted or replaced. If a name already exists, the new file is saved with a timestamp added.</p>
    </div>
  </section>

  <section class="panel" aria-labelledby="lh">
    <div class="phead">
      <div><h2 id="lh">Files</h2><span class="sub num" id="stats">{{ count }} file{{ '' if count == 1 else 's' }} · {{ total }}</span></div>
      <div class="tools">
        <div class="search">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
          <input id="q" type="search" placeholder="Search by name" aria-label="Search files by name">
        </div>
      </div>
    </div>
    {% with m = get_flashed_messages() %}{% if m %}<div class="flash">{% for x in m %}<p class="note ok" role="status">{{ x }}</p>{% endfor %}</div>{% endif %}{% endwith %}
    <div class="scroll"><table>
      <thead><tr>
        <th scope="col" aria-sort="none"><button type="button" data-key="name">Name</button></th>
        <th scope="col" class="r" aria-sort="none"><button type="button" data-key="size">Size</button></th>
        <th scope="col" class="hide-sm" aria-sort="descending"><button type="button" data-key="ts">Modified</button></th>
        <th scope="col" class="r"><span class="sr" style="position:absolute;left:-9999px">Download</span></th>
      </tr></thead>
      <tbody id="rows">
        {% for f in files %}
        <tr data-name="{{ f.name|lower }}" data-size="{{ f.bytes }}" data-ts="{{ f.ts }}">
          <td><div class="file"><span class="badge" data-k="{{ f.kind }}" aria-hidden="true">{{ f.ext }}</span><span class="fname">{{ f.name }}</span></div></td>
          <td class="r num">{{ f.size }}</td>
          <td class="hide-sm num">{{ f.mtime }}</td>
          <td class="r"><a class="dl" href="{{ url_for('download', filename=f.name) }}" aria-label="Download {{ f.name }}">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"/></svg>Download</a></td>
        </tr>
        {% endfor %}
        <tr class="empty" id="empty" {% if files %}hidden{% endif %}><td colspan="4" id="emptytxt">No files yet. Drop a file into the upload panel to add the first one.</td></tr>
      </tbody>
    </table></div>
  </section>
</main>

<script>
(function(){
  var $ = function(id){return document.getElementById(id)};
  var MAX = {{ max_mb }} * 1048576, NEED_PW = {{ 'true' if need_pw else 'false' }};
  var zone=$('zone'), fileIn=$('file'), fill=$('fill'), zin=$('zin'), go=$('go'), err=$('err'),
      qwrap=$('qwrap'), queueEl=$('queue'), qsum=$('qsum'), pw=$('pw'), busy=false, queue=[];

  function fmt(n){
    var u=['B','KB','MB','GB','TB'], i=0;
    while(n>=1024 && i<u.length-1){n/=1024;i++}
    return (i===0? n.toFixed(0) : n.toFixed(1))+' '+u[i];
  }
  function showErr(t){err.textContent=t;err.hidden=!t}
  function total(){return queue.reduce(function(a,f){return a+f.size},0)}

  function render(){
    queueEl.textContent='';
    queue.forEach(function(f,i){
      var li=document.createElement('li'), n=document.createElement('span'), s=document.createElement('span'), x=document.createElement('button');
      n.className='n'; n.textContent=f.name; n.title=f.name;
      s.className='s num'; s.textContent=fmt(f.size);
      x.type='button'; x.className='x'; x.textContent='\u00d7'; x.setAttribute('aria-label','Remove '+f.name);
      x.onclick=function(){queue.splice(i,1);render()};
      li.appendChild(n); li.appendChild(s); li.appendChild(x); queueEl.appendChild(li);
    });
    qwrap.hidden=!queue.length;
    qsum.textContent=queue.length+' file'+(queue.length===1?'':'s')+' \u00b7 '+fmt(total());
    if(total()>MAX){showErr('These files total '+fmt(total())+', over the '+fmt(MAX)+' limit. Remove some files or upload them in batches.')}
    else if(!busy){showErr('')}
    go.disabled = busy || !queue.length || total()>MAX;
  }
  function add(list){
    Array.prototype.forEach.call(list,function(f){
      if(!queue.some(function(q){return q.name===f.name && q.size===f.size})) queue.push(f);
    });
    render();
  }

  zone.onclick=function(){if(!busy)fileIn.click()};
  fileIn.onchange=function(){add(fileIn.files);fileIn.value=''};
  $('qclear').onclick=function(){queue=[];render()};
  ['dragenter','dragover'].forEach(function(e){document.addEventListener(e,function(ev){ev.preventDefault();if(!busy&&zone.contains(ev.target))zone.classList.add('over')})});
  ['dragleave','drop'].forEach(function(e){document.addEventListener(e,function(ev){if(ev.type==='dragleave'&&zone.contains(ev.relatedTarget))return;zone.classList.remove('over')})});
  document.addEventListener('drop',function(ev){ev.preventDefault();if(!busy&&ev.dataTransfer&&ev.dataTransfer.files.length)add(ev.dataTransfer.files)});

  if(pw){
    $('pwt').onclick=function(){
      var show=pw.type==='password'; pw.type=show?'text':'password';
      this.textContent=show?'Hide':'Show'; this.setAttribute('aria-pressed',show);
    };
    pw.addEventListener('keydown',function(e){if(e.key==='Enter'&&!go.disabled)go.click()});
  }

  function setBusy(b){
    busy=b; zone.classList.toggle('busy',b); zone.disabled=b; go.disabled=b||!queue.length;
    if(!b){fill.style.width='0';zin.innerHTML=idle}
  }
  var idle=zin.innerHTML;

  go.onclick=function(){
    if(NEED_PW && !pw.value){showErr('Enter the upload password to continue.');pw.focus();return}
    showErr('');
    var fd=new FormData(); queue.forEach(function(f){fd.append('files',f)});
    if(NEED_PW) fd.append('password',pw.value);
    var x=new XMLHttpRequest(), t0=Date.now();
    x.open('POST','{{ url_for("upload") }}');
    setBusy(true);
    zin.innerHTML='<span class="big num" id="pct">0%</span><span class="sub num" id="spd">Starting upload</span>';
    x.upload.onprogress=function(e){
      if(!e.lengthComputable)return;
      var p=Math.round(e.loaded/e.total*100), secs=Math.max((Date.now()-t0)/1000,.1);
      fill.style.width=p+'%';
      $('pct').textContent=p+'%';
      $('spd').textContent = p>=100 ? 'Saving on the server' : fmt(e.loaded/secs)+'/s \u00b7 '+fmt(e.loaded)+' of '+fmt(e.total);
    };
    x.onload=function(){
      if(x.status>=200 && x.status<400){location.reload();return}
      setBusy(false); render();
      showErr(x.responseText || 'The upload failed. Try again.');
      if(NEED_PW && (x.status===403)){pw.select()}
    };
    x.onerror=function(){setBusy(false);render();showErr('The connection dropped before the upload finished. Check your network and try again.')};
    x.send(fd);
  };

  /* list: search + sort */
  var tbody=$('rows'), empty=$('empty'), q=$('q'), stats=$('stats'), key='ts', dir=-1;
  function rows(){return Array.prototype.slice.call(tbody.querySelectorAll('tr[data-name]'))}
  function filter(){
    var term=q.value.trim().toLowerCase(), shown=0, all=rows();
    all.forEach(function(r){var ok=!term||r.dataset.name.indexOf(term)!==-1;r.hidden=!ok;if(ok)shown++});
    if(!all.length){empty.hidden=false}
    else{empty.hidden=shown>0; $('emptytxt').textContent='No files match \u201c'+q.value.trim()+'\u201d.'}
  }
  q.addEventListener('input',filter);
  Array.prototype.forEach.call(document.querySelectorAll('th button[data-key]'),function(b){
    b.onclick=function(){
      var k=b.dataset.key; dir=(key===k)?-dir:(k==='name'?1:-1); key=k;
      rows().sort(function(a,c){
        var x=a.dataset[k], y=c.dataset[k];
        if(k!=='name'){x=parseFloat(x);y=parseFloat(y);return (x-y)*dir}
        return x.localeCompare(y)*dir;
      }).forEach(function(r){tbody.insertBefore(r,empty)});
      Array.prototype.forEach.call(document.querySelectorAll('th[aria-sort]'),function(th){th.setAttribute('aria-sort','none')});
      b.parentNode.setAttribute('aria-sort',dir===1?'ascending':'descending');
    };
  });
  render();
})();
</script>
</body></html>
"""


@app.get("/")
def index():
    files = list_files()
    return render_template_string(
        PAGE, files=files, need_pw=PROTECT_UPLOAD, title=APP_TITLE, max_mb=MAX_UPLOAD_MB,
        count=len(files), total=human(sum(f["bytes"] for f in files)))


@app.post("/upload")
def upload():
    if PROTECT_UPLOAD:
        ip = client_ip()
        if locked_out(ip):
            return "Too many wrong passwords. Try again later.", 429
        if not password_ok(request.form.get("password", "")):
            _fails.setdefault(ip, []).append(time.time())
            return "Wrong upload password.", 403
        _fails.pop(ip, None)
    saved, skipped = [], []
    for f in request.files.getlist("files"):
        name = secure_filename(f.filename or "")
        if not name:
            skipped.append(f.filename or "(empty)")
            continue
        path = unique_path(name)
        f.save(path)
        os.chmod(path, 0o644)
        saved.append(os.path.basename(path))
    if saved:
        flash(f"Uploaded: {', '.join(saved)}")
    if skipped:
        flash(f"Skipped invalid names: {', '.join(skipped)}")
    return redirect(url_for("index"))


@app.get("/download/<path:filename>")
def download(filename):
    # send_from_directory blocks path traversal; also refuse sub-paths/hidden files
    if "/" in filename or filename == SELF_NAME or (filename.startswith(".") and not SHOW_HIDDEN):
        abort(404)
    return send_from_directory(SHARE_DIR, filename, as_attachment=True)


@app.errorhandler(413)
def too_large(_):
    return f"File too large (limit {MAX_MB} MB).", 413


if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
