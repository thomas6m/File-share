#!/usr/bin/env python3
"""
Simple file share with folders: upload, download and create folders only
(no delete, no overwrite, no rename).
"""
import os
import sys
import hmac
import time
import re
import json
import hashlib
import secrets
import sqlite3
from contextlib import closing
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
from flask import (Flask, request, redirect, url_for, flash,
                   send_from_directory, render_template_string, Response, abort, session)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
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
APP_TITLE     = "FileNest"         # name shown in the page header and browser tab
APP_TAGLINE   = "Your files. Your pages. One place."   # line under the name in the header
PAGE_MAX_WIDTH = "100%"            # page width cap: "100%" = fill the window, or e.g. "1400px" / "90vw"
MAX_FOLDER_DEPTH = 8              # how many folder levels deep users can create
PAGES_ENABLED = True               # host static HTML pages
PAGES_LOGIN   = "shared"           # "shared"   = sign in with the same shared password as uploads, plus a display name
                                   #              (shown as "Uploaded by"; everyone signed in sees every page)
                                   # "accounts" = personal accounts from manage_users.py, with per-user and per-group
                                   #              viewing and a trusted "Uploaded by"
PAGES_DIR     = ""                 # pages and their metadata; "" = <current working dir>/pages
USERS_FILE    = ""                 # user accounts; "" = <SECRETS_DIR>/users.json
PAGE_MAX_MB   = 20                 # max size of one HTML page, in MB
PAGE_SANDBOX  = True               # run hosted pages in an isolated sandbox (recommended; see README)
SESSION_HOURS = 8                  # how long a page sign-in lasts
COOKIE_SECURE = False              # set True when the app is served over HTTPS
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
PAGES_ENABLED    = env_bool("PAGES_ENABLED", PAGES_ENABLED)
PAGES_LOGIN      = os.environ.get("PAGES_LOGIN", PAGES_LOGIN).strip().lower()
if PAGES_LOGIN not in ("shared", "accounts"):
    sys.exit('[FATAL] PAGES_LOGIN must be "shared" or "accounts".')
SHARED_MODE      = PAGES_ENABLED and PAGES_LOGIN == "shared"
PAGE_SANDBOX     = env_bool("PAGE_SANDBOX", PAGE_SANDBOX)
COOKIE_SECURE    = env_bool("COOKIE_SECURE", COOKIE_SECURE)
PAGE_MAX_MB      = int(os.environ.get("PAGE_MAX_MB", PAGE_MAX_MB))
SESSION_HOURS    = float(os.environ.get("SESSION_HOURS", SESSION_HOURS))
PAGES_DIR        = os.path.abspath(os.environ.get("PAGES_DIR") or PAGES_DIR or os.path.join(os.getcwd(), "pages"))
USERS_FILE       = Path(os.environ.get("USERS_FILE") or USERS_FILE or SECRETS_DIR / "users.json")
PAGE_FILES_DIR   = os.path.join(PAGES_DIR, "files")
PAGES_DB         = os.path.join(PAGES_DIR, "pages.db")
PAGE_PREFIXES    = ("/pages", "/p/", "/login", "/logout")   # routes that use user accounts, not the shared password
SESSION_KEY_FILE = SECRETS_DIR / ".session.key"
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
                 f"Run the encryption script first. (The password is needed while PROTECT_DOWNLOAD, PROTECT_UPLOAD "
                 f"or the shared Pages login is on.)")


PASSWORD = load_password() if (PROTECT_DOWNLOAD or PROTECT_UPLOAD or SHARED_MODE) else None
if PROTECT_DOWNLOAD and not USER:
    sys.exit("[FATAL] PROTECT_DOWNLOAD is on but AUTH_USER is empty.")
print(f"[fileshare] download protected: {PROTECT_DOWNLOAD} | upload protected: {PROTECT_UPLOAD}",
      file=sys.stderr)

os.makedirs(SHARE_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_MB * 1024 * 1024


def _session_secret():
    """Random key stored in the secrets folder, shared by all gunicorn workers.
    Sign-in sessions are signed with it, so it must stay private."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    try:
        return SESSION_KEY_FILE.read_text().strip()
    except OSError:
        pass
    try:
        os.makedirs(SECRETS_DIR, mode=0o700, exist_ok=True)
        tmp = f"{SESSION_KEY_FILE}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_hex(32))
        try:
            os.link(tmp, SESSION_KEY_FILE)      # atomic: only one worker wins
        except FileExistsError:
            pass
        finally:
            os.unlink(tmp)
        return SESSION_KEY_FILE.read_text().strip()
    except OSError as e:
        if PAGES_ENABLED:
            sys.exit(f"[FATAL] Cannot create the session key in {SECRETS_DIR}: {e}\n"
                     f"Fix the folder permissions or set the SECRET_KEY environment variable.")
        # file-share only: the session just carries flash messages, a derived key is enough
        return hashlib.sha256(b"fileshare-session:" + SHARE_DIR.encode()).hexdigest()


app.secret_key = _session_secret()
app.config.update(
    SESSION_COOKIE_NAME="fileshare_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)
app.jinja_env.globals["app_tagline"] = APP_TAGLINE


# ---------- optional basic auth ----------
@app.before_request
def check_auth():
    if request.path.startswith(PAGE_PREFIXES):
        if not PAGES_ENABLED:
            abort(404)
        return          # hosted pages use user accounts and their own sign-in page
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


def unique_path(directory, name):
    """Never overwrite an existing file; add a timestamp suffix instead."""
    path = os.path.join(directory, name)
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(name)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    n = 0
    while True:
        suffix = f"_{stamp}" + (f"_{n}" if n else "")
        path = os.path.join(directory, f"{base}{suffix}{ext}")
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


def clean_rel(rel):
    """Validate a user-supplied relative path (folder or file). 404 on anything odd."""
    rel = (rel or "").strip("/")
    if not rel:
        return ""
    parts = rel.split("/")
    for seg in parts:
        if (not seg or seg in (".", "..") or "\\" in seg or "\x00" in seg
                or (seg.startswith(".") and not SHOW_HIDDEN)):
            abort(404)
    return "/".join(parts)


def resolve_dir(rel):
    """Return (clean relative path, absolute path) of an existing folder inside SHARE_DIR."""
    rel = clean_rel(rel)
    root = os.path.realpath(SHARE_DIR)
    full = os.path.realpath(os.path.join(root, rel))
    if full != root and not full.startswith(root + os.sep):
        abort(404)
    if not os.path.isdir(full):
        abort(404)
    return rel, full


def dir_stats(path, limit=20000):
    """(direct item count, total bytes of all files inside, truncated?) for a folder.
    Symlinks and hidden entries are skipped; counting stops after `limit` entries."""
    items = size = seen = 0
    stack, top = [path], True
    while stack:
        cur = stack.pop()
        try:
            it = list(os.scandir(cur))
        except OSError:
            continue
        for e in it:
            if (e.name.startswith(".") and not SHOW_HIDDEN) or e.is_symlink():
                continue
            if top:
                items += 1
            seen += 1
            if seen > limit:
                return items, size, True
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append(e.path)
                elif e.is_file(follow_symlinks=False):
                    size += e.stat(follow_symlinks=False).st_size
            except OSError:
                pass
        top = False
    return items, size, False


def list_dir(full, rel):
    """Folders first (A-Z), then files (newest first). Symlinks and hidden entries are skipped."""
    dirs, files = [], []
    for e in os.scandir(full):
        if (e.name.startswith(".") and not SHOW_HIDDEN) or e.is_symlink():
            continue
        child = f"{rel}/{e.name}" if rel else e.name
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        if e.is_dir(follow_symlinks=False):
            n_items, dsize, partial = dir_stats(e.path)
            dirs.append({"name": e.name, "rel": child, "is_dir": True, "n_items": n_items,
                         "bytes": dsize, "size": ("\u2265 " if partial else "") + human(dsize),
                         "kind": "folder", "ext": "", "mtime": mtime, "ts": st.st_mtime})
        elif e.is_file(follow_symlinks=False):
            if not rel and e.name == SELF_NAME:
                continue
            kind, ext = file_kind(e.name)
            files.append({"name": e.name, "rel": child, "is_dir": False, "n_items": 0,
                          "bytes": st.st_size, "size": human(st.st_size),
                          "kind": kind, "ext": ext, "mtime": mtime, "ts": st.st_mtime})
    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["ts"], reverse=True)
    return dirs + files


def check_password():
    """Return an error response if the upload password is required and wrong, else None."""
    if not PROTECT_UPLOAD:
        return None
    ip = client_ip()
    if locked_out(ip):
        return "Too many wrong passwords. Try again later.", 429
    if not password_ok(request.form.get("password", "")):
        _fails.setdefault(ip, []).append(time.time())
        return "Wrong upload password.", 403
    _fails.pop(ip, None)
    return None


# ---------- routes: browse, download, upload, mkdir (there is no delete or rename route) ----------
HEAD = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ ptitle or title }}</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Crect width='24' height='24' rx='6' fill='%232DD4BF'/%3E%3Cpath d='M5 9.5c1.6-1.4 4-2.2 7-2.2s5.4.8 7 2.2M4 13c1.8-1.5 4.4-2.4 8-2.4s6.2.9 8 2.4M6.5 17c1.4-1.1 3.2-1.7 5.5-1.7s4.1.6 5.5 1.7' fill='none' stroke='%230B2236' stroke-width='1.8' stroke-linecap='round'/%3E%3C/svg%3E">
<style>"""

CSS_BASE = r"""
  :root{
    --bg:#EDF1F4; --panel:#FFFFFF; --soft:#F5F7F9; --ink:#15212B; --mut:#586979; --line:#D6DDE3;
    --acc:#0B6E69; --acc-ink:#FFFFFF; --acc-soft:#DCEEEB;
    --bad:#A32A24; --bad-bg:#FBEDEC; --ok:#0B6E69; --ok-bg:#E3F2EF;
    --b-l:92%; --b-c:30%; --b-s:60%;
    --maxw:{{ max_w }};
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
  .wrap{max-width:var(--maxw);margin:0 auto;padding:0 clamp(16px,2.5vw,40px)}
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
  .grid{display:grid;grid-template-columns:clamp(320px,26vw,440px) minmax(0,1fr);gap:20px;align-items:start;margin:24px auto 48px}
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
  td.num{white-space:nowrap}
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
  .crumbs{font-size:15px;line-height:1.4}
  .crumbs nav{display:flex;flex-wrap:wrap;align-items:center;gap:2px 8px}
  .crumbs a{color:var(--acc);text-decoration:none;font-weight:600}
  .crumbs a:hover{text-decoration:underline;text-underline-offset:3px}
  .crumbs .sep{color:var(--mut);font-weight:400}
  .crumbs [aria-current]{font-weight:650;overflow-wrap:anywhere}
  .badge[data-k="folder"]{background:var(--acc-soft);color:var(--acc)}
  .badge svg{width:20px;height:20px;stroke:currentColor}
  a.fname{color:var(--ink);text-decoration:none;font-weight:650}
  a.fname:hover{color:var(--acc);text-decoration:underline;text-underline-offset:3px}
  .dest{margin:0 0 12px}
  .dest strong{color:var(--ink);font-weight:650;overflow-wrap:anywhere}
  .newf{display:inline-flex;align-items:center;gap:6px;height:36px;padding:0 12px;border:1px solid var(--line);border-radius:8px;
        background:var(--panel);cursor:pointer;font-weight:550;font-size:13.5px;white-space:nowrap}
  .newf:hover{border-color:var(--acc);color:var(--acc)}
  .newf svg{width:15px;height:15px;stroke:currentColor}
  dialog{width:min(440px,92vw);padding:20px;border:1px solid var(--line);border-radius:12px;background:var(--panel);color:var(--ink)}
  dialog::backdrop{background:rgba(8,14,20,.55)}
  dialog h2{font-size:17px}
  dialog input[type=text],dialog input[type=password]{width:100%;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
  dialog input:focus-visible{outline-offset:0}
  .row{display:flex;gap:10px;margin-top:16px}
  .row .btn{margin-top:0;flex:1}
  .btn.ghost{background:var(--soft);color:var(--ink);border:1px solid var(--line)}
  @media (max-width:640px){.hide-sm{display:none}.search input{width:100%}.search{flex:1}}
  @media (prefers-reduced-motion:reduce){*{transition:none!important}}
"""

CSS_EXTRA = r"""
  /* ---- header nav + account ---- */
  .top .left{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
  .top .right{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
  .tabs{display:flex;gap:4px}
  .tabs a{padding:7px 14px;border-radius:8px;color:var(--mut);text-decoration:none;font-weight:600;font-size:14px}
  .tabs a:hover{background:var(--soft);color:var(--ink)}
  .tabs a[aria-current]{background:var(--acc-soft);color:var(--acc)}
  .who{display:inline-flex;align-items:center;gap:10px;font-size:13px;color:var(--mut);flex-wrap:wrap}
  .who strong{color:var(--ink)}
  .who form{margin:0}

  /* ---- forms ---- */
  .fld{width:100%;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);color:var(--ink)}
  .fld:focus-visible{outline-offset:0}
  .fld[aria-invalid="true"]{border-color:var(--bad)}
  input[type=file].fld{height:auto;padding:8px;cursor:pointer}
  input[type=file]::file-selector-button{margin-right:10px;padding:6px 12px;border:1px solid var(--line);border-radius:6px;background:var(--soft);color:var(--ink);cursor:pointer;font:inherit;font-size:13px}
  .req{color:var(--bad)}
  .ferr{margin:6px 0 0;color:var(--bad);font-size:13px}
  .hint{margin:6px 0 0;font-size:12.5px;color:var(--mut)}
  .sr{position:absolute;left:-9999px}
  pre.code{margin:8px 0 0;padding:10px 12px;background:var(--soft);border:1px solid var(--line);border-radius:8px;font:13px ui-monospace,SFMono-Regular,Consolas,monospace;overflow-x:auto}
  .login{max-width:420px;margin:56px auto}

  /* ---- pages list ---- */
  .pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
  .pill.ok{background:var(--ok-bg);color:var(--ok)}
  .pill.off{background:var(--soft);color:var(--mut);border:1px solid var(--line)}
  .chips{display:flex;flex-wrap:wrap;gap:8px;padding:14px 18px;border-bottom:1px solid var(--line)}
  .chip{border:1px solid var(--line);background:var(--panel);border-radius:999px;padding:5px 12px;font-size:13px;cursor:pointer;color:var(--ink)}
  .chip:hover{border-color:var(--acc)}
  .chip[aria-pressed="true"]{background:var(--acc);color:var(--acc-ink);border-color:var(--acc)}
  .chip span{opacity:.7;margin-left:6px}
  .stored{font-size:12.5px;color:var(--mut);overflow-wrap:anywhere;margin-top:2px}
  .vw{display:flex;flex-wrap:wrap;gap:4px}
  .tag{display:inline-block;padding:1px 8px;border-radius:6px;background:var(--soft);border:1px solid var(--line);font-size:12.5px;overflow-wrap:anywhere}
  .act{display:flex;gap:8px;justify-content:flex-end;align-items:center;flex-wrap:wrap}
  .act form{margin:0}
  .mini{height:32px;padding:0 12px;border:1px solid var(--line);border-radius:8px;background:var(--panel);cursor:pointer;font-size:13.5px;font-weight:550;white-space:nowrap}
  .mini:hover{border-color:var(--acc);color:var(--acc)}
  td.top-a{vertical-align:top}
  @media (max-width:1100px){.hide-md{display:none}}

  /* ---- FileNest header: navy bar, teal mark ---- */
  .top{background:#0F2A43;border-bottom:1px solid #1B4163}
  .top h1{color:#FFFFFF}
  .top .brand p{color:#B7C6D8}
  .top .logo{background:#2DD4BF}
  .top .logo svg{stroke:#0B2236;stroke-width:1.8}
  .top .tabs a{color:#B7C6D8}
  .top .tabs a:hover{background:rgba(255,255,255,.09);color:#FFFFFF}
  .top .tabs a[aria-current]{background:rgba(45,212,191,.16);color:#5EEAD4}
  .top .lock{background:rgba(255,255,255,.06);border-color:rgba(255,255,255,.2);color:#B7C6D8}
  .top .who{color:#B7C6D8}
  .top .who strong{color:#FFFFFF}
  .top .who .link{color:#5EEAD4}
  .top .pill.off{background:rgba(255,255,255,.08);border-color:rgba(255,255,255,.2);color:#B7C6D8}
  .top :focus-visible{outline-color:#5EEAD4}
"""

HEADER = r"""<header class="top"><div class="wrap">
  <div class="left">
    <div class="brand">
      <div class="logo" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-linecap="round" stroke-linejoin="round"><path d="M5 9.5c1.6-1.4 4-2.2 7-2.2s5.4.8 7 2.2M4 13c1.8-1.5 4.4-2.4 8-2.4s6.2.9 8 2.4M6.5 17c1.4-1.1 3.2-1.7 5.5-1.7s4.1.6 5.5 1.7"/></svg></div>
      <div><h1>{{ title }}</h1><p>{{ app_tagline }}</p></div>
    </div>
    {% if pages_on %}
    <nav class="tabs" aria-label="Sections">
      <a href="{{ url_for('browse', p='') }}"{% if nav == 'files' %} aria-current="page"{% endif %}>Files</a>
      <a href="{{ url_for('pages') }}"{% if nav == 'pages' %} aria-current="page"{% endif %}>Pages</a>
    </nav>
    {% endif %}
  </div>
  <div class="right">
    {% if user %}
    <div class="who">Signed in as <strong>{{ user.name }}</strong>{% if user.role == 'admin' and not user.shared %}<span class="pill off">admin</span>{% endif %}
      <form method="post" action="{{ url_for('logout') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><button class="link" type="submit">Sign out</button></form></div>
    {% endif %}
    <div class="lock" title="{{ badge_hint or 'Files can be added and downloaded. They can\u2019t be deleted or overwritten.' }}">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
      {{ badge or 'Read-only: upload and download' }}
    </div>
  </div>
</div></header>
"""

PAGE_BODY = r"""</style></head>
<body>
<!--HEADER-->

<main class="wrap grid">
  <section class="panel upload" aria-labelledby="uh">
    <div class="phead"><h2 id="uh">Upload files</h2><span class="sub">Up to {{ max_mb }} MB per upload</span></div>
    <div class="pbody">
      <p class="dest sub">Uploading to <strong>{{ dest_label }}</strong></p>
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
      <div>
        <h2 id="lh" class="crumbs"><nav aria-label="Breadcrumb">{% for c in crumbs %}{% if not loop.last %}<a href="{{ url_for('browse', p=c.rel) }}">{{ c.name }}</a><span class="sep" aria-hidden="true">/</span>{% else %}<span aria-current="page">{{ c.name }}</span>{% endif %}{% endfor %}</nav></h2>
        <span class="sub num" id="stats">{{ nd }} folder{{ '' if nd == 1 else 's' }} · {{ nf }} file{{ '' if nf == 1 else 's' }} · {{ total }}</span>
      </div>
      <div class="tools">
        <button type="button" class="newf" id="newf"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>New folder</button>
        <div class="search">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
          <input id="q" type="search" placeholder="Filter this folder" aria-label="Filter this folder by name">
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
        {% for f in entries %}
        <tr data-name="{{ f.name|lower }}" data-dir="{{ 1 if f.is_dir else 0 }}" data-size="{{ f.bytes }}" data-ts="{{ f.ts }}">
          {% if f.is_dir %}
          <td><div class="file"><span class="badge" data-k="folder" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg></span><div><a class="fname" href="{{ url_for('browse', p=f.rel) }}">{{ f.name }}</a><div class="sub">{{ f.n_items }} item{{ '' if f.n_items == 1 else 's' }}</div></div></div></td>
          <td class="r num">{{ f.size }}</td>
          <td class="hide-sm num">{{ f.mtime }}</td>
          <td class="r"><a class="dl" href="{{ url_for('browse', p=f.rel) }}" aria-label="Open folder {{ f.name }}">Open</a></td>
          {% else %}
          <td><div class="file"><span class="badge" data-k="{{ f.kind }}" aria-hidden="true">{{ f.ext }}</span><span class="fname">{{ f.name }}</span></div></td>
          <td class="r num">{{ f.size }}</td>
          <td class="hide-sm num">{{ f.mtime }}</td>
          <td class="r"><a class="dl" href="{{ url_for('download', filepath=f.rel) }}" aria-label="Download {{ f.name }}">
            <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"/></svg>Download</a></td>
          {% endif %}
        </tr>
        {% endfor %}
        <tr class="empty" id="empty" {% if entries %}hidden{% endif %}><td colspan="4" id="emptytxt">{{ 'This folder is empty.' if cur else 'Nothing here yet.' }} Drop files into the upload panel or create a folder.</td></tr>
      </tbody>
    </table></div>
  </section>
</main>

<dialog id="mk" aria-labelledby="mkh">
  <form id="mkform" novalidate>
    <h2 id="mkh">New folder</h2>
    <p class="sub">It will be created in <strong>{{ dest_label }}</strong>. Folders can’t be renamed or deleted afterwards.</p>
    <label class="f" for="mkname">Folder name</label>
    <input id="mkname" type="text" maxlength="100" autocomplete="off" spellcheck="false">
    <p class="sub" style="margin:6px 0 0">Letters, numbers, dashes, underscores and dots. Spaces become underscores.</p>
    {% if need_pw %}
    <label class="f" for="mkpw">Upload password</label>
    <input id="mkpw" type="password" autocomplete="off" spellcheck="false">
    {% endif %}
    <div id="mkerr" class="note err" role="alert" hidden></div>
    <div class="row">
      <button type="button" class="btn ghost" id="mkcancel">Cancel</button>
      <button type="submit" class="btn" id="mkgo">Create folder</button>
    </div>
  </form>
</dialog>

<script>
(function(){
  var $ = function(id){return document.getElementById(id)};
  var CUR = {{ cur|tojson }}, MAX = {{ max_mb }} * 1048576, NEED_PW = {{ 'true' if need_pw else 'false' }};
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
    var fd=new FormData(); queue.forEach(function(f){fd.append('files',f)}); fd.append('path',CUR);
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
        if(a.dataset.dir!==c.dataset.dir) return a.dataset.dir==='1'?-1:1;
        var x=a.dataset[k], y=c.dataset[k];
        if(k!=='name'){x=parseFloat(x);y=parseFloat(y);return (x-y)*dir}
        return x.localeCompare(y)*dir;
      }).forEach(function(r){tbody.insertBefore(r,empty)});
      Array.prototype.forEach.call(document.querySelectorAll('th[aria-sort]'),function(th){th.setAttribute('aria-sort','none')});
      b.parentNode.setAttribute('aria-sort',dir===1?'ascending':'descending');
    };
  });
  render();

  /* new folder dialog */
  var mk=$('mk'), mkname=$('mkname'), mkpw=$('mkpw'), mkerr=$('mkerr'), mkgo=$('mkgo');
  function mkFail(t){mkerr.textContent=t;mkerr.hidden=false;mkgo.disabled=false}
  $('newf').onclick=function(){
    mkerr.hidden=true; mkname.value=''; mkgo.disabled=false;
    if(mkpw&&pw) mkpw.value=pw.value;
    mk.showModal(); mkname.focus();
  };
  $('mkcancel').onclick=function(){mk.close()};
  $('mkform').onsubmit=function(ev){
    ev.preventDefault();
    var name=mkname.value.trim();
    if(!name){mkFail('Enter a name for the folder.');mkname.focus();return}
    if(NEED_PW && !mkpw.value){mkFail('Enter the upload password to continue.');mkpw.focus();return}
    var fd=new FormData(); fd.append('path',CUR); fd.append('name',name);
    if(NEED_PW) fd.append('password',mkpw.value);
    mkerr.hidden=true; mkgo.disabled=true;
    fetch('{{ url_for("mkdir") }}',{method:'POST',body:fd,credentials:'same-origin'})
      .then(function(r){return r.text().then(function(t){return {ok:r.ok,t:t}})})
      .then(function(res){if(res.ok){location.reload()}else{mkFail(res.t||'The folder could not be created.')}})
      .catch(function(){mkFail('The connection dropped. Check your network and try again.')});
  };
})();
</script>
</body></html>
"""

PAGE = (HEAD + "/*CSS*/" + PAGE_BODY).replace("/*CSS*/", CSS_BASE + CSS_EXTRA).replace("<!--HEADER-->", HEADER)


@app.get("/", defaults={"p": ""})
@app.get("/tree/<path:p>")
def browse(p):
    rel, full = resolve_dir(p)
    entries = list_dir(full, rel)
    crumbs, acc = [{"name": "Home", "rel": ""}], []
    for seg in (rel.split("/") if rel else []):
        acc.append(seg)
        crumbs.append({"name": seg, "rel": "/".join(acc)})
    nd = sum(1 for e in entries if e["is_dir"])
    nf = len(entries) - nd
    user = current_user() if PAGES_ENABLED else None
    return render_template_string(
        PAGE, user=user, csrf=csrf_token() if user else "", pages_on=PAGES_ENABLED, nav="files",
        entries=entries, cur=rel, crumbs=crumbs, nd=nd, nf=nf,
        dest_label=" / ".join(c["name"] for c in crumbs),
        total=human(sum(e["bytes"] for e in entries)),
        need_pw=PROTECT_UPLOAD, title=APP_TITLE, max_mb=MAX_UPLOAD_MB, max_w=PAGE_MAX_WIDTH)


@app.post("/upload")
def upload():
    bad = check_password()
    if bad:
        return bad
    rel, full = resolve_dir(request.form.get("path", ""))
    saved, skipped = [], []
    for f in request.files.getlist("files"):
        name = secure_filename(f.filename or "")
        if not name:
            skipped.append(f.filename or "(empty)")
            continue
        path = unique_path(full, name)
        f.save(path)
        os.chmod(path, 0o644)
        saved.append(os.path.basename(path))
    where = f" to {rel}" if rel else ""
    if saved:
        flash(f"Uploaded{where}: {', '.join(saved)}")
    if skipped:
        flash(f"Skipped invalid names: {', '.join(skipped)}")
    return redirect(url_for("browse", p=rel))


@app.post("/mkdir")
def mkdir():
    bad = check_password()
    if bad:
        return bad
    rel, full = resolve_dir(request.form.get("path", ""))
    raw = (request.form.get("name") or "").strip()
    name = secure_filename(raw)
    if not name or len(name) > 100:
        return "Enter a folder name using letters, numbers, dashes, underscores or dots.", 400
    depth = (rel.count("/") + 1 if rel else 0) + 1
    if depth > MAX_FOLDER_DEPTH:
        return f"Folders can be nested up to {MAX_FOLDER_DEPTH} levels deep.", 400
    try:
        os.mkdir(os.path.join(full, name), 0o750)
    except FileExistsError:
        return f"\u201c{name}\u201d already exists in this folder.", 409
    except OSError as e:
        return f"Could not create the folder ({e.strerror}).", 500
    flash(f"Created folder {name}" + (f" (name adjusted from \u201c{raw}\u201d)" if name != raw else ""))
    return "", 204


@app.get("/download/<path:filepath>")
def download(filepath):
    rel = clean_rel(filepath)
    parent, name = os.path.split(rel)
    if not name or (not parent and name == SELF_NAME):
        abort(404)
    _, full = resolve_dir(parent)
    target = os.path.join(full, name)
    if os.path.islink(target) or not os.path.isfile(target):
        abort(404)
    return send_from_directory(full, name, as_attachment=True)


# ---------- templates for sign-in, pages and messages (share CSS + header with the file page) ----------
_TOP = HEAD + "/*CSS*/</style></head>\n<body>\n<!--HEADER-->\n"


def _build(t):
    return t.replace("/*CSS*/", CSS_BASE + CSS_EXTRA).replace("<!--HEADER-->", HEADER)


LOGIN_TMPL = _build(_TOP + r"""
<main class="wrap">
  <section class="panel login" aria-labelledby="lh">
    <div class="phead"><h2 id="lh">Sign in</h2><span class="sub">to view and publish pages</span></div>
    <div class="pbody">
    {% if not configured %}
      <p class="note err" role="alert" style="margin:0">No user accounts exist yet.</p>
      <p class="sub" style="margin:14px 0 0">An administrator creates accounts on the server:</p>
      <pre class="code">python3 manage_users.py add yourname --role admin</pre>
    {% else %}
      <form method="post" action="{{ url_for('login') }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <input type="hidden" name="next" value="{{ nxt }}">
        <label class="f" for="u" style="margin-top:0">{{ 'Your name' if shared else 'Username' }}</label>
        <input class="fld" id="u" name="username" type="text" autocomplete="{{ 'name' if shared else 'username' }}" autocapitalize="none" spellcheck="false" required autofocus maxlength="32" value="{{ username }}">
        {% if shared %}<p class="hint">Shown as “Uploaded by” on the pages you publish.</p>{% endif %}
        <label class="f" for="p">Password</label>
        <input class="fld" id="p" name="password" type="password" autocomplete="current-password" required>
        {% if error %}<div class="note err" role="alert">{{ error }}</div>{% endif %}
        <button class="btn" type="submit">Sign in</button>
      </form>
    {% endif %}
    </div>
  </section>
</main>
</body></html>
""")

MSG_TMPL = _build(_TOP + r"""
<main class="wrap">
  <section class="panel login" aria-labelledby="lh">
    <div class="phead"><h2 id="lh">{{ heading }}</h2></div>
    <div class="pbody">
      <p style="margin:0 0 16px">{{ text }}</p>
      <a class="dl" href="{{ url_for('pages') }}">Back to pages</a>
    </div>
  </section>
</main>
</body></html>
""")

PAGES_TMPL = _build(_TOP + r"""
<main class="wrap grid">
  <section class="panel upload" aria-labelledby="ph">
    <div class="phead"><h2 id="ph">Publish a page</h2><span class="sub">Up to {{ page_mb }} MB</span></div>
    <div class="pbody">
      {% if errors.form %}<div class="note err" role="alert" style="margin:0 0 14px">{{ errors.form }}</div>{% endif %}
      <form method="post" action="{{ url_for('publish') }}" enctype="multipart/form-data" id="pf">
        <input type="hidden" name="csrf" value="{{ csrf }}">

        <label class="f" for="title" style="margin-top:0">Title <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="title" name="title" type="text" required maxlength="120" autocomplete="off" value="{{ form.title }}"{% if errors.title %} aria-invalid="true" aria-describedby="e-title"{% endif %}>
        {% if errors.title %}<p class="ferr" id="e-title">{{ errors.title }}</p>{% endif %}

        <label class="f" for="category">Category <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="category" name="category" type="text" required maxlength="60" autocomplete="off" list="cats" value="{{ form.category }}"{% if errors.category %} aria-invalid="true" aria-describedby="e-cat"{% endif %}>
        <datalist id="cats">{% for c, n in cats %}<option value="{{ c }}">{% endfor %}</datalist>
        {% if errors.category %}<p class="ferr" id="e-cat">{{ errors.category }}</p>{% endif %}

        {% if not shared %}
        <label class="f" for="viewers">Who can view</label>
        <input class="fld" id="viewers" name="viewers" type="text" autocomplete="off" spellcheck="false" placeholder="Everyone signed in" value="{{ form.viewers }}"{% if errors.viewers %} aria-invalid="true" aria-describedby="e-view"{% endif %}>
        {% if errors.viewers %}<p class="ferr" id="e-view">{{ errors.viewers }}</p>{% endif %}
        <p class="hint">Leave empty for everyone signed in, or list usernames and <code>@groups</code> separated by commas, for example <code>alice, @ops</code>.{% if groups %} Groups: {% for g in groups %}@{{ g }}{{ ', ' if not loop.last }}{% endfor %}.{% endif %} You and admins can always open it.</p>
        {% endif %}

        <label class="f" for="file">HTML file <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="file" name="file" type="file" accept=".html,.htm,text/html" required{% if errors.file %} aria-invalid="true" aria-describedby="e-file"{% endif %}>
        {% if errors.file %}<p class="ferr" id="e-file">{{ errors.file }}</p>{% endif %}
        <p class="ferr" id="e-size" hidden></p>

        {% if need_pw %}
        <label class="f" for="pw">Upload password <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="pw" name="password" type="password" required autocomplete="off"{% if errors.password %} aria-invalid="true" aria-describedby="e-pw"{% endif %}>
        {% if errors.password %}<p class="ferr" id="e-pw">{{ errors.password }}</p>{% endif %}
        <p class="hint">The same password used to upload files.</p>
        {% endif %}

        <button class="btn" type="submit" id="pub">Publish</button>
      </form>
      <p class="rule">Use one self-contained .html file with its CSS, scripts and images inline. Published pages can’t be replaced or deleted. Publish a new page to change one, and {{ 'unpublish a page' if shared else 'unpublish a page you own' }} at any time.{% if sandbox %} Scripts in pages run in an isolated sandbox, so pages can’t use cookies or local storage.{% endif %}</p>
    </div>
  </section>

  <section class="panel" aria-labelledby="lh">
    <div class="phead">
      <div><h2 id="lh">Pages</h2><span class="sub num" id="stats">{{ rows|length }} page{{ '' if rows|length == 1 else 's' }} · {{ cats|length }} categor{{ 'y' if cats|length == 1 else 'ies' }}</span></div>
      <div class="tools"><div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        <input id="q" type="search" placeholder="Search pages" aria-label="Search pages by title, category or author">
      </div></div>
    </div>
    {% with m = get_flashed_messages() %}{% if m %}<div class="flash">{% for x in m %}<p class="note ok" role="status">{{ x }}</p>{% endfor %}</div>{% endif %}{% endwith %}
    {% if cats %}
    <div class="chips" id="chips" role="group" aria-label="Filter by category">
      <button type="button" class="chip" data-cat="" aria-pressed="true">All<span class="num">{{ rows|length }}</span></button>
      {% for c, n in cats %}<button type="button" class="chip" data-cat="{{ c }}" aria-pressed="false">{{ c }}<span class="num">{{ n }}</span></button>{% endfor %}
    </div>
    {% endif %}
    <div class="scroll"><table>
      <thead><tr>
        <th scope="col" aria-sort="none"><button type="button" data-key="title">Title</button></th>
        <th scope="col" aria-sort="none"><button type="button" data-key="cat">Category</button></th>
        <th scope="col" class="hide-md" aria-sort="none"><button type="button" data-key="by">Uploaded by</button></th>
        <th scope="col" class="hide-sm" aria-sort="descending"><button type="button" data-key="ts">Uploaded</button></th>
        <th scope="col">Status</th>
        {% if not shared %}<th scope="col" class="hide-md">Who can view</th>{% endif %}
        <th scope="col" class="r"><span class="sr">Actions</span></th>
      </tr></thead>
      <tbody id="rows">
        {% for r in rows %}
        <tr data-title="{{ r.title|lower }}" data-cat="{{ r.category }}" data-by="{{ r.uploaded_by }}" data-ts="{{ r.ts }}">
          <td><a class="fname" href="{{ url_for('view_page', pid=r.id) }}" target="_blank" rel="noopener">{{ r.title }}</a>
              <div class="stored" title="Stored filename">{{ r.stored_filename }} · {{ r.size }}</div></td>
          <td><span class="tag">{{ r.category }}</span></td>
          <td class="hide-md">{{ r.uploaded_by }}</td>
          <td class="num hide-sm">{{ r.uploaded }}</td>
          <td><span class="pill {{ 'ok' if r.published else 'off' }}">{{ 'Published' if r.published else 'Unpublished' }}</span></td>
          {% if not shared %}<td class="hide-md"><div class="vw">{% if r.everyone %}<span class="sub">Everyone signed in</span>{% else %}{% for v in r.viewers %}<span class="tag">{{ v }}</span>{% endfor %}{% endif %}</div></td>{% endif %}
          <td class="r"><div class="act">
            <a class="dl" href="{{ url_for('view_page', pid=r.id) }}" target="_blank" rel="noopener" aria-label="Open {{ r.title }}">Open</a>
            {% if r.can_manage %}
            <form method="post" action="{{ url_for('set_status', pid=r.id) }}">
              <input type="hidden" name="csrf" value="{{ csrf }}">
              <input type="hidden" name="status" value="{{ 'unpublished' if r.published else 'published' }}">
              <button class="mini" type="submit" aria-label="{{ 'Unpublish' if r.published else 'Publish' }} {{ r.title }}">{{ 'Unpublish' if r.published else 'Publish' }}</button>
            </form>
            {% endif %}
          </div></td>
        </tr>
        {% endfor %}
        <tr class="empty" id="empty" {% if rows %}hidden{% endif %}><td colspan="{{ 6 if shared else 7 }}" id="emptytxt">No pages yet. Publish the first one with the form.</td></tr>
      </tbody>
    </table></div>
  </section>
</main>

<script>
(function(){
  var $=function(i){return document.getElementById(i)};
  var tbody=$('rows'), empty=$('empty'), q=$('q'), cat='', key='ts', dir=-1, MAXB={{ page_mb }}*1048576;
  function rows(){return Array.prototype.slice.call(tbody.querySelectorAll('tr[data-title]'))}
  function apply(){
    var term=q.value.trim().toLowerCase(), shown=0, all=rows();
    all.forEach(function(r){
      var hay=r.dataset.title+' '+r.dataset.cat.toLowerCase()+' '+r.dataset.by;
      var ok=(!cat||r.dataset.cat===cat)&&(!term||hay.indexOf(term)!==-1);
      r.hidden=!ok; if(ok)shown++;
    });
    if(!all.length){empty.hidden=false}
    else{empty.hidden=shown>0; $('emptytxt').textContent='No pages match this filter.'}
  }
  q.addEventListener('input',apply);
  var chips=$('chips');
  if(chips){chips.addEventListener('click',function(e){
    var b=e.target.closest('.chip'); if(!b)return;
    Array.prototype.forEach.call(chips.querySelectorAll('.chip'),function(c){c.setAttribute('aria-pressed',c===b?'true':'false')});
    cat=b.dataset.cat; apply();
  })}
  Array.prototype.forEach.call(document.querySelectorAll('th button[data-key]'),function(b){
    b.onclick=function(){
      var k=b.dataset.key; dir=(key===k)?-dir:(k==='ts'?-1:1); key=k;
      rows().sort(function(a,c){
        var x=a.dataset[k], y=c.dataset[k];
        if(k==='ts'){return (parseFloat(x)-parseFloat(y))*dir}
        return String(x).toLowerCase().localeCompare(String(y).toLowerCase())*dir;
      }).forEach(function(r){tbody.insertBefore(r,empty)});
      Array.prototype.forEach.call(document.querySelectorAll('th[aria-sort]'),function(th){th.setAttribute('aria-sort','none')});
      b.parentNode.setAttribute('aria-sort',dir===1?'ascending':'descending');
    };
  });
  var file=$('file'), esz=$('e-size'), pub=$('pub');
  file.addEventListener('change',function(){
    var f=file.files[0];
    if(f && f.size>MAXB){esz.textContent='That file is '+(f.size/1048576).toFixed(1)+' MB. The limit is {{ page_mb }} MB.';esz.hidden=false;file.value=''}
    else{esz.hidden=true}
  });
  $('pf').addEventListener('submit',function(){pub.disabled=true;pub.textContent='Publishing\u2026'});
})();
</script>
</body></html>
""")


# ===================================================================
# Hosted HTML pages: accounts, publishing, per-user / per-group viewing
# ===================================================================
DUMMY_HASH = generate_password_hash("not-a-real-password")   # equalises login timing
SANDBOX_CSP = ("sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox "
               "allow-downloads allow-modals")
HTML_HINT = re.compile(rb"<\s*(!doctype|html|head|body|div|p|h[1-6]|table|svg|section|main|article|script|style)\b", re.I)
CATEGORY_RE = re.compile(r"[\w &/.\-]{1,60}")

_users_cache = {"mtime": None, "data": {}}


def load_users():
    """Accounts from users.json (made by manage_users.py). Re-read when the file changes."""
    try:
        mtime = USERS_FILE.stat().st_mtime
    except OSError:
        return {}
    if _users_cache["mtime"] != mtime:
        try:
            raw = json.loads(USERS_FILE.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        data = {}
        for name, u in (raw.get("users") or {}).items():
            data[name] = {"name": name, "hash": u.get("password_hash", ""),
                          "groups": sorted({str(g).lower() for g in u.get("groups", [])}),
                          "role": "admin" if u.get("role") == "admin" else "user"}
        _users_cache.update(mtime=mtime, data=data)
    return _users_cache["data"]


NAME_OK = re.compile(r"[\w .\-]{2,32}")


def current_user():
    name = session.get("user")
    if not name:
        return None
    if SHARED_MODE:
        if session.get("mode") != "shared":
            return None
        # one shared password: everyone signed in has the same rights, the name is only a label
        return {"name": name, "groups": [], "role": "admin", "shared": True}
    if session.get("mode") != "accounts":
        return None
    return load_users().get(name)


def csrf_token():
    if not session.get("csrf"):
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


def csrf_ok():
    sent = request.form.get("csrf", "").encode()
    good = session.get("csrf", "").encode()
    return bool(good) and hmac.compare_digest(sent, good)


def safe_next(url):
    return url if url.startswith("/") and not url.startswith("//") and "\\" not in url else ""


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            nxt = request.full_path.rstrip("?") if request.method == "GET" else url_for("pages")
            return redirect(url_for("login", next=nxt))
        return fn(*args, **kwargs)
    return wrapper


# ---------- metadata database (SQLite: safe with several gunicorn workers) ----------
def db():
    con = sqlite3.connect(PAGES_DB, timeout=15)
    con.row_factory = sqlite3.Row
    return con


def query(sql, args=()):
    with closing(db()) as con:
        return con.execute(sql, args).fetchall()


def execute(sql, args=()):
    with closing(db()) as con, con:
        return con.execute(sql, args).lastrowid


def init_pages():
    os.makedirs(PAGE_FILES_DIR, mode=0o750, exist_ok=True)
    execute("""CREATE TABLE IF NOT EXISTS pages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        stored_filename TEXT NOT NULL UNIQUE,
        original_filename TEXT,
        uploaded_by TEXT NOT NULL,
        uploaded_at REAL NOT NULL,
        status TEXT NOT NULL DEFAULT 'published',
        viewer_users TEXT NOT NULL DEFAULT '[]',
        viewer_groups TEXT NOT NULL DEFAULT '[]',
        size INTEGER NOT NULL DEFAULT 0)""")


def can_manage(row, user):
    return bool(user) and (user["role"] == "admin" or row["uploaded_by"] == user["name"])


def can_view(row, user):
    if not user:
        return False
    if can_manage(row, user):
        return True            # owner and admins can always open it (even when unpublished)
    if row["status"] != "published":
        return False
    vu, vg = json.loads(row["viewer_users"]), json.loads(row["viewer_groups"])
    if not vu and not vg:
        return True            # no restriction: every signed-in user
    return user["name"] in vu or bool(set(vg) & set(user["groups"]))


def page_view(row, user):
    vu, vg = json.loads(row["viewer_users"]), json.loads(row["viewer_groups"])
    return {"id": row["id"], "title": row["title"], "category": row["category"],
            "stored_filename": row["stored_filename"], "uploaded_by": row["uploaded_by"],
            "ts": row["uploaded_at"],
            "uploaded": time.strftime("%Y-%m-%d %H:%M", time.localtime(row["uploaded_at"])),
            "published": row["status"] == "published", "size": human(row["size"] or 0),
            "everyone": not (vu or vg), "viewers": vu + ["@" + g for g in vg],
            "can_manage": can_manage(row, user)}


def parse_viewers(text, users):
    """'alice, @ops' -> (['alice'], ['ops'], None). Empty or 'everyone' = no restriction."""
    toks = [t for t in re.split(r"[,;\s]+", (text or "").strip().lower()) if t]
    groups = {g for u in users.values() for g in u["groups"]}
    vu, vg, bad = [], [], []
    for t in toks:
        if t in ("everyone", "*", "all"):
            return [], [], None
        if t.startswith("@"):
            (vg if t[1:] in groups else bad).append(t[1:] if t[1:] in groups else t)
        else:
            (vu if t in users else bad).append(t)
    if bad:
        return [], [], "Unknown user or group: " + ", ".join(dict.fromkeys(bad)) + "."
    return list(dict.fromkeys(vu)), list(dict.fromkeys(vg)), None


def check_html(data):
    """Return an error message if `data` is not an acceptable HTML page, else None."""
    if not data.strip():
        return "The file is empty."
    if len(data) > PAGE_MAX_MB * 1024 * 1024:
        return f"The file is larger than {PAGE_MAX_MB} MB."
    if b"\x00" in data:
        return "That doesn\u2019t look like an HTML file."
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return "The file must be saved as UTF-8."
    if not HTML_HINT.search(data[:65536]):
        return "That doesn\u2019t look like an HTML page (no HTML tags found)."
    return None


def render_pages(errors=None, form=None, status=200):
    user = current_user()
    rows = [page_view(r, user) for r in query("SELECT * FROM pages ORDER BY uploaded_at DESC")
            if can_view(r, user)]
    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    cats = sorted(counts.items(), key=lambda kv: kv[0].lower())
    groups = sorted({g for u in load_users().values() for g in u["groups"]})
    return render_template_string(
        PAGES_TMPL, rows=rows, cats=cats, errors=errors or {}, groups=groups,
        form=form or {"title": "", "category": "", "viewers": ""},
        user=user, csrf=csrf_token(), sandbox=PAGE_SANDBOX, page_mb=PAGE_MAX_MB, need_pw=PROTECT_UPLOAD,
        shared=SHARED_MODE,
        title=APP_TITLE, max_w=PAGE_MAX_WIDTH, pages_on=True, nav="pages",
        ptitle=f"Pages \u00b7 {APP_TITLE}",
        badge="Pages are never deleted or replaced",
        badge_hint="Pages can be published and unpublished. They can\u2019t be deleted or replaced."), status


def msg_page(heading, text, status):
    user = current_user()
    return render_template_string(
        MSG_TMPL, heading=heading, text=text, user=user, csrf=csrf_token(),
        title=APP_TITLE, max_w=PAGE_MAX_WIDTH, pages_on=True, nav="pages",
        ptitle=f"{heading} \u00b7 {APP_TITLE}",
        badge="Pages are never deleted or replaced"), status


# ---------- routes: sign in / out ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    users = load_users()
    nxt = safe_next(request.values.get("next", ""))
    error, username, status = "", "", 200
    if request.method == "POST":
        ip = "login:" + client_ip()
        if SHARED_MODE:
            username = " ".join((request.form.get("username") or "").split())
        else:
            username = (request.form.get("username") or "").strip().lower()
        if not csrf_ok():
            error, status = "Your session expired. Please try again.", 400
        elif locked_out(ip):
            error, status = "Too many failed sign-ins. Try again in a few minutes.", 429
        elif SHARED_MODE and not NAME_OK.fullmatch(username):
            error, status = "Enter your name (2 to 32 letters, numbers, spaces, dots, dashes or underscores).", 400
        else:
            pw = request.form.get("password", "")
            if SHARED_MODE:
                good = password_ok(pw)
                who = username
            else:
                u = users.get(username)
                good = check_password_hash(u["hash"] if u else DUMMY_HASH, pw) and bool(u)
                who = username
            if good:
                _fails.pop(ip, None)
                session.clear()
                session.permanent = True
                session["user"] = who
                session["mode"] = "shared" if SHARED_MODE else "accounts"
                return redirect(nxt or url_for("pages"))
            _fails.setdefault(ip, []).append(time.time())
            error, status = ("Wrong password." if SHARED_MODE else "Wrong username or password."), 401
    return render_template_string(
        LOGIN_TMPL, configured=SHARED_MODE or bool(users), shared=SHARED_MODE, error=error,
        username=username, nxt=nxt, user=None, csrf=csrf_token(), title=APP_TITLE,
        max_w=PAGE_MAX_WIDTH, pages_on=True, nav="pages", ptitle=f"Sign in \u00b7 {APP_TITLE}",
        badge="Pages need a sign-in"), status


@app.post("/logout")
def logout():
    if csrf_ok():
        session.clear()
    return redirect(url_for("login"))


# ---------- routes: pages ----------
@app.get("/pages")
@login_required
def pages():
    return render_pages()


@app.post("/pages/publish")
@login_required
def publish():
    user = current_user()
    if not csrf_ok():
        body, _ = render_pages(errors={"form": "Your session expired. Reload the page and try again."})
        return body, 400
    title = " ".join((request.form.get("title") or "").split())
    category = " ".join((request.form.get("category") or "").split())
    viewers = (request.form.get("viewers") or "").strip()
    f = request.files.get("file")
    bad = check_password()      # same shared upload password as the file area (when PROTECT_UPLOAD is on)
    if bad:
        body, _ = render_pages(errors={"password": bad[0]},
                               form={"title": title, "category": category, "viewers": viewers})
        return body, bad[1]
    errors = {}
    if not title:
        errors["title"] = "Enter a title."
    elif len(title) > 120:
        errors["title"] = "Keep the title under 120 characters."
    if not category:
        errors["category"] = "Enter a category."
    elif not CATEGORY_RE.fullmatch(category):
        errors["category"] = "Use up to 60 letters, numbers, spaces, - _ . / or &."
    vu, vg, verr = ([], [], None) if SHARED_MODE else parse_viewers(viewers, load_users())
    if verr:
        errors["viewers"] = verr
    data = b""
    if not f or not f.filename:
        errors["file"] = "Choose an HTML file."
    elif not f.filename.lower().endswith((".html", ".htm")):
        errors["file"] = "Only .html or .htm files are accepted."
    else:
        data = f.read(PAGE_MAX_MB * 1024 * 1024 + 1)
        errors_file = check_html(data)
        if errors_file:
            errors["file"] = errors_file
    if errors:
        body, _ = render_pages(errors=errors, form={"title": title, "category": category, "viewers": viewers})
        return body, 400
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "page"
    stored = f"{secrets.token_hex(6)}-{slug}.html"
    path = os.path.join(PAGE_FILES_DIR, stored)
    with open(path, "xb") as fh:
        fh.write(data)
    os.chmod(path, 0o640)
    execute("""INSERT INTO pages (title, category, stored_filename, original_filename, uploaded_by,
               uploaded_at, status, viewer_users, viewer_groups, size)
               VALUES (?, ?, ?, ?, ?, ?, 'published', ?, ?, ?)""",
            (title, category, stored, secure_filename(f.filename), user["name"], time.time(),
             json.dumps(vu), json.dumps(vg), len(data)))
    flash(f"Published \u201c{title}\u201d in {category}.")
    return redirect(url_for("pages"))


@app.post("/pages/<int:pid>/status")
@login_required
def set_status(pid):
    user = current_user()
    if not csrf_ok():
        return msg_page("Session expired", "Reload the page and try again.", 400)
    rows = query("SELECT * FROM pages WHERE id = ?", (pid,))
    if not rows:
        abort(404)
    row = rows[0]
    if not can_manage(row, user):
        return msg_page("Not allowed", "Only the person who published a page, or an admin, can change its status.", 403)
    new = "published" if request.form.get("status") == "published" else "unpublished"
    execute("UPDATE pages SET status = ? WHERE id = ?", (new, pid))
    flash(f"\u201c{row['title']}\u201d is now {new}.")
    return redirect(url_for("pages"))


@app.get("/p/<int:pid>")
def view_page(pid):
    user = current_user()
    if not user:
        return redirect(url_for("login", next=request.path))
    rows = query("SELECT * FROM pages WHERE id = ?", (pid,))
    if not rows:
        return msg_page("Page not found", "This page doesn\u2019t exist.", 404)
    row = rows[0]
    if not can_view(row, user):
        return msg_page("No access", "You don\u2019t have permission to view this page, or it isn\u2019t published.", 403)
    path = os.path.join(PAGE_FILES_DIR, row["stored_filename"])
    if not os.path.isfile(path):
        return msg_page("Page not found", "The file for this page is missing on the server.", 404)
    resp = send_from_directory(PAGE_FILES_DIR, row["stored_filename"], mimetype="text/html")
    resp.headers["Cache-Control"] = "private, no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    if PAGE_SANDBOX:
        # Opaque origin: scripts in the page can't use this site's cookies or call its endpoints.
        resp.headers["Content-Security-Policy"] = SANDBOX_CSP
    return resp


@app.after_request
def security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    return resp


if PAGES_ENABLED:
    try:
        init_pages()
    except OSError as e:
        sys.exit(f"[FATAL] Cannot prepare the pages folder {PAGES_DIR}: {e}")
    print(f"[fileshare] pages enabled | folder: {PAGES_DIR} | sign-in: "
          + ("shared password" if SHARED_MODE else f"accounts ({len(load_users())} in {USERS_FILE})"),
          file=sys.stderr)


@app.errorhandler(413)
def too_large(_):
    return f"File too large (limit {MAX_MB} MB).", 413


if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
