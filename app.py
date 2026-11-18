#!/usr/bin/env python3
"""
Simple file share with folders: upload, download, create folders and delete.

Every file and folder is either PUBLIC or PRIVATE:
  * public  - anyone who can reach the page can see it in the list and download it
  * private - hidden until the visitor unlocks private files with the password
              (needed even to see the name, open the folder or download)
A private folder makes everything inside it private.

Uploading, creating folders, deleting and changing public/private always ask
for the password, on every action, whether or not private files are unlocked.
Files are never overwritten: a name clash gets a timestamp suffix.
"""
import os
import sys
import shutil
import hmac
import time
import re
import hashlib
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path
from datetime import datetime, timedelta
from flask import (Flask, request, redirect, url_for, flash, g,
                   send_from_directory, render_template_string, abort, session)
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
DEFAULT_VISIBILITY = "private"     # "private" or "public": used for files and folders that have no
                                   # setting yet (anything copied in by hand, or that existed before
                                   # this version) and pre-selected in the upload form.
                                   # Upload, new folder, delete and public/private changes always
                                   # need the password in SECRETS_DIR.
FILES_DB      = ""                 # public/private settings; "" = <current working dir>/fileshare-meta/files.db
                                   # (must be outside SHARE_DIR)
APP_TITLE     = "FileNest"         # name shown in the page header and browser tab
APP_TAGLINE   = "Your files. Your pages. One place."   # line under the name in the header
PAGE_MAX_WIDTH = "100%"            # page width cap: "100%" = fill the window, or e.g. "1400px" / "90vw"
MAX_FOLDER_DEPTH = 8              # how many folder levels deep users can create
AUTH_USER     = "fileshare"        # the single account. Only its password is ever asked for (no username
                                   # prompt); the name is shown as "Uploaded by" on pages.
PAGES_ENABLED = True               # host static HTML pages (each one public or private, like files)
PAGES_DIR     = ""                 # pages and their metadata; "" = <current working dir>/pages
PAGE_MAX_MB   = 20                 # max size of one HTML page, in MB
PAGE_SANDBOX  = True               # run hosted pages in an isolated sandbox (recommended; see README)
SESSION_HOURS = 8                  # how long "Unlock private" lasts in a browser
COOKIE_SECURE = False              # set True when the app is served over HTTPS
MAX_FAILED    = 5                  # wrong passwords allowed per client IP ...
LOCKOUT_SEC   = 300                # ... within this many seconds, then password checks are blocked
SHOW_HIDDEN   = False              # list files starting with "." ?
# =====================================================================

SHARE_DIR     = os.path.abspath(os.environ.get("SHARE_DIR") or SHARE_DIR or os.path.join(os.getcwd(), "fileshare"))
SECRETS_DIR   = Path(os.environ.get("SECRETS_DIR") or SECRETS_DIR or Path.cwd() / ".secrets")
MAX_UPLOAD_MB = int(os.environ.get("MAX_UPLOAD_MB", MAX_UPLOAD_MB))
HOST          = os.environ.get("HOST", HOST)
PORT          = int(os.environ.get("PORT", PORT))
DEFAULT_VISIBILITY = os.environ.get("DEFAULT_VISIBILITY", DEFAULT_VISIBILITY).strip().lower()
if DEFAULT_VISIBILITY not in ("public", "private"):
    sys.exit('[FATAL] DEFAULT_VISIBILITY must be "public" or "private".')
FILES_DB      = os.path.abspath(os.environ.get("FILES_DB") or FILES_DB
                                or os.path.join(os.getcwd(), "fileshare-meta", "files.db"))
if os.path.realpath(FILES_DB).startswith(os.path.realpath(SHARE_DIR) + os.sep):
    sys.exit("[FATAL] FILES_DB must not be inside SHARE_DIR (it would be downloadable).")


def env_bool(name, default):
    v = os.environ.get(name)
    return default if v is None else v.strip().lower() in ("1", "true", "yes", "on")


for _old in ("PROTECT_DOWNLOAD", "PROTECT_UPLOAD", "SHARE_USER", "PAGES_LOGIN", "USERS_FILE"):
    if os.environ.get(_old) is not None:
        print(f"[fileshare] note: {_old} is no longer used (one password for everything; files and "
              f"pages are public or private one by one)", file=sys.stderr)
AUTH_USER        = os.environ.get("AUTH_USER", AUTH_USER).strip() or "fileshare"
PAGES_ENABLED    = env_bool("PAGES_ENABLED", PAGES_ENABLED)
PAGE_SANDBOX     = env_bool("PAGE_SANDBOX", PAGE_SANDBOX)
COOKIE_SECURE    = env_bool("COOKIE_SECURE", COOKIE_SECURE)
PAGE_MAX_MB      = int(os.environ.get("PAGE_MAX_MB", PAGE_MAX_MB))
SESSION_HOURS    = float(os.environ.get("SESSION_HOURS", SESSION_HOURS))
PAGES_DIR        = os.path.abspath(os.environ.get("PAGES_DIR") or PAGES_DIR or os.path.join(os.getcwd(), "pages"))
PAGE_FILES_DIR   = os.path.join(PAGES_DIR, "files")
PAGES_DB         = os.path.join(PAGES_DIR, "pages.db")
PAGE_PREFIXES    = ("/pages", "/p/")   # 404 when PAGES_ENABLED is off
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
                 f"Run the encryption script first. (The password unlocks private files and is "
                 f"needed for every upload, new folder, delete, publish and public/private change.)")


PASSWORD = load_password()
print(f"[fileshare] files are public or private one by one | default for new and unset items: "
      f"{DEFAULT_VISIBILITY} | settings: {FILES_DB}", file=sys.stderr)

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
        # no guessable fallback: the session says whether private files are unlocked
        sys.exit(f"[FATAL] Cannot create the session key in {SECRETS_DIR}: {e}\n"
                 f"Fix the folder permissions or set the SECRET_KEY environment variable.")


app.secret_key = _session_secret()
app.config.update(
    SESSION_COOKIE_NAME="fileshare_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)
app.jinja_env.globals["app_tagline"] = APP_TAGLINE


@app.before_request
def check_pages_enabled():
    if request.path.startswith(PAGE_PREFIXES) and not PAGES_ENABLED:
        abort(404)


# ---------- public / private settings ----------
def fdb():
    con = sqlite3.connect(FILES_DB, timeout=15)
    return con


def init_files_db():
    os.makedirs(os.path.dirname(FILES_DB), mode=0o750, exist_ok=True)
    with closing(fdb()) as con, con:
        con.execute("""CREATE TABLE IF NOT EXISTS items (
            path TEXT PRIMARY KEY,                -- relative to SHARE_DIR, e.g. "reports/q3.pdf"
            visibility TEXT NOT NULL CHECK (visibility IN ('public', 'private')),
            updated_at REAL NOT NULL)""")


def vis_map():
    """{relative path: 'public' | 'private'} for every item with a setting (cached per request)."""
    if "vis_map" not in g:
        with closing(fdb()) as con:
            g.vis_map = dict(con.execute("SELECT path, visibility FROM items"))
    return g.vis_map


def own_vis(rel, vmap=None):
    """The item's own setting (DEFAULT_VISIBILITY when it has none)."""
    return (vmap if vmap is not None else vis_map()).get(rel, DEFAULT_VISIBILITY)


def effective_vis(rel, vmap=None):
    """'private' if the item itself or any folder above it is private. The root is public."""
    vmap = vmap if vmap is not None else vis_map()
    parts = rel.split("/") if rel else []
    for i in range(1, len(parts) + 1):
        if own_vis("/".join(parts[:i]), vmap) == "private":
            return "private"
    return "public"


def set_vis(rel, visibility):
    with closing(fdb()) as con, con:
        con.execute("INSERT OR REPLACE INTO items (path, visibility, updated_at) VALUES (?, ?, ?)",
                    (rel, visibility, time.time()))
    g.pop("vis_map", None)


def forget_vis(rel):
    """Drop the settings of an item and, for a folder, of everything inside it."""
    prefix = rel + "/"
    with closing(fdb()) as con, con:
        con.execute("DELETE FROM items WHERE path = ? OR substr(path, 1, ?) = ?",
                    (rel, len(prefix), prefix))
    g.pop("vis_map", None)


def _unlock_tag():
    """Stored in the session when private files are unlocked. Tied to the current password,
    so changing the password locks every browser again."""
    return hmac.new(app.secret_key.encode(), b"files-unlock:" + PASSWORD.encode(),
                    hashlib.sha256).hexdigest()[:32]


def files_unlocked():
    """True when this browser has unlocked private files and pages with the password."""
    tag = session.get("files_ok")
    return bool(tag) and hmac.compare_digest(tag, _unlock_tag())


def can_see(rel):
    return files_unlocked() or effective_vis(rel) == "public"


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


def dir_stats(path, rel, show_private, vmap, limit=20000):
    """(direct item count, total bytes of all files inside, truncated?) for a folder.
    Symlinks and hidden entries are skipped; counting stops after `limit` entries.
    Private items are left out of the counts unless show_private, so they leak nothing."""
    items = size = seen = 0
    stack, top = [(path, rel)], True
    while stack:
        cur, cur_rel = stack.pop()
        try:
            it = list(os.scandir(cur))
        except OSError:
            continue
        for e in it:
            if (e.name.startswith(".") and not SHOW_HIDDEN) or e.is_symlink():
                continue
            child = f"{cur_rel}/{e.name}"
            if not show_private and own_vis(child, vmap) == "private":
                continue
            if top:
                items += 1
            seen += 1
            if seen > limit:
                return items, size, True
            try:
                if e.is_dir(follow_symlinks=False):
                    stack.append((e.path, child))
                elif e.is_file(follow_symlinks=False):
                    size += e.stat(follow_symlinks=False).st_size
            except OSError:
                pass
        top = False
    return items, size, False


def list_dir(full, rel, show_private):
    """Folders first (A-Z), then files (newest first). Symlinks and hidden entries are skipped,
    and so are private items unless show_private."""
    vmap = vis_map()
    parent_private = effective_vis(rel, vmap) == "private"
    dirs, files = [], []
    for e in os.scandir(full):
        if (e.name.startswith(".") and not SHOW_HIDDEN) or e.is_symlink():
            continue
        child = f"{rel}/{e.name}" if rel else e.name
        vis = own_vis(child, vmap)
        if not show_private and (parent_private or vis == "private"):
            continue
        try:
            st = e.stat(follow_symlinks=False)
        except OSError:
            continue
        mtime = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        access = {"vis": "private" if parent_private else vis, "inherited": parent_private}
        if e.is_dir(follow_symlinks=False):
            n_items, dsize, partial = dir_stats(e.path, child, show_private, vmap)
            dirs.append({"name": e.name, "rel": child, "is_dir": True, "n_items": n_items,
                         "bytes": dsize, "size": ("\u2265 " if partial else "") + human(dsize),
                         "kind": "folder", "ext": "", "mtime": mtime, "ts": st.st_mtime, **access})
        elif e.is_file(follow_symlinks=False):
            if not rel and e.name == SELF_NAME:
                continue
            kind, ext = file_kind(e.name)
            files.append({"name": e.name, "rel": child, "is_dir": False, "n_items": 0,
                          "bytes": st.st_size, "size": human(st.st_size),
                          "kind": kind, "ext": ext, "mtime": mtime, "ts": st.st_mtime, **access})
    dirs.sort(key=lambda x: x["name"].lower())
    files.sort(key=lambda x: x["ts"], reverse=True)
    return dirs + files


def check_password():
    """Return an error response unless the request carries the right password, else None.
    Asked for on every upload, new folder, delete and public/private change."""
    ip = client_ip()
    if locked_out(ip):
        return "Too many wrong passwords. Try again later.", 429
    supplied = request.form.get("password", "")
    if not supplied:
        return "Enter the password to continue.", 401
    if not password_ok(supplied):
        _fails.setdefault(ip, []).append(time.time())
        return "Wrong password.", 403
    _fails.pop(ip, None)
    return None


def form_vis(parent_rel):
    """Visibility chosen in an upload / new-folder form. Inside a private folder it is always private."""
    if effective_vis(parent_rel) == "private":
        return "private"
    v = (request.form.get("visibility") or "").strip().lower()
    return v if v in ("public", "private") else DEFAULT_VISIBILITY


# ---------- routes: browse, download, upload, mkdir, delete, visibility, unlock (no rename) ----------
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

  label.f,legend.f{display:block;margin:16px 0 6px;font-size:13px;font-weight:600}
  .solo{margin:24px auto 48px}
  /* collapsible side panel (upload / publish) */
  .grid.collapsed{grid-template-columns:44px minmax(0,1fr)}
  .grid.collapsed > .side{display:none}
  .rail{display:none}
  .grid.collapsed > .rail{display:flex;flex-direction:column;align-items:center;gap:12px;width:44px;padding:14px 0;
    border:1px solid var(--line);border-radius:10px;background:var(--panel);color:var(--ink);cursor:pointer;font:inherit;font-size:13px;font-weight:650}
  .rail:hover{border-color:var(--acc);color:var(--acc)}
  .rail svg{width:18px;height:18px;stroke:currentColor;flex:none}
  .rail span{writing-mode:vertical-rl}
  .pclose{display:inline-grid;place-items:center;width:30px;height:30px;padding:0;border:1px solid var(--line);border-radius:8px;
    background:var(--panel);color:var(--mut);cursor:pointer}
  .pclose:hover{border-color:var(--acc);color:var(--acc)}
  .pclose svg{width:16px;height:16px;stroke:currentColor}
  .side .phead{flex-wrap:nowrap}
  .side .phead h2{display:block}
  @media (max-width:880px){
    .grid.collapsed{grid-template-columns:1fr}
    .grid.collapsed > .rail{flex-direction:row;width:auto;padding:11px 14px}
    .rail span{writing-mode:horizontal-tb}
  }
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

  /* ---- public / private ---- */
  fieldset.vis{margin:0;padding:0;border:0}
  fieldset.vis legend{padding:0}
  .opts{display:grid;grid-template-columns:1fr 1fr;gap:8px}
  .opt{display:flex;gap:9px;align-items:flex-start;padding:9px 11px;border:1px solid var(--line);border-radius:8px;cursor:pointer;background:var(--panel)}
  .opt:has(input:checked){border-color:var(--acc);background:var(--acc-soft)}
  .opt input{margin:3px 0 0;accent-color:var(--acc)}
  .opt strong{display:block;font-size:13.5px;font-weight:650}
  .opt .sub{font-size:12px;line-height:1.35}
  button.pill{border:1px solid transparent;cursor:pointer;font:inherit;font-size:12px;font-weight:600}
  button.pill:hover{border-color:var(--acc)}
  .pill.pub{background:var(--ok-bg);color:var(--ok)}
  .pill.priv{background:var(--soft);color:var(--ink);border-color:var(--line)}
  .pill svg{width:11px;height:11px;stroke:currentColor;vertical-align:-1px;margin-right:4px}
  .mini.danger{color:var(--bad)}
  .mini.danger:hover{border-color:var(--bad);color:var(--bad);background:var(--bad-bg)}
  .lockbar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:10px 18px;border-bottom:1px solid var(--line);background:var(--soft);font-size:13.5px;color:var(--mut)}
  .lockbar svg{width:15px;height:15px;stroke:currentColor;flex:none}
  .lockbar form{margin:0}
  .lockbar .link{font-size:13.5px}
  .btn.danger{background:var(--bad);color:#fff}
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
    <div class="lock" title="Public files and pages are open to everyone. Private ones need the password. Every upload, publish, delete or change asks for the password.">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>
      {{ 'Unlocked' if unlocked else 'Public only' }}
    </div>
  </div>
</div></header>
"""

PAGE_BODY = r"""</style></head>
<body>
<!--HEADER-->

<main class="wrap {{ 'grid collapsed' if unlocked else 'solo' }}">
  {% if unlocked %}
  <button type="button" class="rail" id="railbtn" aria-controls="side" aria-expanded="false" title="Show the upload panel"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg><span>Upload files</span></button>
  <section class="panel upload side" id="side" aria-labelledby="uh">
    <div class="phead"><div><h2 id="uh">Upload files</h2><span class="sub">Up to {{ max_mb }} MB per upload</span></div>
      <button type="button" class="pclose" id="sideclose" aria-label="Hide the upload panel" title="Hide"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg></button></div>
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

      <fieldset class="vis">
        <legend class="f">Who can see these files</legend>
        {% if cur_private %}
        <p class="hint" style="margin:0">This folder is private, so files uploaded here are private too.</p>
        {% else %}
        <div class="opts">
          <label class="opt"><input type="radio" name="upvis" value="private"{% if default_vis == 'private' %} checked{% endif %}>
            <span><strong>Private</strong><span class="sub">Password needed to see or download</span></span></label>
          <label class="opt"><input type="radio" name="upvis" value="public"{% if default_vis == 'public' %} checked{% endif %}>
            <span><strong>Public</strong><span class="sub">Anyone with the link, no password</span></span></label>
        </div>
        {% endif %}
      </fieldset>

      <label class="f" for="pw">Password</label>
      <div class="pw">
        <input id="pw" type="password" autocomplete="off" spellcheck="false">
        <button type="button" id="pwt" aria-pressed="false">Show</button>
      </div>

      <div id="err" class="note err" role="alert" hidden></div>
      <button type="button" class="btn" id="go" disabled>Upload files</button>
      <p class="rule">Uploading, creating folders, deleting and switching public/private always ask for the password. If a name already exists, the new file is saved with a timestamp added.</p>
    </div>
  </section>
  {% endif %}

  <section class="panel" aria-labelledby="lh">
    <div class="phead">
      <div>
        <h2 id="lh" class="crumbs"><nav aria-label="Breadcrumb">{% for c in crumbs %}{% if not loop.last %}<a href="{{ url_for('browse', p=c.rel) }}">{{ c.name }}</a><span class="sep" aria-hidden="true">/</span>{% else %}<span aria-current="page">{{ c.name }}</span>{% endif %}{% endfor %}</nav></h2>
        <span class="sub num" id="stats">{{ nd }} folder{{ '' if nd == 1 else 's' }} · {{ nf }} file{{ '' if nf == 1 else 's' }} · {{ total }}</span>
      </div>
      <div class="tools">
        {% if unlocked %}<button type="button" class="newf" id="newf"><svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>New folder</button>{% endif %}
        <div class="search">
          <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
          <input id="q" type="search" placeholder="Filter this folder" aria-label="Filter this folder by name">
        </div>
      </div>
    </div>
<!--LOCKBAR-->
    {% with m = get_flashed_messages() %}{% if m %}<div class="flash">{% for x in m %}<p class="note ok" role="status">{{ x }}</p>{% endfor %}</div>{% endif %}{% endwith %}
    <div class="scroll"><table>
      <thead><tr>
        <th scope="col" aria-sort="none"><button type="button" data-key="name">Name</button></th>
        <th scope="col" class="r" aria-sort="none"><button type="button" data-key="size">Size</button></th>
        <th scope="col" class="hide-sm" aria-sort="descending"><button type="button" data-key="ts">Modified</button></th>
        {% if unlocked %}<th scope="col">Access</th>{% endif %}
        <th scope="col" class="r"><span class="sr">Actions</span></th>
      </tr></thead>
      <tbody id="rows">
        {% for f in entries %}
        <tr data-name="{{ f.name|lower }}" data-label="{{ f.name }}" data-rel="{{ f.rel }}" data-dir="{{ 1 if f.is_dir else 0 }}" data-items="{{ f.n_items }}" data-vis="{{ f.vis }}" data-size="{{ f.bytes }}" data-ts="{{ f.ts }}">
          {% if f.is_dir %}
          <td><div class="file"><span class="badge" data-k="folder" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg></span><div><a class="fname" href="{{ url_for('browse', p=f.rel) }}">{{ f.name }}</a><div class="sub">{{ f.n_items }} item{{ '' if f.n_items == 1 else 's' }}</div></div></div></td>
          {% else %}
          <td><div class="file"><span class="badge" data-k="{{ f.kind }}" aria-hidden="true">{{ f.ext }}</span><span class="fname">{{ f.name }}</span></div></td>
          {% endif %}
          <td class="r num">{{ f.size }}</td>
          <td class="hide-sm num">{{ f.mtime }}</td>
          {% if unlocked %}<td>{% if f.inherited %}<span class="pill priv" title="Inside a private folder">{{ lock_svg|safe }}Private</span>
              {% elif f.vis == 'private' %}<button type="button" class="pill priv" data-act="vis" title="Make public" aria-label="{{ f.name }} is private. Make it public">{{ lock_svg|safe }}Private</button>
              {% else %}<button type="button" class="pill pub" data-act="vis" title="Make private" aria-label="{{ f.name }} is public. Make it private">Public</button>{% endif %}</td>{% endif %}
          <td class="r"><div class="act">
            {% if f.is_dir %}
            <a class="dl" href="{{ url_for('browse', p=f.rel) }}" aria-label="Open folder {{ f.name }}">Open</a>
            {% else %}
            <a class="dl" href="{{ url_for('download', filepath=f.rel) }}" aria-label="Download {{ f.name }}">
              <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 4v11M7.5 10.5L12 15l4.5-4.5M5 20h14"/></svg>Download</a>
            {% endif %}
            {% if unlocked %}<button type="button" class="mini danger" data-act="del" aria-label="Delete {{ f.name }}">Delete</button>{% endif %}
          </div></td>
        </tr>
        {% endfor %}
        <tr class="empty" id="empty" {% if entries %}hidden{% endif %}><td colspan="{{ 5 if unlocked else 4 }}" id="emptytxt">{% if unlocked %}{{ 'This folder is empty.' if cur else 'Nothing here yet.' }} Drop files into the upload panel or create a folder.{% else %}{{ 'No public files in this folder.' if cur else 'No public files yet.' }}{% endif %}</td></tr>
      </tbody>
    </table></div>
  </section>
</main>

{% if unlocked %}
<dialog id="mk" aria-labelledby="mkh">
  <form id="mkform" novalidate>
    <h2 id="mkh">New folder</h2>
    <p class="sub">It will be created in <strong>{{ dest_label }}</strong>. Folders can’t be renamed afterwards.</p>
    <label class="f" for="mkname">Folder name</label>
    <input id="mkname" type="text" maxlength="100" autocomplete="off" spellcheck="false">
    <p class="sub" style="margin:6px 0 0">Letters, numbers, dashes, underscores and dots. Spaces become underscores.</p>
    <fieldset class="vis">
      <legend class="f">Who can see this folder</legend>
      {% if cur_private %}
      <p class="hint" style="margin:0">Private, like the folder it’s in.</p>
      {% else %}
      <div class="opts">
        <label class="opt"><input type="radio" name="mkvis" value="private"{% if default_vis == 'private' %} checked{% endif %}>
          <span><strong>Private</strong><span class="sub">It and everything in it need the password</span></span></label>
        <label class="opt"><input type="radio" name="mkvis" value="public"{% if default_vis == 'public' %} checked{% endif %}>
          <span><strong>Public</strong><span class="sub">Anyone can open it</span></span></label>
      </div>
      {% endif %}
    </fieldset>
    <label class="f" for="mkpw">Password</label>
    <input id="mkpw" type="password" autocomplete="off" spellcheck="false">
    <div id="mkerr" class="note err" role="alert" hidden></div>
    <div class="row">
      <button type="button" class="btn ghost" id="mkcancel">Cancel</button>
      <button type="submit" class="btn" id="mkgo">Create folder</button>
    </div>
  </form>
</dialog>

<dialog id="ad" aria-labelledby="adh">
  <form id="adform" novalidate>
    <h2 id="adh"></h2>
    <p class="sub" id="adtxt"></p>
    <label class="f" for="adpw">Password</label>
    <input id="adpw" type="password" autocomplete="off" spellcheck="false">
    <div id="aderr" class="note err" role="alert" hidden></div>
    <div class="row">
      <button type="button" class="btn ghost" id="adcancel">Cancel</button>
      <button type="submit" class="btn" id="adgo"></button>
    </div>
  </form>
</dialog>
{% endif %}

<script>
/* collapsible side panel: hidden by default, remembered per browser */
(function(){
  var g=document.querySelector('main.grid'), rail=document.getElementById('railbtn'), close=document.getElementById('sideclose');
  if(!g||!rail||!close)return;
  var KEY='filenest-side-'+(location.pathname.indexOf('/pages')===0?'pages':'files');
  function set(open,focus,save){
    g.classList.toggle('collapsed',!open); rail.setAttribute('aria-expanded',open?'true':'false');
    if(save){try{localStorage.setItem(KEY,open?'open':'closed')}catch(e){}}
    if(focus){(open?close:rail).focus()}
  }
  var saved=null; try{saved=localStorage.getItem(KEY)}catch(e){}
  if(g.dataset.force==='open'||saved==='open')set(true,false,false);
  rail.onclick=function(){set(true,true,true)};
  close.onclick=function(){set(false,true,true)};
  document.addEventListener('dragenter',function(e){
    var t=e.dataTransfer&&e.dataTransfer.types;
    if(t&&Array.prototype.indexOf.call(t,'Files')!==-1&&g.classList.contains('collapsed')&&document.getElementById('zone'))set(true,false,false);
  });
})();
(function(){
  var $ = function(id){return document.getElementById(id)};
  var CUR = {{ cur|tojson }}, MAX = {{ max_mb }} * 1048576;
  function picked(name){var r=document.querySelector('input[name="'+name+'"]:checked');return r?r.value:''}

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

  if(!{{ 'true' if unlocked else 'false' }}) return;   /* upload and edit controls exist only after unlock */

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

  $('pwt').onclick=function(){
    var show=pw.type==='password'; pw.type=show?'text':'password';
    this.textContent=show?'Hide':'Show'; this.setAttribute('aria-pressed',show);
  };
  pw.addEventListener('keydown',function(e){if(e.key==='Enter'&&!go.disabled)go.click()});

  function setBusy(b){
    busy=b; zone.classList.toggle('busy',b); zone.disabled=b; go.disabled=b||!queue.length;
    if(!b){fill.style.width='0';zin.innerHTML=idle}
  }
  var idle=zin.innerHTML;

  go.onclick=function(){
    if(!pw.value){showErr('Enter the password to upload.');pw.focus();return}
    showErr('');
    var fd=new FormData(); queue.forEach(function(f){fd.append('files',f)}); fd.append('path',CUR);
    fd.append('visibility',picked('upvis')); fd.append('password',pw.value);
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
      if(x.status===401||x.status===403){pw.select()}
    };
    x.onerror=function(){setBusy(false);render();showErr('The connection dropped before the upload finished. Check your network and try again.')};
    x.send(fd);
  };

  render();

  /* new folder dialog */
  var mk=$('mk'), mkname=$('mkname'), mkpw=$('mkpw'), mkerr=$('mkerr'), mkgo=$('mkgo');
  function mkFail(t){mkerr.textContent=t;mkerr.hidden=false;mkgo.disabled=false}
  $('newf').onclick=function(){
    mkerr.hidden=true; mkname.value=''; mkpw.value=''; mkgo.disabled=false;
    mk.showModal(); mkname.focus();
  };
  $('mkcancel').onclick=function(){mk.close()};
  $('mkform').onsubmit=function(ev){
    ev.preventDefault();
    var name=mkname.value.trim();
    if(!name){mkFail('Enter a name for the folder.');mkname.focus();return}
    if(!mkpw.value){mkFail('Enter the password to create a folder.');mkpw.focus();return}
    var fd=new FormData(); fd.append('path',CUR); fd.append('name',name);
    fd.append('visibility',picked('mkvis')); fd.append('password',mkpw.value);
    mkerr.hidden=true; mkgo.disabled=true;
    post('{{ url_for("mkdir") }}',fd,mkFail,'The folder could not be created.');
  };

  function post(url,fd,fail,fallback){
    fetch(url,{method:'POST',body:fd,credentials:'same-origin'})
      .then(function(r){return r.text().then(function(t){return {ok:r.ok,t:t}})})
      .then(function(res){if(res.ok){location.reload()}else{fail(res.t||fallback)}})
      .catch(function(){fail('The connection dropped. Check your network and try again.')});
  }

  /* delete + public/private: every action asks for the password */
  var ad=$('ad'), adpw=$('adpw'), aderr=$('aderr'), adgo=$('adgo'), act=null;
  function adFail(t){aderr.textContent=t;aderr.hidden=false;adgo.disabled=false;adpw.select()}
  function ask(o){
    act=o; $('adh').textContent=o.title; $('adtxt').textContent=o.text;
    adgo.textContent=o.btn; adgo.className='btn'+(o.danger?' danger':'');
    aderr.hidden=true; adpw.value=''; adgo.disabled=false;
    ad.showModal(); adpw.focus();
  }
  $('adcancel').onclick=function(){ad.close()};
  $('adform').onsubmit=function(ev){
    ev.preventDefault();
    if(!adpw.value){adFail('Enter the password to continue.');return}
    var fd=new FormData(); Object.keys(act.fields).forEach(function(k){fd.append(k,act.fields[k])});
    fd.append('password',adpw.value);
    aderr.hidden=true; adgo.disabled=true;
    post(act.url,fd,adFail,'That didn’t work. Try again.');
  };
  tbody.addEventListener('click',function(e){
    var b=e.target.closest('[data-act]'); if(!b)return;
    var tr=b.closest('tr'), d=tr.dataset, isDir=d.dir==='1', name=d.label;
    if(b.dataset.act==='del'){
      var n=parseInt(d.items,10)||0;
      ask({title:'Delete '+(isDir?'folder':'file')+'?', btn:'Delete', danger:true,
           url:'{{ url_for("delete") }}', fields:{path:d.rel},
           text:'“'+name+'” will be removed permanently'+
                (isDir?(n?' together with everything inside it ('+n+' item'+(n===1?'':'s')+' at the top level, plus anything you can’t see).':' together with anything inside it.'):'.')+
                ' This can’t be undone.'});
    }else{
      var toPub=d.vis==='private';
      ask({title:'Make “'+name+'” '+(toPub?'public':'private')+'?', btn:toPub?'Make public':'Make private',
           url:'{{ url_for("set_visibility") }}', fields:{path:d.rel, visibility:toPub?'public':'private'},
           text: toPub ? ('Anyone who can reach this site will be able to see'+(isDir?' this folder and download the public files in it':' and download it')+' without a password.')
                       : ('Only people who unlock private files with the password will see'+(isDir?' this folder or anything in it.':' or download it.'))});
    }
  });
})();
</script>
</body></html>
"""

LOCKBAR = r"""    <div class="lockbar">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{% if unlocked %}<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/>{% else %}<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>{% endif %}</svg>
      {% if unlocked %}
        <span>Private {{ what }} are unlocked and shown in this list.</span>
        <form method="post" action="{{ url_for('lock') }}"><input type="hidden" name="csrf" value="{{ csrf }}"><input type="hidden" name="next" value="{{ request.path }}"><button class="link" type="submit">Lock</button></form>
      {% else %}
        <span>You’re seeing public {{ what }} only. Unlock to see private {{ what }} and to {{ 'upload or make changes' if what == 'files' else 'publish or make changes' }}.</span>
        <a class="link" href="{{ url_for('unlock', next=request.path) }}">Unlock with password</a>
      {% endif %}
    </div>
"""

PAGE = (HEAD + "/*CSS*/" + PAGE_BODY).replace("/*CSS*/", CSS_BASE + CSS_EXTRA).replace("<!--HEADER-->", HEADER).replace("<!--LOCKBAR-->", LOCKBAR)


@app.context_processor
def common_context():
    """Values every template uses (header, unlock bar)."""
    return {"unlocked": files_unlocked(), "csrf": csrf_token(), "pages_on": PAGES_ENABLED,
            "title": APP_TITLE, "max_w": PAGE_MAX_WIDTH, "lock_svg": LOCK_SVG, "auth_user": AUTH_USER}


LOCK_SVG = ('<svg viewBox="0 0 24 24" fill="none" stroke-width="2.4" stroke-linecap="round" '
            'stroke-linejoin="round" aria-hidden="true"><rect x="5" y="11" width="14" height="9" rx="2"/>'
            '<path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>')


@app.get("/", defaults={"p": ""})
@app.get("/tree/<path:p>")
def browse(p):
    rel, full = resolve_dir(p)
    unlocked = files_unlocked()
    if not unlocked and effective_vis(rel) == "private":
        return redirect(url_for("unlock", next=request.path))
    entries = list_dir(full, rel, show_private=unlocked)
    crumbs, acc = [{"name": "Home", "rel": ""}], []
    for seg in (rel.split("/") if rel else []):
        acc.append(seg)
        crumbs.append({"name": seg, "rel": "/".join(acc)})
    nd = sum(1 for e in entries if e["is_dir"])
    nf = len(entries) - nd
    return render_template_string(
        PAGE, nav="files", what="files",
        entries=entries, cur=rel, crumbs=crumbs, nd=nd, nf=nf,
        dest_label=" / ".join(c["name"] for c in crumbs),
        total=human(sum(e["bytes"] for e in entries)),
        cur_private=effective_vis(rel) == "private", default_vis=DEFAULT_VISIBILITY,
        max_mb=MAX_UPLOAD_MB)


@app.route("/unlock", methods=["GET", "POST"])
def unlock():
    """Password-only prompt (no username) that reveals private files and pages in this
    browser for SESSION_HOURS."""
    nxt = safe_next(request.values.get("next", "")) or url_for("browse", p="")
    if files_unlocked():
        return redirect(nxt)
    error, status = "", 200
    if request.method == "POST":
        ip = "unlock:" + client_ip()
        if not csrf_ok():
            error, status = "Your session expired. Please try again.", 400
        elif locked_out(ip):
            error, status = "Too many wrong passwords. Try again in a few minutes.", 429
        elif password_ok(request.form.get("password", "")):
            _fails.pop(ip, None)
            session.permanent = True
            session["files_ok"] = _unlock_tag()
            return redirect(nxt)
        else:
            _fails.setdefault(ip, []).append(time.time())
            error, status = "Wrong password.", 401
    return render_template_string(
        UNLOCK_TMPL, error=error, nxt=nxt, nav="pages" if nxt.startswith(PAGE_PREFIXES) else "files",
        ptitle=f"Unlock \u00b7 {APP_TITLE}", hours=f"{SESSION_HOURS:g}"), status


@app.post("/lock")
def lock():
    if csrf_ok():
        session.pop("files_ok", None)
        flash("Private files and pages are locked again.")
    return redirect(safe_next(request.form.get("next", "")) or url_for("browse", p=""))


@app.post("/upload")
def upload():
    bad = check_password()
    if bad:
        return bad
    rel, full = resolve_dir(request.form.get("path", ""))
    vis = form_vis(rel)
    saved, skipped = [], []
    for f in request.files.getlist("files"):
        name = secure_filename(f.filename or "")
        if not name:
            skipped.append(f.filename or "(empty)")
            continue
        path = unique_path(full, name)
        stored = os.path.basename(path)
        set_vis(f"{rel}/{stored}" if rel else stored, vis)   # record first: never briefly public
        f.save(path)
        os.chmod(path, 0o644)
        saved.append(stored)
    where = f" to {rel}" if rel else ""
    if saved:
        flash(f"Uploaded{where} as {vis}: {', '.join(saved)}")
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
    child = f"{rel}/{name}" if rel else name
    target = os.path.join(full, name)
    if os.path.lexists(target):
        return f"\u201c{name}\u201d already exists in this folder.", 409
    vis = form_vis(rel)
    set_vis(child, vis)                       # record first: never briefly public
    try:
        os.mkdir(target, 0o750)
    except FileExistsError:
        return f"\u201c{name}\u201d already exists in this folder.", 409
    except OSError as e:
        forget_vis(child)
        return f"Could not create the folder ({e.strerror}).", 500
    flash(f"Created {vis} folder {name}" + (f" (name adjusted from \u201c{raw}\u201d)" if name != raw else ""))
    return "", 204


def resolve_item(rel_raw):
    """(clean relative path, parent abs dir, name, abs path) of an existing file or folder, else 404."""
    rel = clean_rel(rel_raw)
    parent, name = os.path.split(rel)
    if not name or (not parent and name == SELF_NAME):
        abort(404)
    _, full = resolve_dir(parent)
    target = os.path.join(full, name)
    if os.path.islink(target) or not os.path.exists(target):
        abort(404)
    return rel, full, name, target


@app.post("/delete")
def delete():
    bad = check_password()
    if bad:
        return bad
    rel, _, name, target = resolve_item(request.form.get("path", ""))
    try:
        if os.path.isdir(target):
            shutil.rmtree(target)             # does not follow symlinks inside the folder
        else:
            os.remove(target)
    except OSError as e:
        return f"Could not delete \u201c{name}\u201d ({e.strerror}).", 500
    forget_vis(rel)
    flash(f"Deleted {name}")
    return "", 204


@app.post("/visibility")
def set_visibility():
    bad = check_password()
    if bad:
        return bad
    rel, _, name, _ = resolve_item(request.form.get("path", ""))
    vis = (request.form.get("visibility") or "").strip().lower()
    if vis not in ("public", "private"):
        return "Choose public or private.", 400
    parent = os.path.dirname(rel)
    if vis == "public" and effective_vis(parent) == "private":
        return "This item is inside a private folder. Make the folder public first.", 400
    set_vis(rel, vis)
    flash(f"{name} is now {vis}")
    return "", 204


@app.get("/download/<path:filepath>")
def download(filepath):
    rel, full, name, target = resolve_item(filepath)
    if not os.path.isfile(target):
        abort(404)
    if not can_see(rel):
        return redirect(url_for("unlock", next=request.path))
    resp = send_from_directory(full, name, as_attachment=True)
    if effective_vis(rel) == "private":
        resp.headers["Cache-Control"] = "private, no-store"
    return resp


# ---------- templates for sign-in, pages and messages (share CSS + header with the file page) ----------
_TOP = HEAD + "/*CSS*/</style></head>\n<body>\n<!--HEADER-->\n"


def _build(t):
    return (t.replace("/*CSS*/", CSS_BASE + CSS_EXTRA).replace("<!--HEADER-->", HEADER)
             .replace("<!--LOCKBAR-->", LOCKBAR))


MSG_TMPL = _build(_TOP + r"""
<main class="wrap">
  <section class="panel login" aria-labelledby="lh">
    <div class="phead"><h2 id="lh">{{ heading }}</h2></div>
    <div class="pbody">
      <p style="margin:0 0 16px">{{ text }}</p>
      <a class="dl" href="{{ url_for('pages') }}">Back to pages</a>{% if not unlocked %} <a class="dl" href="{{ url_for('unlock', next=request.path) }}">Unlock with password</a>{% endif %}
    </div>
  </section>
</main>
</body></html>
""")

UNLOCK_TMPL = _build(_TOP + r"""
<main class="wrap">
  <section class="panel login" aria-labelledby="lh">
    <div class="phead"><h2 id="lh">Unlock private files and pages</h2></div>
    <div class="pbody">
      <p class="sub" style="margin:0 0 4px">Private files, folders and pages need the password to see or open.
        This browser stays unlocked for {{ hours }} hours or until you lock it.</p>
      <form method="post" action="{{ url_for('unlock') }}">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <input type="hidden" name="next" value="{{ nxt }}">
        <label class="f" for="p">Password</label>
        <input class="fld" id="p" name="password" type="password" autocomplete="current-password" required autofocus>
        {% if error %}<div class="note err" role="alert">{{ error }}</div>{% endif %}
        <button class="btn" type="submit">Unlock</button>
      </form>
      <p class="rule"><a class="link" href="{{ url_for('pages') if nav == 'pages' else url_for('browse', p='') }}">Back to public {{ 'pages' if nav == 'pages' else 'files' }}</a></p>
    </div>
  </section>
</main>
</body></html>
""")

PAGES_TMPL = _build(_TOP + r"""
<main class="wrap {{ ('grid' ~ ('' if errors else ' collapsed')) if unlocked else 'solo' }}"{% if errors %} data-force="open"{% endif %}>
  {% if unlocked %}
  <button type="button" class="rail" id="railbtn" aria-controls="side" aria-expanded="{{ 'true' if errors else 'false' }}" title="Show the publish panel"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 6l6 6-6 6"/></svg><span>Publish a page</span></button>
  <section class="panel upload side" id="side" aria-labelledby="ph">
    <div class="phead"><div><h2 id="ph">Publish a page</h2><span class="sub">Up to {{ page_mb }} MB</span></div>
      <button type="button" class="pclose" id="sideclose" aria-label="Hide the publish panel" title="Hide"><svg viewBox="0 0 24 24" fill="none" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M15 6l-6 6 6 6"/></svg></button></div>
    <div class="pbody">
      {% if errors.form %}<div class="note err" role="alert" style="margin:0 0 14px">{{ errors.form }}</div>{% endif %}
      <form method="post" action="{{ url_for('publish') }}" enctype="multipart/form-data" id="pf">
        <label class="f" for="title" style="margin-top:0">Title <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="title" name="title" type="text" required maxlength="120" autocomplete="off" value="{{ form.title }}"{% if errors.title %} aria-invalid="true" aria-describedby="e-title"{% endif %}>
        {% if errors.title %}<p class="ferr" id="e-title">{{ errors.title }}</p>{% endif %}

        <label class="f" for="category">Category <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="category" name="category" type="text" required maxlength="60" autocomplete="off" list="cats" value="{{ form.category }}"{% if errors.category %} aria-invalid="true" aria-describedby="e-cat"{% endif %}>
        <datalist id="cats">{% for c, n in cats %}<option value="{{ c }}">{% endfor %}</datalist>
        {% if errors.category %}<p class="ferr" id="e-cat">{{ errors.category }}</p>{% endif %}

        <fieldset class="vis">
          <legend class="f">Who can view</legend>
          <div class="opts">
            <label class="opt"><input type="radio" name="visibility" value="private"{% if form.visibility == 'private' %} checked{% endif %}>
              <span><strong>Private</strong><span class="sub">Password needed to open</span></span></label>
            <label class="opt"><input type="radio" name="visibility" value="public"{% if form.visibility == 'public' %} checked{% endif %}>
              <span><strong>Public</strong><span class="sub">Anyone with the link, no password</span></span></label>
          </div>
        </fieldset>

        <label class="f" for="file">HTML file <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="file" name="file" type="file" accept=".html,.htm,text/html" required{% if errors.file %} aria-invalid="true" aria-describedby="e-file"{% endif %}>
        {% if errors.file %}<p class="ferr" id="e-file">{{ errors.file }}</p>{% endif %}
        <p class="ferr" id="e-size" hidden></p>

        <label class="f" for="pw">Password <span class="req" aria-hidden="true">*</span></label>
        <input class="fld" id="pw" name="password" type="password" required autocomplete="off"{% if errors.password %} aria-invalid="true" aria-describedby="e-pw"{% endif %}>
        {% if errors.password %}<p class="ferr" id="e-pw">{{ errors.password }}</p>{% endif %}

        <button class="btn" type="submit" id="pub">Publish</button>
      </form>
      <p class="rule">Use one self-contained .html file with its CSS, scripts and images inline. Publishing, unpublishing and switching public/private always ask for the password. Published pages can’t be replaced: publish a new page to change one.{% if sandbox %} Scripts in pages run in an isolated sandbox, so pages can’t use cookies or local storage.{% endif %}</p>
    </div>
  </section>
  {% endif %}

  <section class="panel" aria-labelledby="lh">
    <div class="phead">
      <div><h2 id="lh">Pages</h2><span class="sub num" id="stats">{{ rows|length }} page{{ '' if rows|length == 1 else 's' }} · {{ cats|length }} categor{{ 'y' if cats|length == 1 else 'ies' }}</span></div>
      <div class="tools"><div class="search">
        <svg viewBox="0 0 24 24" fill="none" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg>
        <input id="q" type="search" placeholder="Search pages" aria-label="Search pages by title or category">
      </div></div>
    </div>
<!--LOCKBAR-->
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
        <th scope="col" class="hide-sm" aria-sort="descending"><button type="button" data-key="ts">Uploaded</button></th>
        {% if unlocked %}<th scope="col">Access</th><th scope="col">Status</th>{% endif %}
        <th scope="col" class="r"><span class="sr">Actions</span></th>
      </tr></thead>
      <tbody id="rows">
        {% for r in rows %}
        <tr data-title="{{ r.title|lower }}" data-label="{{ r.title }}" data-cat="{{ r.category }}" data-ts="{{ r.ts }}" data-id="{{ r.id }}" data-vis="{{ r.vis }}" data-pub="{{ 1 if r.published else 0 }}">
          <td><a class="fname" href="{{ url_for('view_page', pid=r.id) }}" target="_blank" rel="noopener">{{ r.title }}</a>
              <div class="stored" title="Stored filename">{{ r.stored_filename }} · {{ r.size }}</div></td>
          <td><span class="tag">{{ r.category }}</span></td>
          <td class="num hide-sm">{{ r.uploaded }}</td>
          {% if unlocked %}<td>{% if r.vis == 'private' %}<button type="button" class="pill priv" data-act="vis" title="Make public" aria-label="{{ r.title }} is private. Make it public">{{ lock_svg|safe }}Private</button>
              {% else %}<button type="button" class="pill pub" data-act="vis" title="Make private" aria-label="{{ r.title }} is public. Make it private">Public</button>{% endif %}</td>
          <td><span class="pill {{ 'ok' if r.published else 'off' }}">{{ 'Published' if r.published else 'Unpublished' }}</span></td>{% endif %}
          <td class="r"><div class="act">
            <a class="dl" href="{{ url_for('view_page', pid=r.id) }}" target="_blank" rel="noopener" aria-label="Open {{ r.title }}">Open</a>
            {% if unlocked %}<button type="button" class="mini{{ ' danger' if r.published }}" data-act="status" aria-label="{{ 'Unpublish' if r.published else 'Publish' }} {{ r.title }}">{{ 'Unpublish' if r.published else 'Publish' }}</button>{% endif %}
          </div></td>
        </tr>
        {% endfor %}
        <tr class="empty" id="empty" {% if rows %}hidden{% endif %}><td colspan="{{ 6 if unlocked else 4 }}" id="emptytxt">{{ 'No pages yet. Publish the first one with the form.' if unlocked else 'No public pages yet.' }}</td></tr>
      </tbody>
    </table></div>
  </section>
</main>

{% if unlocked %}
<dialog id="ad" aria-labelledby="adh">
  <form id="adform" novalidate>
    <h2 id="adh"></h2>
    <p class="sub" id="adtxt"></p>
    <label class="f" for="adpw">Password</label>
    <input id="adpw" type="password" autocomplete="off" spellcheck="false">
    <div id="aderr" class="note err" role="alert" hidden></div>
    <div class="row">
      <button type="button" class="btn ghost" id="adcancel">Cancel</button>
      <button type="submit" class="btn" id="adgo"></button>
    </div>
  </form>
</dialog>
{% endif %}

<script>
/* collapsible side panel: hidden by default, remembered per browser */
(function(){
  var g=document.querySelector('main.grid'), rail=document.getElementById('railbtn'), close=document.getElementById('sideclose');
  if(!g||!rail||!close)return;
  var KEY='filenest-side-'+(location.pathname.indexOf('/pages')===0?'pages':'files');
  function set(open,focus,save){
    g.classList.toggle('collapsed',!open); rail.setAttribute('aria-expanded',open?'true':'false');
    if(save){try{localStorage.setItem(KEY,open?'open':'closed')}catch(e){}}
    if(focus){(open?close:rail).focus()}
  }
  var saved=null; try{saved=localStorage.getItem(KEY)}catch(e){}
  if(g.dataset.force==='open'||saved==='open')set(true,false,false);
  rail.onclick=function(){set(true,true,true)};
  close.onclick=function(){set(false,true,true)};
  document.addEventListener('dragenter',function(e){
    var t=e.dataTransfer&&e.dataTransfer.types;
    if(t&&Array.prototype.indexOf.call(t,'Files')!==-1&&g.classList.contains('collapsed')&&document.getElementById('zone'))set(true,false,false);
  });
})();
(function(){
  var $=function(i){return document.getElementById(i)};
  var tbody=$('rows'), empty=$('empty'), q=$('q'), cat='', key='ts', dir=-1, MAXB={{ page_mb }}*1048576;
  function rows(){return Array.prototype.slice.call(tbody.querySelectorAll('tr[data-title]'))}
  function apply(){
    var term=q.value.trim().toLowerCase(), shown=0, all=rows();
    all.forEach(function(r){
      var hay=r.dataset.title+' '+r.dataset.cat.toLowerCase();
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
  if(!{{ 'true' if unlocked else 'false' }}) return;   /* publish and edit controls exist only after unlock */
  var file=$('file'), esz=$('e-size'), pub=$('pub');
  file.addEventListener('change',function(){
    var f=file.files[0];
    if(f && f.size>MAXB){esz.textContent='That file is '+(f.size/1048576).toFixed(1)+' MB. The limit is {{ page_mb }} MB.';esz.hidden=false;file.value=''}
    else{esz.hidden=true}
  });
  $('pf').addEventListener('submit',function(){pub.disabled=true;pub.textContent='Publishing…'});

  /* publish / unpublish and public / private: every change asks for the password */
  var ad=$('ad'), adpw=$('adpw'), aderr=$('aderr'), adgo=$('adgo'), act=null;
  function adFail(t){aderr.textContent=t;aderr.hidden=false;adgo.disabled=false;adpw.select()}
  function ask(o){
    act=o; $('adh').textContent=o.title; $('adtxt').textContent=o.text;
    adgo.textContent=o.btn; adgo.className='btn'+(o.danger?' danger':'');
    aderr.hidden=true; adpw.value=''; adgo.disabled=false;
    ad.showModal(); adpw.focus();
  }
  $('adcancel').onclick=function(){ad.close()};
  $('adform').onsubmit=function(ev){
    ev.preventDefault();
    if(!adpw.value){adFail('Enter the password to continue.');return}
    var fd=new FormData(); Object.keys(act.fields).forEach(function(k){fd.append(k,act.fields[k])});
    fd.append('password',adpw.value);
    aderr.hidden=true; adgo.disabled=true;
    fetch(act.url,{method:'POST',body:fd,credentials:'same-origin'})
      .then(function(r){return r.text().then(function(t){return {ok:r.ok,t:t}})})
      .then(function(res){if(res.ok){location.reload()}else{adFail(res.t||'That didn’t work. Try again.')}})
      .catch(function(){adFail('The connection dropped. Check your network and try again.')});
  };
  var STATUS_URL={{ url_for('set_status', pid=0)|tojson }}, VIS_URL={{ url_for('set_page_visibility', pid=0)|tojson }};
  function forPage(u,id){return u.replace('/0/','/'+id+'/')}
  tbody.addEventListener('click',function(e){
    var b=e.target.closest('[data-act]'); if(!b)return;
    var d=b.closest('tr').dataset, name=d.label;
    if(b.dataset.act==='status'){
      var pub=d.pub==='1';
      ask({title:(pub?'Unpublish':'Publish')+' “'+name+'”?', btn:pub?'Unpublish':'Publish', danger:pub,
           url:forPage(STATUS_URL,d.id), fields:{status:pub?'unpublished':'published'},
           text:pub?'Nobody will be able to open it until it is published again. It stays listed for people who unlock with the password.'
                   :'It will open again for '+(d.vis==='public'?'everyone.':'people who unlock with the password.')});
    }else{
      var toPub=d.vis==='private';
      ask({title:'Make “'+name+'” '+(toPub?'public':'private')+'?', btn:toPub?'Make public':'Make private',
           url:forPage(VIS_URL,d.id), fields:{visibility:toPub?'public':'private'},
           text:toPub?'Anyone who can reach this site will be able to open it without a password.'
                     :'Only people who unlock with the password will be able to see or open it.'});
    }
  });
})();
</script>
</body></html>
""")


# ===================================================================
# Hosted HTML pages: each one public or private, like files
# ===================================================================
SANDBOX_CSP = ("sandbox allow-scripts allow-popups allow-popups-to-escape-sandbox "
               "allow-downloads allow-modals")
HTML_HINT = re.compile(rb"<\s*(!doctype|html|head|body|div|p|h[1-6]|table|svg|section|main|article|script|style)\b", re.I)
CATEGORY_RE = re.compile(r"[\w &/.\-]{1,60}")


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
        viewer_users TEXT NOT NULL DEFAULT '[]',     -- no longer used (kept for older databases)
        viewer_groups TEXT NOT NULL DEFAULT '[]',    -- no longer used (kept for older databases)
        size INTEGER NOT NULL DEFAULT 0)""")
    cols = {r["name"] for r in query("PRAGMA table_info(pages)")}
    if "visibility" not in cols:
        # pages published before this version start private, so nothing becomes public by surprise
        execute(f"ALTER TABLE pages ADD COLUMN visibility TEXT NOT NULL DEFAULT '{DEFAULT_VISIBILITY}'")


def can_view(row):
    """Public + published pages are open to everyone. Anything else needs the password."""
    if files_unlocked():
        return True
    return row["status"] == "published" and row["visibility"] == "public"


def page_view(row):
    return {"id": row["id"], "title": row["title"], "category": row["category"],
            "stored_filename": row["stored_filename"], "ts": row["uploaded_at"],
            "uploaded": time.strftime("%Y-%m-%d %H:%M", time.localtime(row["uploaded_at"])),
            "published": row["status"] == "published", "size": human(row["size"] or 0),
            "vis": row["visibility"]}


def get_page(pid):
    rows = query("SELECT * FROM pages WHERE id = ?", (pid,))
    if not rows:
        abort(404)
    return rows[0]


def check_html(data):
    """Return an error message if `data` is not an acceptable HTML page, else None."""
    if not data.strip():
        return "The file is empty."
    if len(data) > PAGE_MAX_MB * 1024 * 1024:
        return f"The file is larger than {PAGE_MAX_MB} MB."
    if b"\x00" in data:
        return "That doesn’t look like an HTML file."
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return "The file must be saved as UTF-8."
    if not HTML_HINT.search(data[:65536]):
        return "That doesn’t look like an HTML page (no HTML tags found)."
    return None


def render_pages(errors=None, form=None, status=200):
    rows = [page_view(r) for r in query("SELECT * FROM pages ORDER BY uploaded_at DESC") if can_view(r)]
    counts = {}
    for r in rows:
        counts[r["category"]] = counts.get(r["category"], 0) + 1
    cats = sorted(counts.items(), key=lambda kv: kv[0].lower())
    return render_template_string(
        PAGES_TMPL, rows=rows, cats=cats, errors=errors or {}, what="pages",
        form=form or {"title": "", "category": "", "visibility": DEFAULT_VISIBILITY},
        sandbox=PAGE_SANDBOX, page_mb=PAGE_MAX_MB, nav="pages",
        ptitle=f"Pages · {APP_TITLE}"), status


def msg_page(heading, text, status):
    return render_template_string(
        MSG_TMPL, heading=heading, text=text, nav="pages",
        ptitle=f"{heading} · {APP_TITLE}"), status


# ---------- old sign-in links: there is no username any more, only the password ----------
@app.get("/login")
def login():
    return redirect(url_for("unlock", next=safe_next(request.args.get("next", "")) or url_for("pages")))


@app.post("/logout")
def logout():
    return lock()


# ---------- routes: pages ----------
@app.get("/pages")
def pages():
    return render_pages()


@app.post("/pages/publish")
def publish():
    title = " ".join((request.form.get("title") or "").split())
    category = " ".join((request.form.get("category") or "").split())
    vis = (request.form.get("visibility") or "").strip().lower()
    vis = vis if vis in ("public", "private") else DEFAULT_VISIBILITY
    form = {"title": title, "category": category, "visibility": vis}
    f = request.files.get("file")
    bad = check_password()      # the same password as uploads in the file area
    if bad:
        body, _ = render_pages(errors={"password": bad[0]}, form=form)
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
        body, _ = render_pages(errors=errors, form=form)
        return body, 400
    slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")[:40] or "page"
    stored = f"{secrets.token_hex(6)}-{slug}.html"
    path = os.path.join(PAGE_FILES_DIR, stored)
    with open(path, "xb") as fh:
        fh.write(data)
    os.chmod(path, 0o640)
    execute("""INSERT INTO pages (title, category, stored_filename, original_filename, uploaded_by,
               uploaded_at, status, visibility, size)
               VALUES (?, ?, ?, ?, ?, ?, 'published', ?, ?)""",
            (title, category, stored, secure_filename(f.filename), AUTH_USER, time.time(), vis, len(data)))
    flash(f"Published “{title}” in {category} as {vis}.")
    return redirect(url_for("pages"))


@app.post("/pages/<int:pid>/status")
def set_status(pid):
    bad = check_password()
    if bad:
        return bad
    row = get_page(pid)
    new = "published" if request.form.get("status") == "published" else "unpublished"
    execute("UPDATE pages SET status = ? WHERE id = ?", (new, pid))
    flash(f"“{row['title']}” is now {new}.")
    return "", 204


@app.post("/pages/<int:pid>/visibility")
def set_page_visibility(pid):
    bad = check_password()
    if bad:
        return bad
    row = get_page(pid)
    vis = (request.form.get("visibility") or "").strip().lower()
    if vis not in ("public", "private"):
        return "Choose public or private.", 400
    execute("UPDATE pages SET visibility = ? WHERE id = ?", (vis, pid))
    flash(f"“{row['title']}” is now {vis}.")
    return "", 204


@app.get("/p/<int:pid>")
def view_page(pid):
    rows = query("SELECT * FROM pages WHERE id = ?", (pid,))
    if not rows:
        return msg_page("Page not found", "This page doesn’t exist.", 404)
    row = rows[0]
    if not can_view(row):
        # private or unpublished: ask for the password (same answer either way, nothing leaks)
        return redirect(url_for("unlock", next=request.path))
    path = os.path.join(PAGE_FILES_DIR, row["stored_filename"])
    if not os.path.isfile(path):
        return msg_page("Page not found", "The file for this page is missing on the server.", 404)
    resp = send_from_directory(PAGE_FILES_DIR, row["stored_filename"], mimetype="text/html")
    resp.headers["Cache-Control"] = "no-cache" if row["visibility"] == "public" else "private, no-store"
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


try:
    init_files_db()
except (OSError, sqlite3.Error) as e:
    sys.exit(f"[FATAL] Cannot prepare the public/private settings database {FILES_DB}: {e}")

if PAGES_ENABLED:
    try:
        init_pages()
    except OSError as e:
        sys.exit(f"[FATAL] Cannot prepare the pages folder {PAGES_DIR}: {e}")
    print(f"[fileshare] pages enabled | folder: {PAGES_DIR}", file=sys.stderr)


@app.errorhandler(413)
def too_large(_):
    return f"File too large (limit {MAX_MB} MB).", 413


if __name__ == "__main__":
    app.run(host=HOST, port=PORT)
