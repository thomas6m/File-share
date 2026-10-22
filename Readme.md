# FileNest

FileNest: your files, your pages, one place. A small web app for moving files between a desktop and a Unix server through a browser.
Files and folders can be **added and downloaded only**. There is no delete, rename or overwrite.

It can also host **static HTML pages** with a title, category and per-user or per-group viewing (see
[Hosted pages](#hosted-pages)).

Built with Python and Flask, and designed to run on CentOS as a systemd service.

## Features

- Browser UI with drag-and-drop upload, upload queue and live progress (percentage and speed)
- Folders and subfolders, browsed like a repository: breadcrumb path, folders listed first, upload into the folder you are viewing
- **New folder** button to create folders (up to `MAX_FOLDER_DEPTH` levels deep)
- Download list with filter and sorting by name, size or modified date
- No delete, no rename, no overwrite. A duplicate filename is saved with a timestamp added
- **Pages**: publish self-contained HTML pages with a mandatory title and category. Signs in with the same shared password as uploads, or optionally with personal accounts that add per-user and per-group viewing
- Optional protection for downloads (browser login prompt) and for uploads (password field)
- Password stored encrypted (Fernet) in a `.secrets` folder, never in plain text
- Lockout after repeated wrong upload passwords
- Light and dark mode, works on phones, no external fonts or CDNs (works offline)
- Everything is tuned from a CONFIG block at the top of `app.py`

## Project layout

```
/opt/fileshare/
├── app.py               # the application (CONFIG block at the top)
├── manage_users.py      # optional: personal accounts for Pages (only with PAGES_LOGIN = "accounts")
├── requirements.txt     # flask, cryptography, gunicorn
├── venv/                # Python virtual environment
├── .secrets/            # .fernet.key, .password.enc, users.json, .session.key
├── pages/               # hosted pages: pages.db (metadata) and files/ (the HTML), created automatically
└── fileshare/           # uploaded files and folders live here (created automatically)
    ├── reports/         # folders created from the UI
    │   └── 2026_q4/
    └── notes.txt
```

By default both `fileshare/` and `.secrets/` are looked up in the **current working directory**.

## Requirements

- CentOS with Python 3.8 or newer
- Python packages: `flask`, `cryptography`, `gunicorn`

## Installation

```bash
# 1. Service user (no login shell)
sudo useradd -r -m -d /opt/fileshare -s /sbin/nologin fileshare

# 2. Copy the app
sudo cp app.py /opt/fileshare/
cd /opt/fileshare

# 3. Dependencies
cat <<EOF | sudo tee requirements.txt
flask
cryptography
gunicorn
EOF

sudo -u fileshare python3 -m venv venv
sudo -u fileshare venv/bin/python3 -m pip install --upgrade pip
sudo -u fileshare venv/bin/pip3 install --no-cache-dir -r requirements.txt
```

### Set the password

The app reads its password from the encrypted files created by the password encryption script.
Run that script from `/opt/fileshare` as the `fileshare` user:

```bash
sudo -u fileshare venv/bin/python3 encrypt_password.py
```

Choose **3. Generate Key + Encrypt Password**, then folder option **1** (the `.secrets` folder in the
current directory). This creates `.secrets/.fernet.key` and `.secrets/.password.enc`.

If you re-generate the key later, the old encrypted password can no longer be decrypted.

### Optional: personal accounts for Pages

By default Pages sign in with the same shared password as uploads, plus a display name, so there is nothing more to
set up. Only if you set `PAGES_LOGIN = "accounts"` do you need personal accounts, which add per-user and per-group
viewing and a trusted "Uploaded by". Create them as the `fileshare` user from `/opt/fileshare`:

```bash
sudo -u fileshare venv/bin/python3 manage_users.py add alice --role admin --groups ops,apac
sudo -u fileshare venv/bin/python3 manage_users.py add bob --groups ops
sudo -u fileshare venv/bin/python3 manage_users.py list
```

Passwords are asked interactively (at least 8 characters) and stored as salted hashes in `.secrets/users.json`.
Other commands: `passwd`, `groups`, `role`, `remove`. Changes apply immediately. The last admin can't be removed or
demoted.

### Permissions

```bash
sudo chown -R fileshare:fileshare /opt/fileshare
sudo chmod 750 /opt/fileshare
sudo chmod 640 /opt/fileshare/app.py /opt/fileshare/requirements.txt
sudo chmod 700 /opt/fileshare/.secrets
sudo chmod 600 /opt/fileshare/.secrets/.fernet.key /opt/fileshare/.secrets/.password.enc
sudo -u fileshare mkdir -p /opt/fileshare/fileshare
sudo chmod 750 /opt/fileshare/fileshare
```

| Path | Owner | Mode |
|---|---|---|
| `/opt/fileshare/` | `fileshare` | `750` |
| `app.py`, `requirements.txt` | `fileshare` | `640` |
| `.secrets/` | `fileshare` | `700` |
| `.fernet.key`, `.password.enc` | `fileshare` | `600` |
| `fileshare/` (uploads) | `fileshare` | `750` |

### Run as a service

Create `/etc/systemd/system/fileshare.service`:

```ini
[Unit]
Description=FileNest
After=network.target

[Service]
User=fileshare
WorkingDirectory=/opt/fileshare
ExecStart=/opt/fileshare/venv/bin/gunicorn -w 2 --timeout 600 -b 0.0.0.0:8080 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now fileshare
sudo systemctl status fileshare
```

`WorkingDirectory` matters: the app finds `fileshare/` and `.secrets/` relative to it.

### Firewall

Open the port to everyone:

```bash
sudo firewall-cmd --permanent --add-port=8080/tcp
sudo firewall-cmd --reload
```

Or allow only a specific network (recommended):

```bash
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.0.0.0/24" port port="8080" protocol="tcp" accept'
sudo firewall-cmd --reload
```

Then browse to `http://<server-ip>:8080`.

## Using folders

- Click a folder to open it. The breadcrumb at the top of the list (`Home / reports / 2026_q4`) takes you back up.
- **Upload files** always saves into the folder you are viewing. The panel shows the destination.
- **New folder** creates a folder inside the current one. It asks for the upload password when
  `PROTECT_UPLOAD` is on.
- Folder and file names are sanitised: spaces become underscores, and characters other than letters,
  numbers, `-`, `_` and `.` are removed. Names can't start with a dot.
- Folders can't be renamed or deleted from the app. If a folder name already exists, creation is refused.
  If a file name already exists in a folder, the new file is saved with a timestamp added.
- Direct links work: `/tree/<folder path>` opens a folder and `/download/<file path>` downloads a file.

## Hosted pages

Open the **Pages** tab. There are two sign-in modes, set with `PAGES_LOGIN`:

| | `shared` (default) | `accounts` |
|---|---|---|
| Sign in with | The shared upload password and a display name | A personal username and password (`manage_users.py`) |
| Uploaded by | The name typed at sign-in (not verified) | The signed-in account (trusted) |
| Who can view | Everyone who signs in | Chosen per page: users and `@groups` |
| Unpublish / publish | Anyone signed in | The uploader or an admin |

With one shared password nobody can prove who they are, so `shared` mode can't restrict viewing by person or group.
Choose `accounts` if you need that.

**Publishing.** Sign in, fill in the title and category (both required), optionally who can view it, choose a
`.html` file, enter the upload password and click **Publish**. The upload password is the same shared password used
for file uploads, and it is asked for only while `PROTECT_UPLOAD` is `True`. Wrong passwords count toward the same
lockout (`MAX_FAILED`, `LOCKOUT_SEC`). Each page keeps this metadata:

| Field | Source |
|---|---|
| Title | Entered in the form (required) |
| Category | Entered in the form (required). Existing categories are suggested. |
| Stored filename | Generated, for example `ebf6e433bce5-ossm3-infra.html` |
| Uploaded by | The name entered at sign-in (`shared`) or the signed-in account (`accounts`) |
| Upload date | Server time when published |
| Publication status | `Published` or `Unpublished` |
| Users or groups permitted to view | `accounts` mode: entered in the form, empty means every signed-in user. `shared` mode: not used, everyone who signs in can view. |

**Who can view** (`accounts` mode). Enter usernames and `@groups` separated by commas, for example `alice, @ops`. The uploader and
admins can always open a page. Everyone else must be listed (directly or through a group), and the page must be
published. Unknown names are rejected.

**Status.** In `accounts` mode the uploader or an admin can **Unpublish** a page (it disappears for other people)
and publish it again. In `shared` mode anyone signed in can change the status, and unpublished pages stay listed so they
can be published again. Pages can't be deleted or replaced. Publish a new page to change one.

**Page requirements.**

- One self-contained file with CSS, scripts and images inline (other files aren't hosted alongside it)
- `.html` or `.htm`, saved as UTF-8, up to `PAGE_MAX_MB`
- Pages open at `/p/<id>`. Every request is checked against the signed-in user, so links only work for people
  who are allowed to see the page.

**Sandbox.** With `PAGE_SANDBOX = True` (default) each page is served with a Content-Security-Policy sandbox. Scripts
still run, but the page gets an isolated origin: it can't read this site's cookies or call its endpoints, which
stops a published page from acting as the person viewing it. The trade-off is that pages can't use
`localStorage` or `sessionStorage`, and some pages that remember settings (for example a theme toggle) may show
a script error for that feature. Setting `PAGE_SANDBOX = False` removes the isolation, so do it only if everyone
who can publish is fully trusted.

## Configuration

Edit the CONFIG block at the top of `app.py`. Environment variables (for example in the systemd unit
with `Environment=`) override the script values where listed.

| Variable | Default | Environment override | Description |
|---|---|---|---|
| `SHARE_DIR` | `""` (`<cwd>/fileshare`) | `SHARE_DIR` | Where files are stored |
| `SECRETS_DIR` | `""` (`<cwd>/.secrets`) | `SECRETS_DIR` | Folder with `.fernet.key` and `.password.enc` |
| `MAX_UPLOAD_MB` | `2048` | `MAX_UPLOAD_MB` | Max size of one upload request (all files in it combined) |
| `HOST` | `0.0.0.0` | `HOST` | Bind address (used when run with `python3 app.py`) |
| `PORT` | `8080` | `PORT` | Listen port (used when run with `python3 app.py`) |
| `PROTECT_DOWNLOAD` | `True` | `PROTECT_DOWNLOAD` | Browser login prompt to view and download |
| `PROTECT_UPLOAD` | `True` | `PROTECT_UPLOAD` | Password field on the upload form |
| `AUTH_USER` | `fileshare` | `SHARE_USER` | Username for the download login prompt |
| `APP_TITLE` | `FileNest` | none | Name shown in the header and browser tab |
| `APP_TAGLINE` | `Your files. Your pages. One place.` | none | Line under the name in the header |
| `PAGE_MAX_WIDTH` | `100%` | none | Page width cap. `100%` fills the window; use e.g. `1400px` or `90vw` to limit it |
| `MAX_FOLDER_DEPTH` | `8` | none | How many folder levels deep users can create |
| `PAGES_ENABLED` | `True` | `PAGES_ENABLED` | Turn the Pages area on or off. When off, `/pages`, `/p/` and `/login` return 404. |
| `PAGES_LOGIN` | `shared` | `PAGES_LOGIN` | `shared` = shared password plus a display name. `accounts` = personal accounts from `manage_users.py`. |
| `PAGES_DIR` | `""` (`<cwd>/pages`) | `PAGES_DIR` | Where page files and `pages.db` are stored |
| `USERS_FILE` | `""` (`<SECRETS_DIR>/users.json`) | `USERS_FILE` | User accounts, managed with `manage_users.py` |
| `PAGE_MAX_MB` | `20` | `PAGE_MAX_MB` | Max size of one HTML page |
| `PAGE_SANDBOX` | `True` | `PAGE_SANDBOX` | Isolate hosted pages (see Hosted pages) |
| `SESSION_HOURS` | `8` | `SESSION_HOURS` | How long a Pages sign-in lasts |
| `COOKIE_SECURE` | `False` | `COOKIE_SECURE` | Set `True` when served over HTTPS, so the cookie is never sent over HTTP |
| `MAX_FAILED` | `5` | none | Wrong upload passwords allowed per IP before lockout |
| `LOCKOUT_SEC` | `300` | none | Lockout window in seconds |
| `SHOW_HIDDEN` | `False` | none | List files that start with `.` |

Boolean environment values accept `1`, `true`, `yes` or `on`. After a change, run
`sudo systemctl restart fileshare`.

### Protection modes

| `PROTECT_DOWNLOAD` | `PROTECT_UPLOAD` | Behaviour |
|---|---|---|
| `True` | `True` | Login to view and download. Password asked again on each upload. |
| `True` | `False` | Login to view and download. No extra password for uploads. |
| `False` | `True` | Anyone can view and download. Uploads need the password. |
| `False` | `False` | Fully open. The `.secrets` folder is not needed. |

The app logs its active mode at startup. Check it with `journalctl -u fileshare`:

```
[fileshare] download protected: True | upload protected: True
```

If a protected mode is on and the key or password file can't be read, the app exits with an error
instead of starting unprotected.

### Choosing the upload size limit

- Keep it well below the free space on the filesystem that holds `fileshare/`.
- It limits the whole request, so five 500 MB files in one go count as 2.5 GB.
- If uploads take longer than the gunicorn `--timeout`, they are cut off. Raise the timeout for large
  files or slow links.
- If you add nginx in front, set `client_max_body_size` to the same value.

## Security notes

- **Plain HTTP.** Passwords and files travel unencrypted. Use it on a trusted network, or put nginx
  with TLS in front.
- **Files use one shared password**, so you can't tell who uploaded a file. Pages use personal accounts, so every
  page records who published it.
- **Pages sign-in** uses a signed, HttpOnly, SameSite=Lax session cookie plus a token on every form, and failed
  sign-ins are rate-limited per IP. The cookie travels in clear text over plain HTTP, so use TLS (and set
  `COOKIE_SECURE = True`) beyond a trusted network.
- **Pages sign-in.** In `shared` mode the sign-in password is the same one used for uploads, so the "Uploaded by"
  name is only a label that anyone can type, and everyone signed in can see and change every page. In `accounts` mode
  each page records a verified uploader and can be limited to chosen users and groups. While `PROTECT_UPLOAD` is on,
  publishing also asks for the upload password. `PROTECT_DOWNLOAD` protects the file area only.
- **Hosted pages are code that runs in people's browsers.** Keep `PAGE_SANDBOX` on and only give accounts to people
  you trust to publish.
- **Key and password sit side by side.** Anyone who can read `.secrets/` can decrypt the password.
  The `700`/`600` permissions are what protect it. The encryption mainly keeps it out of plain sight.
- **The app has no delete function**, but an admin or the `fileshare` user can still delete files from
  the shell. To block that at filesystem level, make the uploads folder append-only (works on XFS and
  ext4, only root can undo it):

  ```bash
  sudo chattr +a /opt/fileshare/fileshare
  lsattr -d /opt/fileshare/fileshare
  ```

  This protects the top-level folder only. Folders created later from the UI are not append-only
  automatically. To cover existing subfolders run `sudo chattr -R +a /opt/fileshare/fileshare`, and repeat
  it from time to time (for example from cron) for newly created ones.

- **Lockout is per worker.** With `-w 2` the effective limit is slightly looser than `MAX_FAILED`.
- Only items inside `fileshare/` are served. Paths are validated segment by segment (no `..`, no hidden names),
  and symbolic links are ignored, so a link inside `fileshare/` can't expose files elsewhere on the server.
- New folders are created with mode `750`.

## Updating

```bash
sudo cp app.py /opt/fileshare/app.py
sudo chown fileshare:fileshare /opt/fileshare/app.py
sudo systemctl restart fileshare
```

## Troubleshooting

| Problem | What to check |
|---|---|
| Service fails to start | `journalctl -u fileshare -e`. A `[FATAL] Cannot load password` line means the key or password file is missing, unreadable or doesn't match. |
| Upload gives a 413 error | The upload is over `MAX_UPLOAD_MB`. If nginx is in front, also check `client_max_body_size`. |
| Upload cut off on large files | Raise gunicorn `--timeout` in the systemd unit. |
| "Wrong upload password" | Re-run the encryption script. Confirm you are using the password you entered there. |
| "Too many wrong passwords" (429) | Wait `LOCKOUT_SEC` seconds, or restart the service to clear the counter. |
| Permission denied when saving | Check that `fileshare` owns `/opt/fileshare/fileshare`. With SELinux enforcing, run `sudo ausearch -m avc -ts recent`. |
| "No user accounts exist yet" on the sign-in page | Only in `accounts` mode: create the first account with `manage_users.py add <name> --role admin`. |
| Signed out immediately or in a loop | Check that `.secrets/.session.key` exists and is readable by the service user, or set a fixed `SECRET_KEY`. |
| A published page's script shows a storage error | The sandbox blocks `localStorage`. See Hosted pages. |
| "Cannot prepare the pages folder" at startup | The service user needs write access to `PAGES_DIR`. |
| Can't reach the page | Check `systemctl status fileshare`, the firewall rule and that the port matches. |
| Uploads fail after `chattr +a` | Appending is allowed but renaming is not. Check that `lsattr -d` shows `a` only on the uploads folder. |
| Folder creation fails with "Could not create the folder" | The `fileshare` user needs write access to the parent folder. Check ownership and mode. |
| Flash messages ("Uploaded: ...") don't always appear | Set a fixed `SECRET_KEY` environment variable. By default the app derives a stable one from the key file. |

SELinux fix if writes are denied:

```bash
sudo semanage fcontext -a -t httpd_sys_rw_content_t "/opt/fileshare/fileshare(/.*)?"
sudo restorecon -Rv /opt/fileshare/fileshare
```

## Version control

If you keep the project in git, add a `.gitignore`. Never commit the secrets or the uploads:

```
.secrets/
fileshare/
pages/
venv/
__pycache__/
```

Each server should have its own `.secrets` folder. Don't copy keys between servers.
