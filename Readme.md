# FileShare

A small web app for moving files between a desktop and a Unix server through a browser.
Files and folders can be **added and downloaded only**. There is no delete, rename or overwrite.

Built with Python and Flask, and designed to run on CentOS as a systemd service.

## Features

- Browser UI with drag-and-drop upload, upload queue and live progress (percentage and speed)
- Folders and subfolders, browsed like a repository: breadcrumb path, folders listed first, upload into the folder you are viewing
- **New folder** button to create folders (up to `MAX_FOLDER_DEPTH` levels deep)
- Download list with filter and sorting by name, size or modified date
- No delete, no rename, no overwrite. A duplicate filename is saved with a timestamp added
- Optional protection for downloads (browser login prompt) and for uploads (password field)
- Password stored encrypted (Fernet) in a `.secrets` folder, never in plain text
- Lockout after repeated wrong upload passwords
- Light and dark mode, works on phones, no external fonts or CDNs (works offline)
- Everything is tuned from a CONFIG block at the top of `app.py`

## Project layout

```
/opt/fileshare/
├── app.py               # the application (CONFIG block at the top)
├── requirements.txt     # flask, cryptography, gunicorn
├── venv/                # Python virtual environment
├── .secrets/            # .fernet.key and .password.enc (created by the encryption script)
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
Description=FileShare
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
| `APP_TITLE` | `File share` | none | Name shown in the header and browser tab |
| `PAGE_MAX_WIDTH` | `100%` | none | Page width cap. `100%` fills the window; use e.g. `1400px` or `90vw` to limit it |
| `MAX_FOLDER_DEPTH` | `8` | none | How many folder levels deep users can create |
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
- **One shared password.** There are no per-user accounts, so you can't tell who uploaded a file.
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
venv/
__pycache__/
```

Each server should have its own `.secrets` folder. Don't copy keys between servers.
