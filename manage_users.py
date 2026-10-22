#!/usr/bin/env python3
"""
Manage FileNest user accounts. Only needed when PAGES_LOGIN = "accounts" in app.py.

Accounts live in users.json inside the secrets folder. Passwords are stored as
salted hashes, never in plain text. Changes apply immediately, no restart needed.

Examples (run as the service user, from the app folder):
  python3 manage_users.py add alice --role admin --groups ops,apac
  python3 manage_users.py add bob --groups ops
  python3 manage_users.py passwd bob
  python3 manage_users.py groups bob ops,dev        # replace bob's groups
  python3 manage_users.py role bob admin
  python3 manage_users.py list
  python3 manage_users.py remove bob
"""
import argparse
import getpass
import json
import os
import re
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")
GROUP_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
MIN_PASSWORD = 8


def default_file():
    if os.environ.get("USERS_FILE"):
        return Path(os.environ["USERS_FILE"])
    secrets_dir = Path(os.environ.get("SECRETS_DIR") or Path.cwd() / ".secrets")
    return secrets_dir / "users.json"


def load(path):
    if not path.exists():
        return {"users": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        sys.exit(f"Cannot read {path}: {e}")
    data.setdefault("users", {})
    return data


def save(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)          # atomic, so the app never reads a half-written file
    os.chmod(path, 0o600)


def parse_groups(text):
    groups = sorted({g.strip().lower().lstrip("@") for g in (text or "").split(",") if g.strip()})
    for g in groups:
        if not GROUP_RE.match(g):
            sys.exit(f"Invalid group name: {g!r} (use letters, numbers, . _ -)")
    return groups


def ask_password(args):
    if args.password_stdin:
        pw = sys.stdin.readline().rstrip("\n")
    else:
        pw = getpass.getpass("Password: ")
        if pw != getpass.getpass("Repeat password: "):
            sys.exit("Passwords do not match.")
    if len(pw) < MIN_PASSWORD:
        sys.exit(f"Use at least {MIN_PASSWORD} characters.")
    return generate_password_hash(pw)


def need_user(data, name):
    name = name.lower()
    if name not in data["users"]:
        sys.exit(f"No such user: {name}")
    return name


def main():
    ap = argparse.ArgumentParser(description="Manage FileNest user accounts.")
    ap.add_argument("--file", type=Path, default=default_file(), help="users.json location")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("add", help="create a user")
    p.add_argument("name")
    p.add_argument("--role", choices=["user", "admin"], default="user")
    p.add_argument("--groups", default="", help="comma-separated, e.g. ops,apac")
    p.add_argument("--password-stdin", action="store_true", help="read the password from stdin")

    p = sub.add_parser("passwd", help="change a user's password")
    p.add_argument("name")
    p.add_argument("--password-stdin", action="store_true")

    p = sub.add_parser("groups", help="replace a user's groups")
    p.add_argument("name")
    p.add_argument("groups", help="comma-separated; empty string clears them")

    p = sub.add_parser("role", help="set a user's role")
    p.add_argument("name")
    p.add_argument("role", choices=["user", "admin"])

    p = sub.add_parser("remove", help="remove a user (their published pages stay)")
    p.add_argument("name")
    p.add_argument("--yes", action="store_true", help="do not ask for confirmation")

    sub.add_parser("list", help="show all users")

    args = ap.parse_args()
    data = load(args.file)
    users = data["users"]

    if args.cmd == "add":
        name = args.name.lower()
        if not NAME_RE.match(name):
            sys.exit("Username: 2-32 characters, lowercase letters, numbers, . _ - (start with a letter or number).")
        if name in users:
            sys.exit(f"User {name} already exists. Use 'passwd', 'groups' or 'role' to change it.")
        users[name] = {"password_hash": ask_password(args), "role": args.role,
                       "groups": parse_groups(args.groups)}
        save(args.file, data)
        print(f"Created {name} ({args.role}) in {args.file}")

    elif args.cmd == "passwd":
        name = need_user(data, args.name)
        users[name]["password_hash"] = ask_password(args)
        save(args.file, data)
        print(f"Password updated for {name}.")

    elif args.cmd == "groups":
        name = need_user(data, args.name)
        users[name]["groups"] = parse_groups(args.groups)
        save(args.file, data)
        print(f"{name} is now in: {', '.join(users[name]['groups']) or '(no groups)'}")

    elif args.cmd == "role":
        name = need_user(data, args.name)
        admins = [n for n, u in users.items() if u.get("role") == "admin" and n != name]
        if args.role != "admin" and not admins:
            sys.exit("Refusing to remove the last admin.")
        users[name]["role"] = args.role
        save(args.file, data)
        print(f"{name} is now {args.role}.")

    elif args.cmd == "remove":
        name = need_user(data, args.name)
        others = [n for n, u in users.items() if u.get("role") == "admin" and n != name]
        if users[name].get("role") == "admin" and not others:
            sys.exit("Refusing to remove the last admin.")
        if not args.yes and input(f"Remove {name}? (y/n): ").strip().lower() != "y":
            sys.exit("Aborted.")
        del users[name]
        save(args.file, data)
        print(f"Removed {name}.")

    elif args.cmd == "list":
        if not users:
            print(f"No users yet in {args.file}")
        for n in sorted(users):
            u = users[n]
            print(f"{n:20} {u.get('role', 'user'):6} groups: {', '.join(u.get('groups', [])) or '-'}")


if __name__ == "__main__":
    main()
