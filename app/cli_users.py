from __future__ import annotations
import argparse
import os
from pathlib import Path

from .storage import ensure_files, load_users, save_users, utcnow_iso
from .auth import hash_password

def ulid_like(prefix: str) -> str:
    import time, secrets
    return f"{prefix}_{int(time.time()*1000)}_{secrets.token_hex(6)}"

def main():
    parser = argparse.ArgumentParser(prog="miniipam-users")
    parser.add_argument("--data-dir", default=os.getenv("DATA_DIR", "/data"))
    sub = parser.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("create")
    c.add_argument("username")
    c.add_argument("password")
    c.add_argument("--role", default="admin", choices=["admin", "readwrite", "readonly"])

    r = sub.add_parser("reset-password")
    r.add_argument("username")
    r.add_argument("password")

    d = sub.add_parser("disable")
    d.add_argument("username")

    e = sub.add_parser("enable")
    e.add_argument("username")

    l = sub.add_parser("list")

    args = parser.parse_args()
    data_dir = Path(args.data_dir)
    ensure_files(data_dir)

    users_file = load_users(data_dir)

    if args.cmd == "create":
        if any(u.username == args.username for u in users_file.users):
            raise SystemExit("User already exists")
        now = utcnow_iso()
        users_file.users.append({
            "id": ulid_like("user"),
            "username": args.username,
            "password_bcrypt": hash_password(args.password),
            "role": args.role,
            "created_at": now,
            "disabled": False
        })
        save_users(data_dir, users_file)
        print(f"Created user: {args.username} ({args.role})")

    elif args.cmd == "reset-password":
        u = next((u for u in users_file.users if u.username == args.username), None)
        if not u:
            raise SystemExit("User not found")
        u.password_bcrypt = hash_password(args.password)  # type: ignore
        save_users(data_dir, users_file)
        print(f"Password reset for: {args.username}")

    elif args.cmd == "disable":
        u = next((u for u in users_file.users if u.username == args.username), None)
        if not u:
            raise SystemExit("User not found")
        u.disabled = True  # type: ignore
        save_users(data_dir, users_file)
        print(f"Disabled: {args.username}")

    elif args.cmd == "enable":
        u = next((u for u in users_file.users if u.username == args.username), None)
        if not u:
            raise SystemExit("User not found")
        u.disabled = False  # type: ignore
        save_users(data_dir, users_file)
        print(f"Enabled: {args.username}")

    elif args.cmd == "list":
        for u in users_file.users:
            print(f"{u.username:16} role={u.role:9} disabled={u.disabled}")

if __name__ == "__main__":
    main()
