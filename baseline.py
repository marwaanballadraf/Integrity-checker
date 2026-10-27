import getpass
import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path

from integrity import hash_and_size

BASE_DIR = Path.home() / ".integrity-check"
DB_PATH = BASE_DIR / "baseline.json"
SALT_PATH = BASE_DIR / "salt"

_key = None  # derived once per run


class BaselineError(Exception):
    pass


def _ask_passphrase(confirm):
    env = os.environ.get("INTEGRITY_PASSPHRASE")
    if env:
        return env
    p = getpass.getpass("Baseline passphrase: ")
    if confirm and getpass.getpass("Repeat passphrase: ") != p:
        raise BaselineError("Passphrases do not match.")
    return p


def _get_key():
    global _key
    if _key is not None:
        return _key
    BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    new_install = not SALT_PATH.exists()
    if new_install:
        SALT_PATH.write_bytes(os.urandom(16))
        os.chmod(SALT_PATH, 0o600)
    salt = SALT_PATH.read_bytes()
    passphrase = _ask_passphrase(confirm=new_install)
    _key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 200_000)
    return _key


def _sign(files):
    data = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(_get_key(), data, hashlib.sha256).hexdigest()


def collect_files(target):
    """Return the single file, or every file under a directory."""
    p = Path(target).resolve()
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(f for f in p.rglob("*") if f.is_file() and not f.is_symlink())
    raise FileNotFoundError(f"No such file or directory: {target}")


def load_db():
    if not DB_PATH.exists():
        return {}
    try:
        doc = json.loads(DB_PATH.read_text())
        files, mac = doc["files"], doc["hmac"]
    except (ValueError, KeyError, TypeError):
        raise BaselineError("Baseline is corrupted or in an old format.")
    if not hmac.compare_digest(mac, _sign(files)):
        raise BaselineError(
            "Baseline signature mismatch: wrong passphrase, or the baseline was tampered with."
        )
    return files


def save_db(db):
    BASE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    doc = {"version": 2, "files": db, "hmac": _sign(db)}
    fd, tmp = tempfile.mkstemp(dir=BASE_DIR)
    with os.fdopen(fd, "w") as f:
        json.dump(doc, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, DB_PATH)


def init(target):
    _get_key()  # ask for the passphrase up front, before hashing anything
    db = load_db()
    stored = 0
    for f in collect_files(target):
        try:
            digest, size = hash_and_size(f)
            db[str(f)] = {"sha256": digest, "size": size}
            stored += 1
        except PermissionError:
            print(f"Skipped (permission denied): {f}")
    save_db(db)
    print(f"Hashes stored successfully. ({stored} files)")


if __name__ == "__main__":
    import sys
    init(sys.argv[1])
