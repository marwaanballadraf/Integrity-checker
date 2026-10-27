import sys
from pathlib import Path

from integrity import sha256_prefix
from baseline import load_db, collect_files


def check(target):
    db = load_db()
    if not db:
        print("No baseline found. Run init first.")
        return 2

    p = Path(target).resolve()
    current = [str(f) for f in collect_files(target)] if p.exists() else []
    if p.is_dir():
        tracked = [k for k in db if Path(k).is_relative_to(p)]
    else:
        tracked = [str(p)] if str(p) in db else []

    if not current and not tracked:
        print(f"Error: nothing to check at {target} (not found and not in baseline).")
        return 2

    problems = 0
    appended = 0

    for path in current:
        if path not in db:
            print(f"{path}: Status: New (not in baseline)")
            problems += 1
            continue

        old_hash = db[path]["sha256"]
        old_size = db[path]["size"]
        try:
            size_now = Path(path).stat().st_size
            if size_now < old_size:
                print(f"{path}: Status: Truncated (was {old_size} bytes, now {size_now})")
                problems += 1
                continue
            prefix_hash = sha256_prefix(path, old_size)
        except PermissionError:
            print(f"{path}: Status: Unreadable (permission denied)")
            problems += 1
            continue
        except FileNotFoundError:
            print(f"{path}: Status: Missing (vanished during check)")
            problems += 1
            continue

        if prefix_hash != old_hash:
            print(f"{path}: Status: Modified (existing content changed)")
            problems += 1
        elif size_now > old_size:
            print(f"{path}: Status: Appended (+{size_now - old_size} bytes, old content intact)")
            appended += 1
        else:
            print(f"{path}: Status: Unmodified")

    for path in tracked:
        if path not in current:
            print(f"{path}: Status: Missing (file deleted?)")
            problems += 1

    print(f"\nChecked {len(current)} file(s), {problems} problem(s) found, {appended} appended.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(check(sys.argv[1]))
