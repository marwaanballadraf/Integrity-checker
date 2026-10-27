import sys
from pathlib import Path

from integrity import hash_and_size
from baseline import load_db, save_db, collect_files


def update(target):
    db = load_db()
    p = Path(target).resolve()

    current = [str(f) for f in collect_files(target)] if p.exists() else []
    if p.is_dir():
        tracked = [k for k in db if Path(k).is_relative_to(p)]
    else:
        tracked = [str(p)] if str(p) in db else []

    if not current and not tracked:
        print("Nothing to update.")
        return 1

    answer = input(
        f"This will accept the CURRENT state of {target} as trusted. Continue? [y/N] "
    )
    if answer.strip().lower() != "y":
        print("Cancelled.")
        return 1

    updated = removed = 0
    for path in current:
        try:
            digest, size = hash_and_size(path)
            db[path] = {"sha256": digest, "size": size}
            updated += 1
        except PermissionError:
            print(f"Skipped (permission denied): {path}")

    for path in tracked:
        if path not in current:
            del db[path]
            removed += 1

    save_db(db)
    print(f"Hash updated successfully. ({updated} updated, {removed} removed)")
    return 0


if __name__ == "__main__":
    sys.exit(update(sys.argv[1]))
