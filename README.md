# integrity-check

A command-line tool that detects tampering in log files using SHA-256 hashing,
append-aware verification, and an HMAC-signed baseline.

Built as a learning project (roadmap.sh "File Integrity Checker") in Python 3,
standard library only.

## Why this exists

Attackers who gain access often edit or delete logs to hide their tracks.
File integrity monitoring (FIM) records a trusted fingerprint of each file and
flags later changes. Logs make that harder than normal files, because active
logs legitimately grow all the time.

## Features

- Accepts a single log file or a whole directory (recursive)
- SHA-256 hashing, read in chunks so multi-GB logs don't fill memory
- **Append-aware:** normal growth at the end of a log is reported as `Appended`,
  not as tampering
- Detects edits to existing content, truncation, deleted files, and unknown new files
- **HMAC-signed baseline:** editing the stored baseline is detected without
  the passphrase
- Baseline stored outside the log directory with restrictive permissions
  (`700` directory, `600` files), written atomically
- Meaningful exit codes for scripting and cron

## Usage

    ./integrity-check init /var/log          # hash everything and store the baseline
    ./integrity-check check /var/log/auth.log
    ./integrity-check update /var/log/syslog # accept the current state as trusted

Requires Python 3.9+. On first `init` you choose a passphrase (asked twice).
Later commands ask for it once. For unattended runs it can be supplied through
the `INTEGRITY_PASSPHRASE` environment variable (this lowers security, see
Limitations).

### Statuses

| Status | Meaning | Alarm |
|---|---|---|
| Unmodified | Identical to baseline | no |
| Appended | Old content intact, new data added at the end | no |
| Modified | Previously recorded content changed | yes |
| Truncated | File is smaller than at baseline (lines removed) | yes |
| Missing | In the baseline but gone from disk | yes |
| New | On disk but not in the baseline | yes |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Everything clean |
| 1 | Tampering indicators found |
| 2 | Could not check (no baseline, bad path, signature mismatch) |

## Demo

    $ ./integrity-check init ~/logtest
    Hashes stored successfully. (1 files)

    $ echo "line4 new entry" >> ~/logtest/app.log
    $ ./integrity-check check ~/logtest/app.log
    /root/logtest/app.log: Status: Appended (+16 bytes, old content intact)

    $ sed -i 's/ip=10.0.0.5/ip=127.0.0.1/' ~/logtest/app.log
    $ ./integrity-check check ~/logtest/app.log
    /root/logtest/app.log: Status: Modified (existing content changed)

    $ sed -i '2d' ~/logtest/app.log
    $ ./integrity-check check ~/logtest/app.log
    /root/logtest/app.log: Status: Truncated (was 106 bytes, now 64)

## How it works

1. **Hashing.** `init` records the SHA-256 and byte count of each file, counted
   in the same pass so the two always agree even on a live log.
2. **Append-aware check.** `check` hashes only the first N bytes of the file
   (N = size at baseline). A match means the old content is untouched. A longer
   file is `Appended`, a shorter one is `Truncated`, a mismatch is `Modified`.
3. **Signed baseline.** The baseline is signed with HMAC-SHA256. The key is
   derived from your passphrase with PBKDF2 (200,000 iterations) and a random
   salt. The passphrase is never stored. If the signature does not verify, the
   tool refuses to compare against the baseline.

## Tests

    python3 -m pytest -v

The suite covers clean checks, appends, edits, truncation, deleted and planted
files, nonexistent paths, tampered baselines, wrong passphrases, and the
update flow.

## Limitations

- **Forged appends pass.** Fake lines added at the end of a log look like normal
  growth. Hash chaining would detect more of this.
- **Log rotation** looks like truncation. Run `update` after confirming a
  rotation was legitimate.
- **The baseline can be deleted and recreated** by an attacker with root, who
  could re-run `init` with their own passphrase. Keep an off-machine copy of
  `baseline.json` and `salt`.
- **The tool's own code can be replaced.** Production FIM tools (AIDE,
  Tripwire) run from read-only media.
- Using `INTEGRITY_PASSPHRASE` leaves the passphrase on the machine and in
  the process environment.
- Symlinks are skipped.
- It is a point-in-time checker, not real-time monitoring.

## Possible extensions

- Hash chaining for stronger append verification
- Real-time monitoring with inotify
- Alerting (email or syslog) on exit code 1
- Handling `.gz` rotated logs and automatic rotation detection
