import hashlib

CHUNK_SIZE = 64 * 1024  # read 64 KB at a time


def sha256_file(path):
    """Return the SHA-256 hex digest of a whole file."""
    return hash_and_size(path)[0]


def hash_and_size(path):
    """Hash a file and count the bytes hashed, in a single pass."""
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        while chunk := f.read(CHUNK_SIZE):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def sha256_prefix(path, length):
    """Hash only the first `length` bytes of a file."""
    h = hashlib.sha256()
    remaining = length
    with open(path, "rb") as f:
        while remaining > 0:
            chunk = f.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    import sys
    print(sha256_file(sys.argv[1]))
