#!/usr/bin/env python3
"""Publish the checked bytes without reopening a mutable source pathname."""

from __future__ import annotations

import os
import hashlib
import secrets
import stat
import sys
from pathlib import Path

from publication_guard import open_trusted_destination_parent, read_verified_source, validated_publication


def main() -> None:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
    subject = sys.argv[2] if len(sys.argv) > 2 else "subject-0001"
    try:
        source, destination, expected_sha = validated_publication(repo, subject)
        data = read_verified_source(source, expected_sha)
        parent = open_trusted_destination_parent(destination)
        try:
            try:
                current = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                current = None
            if current is not None and not stat.S_ISREG(current.st_mode):
                raise ValueError("publication destination is not a regular file")
            temporary = f".prime-publish-{secrets.token_hex(12)}"
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as out:
                    out.write(data)
                    out.flush()
                    os.fsync(out.fileno())
                os.replace(temporary, destination.name, src_dir_fd=parent, dst_dir_fd=parent)
                os.fsync(parent)
                published = os.open(destination.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                with os.fdopen(published, "rb") as final:
                    if not stat.S_ISREG(os.fstat(final.fileno()).st_mode):
                        raise ValueError("published destination is not a regular file")
                    if hashlib.sha256(final.read()).hexdigest() != expected_sha:
                        raise ValueError("published destination hash mismatch")
                    observed = os.fstat(final.fileno())
                    selected = os.stat(destination.name, dir_fd=parent, follow_symlinks=False)
                    if (observed.st_dev, observed.st_ino) != (selected.st_dev, selected.st_ino):
                        raise ValueError("published destination changed during readback")
            finally:
                try:
                    os.unlink(temporary, dir_fd=parent)
                except FileNotFoundError:
                    pass
        finally:
            os.close(parent)
    except (ValueError, KeyError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print(f"published_subject={subject}")
    print(f"published_to={destination}")


if __name__ == "__main__":
    main()
