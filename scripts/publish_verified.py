#!/usr/bin/env python3
"""Publish the checked bytes without reopening a mutable source pathname."""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from publication_guard import read_verified_source, validated_publication


def main() -> None:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
    subject = sys.argv[2] if len(sys.argv) > 2 else "subject-0001"
    try:
        source, destination, expected_sha = validated_publication(repo, subject)
        data = read_verified_source(source, expected_sha)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_symlink():
            raise ValueError("publication destination became a symlink")
        fd, temporary = tempfile.mkstemp(prefix=".prime-publish-", dir=destination.parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            if destination.is_symlink():
                raise ValueError("publication destination became a symlink")
            os.replace(temporary, destination)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except (ValueError, KeyError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print(f"published_subject={subject}")
    print(f"published_to={destination}")


if __name__ == "__main__":
    main()
