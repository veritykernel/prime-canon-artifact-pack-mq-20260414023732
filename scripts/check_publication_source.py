#!/usr/bin/env python3
"""Verify rendered source derivation without claiming destination readiness."""

from __future__ import annotations

import sys
from pathlib import Path

from publication_guard import validated_source


def main() -> None:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
    subject = sys.argv[2] if len(sys.argv) > 2 else "subject-0001"
    try:
        _, source_sha = validated_source(repo, subject)
    except (ValueError, KeyError, OSError) as exc:
        raise SystemExit(str(exc)) from exc
    print("publication_source_verified=true")
    print(f"rendered_sha256={source_sha}")


if __name__ == "__main__":
    main()
