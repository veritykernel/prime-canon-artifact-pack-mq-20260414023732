#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from publication_guard import validated_publication

def main() -> None:
    repo = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(".").resolve()
    subject_slug = sys.argv[2] if len(sys.argv) > 2 else "subject-0001"

    try:
        _, destination, source_sha = validated_publication(repo, subject_slug)
    except (ValueError, KeyError, OSError) as exc:
        print("export_prep_ready=false")
        raise SystemExit(str(exc)) from exc
    print("export_prep_ready=true")
    print(f"rendered_sha256={source_sha}")
    print(f"destination={destination}")

if __name__ == "__main__":
    main()
