"""Validate the exact rendered bytes and their frozen publication context."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

import yaml


def _load(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing regular publication input: {path}")
    obj = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"invalid publication input: {path}")
    return obj


def _no_symlink_components(path: Path) -> None:
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError(f"symlinked publication path: {parent}")


def validated_publication(repo: Path, subject: str) -> tuple[Path, Path, str]:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", subject):
        raise ValueError("invalid subject slug")
    relative_paths = [
        f"views/rendered/{subject}.md",
        f"views/current/{subject}.yaml",
        f"receipts/immutable/{subject}/render-execution.yaml",
        f"receipts/immutable/{subject}/render-drift.yaml",
        "control/render/render-profile.default.yaml",
        "control/publish/publish-targets.default.yaml",
    ]
    for relative in relative_paths:
        path = repo / relative
        _no_symlink_components(path)
        tracked = subprocess.run(["git", "-C", str(repo), "ls-files", "--error-unmatch", "--", relative], capture_output=True)
        if tracked.returncode != 0:
            raise ValueError(f"publication input is not tracked: {relative}")
    clean = subprocess.run(["git", "-C", str(repo), "diff", "--quiet", "HEAD", "--", *relative_paths])
    if clean.returncode != 0:
        raise ValueError("publication inputs differ from the frozen Git revision")

    source = repo / relative_paths[0]
    view = _load(repo / relative_paths[1])
    execution = _load(repo / relative_paths[2])
    drift = _load(repo / relative_paths[3])
    profile = _load(repo / relative_paths[4])
    targets = _load(repo / relative_paths[5])
    source_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    view_id = view["metadata"]["object_id"]
    expected_source = f"views/rendered/{subject}.md"
    e = execution["spec"]
    d = drift["spec"]
    if execution["kind"] != "PRIME_CANON_RENDER_EXECUTION_RECEIPT_V1" or drift["kind"] != "PRIME_CANON_RENDER_DRIFT_RECEIPT_V1":
        raise ValueError("render receipt kind mismatch")
    if execution["attributes"]["identity"]["subject_slug"] != subject or drift["attributes"]["identity"]["subject_slug"] != subject:
        raise ValueError("render receipt subject mismatch")
    if e["execution_status"] != "success" or not e["drift_check_required"]:
        raise ValueError("render execution is not publishable")
    if e["target_view_ref"] != view_id or d["target_view_ref"] != view_id or d["current_view_hash"] != view["spec"]["view_hash"]:
        raise ValueError("render view binding mismatch")
    if e["plan_ref"] != d["plan_ref"] or e["output_ref"] != expected_source or d["output_ref"] != expected_source:
        raise ValueError("render plan or output binding mismatch")
    if e["profile_ref"] != profile["profile_id"]:
        raise ValueError("render profile binding mismatch")
    if source_sha != e["output_sha256"] or source_sha != d["output_sha256"]:
        raise ValueError("rendered source hash differs from execution or drift receipt")
    if d["drift_status"] != "in_sync" or d["blocker"] is not False or d["recommended_route"] != "export_prep":
        raise ValueError("render drift is not in sync")
    target_text = targets["subjects"][subject]["rendered_markdown_path"]
    destination = Path(target_text)
    if not destination.is_absolute() or destination == source:
        raise ValueError("invalid publication destination")
    _no_symlink_components(destination)
    if destination.exists() and not destination.is_file():
        raise ValueError("publication destination is not a regular file")
    return source, destination, source_sha


def read_verified_source(source: Path, expected_sha: str) -> bytes:
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("rendered source is not a regular file")
        data = stream.read()
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("rendered source changed during publication")
    return data
