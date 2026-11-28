"""Validate the exact rendered bytes and their frozen publication context."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

import yaml


def _load(data: bytes, path: Path) -> dict:
    obj = yaml.safe_load(data.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError(f"invalid publication input: {path}")
    return obj


def _no_symlink_components(path: Path) -> None:
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError(f"symlinked publication path: {parent}")


def _open_directory(path: Path, *, require_private: bool = False) -> int:
    absolute = Path(os.path.abspath(path))
    if len(absolute.parts) > 1 and absolute.parts[1] in {"var", "tmp"}:
        root_name = absolute.parts[1]
        system_root = f"/private/{root_name}"
        if os.path.islink(f"/{root_name}") and os.path.realpath(f"/{root_name}") == system_root:
            absolute = Path(system_root, *absolute.parts[2:])
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            details = os.fstat(child)
            if require_private and details.st_mode & 0o022:
                # Root-owned sticky system roots such as /Users/Shared are
                # safe ancestors; a writable non-sticky stage is not.
                if not (details.st_uid == 0 and details.st_mode & stat.S_ISVTX):
                    os.close(child)
                    raise ValueError(f"writable publication directory: {path}")
            os.close(directory)
            directory = child
        result = directory
        directory = -1
        return result
    finally:
        if directory >= 0:
            os.close(directory)


def _read_regular_no_follow(path: Path) -> bytes:
    directory = _open_directory(path.parent)
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory)
        with os.fdopen(fd, "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError(f"missing regular publication input: {path}")
            return stream.read()
    finally:
        os.close(directory)


def _frozen_bytes(repo: Path, revision: str, relative: str) -> bytes:
    path = repo / relative
    try:
        committed = subprocess.run(
            ["/usr/bin/git", "-C", str(repo), "show", f"{revision}:{relative}"],
            check=True, capture_output=True,
        ).stdout
        actual = _read_regular_no_follow(path)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise ValueError(f"missing frozen publication input: {relative}") from exc
    if actual != committed:
        raise ValueError("publication inputs differ from the frozen Git revision")
    return committed


def open_trusted_destination_parent(destination: Path) -> int:
    """Pin a destination directory and reject writable redirect ancestors."""
    return _open_directory(destination.parent, require_private=True)


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
    revision = subprocess.run(
        ["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if re.fullmatch(r"[0-9a-f]{40,64}", revision) is None:
        raise ValueError("invalid frozen Git revision")
    frozen = {relative: _frozen_bytes(repo, revision, relative) for relative in relative_paths}

    source = repo / relative_paths[0]
    view = _load(frozen[relative_paths[1]], repo / relative_paths[1])
    execution = _load(frozen[relative_paths[2]], repo / relative_paths[2])
    drift = _load(frozen[relative_paths[3]], repo / relative_paths[3])
    profile = _load(frozen[relative_paths[4]], repo / relative_paths[4])
    targets = _load(frozen[relative_paths[5]], repo / relative_paths[5])
    source_sha = hashlib.sha256(frozen[relative_paths[0]]).hexdigest()
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
    data = _read_regular_no_follow(source)
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("rendered source changed during publication")
    return data
