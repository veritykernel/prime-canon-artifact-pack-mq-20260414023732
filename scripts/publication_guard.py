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


def _open_directory(path: Path, *, require_private: bool = False, create: bool = False) -> int:
    absolute = Path(os.path.abspath(path))
    if len(absolute.parts) > 1 and absolute.parts[1] in {"var", "tmp"}:
        root_name = absolute.parts[1]
        system_root = f"/private/{root_name}"
        if os.path.islink(f"/{root_name}") and os.path.realpath(f"/{root_name}") == system_root:
            absolute = Path(system_root, *absolute.parts[2:])
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in absolute.parts[1:]:
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, mode=0o700, dir_fd=directory)
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


def _expected_rendered_bytes(repo: Path, revision: str, subject: str, view: dict,
                             execution: dict, profile: dict) -> bytes:
    """Replay the maintained render template from frozen governed nodes."""
    if profile.get("default_output_format") != "markdown" or profile.get("target_projection_flag") != "rendered_text":
        raise ValueError("unsupported render profile for publication")
    if profile.get("section_strategy") != "linear_nodes" or profile.get("ordering_strategy") != "active_node_order":
        raise ValueError("unsupported render order for publication")
    order = _load(_frozen_bytes(repo, revision, "control/render/render-order.default.yaml"),
                  repo / "control/render/render-order.default.yaml")
    targets = _load(_frozen_bytes(repo, revision, "control/render/render-targets.default.yaml"),
                    repo / "control/render/render-targets.default.yaml")
    redaction = _load(_frozen_bytes(repo, revision, "control/render/render-redaction.default.yaml"),
                      repo / "control/render/render-redaction.default.yaml")
    if order.get("ordering_mode") != "active_node_refs" or redaction.get("policy_mode") != "none":
        raise ValueError("unsupported render policy for publication")
    if "markdown" not in targets.get("allowed_output_formats", []) or "rendered_text" not in targets.get("allowed_projection_flags", []):
        raise ValueError("render target policy disallows publication")
    node_ids = view["spec"].get("active_node_refs", [])
    if not node_ids or len(node_ids) != len(set(node_ids)):
        raise ValueError("invalid active node set")
    if execution["spec"].get("rendered_node_count") != len(node_ids):
        raise ValueError("render receipt node count mismatch")
    if execution["spec"].get("cited_object_refs") != node_ids + [view["metadata"]["object_id"]]:
        raise ValueError("render receipt does not cite the active nodes")
    corpus_id = view["spec"]["scope_ref"]
    view_id = view["metadata"]["object_id"]
    if view["spec"].get("view_id") != view_id:
        raise ValueError("current view identity mismatch")
    fields = profile.get("include_metadata_fields", [])
    if not isinstance(fields, list) or any(field not in {"corpus_id", "current_state_view", "generated_at"} for field in fields):
        raise ValueError("unsupported render metadata field")
    style = profile.get("heading_style")
    if style not in {"numbered", "title_only"}:
        raise ValueError("unsupported heading style")
    metadata = {"corpus_id": corpus_id, "current_state_view": view_id,
                "generated_at": execution["spec"]["generated_at"]}
    lines = [f"# {subject} rendered canon", ""]
    for field in fields:
        lines.append(f"- {field}: `{metadata[field]}`")
    lines += [f"- active_node_count: `{len(node_ids)}`", "", "## Promoted canon nodes", ""]
    for index, node_id in enumerate(node_ids, start=1):
        prefix = f"pc.canon_node.{subject}."
        if not isinstance(node_id, str) or not node_id.startswith(prefix):
            raise ValueError("active node identity mismatch")
        sequence = node_id[len(prefix):]
        if not re.fullmatch(r"[0-9]{4,}", sequence):
            raise ValueError("invalid active node sequence")
        relative = f"canon/nodes/{subject}/node-{sequence}.yaml"
        node = _load(_frozen_bytes(repo, revision, relative), repo / relative)
        if node["metadata"]["object_id"] != node_id or node["spec"]["canon_node_id"] != node_id:
            raise ValueError("active node file identity mismatch")
        if node["spec"].get("state") != "promoted":
            raise ValueError("active node is not promoted")
        body = node["spec"]["canonical_body"]
        if not isinstance(body, str):
            raise ValueError("invalid canonical body")
        lines.append(f"{index}. {body}" if style == "numbered" else f"- {body}")
    if profile.get("include_receipt_footer"):
        lines += ["", "## Projection receipts", "",
                  f"- render_profile_ref: `{profile['profile_id']}`",
                  f"- render_plan_ref: `pc.render_plan.{subject}.default`"]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _verified_source_context(repo: Path, subject: str) -> tuple[Path, str, dict]:
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
    if frozen[relative_paths[0]] != _expected_rendered_bytes(repo, revision, subject, view, execution, profile):
        raise ValueError("rendered source is not derived from governed nodes")
    return source, source_sha, targets


def validated_source(repo: Path, subject: str) -> tuple[Path, str]:
    """Check governed source bytes without claiming destination readiness."""
    source, source_sha, _ = _verified_source_context(repo, subject)
    return source, source_sha


def validated_publication(repo: Path, subject: str) -> tuple[Path, Path, str]:
    source, source_sha, targets = _verified_source_context(repo, subject)
    target_text = targets["subjects"][subject]["rendered_markdown_path"]
    destination = Path(target_text)
    if not destination.is_absolute() or destination == source:
        raise ValueError("invalid publication destination")
    trusted_root_text = os.environ.get("PRIME_PUBLISH_ROOT", "")
    trusted_root = Path(trusted_root_text)
    if not trusted_root.is_absolute() or destination.parent != trusted_root or destination.name != f"{subject}.rendered.md":
        raise ValueError("publication destination is outside the operator-bound root")
    _no_symlink_components(destination)
    if destination.exists() and not destination.is_file():
        raise ValueError("publication destination is not a regular file")
    return source, destination, source_sha


def read_verified_source(source: Path, expected_sha: str) -> bytes:
    data = _read_regular_no_follow(source)
    if hashlib.sha256(data).hexdigest() != expected_sha:
        raise ValueError("rendered source changed during publication")
    return data
