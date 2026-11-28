"""Fail-closed checks at canon promotion and receipt boundaries."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
from pathlib import Path

import yaml

from publication_guard import _frozen_bytes, _open_directory, _read_regular_no_follow


def sha256_file(path: Path) -> str:
    return hashlib.sha256(_read_regular_no_follow(path)).hexdigest()


def require_new_paths(paths: list[Path]) -> None:
    if len(set(paths)) != len(paths):
        raise ValueError("duplicate output path")
    for path in paths:
        if path.exists() or path.is_symlink():
            raise ValueError(f"append-only output already exists: {path}")


def write_new_yaml(path: Path, obj: dict) -> None:
    """Create an immutable object through a pinned, private directory fd."""
    parent = _open_directory(path.parent, require_private=True, create=True)
    created = None
    try:
        fd = os.open(path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                     0o644, dir_fd=parent)
        created = os.fstat(fd)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                yaml.safe_dump(obj, out, sort_keys=False)
                out.flush()
                os.fsync(out.fileno())
            os.fsync(parent)
        except BaseException:
            try:
                observed = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if created and (observed.st_dev, observed.st_ino) == (created.st_dev, created.st_ino):
                    os.unlink(path.name, dir_fd=parent)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(parent)


def replace_yaml_if_unchanged(path: Path, obj: dict, old_bytes: bytes | None) -> None:
    """Replace a mutable projection only if its pinned parent and old bytes agree."""
    parent = _open_directory(path.parent, require_private=True, create=True)
    temporary = f".prime-update-{secrets.token_hex(12)}"
    try:
        try:
            current = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
        except FileNotFoundError:
            current = None
        if current is None:
            if old_bytes is not None:
                raise ValueError(f"mutable output disappeared: {path}")
        else:
            with os.fdopen(current, "rb") as existing:
                if not stat.S_ISREG(os.fstat(existing.fileno()).st_mode) or existing.read() != old_bytes:
                    raise ValueError(f"mutable output changed: {path}")
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            yaml.safe_dump(obj, out, sort_keys=False)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent)
        except FileNotFoundError:
            pass
        os.close(parent)


def require_frozen_files(repo: Path, paths: list[Path]) -> None:
    revision = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    for path in paths:
        _frozen_bytes(repo, revision, str(path.relative_to(repo)))


def verify_manifest_inputs(repo: Path, subject: str, manifest_path: Path, manifest: dict, packet: dict, summary: dict) -> tuple[str, dict[str, tuple[Path, dict]]]:
    """Return a single Git-bound snapshot of every promoted input."""
    revision = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    packet_path = repo / "receipts" / "immutable" / subject / "promotion-readiness-packet.yaml"
    summary_path = repo / "receipts" / "immutable" / subject / "promotion-readiness-summary.yaml"
    for path, passed in ((manifest_path, manifest), (packet_path, packet), (summary_path, summary)):
        frozen = yaml.safe_load(_frozen_bytes(repo, revision, str(path.relative_to(repo))))
        if frozen != passed:
            raise ValueError(f"promotion input differs from frozen Git revision: {path}")
    spec = manifest["spec"]
    packet_spec = packet["spec"]
    expected_manifest_id = f"pc.replay_manifest.{subject}.promotion-readiness"
    if manifest["metadata"]["object_id"] != expected_manifest_id or spec["manifest_id"] != expected_manifest_id:
        raise ValueError("replay manifest identity mismatch")
    if packet_spec["replay_manifest_ref"] != expected_manifest_id:
        raise ValueError("packet references another replay manifest")
    if spec["scope_ref"] != packet["attributes"]["identity"]["corpus_id"]:
        raise ValueError("replay manifest corpus mismatch")
    expected_outputs = {packet["metadata"]["object_id"], summary["metadata"]["object_id"]}
    if set(spec["expected_output_refs"]) != expected_outputs:
        raise ValueError("replay manifest output set mismatch")

    refs = spec["object_refs"]
    hashes = spec["input_hashes"]
    if len(refs) != len(set(refs)) or len(hashes) != len(refs):
        raise ValueError("replay manifest has duplicate or missing inputs")
    pinned = {row["object_ref"]: row["sha256"] for row in hashes}
    if set(refs) != set(pinned) or len(pinned) != len(hashes):
        raise ValueError("replay manifest hashes do not exactly cover object refs")

    allowed_dirs = [
        repo / "canon" / "candidate_claims" / subject,
        repo / "canon" / "evidence_links" / subject,
        repo / "receipts" / "immutable" / subject,
    ]
    found: dict[str, tuple[Path, dict]] = {}
    snapshots: dict[str, bytes] = {}
    profile_path = repo / "control" / "admissibility" / "core-default.yaml"
    profile_bytes = _frozen_bytes(repo, revision, str(profile_path.relative_to(repo)))
    profile = yaml.safe_load(profile_bytes)
    profile_id = profile["metadata"]["object_id"]
    if spec["profile_refs"] != [profile_id] or profile_id not in refs:
        raise ValueError("admissibility profile is not pinned by replay manifest")
    found[profile_id] = (profile_path, profile)
    snapshots[profile_id] = profile_bytes
    for directory in allowed_dirs:
        for path in directory.glob("*.yaml"):
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"unsafe manifest input: {path}")
            data = _frozen_bytes(repo, revision, str(path.relative_to(repo)))
            obj = yaml.safe_load(data)
            object_id = obj.get("metadata", {}).get("object_id") if isinstance(obj, dict) else None
            if object_id in pinned:
                if object_id in found:
                    raise ValueError(f"duplicate pinned object: {object_id}")
                found[object_id] = (path, obj)
                snapshots[object_id] = data
    if set(found) != set(refs):
        raise ValueError(f"missing pinned objects: {sorted(set(refs) - set(found))}")
    for object_id, data in snapshots.items():
        if hashlib.sha256(data).hexdigest() != pinned[object_id]:
            raise ValueError(f"replay manifest hash mismatch: {object_id}")
    claim_refs = {ref for ref in refs if ref.startswith(f"pc.candidate_claim.{subject}.")}
    if claim_refs != set(packet_spec["target_refs"]):
        raise ValueError("packet targets differ from pinned claims")
    return revision, found


def evaluate_evidence(repo: Path, subject: str, claim: dict, profile: dict) -> tuple[list[str], list[str], list[str], list[str], bool]:
    """Evaluate control burden against the referenced source-unit bytes."""
    claim_id = claim["spec"]["claim_id"]
    burden = claim["attributes"]["evidence"].get("burden_level")
    classes = profile["spec"]["burden_classes"]
    selected = [entry for entry in classes if entry["name"] == burden]
    if len(selected) != 1:
        raise ValueError(f"unconfigured burden level: {burden}")
    rule = selected[0]
    unit_refs = claim["spec"].get("source_unit_refs", [])
    if not unit_refs or len(unit_refs) != len(set(unit_refs)):
        raise ValueError(f"missing or duplicate source units: {claim_id}")
    units = []
    for ref in unit_refs:
        prefix = f"pc.source_unit.{subject}."
        if not isinstance(ref, str) or not ref.startswith(prefix) or not re.fullmatch(r"[0-9]{4,}", ref[len(prefix):]):
            raise ValueError(f"invalid source unit reference: {ref}")
        path = repo / "canon" / "source_units" / subject / f"unit-{ref[len(prefix):]}.yaml"
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"missing source unit: {ref}")
        unit = yaml.safe_load(path.read_text(encoding="utf-8"))
        if unit["metadata"]["object_id"] != ref or unit["spec"]["source_unit_id"] != ref:
            raise ValueError(f"source unit identity mismatch: {ref}")
        units.append(unit)
    source_refs = {unit["spec"]["source_ref"] for unit in units}
    claim_sources = set(claim["attributes"]["lineage"].get("source_refs", []))
    if source_refs != claim_sources or set(unit_refs) != set(claim["attributes"]["lineage"].get("source_unit_refs", [])):
        raise ValueError(f"claim lineage differs from source units: {claim_id}")

    replayable = True
    for unit in units:
        spec = unit["spec"]
        span = spec["span_ref"]
        payload = "|".join([spec["source_ref"], span["locator"], str(span["start"]), str(span["end"]), spec["normalized_text"]])
        digest = "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if digest != spec["checksum"] or not spec["normalized_text"].strip():
            replayable = False
    if len(units) == 1 and claim["spec"]["normalized_claim_body"] != units[0]["spec"]["normalized_text"]:
        replayable = False

    evidence_classes = {unit["attributes"]["evidence"]["evidence_class"] for unit in units}
    if claim["attributes"]["evidence"].get("evidence_class") not in evidence_classes:
        raise ValueError(f"claim evidence class differs from source unit: {claim_id}")
    open_critical = False
    for path in (repo / "canon" / "contradictions" / subject).glob("*.yaml"):
        contradiction = yaml.safe_load(path.read_text(encoding="utf-8"))
        conflict = contradiction.get("spec", {})
        if conflict.get("severity") == "critical" and conflict.get("blocking") is True and claim_id in conflict.get("object_refs", []):
            open_critical = True

    checks = {
        # This compiler emits one evidence-link object per claim. Source units
        # are sources, not additional evidence-link objects.
        "minimum_evidence_links": 1 >= rule["min_evidence_links"],
        "minimum_source_diversity": len(source_refs) >= rule["min_source_diversity"],
        "allowed_evidence_classes": evidence_classes <= set(rule["allowed_evidence_classes"]),
        "replayability": replayable or not rule["requires_replayability"],
        "no_open_critical_contradictions": not (open_critical and rule["block_on_open_critical_contradictions"]),
    }
    met = [name for name, ok in checks.items() if ok]
    unmet = [name for name, ok in checks.items() if not ok]
    evidence_set = sorted((unit["metadata"]["object_id"], unit["spec"]["checksum"]) for unit in units)
    evidence_digest = hashlib.sha256(json.dumps(evidence_set, separators=(",", ":")).encode()).hexdigest()
    reasons = [f"profile_sha256={sha256_file(repo / 'control/admissibility/core-default.yaml')}", f"evidence_set_sha256={evidence_digest}"]
    return met, unmet, reasons, unit_refs, replayable


def verify_human_review(repo: Path, subject: str, manifest_path: Path, packet: dict, attestation_path: Path | None,
                        *, revision: str | None = None) -> tuple[str, str]:
    """Verify an externally signed, exact-revision human promotion decision.

    The public key is an explicit issuer binding. Without it promotion stays
    closed; a compiler-produced YAML label is never approval evidence.
    """
    if attestation_path is None:
        raise ValueError("human review attestation required")
    binding_path = repo / "control" / "jurisdictions" / "human-reviewer.yaml"
    public_key = repo / "control" / "jurisdictions" / "human-reviewer.pub.pem"
    if revision is None:
        revision = subprocess.check_output(["/usr/bin/git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    try:
        binding = yaml.safe_load(_frozen_bytes(repo, revision, str(binding_path.relative_to(repo))))["spec"]
        key_bytes = _frozen_bytes(repo, revision, str(public_key.relative_to(repo)))
    except ValueError as exc:
        raise ValueError("trusted human reviewer public key is not configured") from exc
    trusted_digest = os.environ.get("PRIME_HUMAN_REVIEWER_PUBLIC_KEY_SHA256", "")
    if not re.fullmatch(r"[0-9a-f]{64}", trusted_digest) or hashlib.sha256(key_bytes).hexdigest() != trusted_digest:
        raise ValueError("human reviewer public key lacks an external trusted digest")
    if binding["actor_class"] != "human" or "promote" not in binding["allowed_actions"]:
        raise ValueError("human reviewer jurisdiction cannot promote")
    required = packet["spec"]["required_reviewer_classes"]
    if set(required) != {"human-reviewer"}:
        raise ValueError("unsupported required reviewer classes")
    try:
        attestation_bytes = _read_regular_no_follow(attestation_path)
    except OSError as exc:
        raise ValueError("missing regular review attestation") from exc
    attestation = json.loads(attestation_bytes)
    payload = attestation.get("payload")
    signature_hex = attestation.get("signature_hex")
    if not isinstance(payload, dict) or not isinstance(signature_hex, str) or not re.fullmatch(r"[0-9a-f]+", signature_hex):
        raise ValueError("invalid review attestation format")
    expected = {
        "subject_slug": subject,
        "manifest_sha256": hashlib.sha256(_frozen_bytes(repo, revision, str(manifest_path.relative_to(repo)))).hexdigest(),
        "frozen_git_revision": revision,
        "target_claim_refs": packet["spec"]["target_refs"],
        "reviewer_ref": binding["actor_ref"],
        "jurisdiction_ref": binding["binding_id"],
        "decision": "promote",
    }
    if payload != expected:
        raise ValueError("review attestation is not bound to current promotion inputs")
    import tempfile
    with tempfile.TemporaryDirectory() as temporary:
        data = Path(temporary) / "payload.json"
        signature = Path(temporary) / "signature.bin"
        key = Path(temporary) / "reviewer.pub.pem"
        data.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
        signature.write_bytes(bytes.fromhex(signature_hex))
        key.write_bytes(key_bytes)
        result = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(key), "-signature", str(signature), str(data)],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise ValueError("human reviewer signature did not verify")
    return binding["actor_ref"], hashlib.sha256(attestation_bytes).hexdigest()
