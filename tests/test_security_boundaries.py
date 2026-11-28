from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

from publication_guard import validated_publication
from security_guards import evaluate_evidence, require_new_paths, verify_human_review, verify_manifest_inputs, write_new_yaml


def git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


class SecurityBoundaryTests(unittest.TestCase):
    def test_publisher_uses_frozen_bytes_and_holds_writable_stage(self):
        paths = [
            "views/rendered/subject-0001.md",
            "views/current/subject-0001.yaml",
            "receipts/immutable/subject-0001/render-execution.yaml",
            "receipts/immutable/subject-0001/render-drift.yaml",
            "control/render/render-profile.default.yaml",
            "control/publish/publish-targets.default.yaml",
        ]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve() / "repo"
            stage = Path(directory).resolve() / "stage"
            stage.mkdir(mode=0o700)
            for relative in paths:
                dest = repo / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, dest)
            targets = repo / paths[-1]
            target_data = yaml.safe_load(targets.read_text(encoding="utf-8"))
            destination = stage / "subject-0001.rendered.md"
            target_data["subjects"]["subject-0001"]["rendered_markdown_path"] = str(destination)
            targets.write_text(yaml.safe_dump(target_data), encoding="utf-8")
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "frozen inputs")
            command = [sys.executable, str(REPO / "scripts/publish_verified.py"), str(repo), "subject-0001"]
            published = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(published.returncode, 0, published.stderr)
            expected = (repo / paths[0]).read_bytes()
            self.assertEqual(destination.read_bytes(), expected)
            stage.chmod(0o775)
            denied = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(denied.returncode, 0)
            self.assertIn("writable publication directory", denied.stderr)
            self.assertEqual(destination.read_bytes(), expected)
            stage.chmod(0o700)
            destination.unlink()
            stage.rmdir()
            stage.symlink_to(repo, target_is_directory=True)
            redirected = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(redirected.returncode, 0)
            self.assertFalse((repo / destination.name).exists())

    def test_publication_rechecks_source_bytes_and_git_state(self):
        paths = [
            "views/rendered/subject-0001.md",
            "views/current/subject-0001.yaml",
            "receipts/immutable/subject-0001/render-execution.yaml",
            "receipts/immutable/subject-0001/render-drift.yaml",
            "control/render/render-profile.default.yaml",
            "control/publish/publish-targets.default.yaml",
        ]
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            for relative in paths:
                dest = repo / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, dest)
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "frozen inputs")
            source, _, digest = validated_publication(repo, "subject-0001")
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), digest)
            source.write_text(source.read_text() + "\nchanged\n")
            with self.assertRaisesRegex(ValueError, "frozen Git revision"):
                validated_publication(repo, "subject-0001")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "tampered output")
            with self.assertRaisesRegex(ValueError, "source hash differs"):
                validated_publication(repo, "subject-0001")

    def test_manifest_checks_every_pinned_input(self):
        base = REPO / "receipts/immutable/subject-0001"
        manifest = yaml.safe_load((REPO / "replay/manifests/subject-0001/promotion-readiness-replay.yaml").read_text())
        packet = yaml.safe_load((base / "promotion-readiness-packet.yaml").read_text())
        summary = yaml.safe_load((base / "promotion-readiness-summary.yaml").read_text())
        profile_path = REPO / "control/admissibility/core-default.yaml"
        profile_id = "pc.admissibility_profile.core-default"
        manifest["spec"]["profile_refs"][0] = profile_id
        manifest["spec"]["object_refs"].append(profile_id)
        manifest["spec"]["input_hashes"].append({"object_ref": profile_id, "sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest()})
        manifest_path = REPO / "replay/manifests/subject-0001/promotion-readiness-replay.yaml"
        verify_manifest_inputs(REPO, "subject-0001", manifest_path, manifest, packet, summary)
        forged = copy.deepcopy(manifest)
        forged["spec"]["input_hashes"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_manifest_inputs(REPO, "subject-0001", manifest_path, forged, packet, summary)

    def test_burden_uses_source_units_and_blocks_high_profile(self):
        claim = yaml.safe_load((REPO / "canon/candidate_claims/subject-0001/claim-0001.yaml").read_text())
        profile = yaml.safe_load((REPO / "control/admissibility/core-default.yaml").read_text())
        met, unmet, _, _, replayable = evaluate_evidence(REPO, "subject-0001", claim, profile)
        self.assertFalse(unmet)
        self.assertTrue(replayable)
        self.assertIn("replayability", met)
        claim["attributes"]["evidence"]["burden_level"] = "high"
        _, unmet, _, _, _ = evaluate_evidence(REPO, "subject-0001", claim, profile)
        self.assertIn("minimum_evidence_links", unmet)
        self.assertIn("minimum_source_diversity", unmet)
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory).resolve()
            for relative in ["canon/source_units/subject-0001/unit-0001.yaml", "control/admissibility/core-default.yaml"]:
                dest = repo / relative
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, dest)
            unit_path = repo / "canon/source_units/subject-0001/unit-0001.yaml"
            unit = yaml.safe_load(unit_path.read_text())
            unit["spec"]["normalized_text"] += " forged"
            unit_path.write_text(yaml.safe_dump(unit))
            claim["attributes"]["evidence"]["burden_level"] = "medium"
            _, unmet, _, _, replayable = evaluate_evidence(repo, "subject-0001", claim, profile)
            self.assertIn("replayability", unmet)
            self.assertFalse(replayable)

    def test_immutable_write_refuses_existing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "receipt.yaml"
            require_new_paths([target])
            write_new_yaml(target, {"proof": "first"})
            with self.assertRaisesRegex(ValueError, "already exists"):
                require_new_paths([target])
            with self.assertRaises(FileExistsError):
                write_new_yaml(target, {"proof": "replacement"})
            self.assertEqual(yaml.safe_load(target.read_text()), {"proof": "first"})

    def test_human_signature_binds_manifest_targets_and_revision(self):
        if shutil.which("openssl") is None:
            self.skipTest("OpenSSL unavailable")
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            binding = repo / "control/jurisdictions/human-reviewer.yaml"
            binding.parent.mkdir(parents=True)
            shutil.copy2(REPO / "control/jurisdictions/human-reviewer.yaml", binding)
            manifest = repo / "manifest.yaml"
            manifest.write_text("manifest\n")
            git(repo, "init", "-q")
            git(repo, "config", "user.name", "Test")
            git(repo, "config", "user.email", "test@example.invalid")
            git(repo, "add", ".")
            git(repo, "commit", "-qm", "frozen revision")
            private_key = repo / "private.pem"
            public_key = repo / "control/jurisdictions/human-reviewer.pub.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(private_key)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)], check=True, capture_output=True)
            git(repo, "add", "control/jurisdictions/human-reviewer.pub.pem")
            git(repo, "commit", "-qm", "trusted reviewer key")
            packet = {"spec": {"required_reviewer_classes": ["human-reviewer"], "target_refs": ["claim-1"]}}
            revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            payload = {"subject_slug": "subject-0001", "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(), "frozen_git_revision": revision, "target_claim_refs": ["claim-1"], "reviewer_ref": "human:reviewer", "jurisdiction_ref": "pc.jurisdiction.human-reviewer", "decision": "promote"}
            data = repo / "payload.json"
            signature = repo / "signature.bin"
            data.write_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", str(private_key), "-out", str(signature), str(data)], check=True, capture_output=True)
            attestation = repo / "attestation.json"
            attestation.write_text(json.dumps({"payload": payload, "signature_hex": signature.read_bytes().hex()}))
            self.assertEqual(verify_human_review(repo, "subject-0001", manifest, packet, attestation), "human:reviewer")
            packet["spec"]["target_refs"] = ["other-claim"]
            with self.assertRaisesRegex(ValueError, "not bound"):
                verify_human_review(repo, "subject-0001", manifest, packet, attestation)


if __name__ == "__main__":
    unittest.main()
