# Freeze Order

Freeze these artifacts in order. This is the smallest sequence that gives you a lawful, replayable, repo-native canon control plane.

1. `control/repo.manifest.yaml`
2. `control/attributes/core-attribute-dictionary.yaml`
3. `control/formulas/core-default.yaml`
4. `control/admissibility/core-default.yaml`
5. `control/jurisdictions/*.yaml`
6. `control/lanes/*.yaml`
7. `schemas/prime-canon-bundle.schema.json`
8. `scripts/validate_pack.py`
9. `canon/corpora/**`
10. `canon/source_units/**`
11. `canon/candidate_claims/**`
12. `canon/evidence_links/**`
13. `receipts/immutable/**`
14. `canon/contradictions/**`
15. `canon/supersession/**`
16. `canon/nodes/**`
17. `replay/manifests/**`
18. `views/current/**`

## Freeze rules

- Objects under `receipts/immutable/` are append-only after commit.
- Compiler receipt writers now refuse an occupied path before changing derived state. Existing `subject-0001` receipt names are occupied; a new cycle needs a new subject or an explicitly versioned successor path. Do not delete or replace old receipts to restart a stage.
- Promotion requires a reviewer-signed attestation for the exact replay manifest, target claims, subject and Git revision. The trusted reviewer public key must be qualified and installed by the jurisdiction owner at `control/jurisdictions/human-reviewer.pub.pem`; until then promotion remains closed. A compiler-generated receipt is not human approval.
- Pass the signed JSON attestation as the third argument to `promote_nodes_and_current_state.py`, or as the second argument to `promote_nodes_and_current_state_commit.sh`. The `payload` keys are `subject_slug`, `manifest_sha256`, `frozen_git_revision`, `target_claim_refs`, `reviewer_ref`, `jurisdiction_ref`, and `decision: promote`. Sign the compact, sorted-key JSON payload with SHA-256 and the qualified private key; put the lowercase signature bytes in `signature_hex`. Keep the private key outside this repository.
- Objects under `views/current/` are derived and may only be updated from a lawful promotion path.
- Objects under `canon/nodes/` may not change without a matching promotion readiness packet and reduction decision receipt.
- `schemas/` and `control/` changes should be reviewed before runtime object changes in the same PR.
