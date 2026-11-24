# Unsigned-core split — review pending

Owner approved separating independent stable unsigned improvements from signing and advanced TOCTOU work. This is an AI-assisted draft, not a merge or production authorization.

- Base main: 60654e8265650bf74626198ddd9692acddf8071e
- Extraction baseline: 17359afc0ef6187a9e2ac81bb68c1f164a190072
- Original cumulative PR #20 remains intact at its own head. Retain all unsigned native and manifest regressions; exclude signing-only tests, modules, dependency locks, provider tooling and experimental guarded/snapshot features. Keep strict schema preflight as a reusable pure validation API, not signature authentication.
- Existing rule set 27955931 requires twelve contexts. The proposed unsigned-only workflow preserves their names and adds six real scope-policy jobs: exact tracked payload paths and pinned Git blob IDs from c5f6acb, clean checkout, negative tests for added/changed/missing payload, and a no-site-packages CLI test. A success here means signing provider NOT APPLICABLE, not provider approved (JSON provider_release_gate_passed=null). Any changed or unknown payload fails closed until reviewed. The separate signed PR #20 retains its full provider gate and dependency checks; the unsigned gate cannot approve signed payload. The policy/workflow themselves require human review; this is not protection against a malicious PR author who can edit CI. No ruleset changes or bypass actors.
- The earlier final-sample TOCTOU residual remains rejected by the owner for production. A scoped incremental core merge must not be presented as closing it; independent review and explicit authorization are needed before any merge. No release/tag until applicable security acceptance and provider requirements are fulfilled.
- Obtain exact-head CI results, review source and exclusions, and reconcile cumulative branch with main only after approved merge.

## Incremental merge outcome

PR #21 merged at `5f1c01439e3d65a635a164507e92fcf8f68a695f` with explicit owner authorization for the unsigned stable-evidence development scope only. Its pinned unsigned-only scope gate and tests are intentionally superseded in the signed cumulative branch by the full mandatory signing provider gate and native functional/crypto tests. They remain in the historical main commit. No provider approval or production risk acceptance was granted. See PR #21 and its exact-head run 45321291298; post-merge main run 45321548605 completed successfully.

## First-stage F07 backport — merged

### Historical proposal (superseded by merge outcome below)

Base main 5f1c01439e3d65a635a164507e92fcf8f68a695f. Source is the already functionally tested F07 implementation in signed draft #26 exact head 93a111001d25d07cc0a7cb1b95009ef5b10e7569; only the structural scanner and one call in the existing unsigned decoder are backported, plus nine synthetic regression methods verbatim. The unsigned CLI and manifest format are otherwise unchanged. Existing scope policy pins the proposed runtime blob 26a852049e4be432cc0da2530c0e95321c7e3fbb and new test blob 7b13a4b0a6488af41a676d30d12b584eec9c544c; the full exact file set, no-site-packages tests, all twelve required CI context names and negative scope checks remain mandatory. No signing modules, third-party dependencies, native snapshot features or provider approvals are added. This is a separate draft for independent review and exact-head CI; prior signed-branch results are not evidence that this extraction passes. Main remains unchanged. Reconcile signed candidate with main only after an authorized unsigned merge and repeat exact-head qualification; do not relax provider gates.

PR #28 merged into main at `85a6b7939ef0ae96d44999e2b7afcef85ae5a2a5` from exact head `6e680950de46e259c395b63452a00c82ba346833`. Both mandatory CI matrices passed all 12 checks; PR run 45476603819 recorded 978 passing test executions and 120 explained platform skips. Push run 45476589163 passed after the cancelled macOS 3.13 job was rerun. Owner explicitly waived separate independent review for this unsigned-only first-stage merge; this exception does not carry forward to the signed candidate. See PR #28 comment 7144246284 and issue #27 comment 7144298372. No ruleset bypass, provider approval, release/tag or acceptance of residual TOCTOU risk. Post-merge main run 45486218119 was not yet fully complete at reconciliation.

### Signed candidate reconciliation

The F07 decoder/scanner is byte-identical to the unsigned main implementation; the nine-test file is the identical Git blob 7b13a4b0a6488af41a676d30d12b584eec9c544c. Signed README already explains the same budgets and compatibility restriction. Retain the signed runtime, tests, README and full signing-provider workflow. Do not restore the unsigned-only policy or its test (superseded by the full signed provider gate). This two-parent draft merge preserves both histories and changes only this record and the release-gate record relative to the previously tested signed tree. Requalify the exact new head; comprehensive independent review, explicit owner threat-model acceptance and all three provider approval allowlists remain mandatory before any second merge.
