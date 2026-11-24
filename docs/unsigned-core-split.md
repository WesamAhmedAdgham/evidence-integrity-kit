# Unsigned-core split — review pending

Owner approved separating independent stable unsigned improvements from signing and advanced TOCTOU work. This is an AI-assisted draft, not a merge or production authorization.

- Base main: 60654e8265650bf74626198ddd9692acddf8071e
- Extraction baseline: 17359afc0ef6187a9e2ac81bb68c1f164a190072
- Original cumulative PR #20 remains intact at its own head. Retain all unsigned native and manifest regressions; exclude signing-only tests, modules, dependency locks, provider tooling and experimental guarded/snapshot features. Keep strict schema preflight as a reusable pure validation API, not signature authentication.
- Existing rule set 27955931 requires twelve contexts. The proposed unsigned-only workflow preserves their names and adds six real scope-policy jobs: exact tracked payload paths and pinned Git blob IDs from c5f6acb, clean checkout, negative tests for added/changed/missing payload, and a no-site-packages CLI test. A success here means signing provider NOT APPLICABLE, not provider approved (JSON provider_release_gate_passed=null). Any changed or unknown payload fails closed until reviewed. The separate signed PR #20 retains its full provider gate and dependency checks; the unsigned gate cannot approve signed payload. The policy/workflow themselves require human review; this is not protection against a malicious PR author who can edit CI. No ruleset changes or bypass actors.
- The earlier final-sample TOCTOU residual remains rejected by the owner for production. A scoped incremental core merge must not be presented as closing it; independent review and explicit authorization are needed before any merge. No release/tag until applicable security acceptance and provider requirements are fulfilled.
- Obtain exact-head CI results, review source and exclusions, and reconcile cumulative branch with main only after approved merge.
