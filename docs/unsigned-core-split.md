# Unsigned-core split — review pending

Owner approved separating independent stable unsigned improvements from signing and advanced TOCTOU work. This is an AI-assisted draft, not a merge or production authorization.

- Base main: 60654e8265650bf74626198ddd9692acddf8071e
- Extraction baseline: 17359afc0ef6187a9e2ac81bb68c1f164a190072
- Original cumulative PR #20 remains intact at its own head. Retain all unsigned native and manifest regressions; exclude signing-only tests, modules, dependency locks, provider tooling and experimental guarded/snapshot features. Keep strict schema preflight as a reusable pure validation API, not signature authentication.
- Existing rule set 27955931 requires twelve GitHub Actions contexts, including six signing-provider contexts. This draft runs the six native core checks only. The missing six contexts are an explicit governance blocker, not successful checks. No rule changes, fabricated passes or bypasses. A separately reviewed scope-aware policy would need to require the full provider gate whenever signing is present and a meaningful unsigned-scope validation when it is absent.
- The earlier final-sample TOCTOU residual remains rejected by the owner for production. A scoped incremental core merge must not be presented as closing it; independent review and explicit authorization are needed before any merge. No release/tag until applicable security acceptance and provider requirements are fulfilled.
- Obtain exact-head CI results, review source and exclusions, and reconcile cumulative branch with main only after approved merge.
