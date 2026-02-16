# @rezilient/types Code Summary

Purpose:
- Shared package for cross-service contracts used by Rezilient services.

Primary entrypoints:
- `src/schemas.ts`: CloudEvent envelope and event payload schemas.
- `src/partitioning.ts`: Topic routing and partition-key helpers.
- `src/restore-contracts.ts`: Restore/auth-adjacent shared contracts for
  plan/job/conflict/evidence/journal/watermark metadata, PIT tuple utilities,
  and deterministic plan-hash canonicalization helpers.
- `src/index.ts`: Public export surface.

Testing:
- `src/schemas.test.ts`
- `src/partitioning.test.ts`
- `src/restore-contracts.test.ts`
