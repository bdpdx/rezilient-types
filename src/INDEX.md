# src Index

- `index.ts`: Barrel exports for package consumers.
- `schemas.ts`: CloudEvent + payload zod schemas.
- `partitioning.ts`: Partition key and Kafka topic mapping helpers.
- `restore-contracts.ts`: RS-01 restore shared contract profile and
  zero-knowledge constraints, plus PIT tuple and deterministic plan-hash
  helper utilities, and RS-12 evidence integrity fields/reason-codes.
- `audit-contracts.ts`: Shared cross-service audit event schema, deterministic
  replay ordering profile, and legacy ACP/RRS audit adapter utilities.
- `schemas.test.ts`: CloudEvent schema tests.
- `partitioning.test.ts`: partitioning/topic routing tests.
- `restore-contracts.test.ts`: restore contract and plaintext-rejection tests.
- `audit-contracts.test.ts`: audit contract and legacy-adapter tests.
