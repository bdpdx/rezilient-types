import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
    EncryptedPayload,
    canonicalizeIsoDateTimeUtc,
    isoDateTime,
    serviceNowDateTime,
} from './schemas';

export const RESTORE_CONTRACT_VERSION = 'restore.contracts.v1';
export const RESTORE_METADATA_ALLOWLIST_VERSION =
    'rrs.metadata.allowlist.v1';
export const PIT_ALGORITHM_VERSION =
    'pit.v1.sys_updated_on-sys_mod_count-__time-event_id';
export const PLAN_HASH_INPUT_VERSION = 'plan-hash-input.v1';
export const PLAN_HASH_ALGORITHM = 'sha256';
export const EVIDENCE_CANONICALIZATION_VERSION =
    'evidence.canonical-json.v1';

export const isoDateTimeWithMillis = isoDateTime;

export type IsoDateTimeWithMillis = z.infer<typeof isoDateTimeWithMillis>;

export function canonicalizeIsoDateTimeWithMillis(
    value: string,
): IsoDateTimeWithMillis {
    return canonicalizeIsoDateTimeUtc(value);
}

const OFFSET_DECIMAL_STRING_REGEX = /^\d+$/;
const OFFSET_DECIMAL_STRING_ERROR =
    'must be non-negative integer offset as decimal string';

function normalizeRestoreOffsetDecimalString(
    value: string | number,
): string | null {
    if (typeof value === 'number') {
        if (
            !Number.isFinite(value) ||
            !Number.isInteger(value) ||
            !Number.isSafeInteger(value) ||
            value < 0
        ) {
            return null;
        }

        return value.toString(10);
    }

    if (!OFFSET_DECIMAL_STRING_REGEX.test(value)) {
        return null;
    }

    try {
        return BigInt(value).toString(10);
    } catch {
        return null;
    }
}

export function isRestoreOffsetDecimalString(value: string): boolean {
    return normalizeRestoreOffsetDecimalString(value) !== null;
}

export function canonicalizeRestoreOffsetDecimalString(
    value: string | number,
): string {
    const normalized = normalizeRestoreOffsetDecimalString(value);

    if (!normalized) {
        throw new Error(OFFSET_DECIMAL_STRING_ERROR);
    }

    return normalized;
}

export const RestoreOffsetDecimalString = z
    .union([z.string(), z.number()])
    .superRefine((value, ctx) => {
        if (normalizeRestoreOffsetDecimalString(value) !== null) {
            return;
        }

        ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: OFFSET_DECIMAL_STRING_ERROR,
        });
    })
    .transform((value) => {
        return canonicalizeRestoreOffsetDecimalString(value);
    });

export type RestoreOffsetDecimalString = z.infer<
    typeof RestoreOffsetDecimalString
>;

export const Sha256Hex = z
    .string()
    .regex(
        /^[a-f0-9]{64}$/i,
        'must be 64-char SHA-256 hex digest',
    )
    .transform((v) => v.toLowerCase());

export type Sha256Hex = z.infer<typeof Sha256Hex>;

export const RestoreCapability = z.enum([
    'restore_execute',
    'restore_delete',
    'restore_override_caps',
    'restore_schema_override',
]);

export type RestoreCapability = z.infer<typeof RestoreCapability>;

export const RestoreReasonCode = z.enum([
    'none',
    'queued_scope_lock',
    'blocked_unknown_source_mapping',
    'blocked_missing_capability',
    'blocked_unresolved_delete_candidates',
    'blocked_unresolved_media_candidates',
    'blocked_reference_conflict',
    'blocked_media_parent_missing',
    'blocked_freshness_stale',
    'blocked_freshness_unknown',
    'blocked_auth_control_plane_outage',
    'blocked_plan_hash_mismatch',
    'blocked_evidence_not_ready',
    'blocked_resume_precondition_mismatch',
    'blocked_resume_checkpoint_missing',
    'paused_token_refresh_grace_exhausted',
    'paused_entitlement_disabled',
    'paused_instance_disabled',
    'failed_media_parent_missing',
    'failed_media_hash_mismatch',
    'failed_media_retry_exhausted',
    'failed_evidence_report_hash_mismatch',
    'failed_evidence_artifact_hash_mismatch',
    'failed_evidence_signature_verification',
    'failed_schema_conflict',
    'failed_permission_conflict',
    'failed_internal_error',
]);

export type RestoreReasonCode = z.infer<typeof RestoreReasonCode>;

export const RestoreApprovalState = z.enum([
    'placeholder_not_enforced',
    'approval_not_required',
    'requested',
    'approved',
    'rejected',
    'expired',
]);

export type RestoreApprovalState = z.infer<typeof RestoreApprovalState>;

export const RestoreApprovalMetadata = z
    .object({
        approval_required: z.boolean(),
        approval_state: RestoreApprovalState,
        approval_policy_id: z.string().min(1).optional(),
        approval_requested_at: isoDateTimeWithMillis.optional(),
        approval_requested_by: z.string().min(1).optional(),
        approval_decided_at: isoDateTimeWithMillis.optional(),
        approval_decided_by: z.string().min(1).optional(),
        approval_decision: z
            .enum(['approve', 'reject', 'placeholder'])
            .optional(),
        approval_decision_reason: z.string().min(1).optional(),
        approval_external_ref: z.string().min(1).optional(),
        approval_snapshot_hash: Sha256Hex.optional(),
        approval_valid_until: isoDateTimeWithMillis.optional(),
        approval_revalidated_at: isoDateTimeWithMillis.optional(),
        approval_revalidation_result: z
            .enum(['not_applicable', 'valid', 'expired', 'rejected'])
            .optional(),
        approval_placeholder_mode: z.literal('mvp_not_enforced'),
    })
    .strict();

export type RestoreApprovalMetadata = z.infer<typeof RestoreApprovalMetadata>;

export const RRS_METADATA_ALLOWLIST_FIELDS = [
    'tenant_id',
    'instance_id',
    'source',
    'table',
    'record_sys_id',
    'attachment_sys_id',
    'media_id',
    'event_id',
    'event_type',
    'operation',
    'schema_version',
    'sys_updated_on',
    'sys_mod_count',
    '__time',
    'topic',
    'partition',
    'offset',
    'content_type',
    'size_bytes',
    'sha256_plain',
] as const;

export type RrsMetadataAllowlistField =
    typeof RRS_METADATA_ALLOWLIST_FIELDS[number];

export const RrsOperationalMetadata = z
    .object({
        tenant_id: z.string().min(1).optional(),
        instance_id: z.string().min(1).optional(),
        source: z.string().min(1).optional(),
        table: z.string().min(1).optional(),
        record_sys_id: z.string().min(1).optional(),
        attachment_sys_id: z.string().min(1).optional(),
        media_id: z.string().min(1).optional(),
        event_id: z.string().min(1).optional(),
        event_type: z.string().min(1).optional(),
        operation: z.enum(['I', 'U', 'D']).optional(),
        schema_version: z.number().int().positive().optional(),
        sys_updated_on: serviceNowDateTime.optional(),
        sys_mod_count: z.number().int().nonnegative().optional(),
        __time: isoDateTimeWithMillis.optional(),
        topic: z.string().min(1).optional(),
        partition: z.number().int().nonnegative().optional(),
        offset: RestoreOffsetDecimalString.optional(),
        content_type: z.string().min(1).optional(),
        size_bytes: z.number().int().nonnegative().optional(),
        sha256_plain: Sha256Hex.optional(),
    })
    .strict();

export type RrsOperationalMetadata = z.infer<typeof RrsOperationalMetadata>;

export const RrsMetadataEnvelope = z
    .object({
        allowlist_version: z.literal(RESTORE_METADATA_ALLOWLIST_VERSION),
        metadata: RrsOperationalMetadata,
    })
    .strict();

export type RrsMetadataEnvelope = z.infer<typeof RrsMetadataEnvelope>;

export const RestoreScope = z
    .object({
        mode: z.enum(['table', 'record', 'column']),
        tables: z.array(z.string().min(1)).min(1),
        encoded_query: z.string().min(1).optional(),
        record_sys_ids: z.array(z.string().min(1)).min(1).optional(),
        columns: z.array(z.string().min(1)).min(1).optional(),
    })
    .strict()
    .superRefine((scope, ctx) => {
        const hasRecordFilter =
            scope.encoded_query !== undefined ||
            scope.record_sys_ids !== undefined;

        if (scope.mode === 'record' && !hasRecordFilter) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'record mode requires encoded_query or record_sys_ids',
                path: ['encoded_query'],
            });
        }

        if (scope.mode === 'column') {
            if (!scope.columns || scope.columns.length === 0) {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message: 'column mode requires at least one column',
                    path: ['columns'],
                });
            }

            if (!hasRecordFilter) {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message:
                        'column mode requires encoded_query or record_sys_ids',
                    path: ['record_sys_ids'],
                });
            }
        }
    });

export type RestoreScope = z.infer<typeof RestoreScope>;

export const RestorePitContract = z
    .object({
        restore_time: isoDateTimeWithMillis,
        restore_timezone: z.literal('UTC'),
        pit_algorithm_version: z.literal(PIT_ALGORITHM_VERSION),
        tie_breaker: z.tuple([
            z.literal('sys_updated_on'),
            z.literal('sys_mod_count'),
            z.literal('__time'),
            z.literal('event_id'),
        ]),
        tie_breaker_fallback: z.tuple([
            z.literal('sys_updated_on'),
            z.literal('__time'),
            z.literal('event_id'),
        ]),
    })
    .strict();

export type RestorePitContract = z.infer<typeof RestorePitContract>;

export const RestorePitRowTuple = z
    .object({
        sys_updated_on: serviceNowDateTime,
        sys_mod_count: z.number().int().nonnegative().optional(),
        __time: isoDateTimeWithMillis,
        event_id: z.string().min(1),
    })
    .strict();

export type RestorePitRowTuple = z.infer<typeof RestorePitRowTuple>;

function compareNumbers(left: number, right: number): number {
    if (left < right) {
        return -1;
    }

    if (left > right) {
        return 1;
    }

    return 0;
}

function asServiceNowUtcMillis(value: string): number {
    const parsed = Date.parse(value.replace(' ', 'T') + '.000Z');

    if (!Number.isFinite(parsed)) {
        throw new Error('invalid ServiceNow datetime value');
    }

    return parsed;
}

function asIsoUtcMillis(value: string): number {
    const parsed = Date.parse(value);

    if (!Number.isFinite(parsed)) {
        throw new Error('invalid ISO datetime value');
    }

    return parsed;
}

export function comparePitRowTuple(
    left: RestorePitRowTuple,
    right: RestorePitRowTuple,
): number {
    const bySysUpdatedOn = compareNumbers(
        asServiceNowUtcMillis(left.sys_updated_on),
        asServiceNowUtcMillis(right.sys_updated_on),
    );

    if (bySysUpdatedOn !== 0) {
        return bySysUpdatedOn;
    }

    if (
        left.sys_mod_count !== undefined &&
        right.sys_mod_count !== undefined
    ) {
        const bySysModCount = compareNumbers(
            left.sys_mod_count,
            right.sys_mod_count,
        );

        if (bySysModCount !== 0) {
            return bySysModCount;
        }
    }

    const byEventTime = compareNumbers(
        asIsoUtcMillis(left.__time),
        asIsoUtcMillis(right.__time),
    );

    if (byEventTime !== 0) {
        return byEventTime;
    }

    return left.event_id.localeCompare(right.event_id);
}

export function selectLatestPitRowTuple<T extends RestorePitRowTuple>(
    rows: readonly T[],
): T {
    if (rows.length === 0) {
        throw new Error('rows must include at least one PIT tuple');
    }

    let winner = rows[0];

    for (let index = 1; index < rows.length; index += 1) {
        if (comparePitRowTuple(rows[index], winner) > 0) {
            winner = rows[index];
        }
    }

    return winner;
}

export const RestorePlanAction = z.enum([
    'update',
    'insert',
    'delete',
    'skip',
]);

export type RestorePlanAction = z.infer<typeof RestorePlanAction>;

export const RestoreConflictClass = z.enum([
    'value_conflict',
    'missing_row_conflict',
    'unexpected_existing_conflict',
    'reference_conflict',
    'schema_conflict',
    'permission_conflict',
    'stale_conflict',
]);

export type RestoreConflictClass = z.infer<typeof RestoreConflictClass>;

export const RestoreConflictResolution = z.enum([
    'skip',
    'abort_and_replan',
]);

export type RestoreConflictResolution = z.infer<
    typeof RestoreConflictResolution
>;

export const RestoreDeleteDecision = z.enum([
    'allow_deletion',
    'skip_deletion',
]);

export type RestoreDeleteDecision = z.infer<typeof RestoreDeleteDecision>;

export const RestoreMediaDecision = z.enum([
    'include',
    'exclude',
]);

export type RestoreMediaDecision = z.infer<typeof RestoreMediaDecision>;

export const RestoreMediaCandidate = z
    .object({
        candidate_id: z.string().min(1),
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        attachment_sys_id: z.string().min(1).optional(),
        media_id: z.string().min(1).optional(),
        content_type: z.string().min(1).optional(),
        size_bytes: z.number().int().nonnegative(),
        sha256_plain: Sha256Hex,
        decision: RestoreMediaDecision.optional(),
        parent_record_exists: z.boolean().optional(),
        observed_sha256_plain: Sha256Hex.optional(),
        retryable_failures: z.number().int().nonnegative().optional(),
        max_retry_attempts: z.number().int().positive().optional(),
        metadata: RrsMetadataEnvelope.optional(),
    })
    .strict()
    .superRefine((candidate, ctx) => {
        if (!candidate.attachment_sys_id && !candidate.media_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'media candidate requires attachment_sys_id or media_id',
                path: ['attachment_sys_id'],
            });
        }

        if (
            candidate.metadata?.metadata.table &&
            candidate.metadata.metadata.table !== candidate.table
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'metadata.table must match table',
                path: ['metadata', 'metadata', 'table'],
            });
        }

        if (
            candidate.metadata?.metadata.record_sys_id &&
            candidate.metadata.metadata.record_sys_id !==
                candidate.record_sys_id
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'metadata.record_sys_id must match record_sys_id',
                path: ['metadata', 'metadata', 'record_sys_id'],
            });
        }
    });

export type RestoreMediaCandidate = z.infer<typeof RestoreMediaCandidate>;

export const RestoreEncryptedValueEnvelope = z
    .object({
        diff_enc: EncryptedPayload.optional(),
        before_image_enc: EncryptedPayload.optional(),
        after_image_enc: EncryptedPayload.optional(),
        diff_plain: z.unknown().optional(),
        before_image_plain: z.unknown().optional(),
        after_image_plain: z.unknown().optional(),
    })
    .strict()
    .superRefine((values, ctx) => {
        if (values.diff_plain !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'diff_plain is not allowed in RRS payloads',
                path: ['diff_plain'],
            });
        }

        if (values.before_image_plain !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'before_image_plain is not allowed in RRS payloads',
                path: ['before_image_plain'],
            });
        }

        if (values.after_image_plain !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'after_image_plain is not allowed in RRS payloads',
                path: ['after_image_plain'],
            });
        }
    });

export type RestoreEncryptedValueEnvelope = z.infer<
    typeof RestoreEncryptedValueEnvelope
>;

export const RestorePlanHashRowInput = z
    .object({
        row_id: z.string().min(1),
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        action: RestorePlanAction,
        precondition_hash: Sha256Hex,
        metadata: RrsMetadataEnvelope,
        values: RestoreEncryptedValueEnvelope.optional(),
    })
    .strict()
    .superRefine((row, ctx) => {
        if (row.metadata.metadata.table &&
            row.metadata.metadata.table !== row.table) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'metadata.table must match table',
                path: ['metadata', 'metadata', 'table'],
            });
        }

        if (row.metadata.metadata.record_sys_id &&
            row.metadata.metadata.record_sys_id !== row.record_sys_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'metadata.record_sys_id must match record_sys_id',
                path: ['metadata', 'metadata', 'record_sys_id'],
            });
        }

        if (row.action !== 'skip') {
            const hasEncryptedValues =
                row.values?.diff_enc !== undefined ||
                row.values?.before_image_enc !== undefined ||
                row.values?.after_image_enc !== undefined;

            if (!hasEncryptedValues) {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message:
                        'non-skip plan rows require encrypted value material',
                    path: ['values'],
                });
            }
        }
    });

export type RestorePlanHashRowInput = z.infer<typeof RestorePlanHashRowInput>;

export const RestoreActionCounts = z
    .object({
        update: z.number().int().nonnegative(),
        insert: z.number().int().nonnegative(),
        delete: z.number().int().nonnegative(),
        skip: z.number().int().nonnegative(),
        conflict: z.number().int().nonnegative(),
        attachment_apply: z.number().int().nonnegative(),
        attachment_skip: z.number().int().nonnegative(),
    })
    .strict();

export type RestoreActionCounts = z.infer<typeof RestoreActionCounts>;

export const RestoreExecutionOptions = z
    .object({
        missing_row_mode: z.enum(['existing_only', 'explicit_insert']),
        conflict_policy: z.literal('review_required'),
        schema_compatibility_mode: z.enum([
            'compatible_only',
            'manual_override',
        ]),
        workflow_mode: z.enum(['suppressed_default', 'allowlist']),
    })
    .strict();

export type RestoreExecutionOptions = z.infer<typeof RestoreExecutionOptions>;

export const RestorePlanHashInput = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        plan_hash_input_version: z.literal(PLAN_HASH_INPUT_VERSION),
        plan_hash_algorithm: z.literal(PLAN_HASH_ALGORITHM),
        pit: RestorePitContract,
        scope: RestoreScope,
        execution_options: RestoreExecutionOptions,
        action_counts: RestoreActionCounts,
        rows: z.array(RestorePlanHashRowInput).min(1),
        media_candidates: z.array(RestoreMediaCandidate).default([]),
        metadata_allowlist_version: z.literal(
            RESTORE_METADATA_ALLOWLIST_VERSION,
        ),
    })
    .strict()
    .superRefine((input, ctx) => {
        const rowIds = input.rows.map((row) => row.row_id);
        const uniqueRowIds = new Set(rowIds);

        if (uniqueRowIds.size !== rowIds.length) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'rows must have unique row_id values',
                path: ['rows'],
            });
        }

        const sortedRowIds = [...rowIds].sort((left, right) =>
            left.localeCompare(right),
        );

        const isSorted = rowIds.every((rowId, index) => {
            return rowId === sortedRowIds[index];
        });

        if (!isSorted) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'rows must be sorted by row_id for deterministic hash',
                path: ['rows'],
            });
        }

        const candidateIds = input.media_candidates.map((candidate) =>
            candidate.candidate_id
        );
        const uniqueCandidateIds = new Set(candidateIds);

        if (uniqueCandidateIds.size !== candidateIds.length) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'media_candidates must have unique candidate_id values',
                path: ['media_candidates'],
            });
        }

        const sortedCandidateIds = [...candidateIds].sort((left, right) =>
            left.localeCompare(right),
        );
        const candidatesAreSorted = candidateIds.every((candidateId, index) => {
            return candidateId === sortedCandidateIds[index];
        });

        if (!candidatesAreSorted) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'media_candidates must be sorted by candidate_id ' +
                    'for deterministic hash',
                path: ['media_candidates'],
            });
        }
    });

export type RestorePlanHashInput = z.infer<typeof RestorePlanHashInput>;

type CanonicalJson =
    | null
    | boolean
    | number
    | string
    | CanonicalJson[]
    | {
        [key: string]: CanonicalJson;
    };

function toCanonicalJson(value: unknown): CanonicalJson {
    if (
        value === null ||
        typeof value === 'boolean' ||
        typeof value === 'number' ||
        typeof value === 'string'
    ) {
        return value;
    }

    if (Array.isArray(value)) {
        return value.map((entry) => toCanonicalJson(entry));
    }

    if (typeof value === 'object') {
        const entries = Object.entries(value as Record<string, unknown>)
            .filter(([, v]) => v !== undefined)
            .sort((left, right) => left[0].localeCompare(right[0]));
        const out: {
            [key: string]: CanonicalJson;
        } = {};

        for (const [key, entryValue] of entries) {
            out[key] = toCanonicalJson(entryValue);
        }

        return out;
    }

    throw new Error('unsupported value in canonical JSON serialization');
}

export function canonicalJsonStringify(value: unknown): string {
    return JSON.stringify(toCanonicalJson(value));
}

export function computeRestorePlanHash(
    input: RestorePlanHashInput,
): {
    canonical_json: string;
    plan_hash: string;
} {
    const canonicalJson = canonicalJsonStringify(input);
    const planHash = createHash('sha256')
        .update(canonicalJson, 'utf8')
        .digest('hex');

    return {
        canonical_json: canonicalJson,
        plan_hash: planHash,
    };
}

export const RestoreConflict = z
    .object({
        conflict_id: z.string().min(1),
        class: RestoreConflictClass,
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        column: z.string().min(1).optional(),
        reason_code: RestoreReasonCode,
        reason: z.string().min(1),
        resolution: RestoreConflictResolution.optional(),
        observed_at: isoDateTimeWithMillis,
        metadata: RrsMetadataEnvelope.optional(),
    })
    .strict()
    .superRefine((conflict, ctx) => {
        if (
            conflict.class === 'reference_conflict' &&
            conflict.resolution === 'skip'
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'reference_conflict cannot resolve to skip in P0',
                path: ['resolution'],
            });
        }
    });

export type RestoreConflict = z.infer<typeof RestoreConflict>;

export const RestorePlan = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        plan_id: z.string().min(1),
        plan_hash: Sha256Hex,
        plan_hash_algorithm: z.literal(PLAN_HASH_ALGORITHM),
        plan_hash_input_version: z.literal(PLAN_HASH_INPUT_VERSION),
        generated_at: isoDateTimeWithMillis,
        pit: RestorePitContract,
        scope: RestoreScope,
        execution_options: RestoreExecutionOptions,
        action_counts: RestoreActionCounts,
        conflicts: z.array(RestoreConflict),
        approval: RestoreApprovalMetadata,
        metadata_allowlist_version: z.literal(
            RESTORE_METADATA_ALLOWLIST_VERSION,
        ),
    })
    .strict();

export type RestorePlan = z.infer<typeof RestorePlan>;

export const RestoreJobStatus = z.enum([
    'queued',
    'running',
    'paused',
    'completed',
    'failed',
    'cancelled',
]);

export type RestoreJobStatus = z.infer<typeof RestoreJobStatus>;

export const RestoreJob = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        job_id: z.string().min(1),
        tenant_id: z.string().min(1),
        instance_id: z.string().min(1),
        source: z.string().min(1),
        plan_id: z.string().min(1),
        plan_hash: Sha256Hex,
        status: RestoreJobStatus,
        status_reason_code: RestoreReasonCode,
        lock_scope_tables: z.array(z.string().min(1)).min(1),
        required_capabilities: z.array(RestoreCapability).min(1),
        requested_by: z.string().min(1),
        requested_at: isoDateTimeWithMillis,
        approval: RestoreApprovalMetadata,
        metadata_allowlist_version: z.literal(
            RESTORE_METADATA_ALLOWLIST_VERSION,
        ),
    })
    .strict();

export type RestoreJob = z.infer<typeof RestoreJob>;

export const RestoreWatermarkFreshness = z.enum([
    'fresh',
    'stale',
    'unknown',
]);

export type RestoreWatermarkFreshness = z.infer<
    typeof RestoreWatermarkFreshness
>;

export const RestoreWatermarkExecutability = z.enum([
    'executable',
    'preview_only',
    'blocked',
]);

export type RestoreWatermarkExecutability = z.infer<
    typeof RestoreWatermarkExecutability
>;

export const RestoreWatermark = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        tenant_id: z.string().min(1),
        instance_id: z.string().min(1),
        source: z.string().min(1),
        topic: z.string().min(1),
        partition: z.number().int().nonnegative(),
        generation_id: z.string().min(1),
        indexed_through_offset: RestoreOffsetDecimalString,
        indexed_through_time: isoDateTimeWithMillis,
        coverage_start: isoDateTimeWithMillis,
        coverage_end: isoDateTimeWithMillis,
        freshness: RestoreWatermarkFreshness,
        executability: RestoreWatermarkExecutability,
        reason_code: RestoreReasonCode,
        measured_at: isoDateTimeWithMillis,
    })
    .strict()
    .superRefine((watermark, ctx) => {
        if (
            watermark.freshness === 'fresh' &&
            watermark.executability !== 'executable'
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'fresh watermark must be executable',
                path: ['executability'],
            });
        }

        if (
            watermark.freshness !== 'fresh' &&
            watermark.executability === 'executable'
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'stale or unknown watermark cannot be executable',
                path: ['executability'],
            });
        }
    });

export type RestoreWatermark = z.infer<typeof RestoreWatermark>;

export const RestoreDryRunWatermarkHint = z
    .object({
        topic: z.string().min(1),
        partition: z.number().int().nonnegative().optional(),
    })
    .strict();

export type RestoreDryRunWatermarkHint = z.infer<
    typeof RestoreDryRunWatermarkHint
>;

export const RestoreJournalEntry = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        journal_id: z.string().min(1),
        job_id: z.string().min(1),
        plan_hash: Sha256Hex,
        plan_row_id: z.string().min(1),
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        action: RestorePlanAction,
        touched_fields: z.array(z.string().min(1)).min(1),
        before_image_enc: EncryptedPayload.optional(),
        before_image_plain: z.unknown().optional(),
        chunk_id: z.string().min(1),
        row_attempt: z.number().int().positive(),
        executed_by: z.string().min(1),
        executed_at: isoDateTimeWithMillis,
        outcome: z.enum(['applied', 'skipped', 'failed']),
        error_code: RestoreReasonCode.optional(),
    })
    .strict()
    .superRefine((entry, ctx) => {
        if (entry.before_image_plain !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'before_image_plain is not allowed in RRS payloads',
                path: ['before_image_plain'],
            });
        }

        if (entry.outcome === 'applied' && !entry.before_image_enc) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'applied journal entries require before_image_enc',
                path: ['before_image_enc'],
            });
        }
    });

export type RestoreJournalEntry = z.infer<typeof RestoreJournalEntry>;

export const RestoreEvidenceArtifactHash = z
    .object({
        artifact_id: z.string().min(1),
        sha256: Sha256Hex,
        bytes: z.number().int().nonnegative(),
    })
    .strict();

export type RestoreEvidenceArtifactHash = z.infer<
    typeof RestoreEvidenceArtifactHash
>;

export const RestoreEvidenceSignature = z
    .object({
        signature_algorithm: z.enum(['ed25519', 'rsa-pss-sha256']),
        signer_key_id: z.string().min(1),
        signature: z.string().min(1),
        signature_verification: z.enum([
            'verified',
            'verification_pending',
            'verification_failed',
        ]),
        signed_at: isoDateTimeWithMillis,
    })
    .strict();

export type RestoreEvidenceSignature = z.infer<typeof RestoreEvidenceSignature>;

export const RestoreEvidence = z
    .object({
        contract_version: z.literal(RESTORE_CONTRACT_VERSION),
        evidence_id: z.string().min(1),
        job_id: z.string().min(1),
        plan_hash: Sha256Hex,
        report_hash: Sha256Hex,
        pit_algorithm_version: z.literal(PIT_ALGORITHM_VERSION),
        backup_timestamp: isoDateTimeWithMillis,
        approved_scope: RestoreScope,
        schema_drift_summary: z
            .object({
                compatible_columns: z.number().int().nonnegative(),
                incompatible_columns: z.number().int().nonnegative(),
                override_applied: z.boolean(),
            })
            .strict(),
        conflict_summary: z
            .object({
                total: z.number().int().nonnegative(),
                unresolved: z.number().int().nonnegative(),
            })
            .strict(),
        delete_decision_summary: z
            .object({
                allow_deletion: z.number().int().nonnegative(),
                skip_deletion: z.number().int().nonnegative(),
            })
            .strict(),
        execution_outcomes: z
            .object({
                rows_applied: z.number().int().nonnegative(),
                rows_skipped: z.number().int().nonnegative(),
                rows_failed: z.number().int().nonnegative(),
                attachments_applied: z.number().int().nonnegative(),
                attachments_skipped: z.number().int().nonnegative(),
                attachments_failed: z.number().int().nonnegative(),
            })
            .strict(),
        resume_metadata: z
            .object({
                resume_attempt_count: z.number().int().nonnegative(),
                checkpoint_id: z.string().min(1),
                next_chunk_index: z.number().int().nonnegative(),
                total_chunks: z.number().int().nonnegative(),
                last_chunk_id: z.string().min(1).nullable(),
                plan_checksum: Sha256Hex,
                precondition_checksum: Sha256Hex,
            })
            .strict(),
        artifact_hashes: z.array(RestoreEvidenceArtifactHash).min(1),
        canonicalization_version: z.literal(
            EVIDENCE_CANONICALIZATION_VERSION,
        ),
        manifest_signature: RestoreEvidenceSignature,
        immutable_storage: z
            .object({
                worm_enabled: z.boolean(),
                retention_class: z.string().min(1),
            })
            .strict(),
        approval: RestoreApprovalMetadata,
    })
    .strict();

export type RestoreEvidence = z.infer<typeof RestoreEvidence>;
