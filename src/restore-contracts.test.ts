import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { CloudEventSchema } from './schemas';
import {
    canonicalizeIsoDateTimeWithMillis,
    comparePitRowTuple,
    computeRestorePlanHash,
    selectLatestPitRowTuple,
    PIT_ALGORITHM_VERSION,
    RESTORE_CONTRACT_VERSION,
    RESTORE_METADATA_ALLOWLIST_VERSION,
    EVIDENCE_CANONICALIZATION_VERSION,
    PLAN_HASH_ALGORITHM,
    PLAN_HASH_INPUT_VERSION,
    RrsMetadataEnvelope,
    RestoreConflict,
    RestoreEvidence,
    RestoreJob,
    RestoreJournalEntry,
    RestorePitContract,
    RestorePlan,
    RestorePlanHashInput,
    RestoreWatermark,
} from './restore-contracts';

const HASH_A = 'a'.repeat(64);
const HASH_B = 'b'.repeat(64);
const HASH_C = 'c'.repeat(64);

function encryptedPayload(label: string) {
    return {
        alg: 'AES-256-CBC',
        module: 'x_rezrp_rezilient.encrypter',
        format: 'kmf',
        compression: 'none' as const,
        ciphertext: `cipher:${label}`,
    };
}

function approvalPlaceholder() {
    return {
        approval_required: false,
        approval_state: 'placeholder_not_enforced' as const,
        approval_placeholder_mode: 'mvp_not_enforced' as const,
    };
}

function pitContract() {
    return {
        restore_time: '2026-02-16T12:00:00.123Z',
        restore_timezone: 'UTC' as const,
        pit_algorithm_version: PIT_ALGORITHM_VERSION,
        tie_breaker: [
            'sys_updated_on',
            'sys_mod_count',
            '__time',
            'event_id',
        ] as const,
        tie_breaker_fallback: [
            'sys_updated_on',
            '__time',
            'event_id',
        ] as const,
    };
}

function scopeContract() {
    return {
        mode: 'record' as const,
        tables: ['x_app.ticket'],
        encoded_query: 'active=true',
    };
}

function executionOptions() {
    return {
        missing_row_mode: 'existing_only' as const,
        conflict_policy: 'review_required' as const,
        schema_compatibility_mode: 'compatible_only' as const,
        workflow_mode: 'suppressed_default' as const,
    };
}

function actionCounts() {
    return {
        update: 1,
        insert: 0,
        delete: 0,
        skip: 0,
        conflict: 0,
        attachment_apply: 0,
        attachment_skip: 0,
    };
}

function metadataEnvelope() {
    return {
        allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
        metadata: {
            tenant_id: 'tenant-acme',
            instance_id: 'sn-dev-01',
            source: 'sn://acme-dev.service-now.com',
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
            event_id: 'evt_01',
            event_type: 'cdc.write',
            operation: 'U' as const,
            schema_version: 3,
            sys_updated_on: '2026-02-16 12:00:00',
            sys_mod_count: 18,
            __time: '2026-02-16T12:00:00.123Z',
            topic: 'rez.cdc',
            partition: 2,
            offset: 1234,
        },
    };
}

function hashRowInput() {
    return {
        row_id: 'row-01',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        action: 'update' as const,
        precondition_hash: HASH_A,
        metadata: metadataEnvelope(),
        values: {
            diff_enc: encryptedPayload('row-diff'),
        },
    };
}

function mediaCandidate(id: string, decision?: 'include' | 'exclude') {
    return {
        candidate_id: id,
        table: 'x_app.ticket',
        record_sys_id: `rec-${id}`,
        attachment_sys_id: `att-${id}`,
        size_bytes: 128,
        sha256_plain: HASH_B,
        decision,
        metadata: {
            allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
            metadata: {
                table: 'x_app.ticket',
                record_sys_id: `rec-${id}`,
                attachment_sys_id: `att-${id}`,
                size_bytes: 128,
                sha256_plain: HASH_B,
            },
        },
    };
}

function basePlanHashInput() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        plan_hash_input_version: PLAN_HASH_INPUT_VERSION,
        plan_hash_algorithm: PLAN_HASH_ALGORITHM,
        pit: pitContract(),
        scope: scopeContract(),
        execution_options: executionOptions(),
        action_counts: actionCounts(),
        rows: [hashRowInput()],
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    };
}

function basePlan() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        plan_id: 'plan-01',
        plan_hash: HASH_A,
        plan_hash_algorithm: PLAN_HASH_ALGORITHM,
        plan_hash_input_version: PLAN_HASH_INPUT_VERSION,
        generated_at: '2026-02-16T12:10:00.000Z',
        pit: pitContract(),
        scope: scopeContract(),
        execution_options: executionOptions(),
        action_counts: actionCounts(),
        conflicts: [],
        approval: approvalPlaceholder(),
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    };
}

function baseJob() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        job_id: 'job-01',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        source: 'sn://acme-dev.service-now.com',
        plan_id: 'plan-01',
        plan_hash: HASH_A,
        status: 'queued' as const,
        status_reason_code: 'queued_scope_lock' as const,
        lock_scope_tables: ['x_app.ticket'],
        required_capabilities: ['restore_execute'] as const,
        requested_by: 'operator@example.com',
        requested_at: '2026-02-16T12:11:00.000Z',
        approval: approvalPlaceholder(),
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    };
}

function baseWatermark() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        source: 'sn://acme-dev.service-now.com',
        topic: 'rez.cdc',
        partition: 2,
        generation_id: 'gen-01',
        indexed_through_offset: 100,
        indexed_through_time: '2026-02-16T12:00:00.000Z',
        coverage_start: '2026-02-16T00:00:00.000Z',
        coverage_end: '2026-02-16T12:00:00.000Z',
        freshness: 'fresh' as const,
        executability: 'executable' as const,
        reason_code: 'none' as const,
        measured_at: '2026-02-16T12:12:00.000Z',
    };
}

function baseJournalEntry() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        journal_id: 'journal-01',
        job_id: 'job-01',
        plan_hash: HASH_A,
        plan_row_id: 'row-01',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        action: 'update' as const,
        touched_fields: ['state'],
        before_image_enc: encryptedPayload('before-image'),
        chunk_id: 'chunk-01',
        row_attempt: 1,
        executed_by: 'operator@example.com',
        executed_at: '2026-02-16T12:13:00.000Z',
        outcome: 'applied' as const,
    };
}

function baseEvidence() {
    return {
        contract_version: RESTORE_CONTRACT_VERSION,
        evidence_id: 'evidence-01',
        job_id: 'job-01',
        plan_hash: HASH_A,
        report_hash: HASH_B,
        pit_algorithm_version: PIT_ALGORITHM_VERSION,
        backup_timestamp: '2026-02-16T12:00:00.000Z',
        approved_scope: scopeContract(),
        schema_drift_summary: {
            compatible_columns: 12,
            incompatible_columns: 0,
            override_applied: false,
        },
        conflict_summary: {
            total: 1,
            unresolved: 0,
        },
        delete_decision_summary: {
            allow_deletion: 0,
            skip_deletion: 0,
        },
        execution_outcomes: {
            rows_applied: 1,
            rows_skipped: 0,
            rows_failed: 0,
            attachments_applied: 0,
            attachments_skipped: 0,
            attachments_failed: 0,
        },
        resume_metadata: {
            resume_attempt_count: 0,
            checkpoint_id: 'chk_abcdef',
            next_chunk_index: 1,
            total_chunks: 1,
            last_chunk_id: 'chunk_0001',
            plan_checksum: HASH_A,
            precondition_checksum: HASH_B,
        },
        artifact_hashes: [
            {
                artifact_id: 'plan.json',
                sha256: HASH_C,
                bytes: 1024,
            },
        ],
        canonicalization_version: EVIDENCE_CANONICALIZATION_VERSION,
        manifest_signature: {
            signature_algorithm: 'ed25519' as const,
            signer_key_id: 'signer-01',
            signature: 'signature-bytes',
            signature_verification: 'verified' as const,
            signed_at: '2026-02-16T12:14:00.000Z',
        },
        immutable_storage: {
            worm_enabled: true,
            retention_class: 'compliance-7y',
        },
        approval: approvalPlaceholder(),
    };
}

test('RrsMetadataEnvelope accepts allowlisted operational metadata', () => {
    const parsed = RrsMetadataEnvelope.safeParse(metadataEnvelope());

    assert.equal(parsed.success, true);
});

test('RrsMetadataEnvelope rejects metadata fields outside allowlist', () => {
    const parsed = RrsMetadataEnvelope.safeParse({
        ...metadataEnvelope(),
        metadata: {
            ...metadataEnvelope().metadata,
            short_description: 'plaintext value',
        },
    });

    assert.equal(parsed.success, false);
    if (parsed.success) {
        return;
    }

    const paths = parsed.error.issues.map((issue) => issue.path.join('.'));

    assert(paths.includes('metadata'));
});

test('RestorePitContract accepts second and millisecond UTC timestamps', () => {
    const secondPrecision = RestorePitContract.safeParse({
        ...pitContract(),
        restore_time: '2026-02-16T12:00:00Z',
    });

    const millisPrecision = RestorePitContract.safeParse(pitContract());

    assert.equal(secondPrecision.success, true);
    assert.equal(millisPrecision.success, true);
});

test('canonicalizeIsoDateTimeWithMillis normalizes to millis', () => {
    const secondPrecision = canonicalizeIsoDateTimeWithMillis(
        '2026-02-16T12:00:00Z',
    );
    const millisPrecision = canonicalizeIsoDateTimeWithMillis(
        '2026-02-16T12:00:00.250Z',
    );

    assert.equal(secondPrecision, '2026-02-16T12:00:00.000Z');
    assert.equal(millisPrecision, '2026-02-16T12:00:00.250Z');
});

test('comparePitRowTuple uses sys_mod_count when available', () => {
    const older = {
        sys_updated_on: '2026-02-16 12:00:00',
        sys_mod_count: 7,
        __time: '2026-02-16T12:00:00.100Z',
        event_id: 'evt-a',
    };
    const newer = {
        ...older,
        sys_mod_count: 8,
        __time: '2026-02-16T12:00:00.050Z',
        event_id: 'evt-b',
    };

    assert.equal(comparePitRowTuple(older, newer), -1);
    assert.equal(comparePitRowTuple(newer, older), 1);
});

test('comparePitRowTuple falls back when sys_mod_count is unavailable', () => {
    const first = {
        sys_updated_on: '2026-02-16 12:00:00',
        __time: '2026-02-16T12:00:00.100Z',
        event_id: 'evt-a',
    };
    const second = {
        sys_updated_on: '2026-02-16 12:00:00',
        __time: '2026-02-16T12:00:00.200Z',
        event_id: 'evt-b',
    };

    assert.equal(comparePitRowTuple(first, second), -1);
    assert.equal(comparePitRowTuple(second, first), 1);
});

test('comparePitRowTuple falls back when one side lacks sys_mod_count', () => {
    const first = {
        sys_updated_on: '2026-02-16 12:00:00',
        sys_mod_count: 3,
        __time: '2026-02-16T12:00:00.100Z',
        event_id: 'evt-a',
    };
    const second = {
        sys_updated_on: '2026-02-16 12:00:00',
        __time: '2026-02-16T12:00:00.200Z',
        event_id: 'evt-b',
    };

    assert.equal(comparePitRowTuple(first, second), -1);
    assert.equal(comparePitRowTuple(second, first), 1);
});

test('selectLatestPitRowTuple chooses deterministic winner', () => {
    const winner = selectLatestPitRowTuple([
        {
            sys_updated_on: '2026-02-16 12:00:00',
            sys_mod_count: 3,
            __time: '2026-02-16T12:00:00.100Z',
            event_id: 'evt-a',
        },
        {
            sys_updated_on: '2026-02-16 12:00:00',
            sys_mod_count: 3,
            __time: '2026-02-16T12:00:00.100Z',
            event_id: 'evt-z',
        },
    ]);

    assert.equal(winner.event_id, 'evt-z');
});

test('RestorePlanHashInput validates plan-hash contract payload', () => {
    const parsed = RestorePlanHashInput.safeParse(basePlanHashInput());

    assert.equal(parsed.success, true);
});

test('computeRestorePlanHash is deterministic for identical input', () => {
    const parsed = RestorePlanHashInput.parse(basePlanHashInput());
    const firstHash = computeRestorePlanHash(parsed);
    const secondHash = computeRestorePlanHash(
        RestorePlanHashInput.parse(basePlanHashInput()),
    );

    assert.equal(firstHash.plan_hash, secondHash.plan_hash);
    assert.equal(firstHash.canonical_json, secondHash.canonical_json);
});

test('RestorePlanHashInput rejects plaintext value material', () => {
    const parsed = RestorePlanHashInput.safeParse({
        contract_version: RESTORE_CONTRACT_VERSION,
        plan_hash_input_version: PLAN_HASH_INPUT_VERSION,
        plan_hash_algorithm: PLAN_HASH_ALGORITHM,
        pit: pitContract(),
        scope: scopeContract(),
        execution_options: executionOptions(),
        action_counts: actionCounts(),
        rows: [
            {
                ...hashRowInput(),
                values: {
                    diff_plain: {
                        state: '3',
                    },
                },
            },
        ],
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    });

    assert.equal(parsed.success, false);
    if (parsed.success) {
        return;
    }

    const messages = parsed.error.issues.map((issue) => issue.message);

    assert(messages.includes('diff_plain is not allowed in RRS payloads'));
});

test('RestorePlanHashInput enforces sorted unique row_id values', () => {
    const firstRow = hashRowInput();
    const secondRow = {
        ...hashRowInput(),
        row_id: 'row-02',
        record_sys_id: 'abc124',
        metadata: {
            ...metadataEnvelope(),
            metadata: {
                ...metadataEnvelope().metadata,
                record_sys_id: 'abc124',
                event_id: 'evt_02',
            },
        },
    };

    const duplicate = RestorePlanHashInput.safeParse({
        contract_version: RESTORE_CONTRACT_VERSION,
        plan_hash_input_version: PLAN_HASH_INPUT_VERSION,
        plan_hash_algorithm: PLAN_HASH_ALGORITHM,
        pit: pitContract(),
        scope: scopeContract(),
        execution_options: executionOptions(),
        action_counts: actionCounts(),
        rows: [firstRow, { ...secondRow, row_id: 'row-01' }],
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    });

    assert.equal(duplicate.success, false);

    const unsorted = RestorePlanHashInput.safeParse({
        contract_version: RESTORE_CONTRACT_VERSION,
        plan_hash_input_version: PLAN_HASH_INPUT_VERSION,
        plan_hash_algorithm: PLAN_HASH_ALGORITHM,
        pit: pitContract(),
        scope: scopeContract(),
        execution_options: executionOptions(),
        action_counts: actionCounts(),
        rows: [secondRow, firstRow],
        metadata_allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
    });

    assert.equal(unsorted.success, false);
});

test('RestorePlanHashInput validates RS-11 media candidate contract', () => {
    const valid = RestorePlanHashInput.safeParse({
        ...basePlanHashInput(),
        media_candidates: [
            mediaCandidate('candidate-01', 'include'),
            mediaCandidate('candidate-02', 'exclude'),
        ],
    });

    assert.equal(valid.success, true);

    const unsorted = RestorePlanHashInput.safeParse({
        ...basePlanHashInput(),
        media_candidates: [
            mediaCandidate('candidate-02', 'include'),
            mediaCandidate('candidate-01', 'exclude'),
        ],
    });

    assert.equal(unsorted.success, false);

    const missingIdentity = RestorePlanHashInput.safeParse({
        ...basePlanHashInput(),
        media_candidates: [
            {
                ...mediaCandidate('candidate-01', 'include'),
                attachment_sys_id: undefined,
                media_id: undefined,
            },
        ],
    });

    assert.equal(missingIdentity.success, false);
});

test('RestoreConflict blocks skip resolution for reference_conflict', () => {
    const parsed = RestoreConflict.safeParse({
        conflict_id: 'conflict-01',
        class: 'reference_conflict',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        reason_code: 'blocked_reference_conflict',
        reason: 'Referenced caller record is missing',
        resolution: 'skip',
        observed_at: '2026-02-16T12:15:00.000Z',
    });

    assert.equal(parsed.success, false);
});

test('RestorePlan schema accepts versioned plan contract', () => {
    const parsed = RestorePlan.safeParse(basePlan());

    assert.equal(parsed.success, true);
});

test('RestoreJob schema accepts queued job with capability contract', () => {
    const parsed = RestoreJob.safeParse(baseJob());

    assert.equal(parsed.success, true);
});

test('RestoreWatermark blocks executable state when freshness is stale', () => {
    const invalid = RestoreWatermark.safeParse({
        ...baseWatermark(),
        freshness: 'stale',
        executability: 'executable',
    });

    assert.equal(invalid.success, false);

    const valid = RestoreWatermark.safeParse(baseWatermark());

    assert.equal(valid.success, true);
});

test('RestoreJournalEntry rejects plaintext and enforces before-image', () => {
    const plaintext = RestoreJournalEntry.safeParse({
        ...baseJournalEntry(),
        before_image_plain: {
            state: '1',
        },
    });

    assert.equal(plaintext.success, false);

    const missingBeforeImage = RestoreJournalEntry.safeParse({
        ...baseJournalEntry(),
        before_image_enc: undefined,
    });

    assert.equal(missingBeforeImage.success, false);

    const valid = RestoreJournalEntry.safeParse(baseJournalEntry());

    assert.equal(valid.success, true);
});

test('RestoreEvidence requires PIT version, hashes, and signed manifest', () => {
    const parsed = RestoreEvidence.safeParse(baseEvidence());

    assert.equal(parsed.success, true);
});

test('RestoreEvidence requires resume metadata fields', () => {
    const invalid = RestoreEvidence.safeParse({
        ...baseEvidence(),
        resume_metadata: undefined,
    });

    assert.equal(invalid.success, false);
});

test('CloudEvent envelope remains compatible with restore metadata mapping', () => {
    const eventParsed = CloudEventSchema.safeParse({
        datacontenttype: 'application/json',
        id: 'evt_compat_01',
        source: 'sn://acme-dev.service-now.com',
        specversion: '1.0',
        subject: 'x_app.ticket/abc123',
        time: '2026-02-16T12:00:00Z',
        type: 'cdc.write',
        data: {
            op: 'U',
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
            schema_version: 3,
            sys_updated_on: '2026-02-16 12:00:00',
            snapshot_enc: encryptedPayload('compat'),
        },
    });

    assert.equal(eventParsed.success, true);
    if (!eventParsed.success) {
        return;
    }

    if (eventParsed.data.type !== 'cdc.write') {
        assert.fail('Expected cdc.write compatibility fixture');
    }

    const metadataParsed = RrsMetadataEnvelope.safeParse({
        allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
        metadata: {
            source: eventParsed.data.source,
            event_id: eventParsed.data.id,
            event_type: eventParsed.data.type,
            table: eventParsed.data.data.table,
            record_sys_id: eventParsed.data.data.record_sys_id,
            schema_version: eventParsed.data.data.schema_version,
            operation: eventParsed.data.data.op,
            sys_updated_on: eventParsed.data.data.sys_updated_on,
            __time: '2026-02-16T12:00:00.000Z',
        },
    });

    assert.equal(metadataParsed.success, true);
});
