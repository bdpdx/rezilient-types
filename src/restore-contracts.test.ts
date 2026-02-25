import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { CloudEventSchema } from './schemas';
import {
    Sha256Hex,
    canonicalJsonStringify,
    canonicalizeIsoDateTimeWithMillis,
    canonicalizeRestoreOffsetDecimalString,
    comparePitRowTuple,
    computeRestorePlanHash,
    isRestoreOffsetDecimalString,
    selectLatestPitRowTuple,
    PIT_ALGORITHM_VERSION,
    RESTORE_CONTRACT_VERSION,
    RESTORE_METADATA_ALLOWLIST_VERSION,
    EVIDENCE_CANONICALIZATION_VERSION,
    PLAN_HASH_ALGORITHM,
    PLAN_HASH_INPUT_VERSION,
    RestoreApprovalMetadata,
    RestoreApprovalState,
    RestoreCapability,
    RestoreConflict,
    RestoreEncryptedValueEnvelope,
    RestoreEvidence,
    RestoreEvidenceArtifactHash,
    RestoreEvidenceSignature,
    RestoreJob,
    RestoreJobStatus,
    RestoreJournalEntry,
    RestoreMediaCandidate,
    RestorePitContract,
    RestorePlan,
    RestorePlanHashInput,
    RestorePlanHashRowInput,
    RestoreReasonCode,
    RestoreScope,
    RestoreWatermark,
    RrsMetadataEnvelope,
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
            offset: '1234',
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
        indexed_through_offset: '100',
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

test('RrsMetadataEnvelope canonicalizes legacy numeric offset input to string', () => {
    const parsed = RrsMetadataEnvelope.safeParse({
        ...metadataEnvelope(),
        metadata: {
            ...metadataEnvelope().metadata,
            offset: 1234,
        },
    });

    assert.equal(parsed.success, true);
    if (!parsed.success) {
        return;
    }

    assert.equal(typeof parsed.data.metadata.offset, 'string');
    assert.equal(parsed.data.metadata.offset, '1234');
});

test('RestoreWatermark accepts large decimal-string offsets beyond safe integer range', () => {
    const largeOffset = '900719925474099312345678901234567890';
    const parsed = RestoreWatermark.safeParse({
        ...baseWatermark(),
        indexed_through_offset: largeOffset,
    });

    assert.equal(parsed.success, true);
    if (!parsed.success) {
        return;
    }

    assert.equal(parsed.data.indexed_through_offset, largeOffset);
});

test('offset decimal-string helper canonicalizes numeric input', () => {
    assert.equal(
        canonicalizeRestoreOffsetDecimalString('000000123'),
        '123',
    );
    assert.equal(
        canonicalizeRestoreOffsetDecimalString(42),
        '42',
    );
    assert.equal(isRestoreOffsetDecimalString('9007199254740993123'), true);
    assert.equal(isRestoreOffsetDecimalString('-1'), false);
});

test('offset fields reject signed, decimal, and non-numeric strings', () => {
    const invalidOffsets = ['-1', '+1', '1.5', 'abc'];

    for (const invalidOffset of invalidOffsets) {
        const metadataParsed = RrsMetadataEnvelope.safeParse({
            ...metadataEnvelope(),
            metadata: {
                ...metadataEnvelope().metadata,
                offset: invalidOffset,
            },
        });

        assert.equal(metadataParsed.success, false);

        const watermarkParsed = RestoreWatermark.safeParse({
            ...baseWatermark(),
            indexed_through_offset: invalidOffset,
        });

        assert.equal(watermarkParsed.success, false);
    }
});

test('offset fields reject unsafe integer numbers', () => {
    const unsafeOffset = Number.MAX_SAFE_INTEGER + 1;
    const metadataParsed = RrsMetadataEnvelope.safeParse({
        ...metadataEnvelope(),
        metadata: {
            ...metadataEnvelope().metadata,
            offset: unsafeOffset,
        },
    });
    const watermarkParsed = RestoreWatermark.safeParse({
        ...baseWatermark(),
        indexed_through_offset: unsafeOffset,
    });

    assert.equal(metadataParsed.success, false);
    assert.equal(watermarkParsed.success, false);
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

test('Sha256Hex canonicalizes uppercase hex to lowercase', () => {
    const upper = 'A'.repeat(64);
    const mixed = 'aAbBcCdD'.repeat(8);

    const parsedUpper = Sha256Hex.parse(upper);
    const parsedMixed = Sha256Hex.parse(mixed);

    assert.equal(parsedUpper, 'a'.repeat(64));
    assert.equal(parsedMixed, mixed.toLowerCase());
});

test('canonicalJsonStringify skips undefined values in objects', () => {
    const result = canonicalJsonStringify({
        a: 1,
        b: undefined,
        c: 'hello',
    });

    assert.equal(result, '{"a":1,"c":"hello"}');
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

// Stage 5: Enums and Leaf Schemas

test('Sha256Hex rejects invalid hex values', () => {
    const tooShort = Sha256Hex.safeParse('a'.repeat(63));
    const tooLong = Sha256Hex.safeParse('a'.repeat(65));
    const nonHex = Sha256Hex.safeParse('g'.repeat(64));
    const empty = Sha256Hex.safeParse('');

    assert.equal(tooShort.success, false);
    assert.equal(tooLong.success, false);
    assert.equal(nonHex.success, false);
    assert.equal(empty.success, false);
});

test('RestoreCapability accepts all valid values', () => {
    const values = [
        'restore_execute',
        'restore_delete',
        'restore_override_caps',
        'restore_schema_override',
    ];

    for (const value of values) {
        assert.equal(
            RestoreCapability.safeParse(value).success,
            true,
            `expected ${value} to be valid`,
        );
    }

    assert.equal(
        RestoreCapability.safeParse('invalid').success,
        false,
    );
});

test('RestoreReasonCode accepts representative values and rejects invalid', () => {
    const valid = [
        'none',
        'queued_scope_lock',
        'blocked_plan_hash_mismatch',
        'failed_internal_error',
    ];

    for (const value of valid) {
        assert.equal(
            RestoreReasonCode.safeParse(value).success,
            true,
            `expected ${value} to be valid`,
        );
    }

    assert.equal(
        RestoreReasonCode.safeParse('made_up_code').success,
        false,
    );
});

test('RestoreApprovalState accepts all values', () => {
    const values = [
        'placeholder_not_enforced',
        'approval_not_required',
        'requested',
        'approved',
        'rejected',
        'expired',
    ];

    for (const value of values) {
        assert.equal(
            RestoreApprovalState.safeParse(value).success,
            true,
            `expected ${value} to be valid`,
        );
    }
});

test('RestoreScope table mode accepts without record filter', () => {
    const parsed = RestoreScope.safeParse({
        mode: 'table',
        tables: ['x_app.ticket'],
    });

    assert.equal(parsed.success, true);
});

test('RestoreScope record mode rejects without record filter', () => {
    const parsed = RestoreScope.safeParse({
        mode: 'record',
        tables: ['x_app.ticket'],
    });

    assert.equal(parsed.success, false);
});

test('RestoreScope record mode accepts with encoded_query', () => {
    const parsed = RestoreScope.safeParse({
        mode: 'record',
        tables: ['x_app.ticket'],
        encoded_query: 'active=true',
    });

    assert.equal(parsed.success, true);
});

test('RestoreScope record mode accepts with record_sys_ids', () => {
    const parsed = RestoreScope.safeParse({
        mode: 'record',
        tables: ['x_app.ticket'],
        record_sys_ids: ['abc123'],
    });

    assert.equal(parsed.success, true);
});

test('RestoreScope column mode requires columns and record filter', () => {
    const noColumns = RestoreScope.safeParse({
        mode: 'column',
        tables: ['x_app.ticket'],
        record_sys_ids: ['abc123'],
    });
    const noFilter = RestoreScope.safeParse({
        mode: 'column',
        tables: ['x_app.ticket'],
        columns: ['state'],
    });
    const valid = RestoreScope.safeParse({
        mode: 'column',
        tables: ['x_app.ticket'],
        columns: ['state', 'priority'],
        encoded_query: 'active=true',
    });

    assert.equal(noColumns.success, false);
    assert.equal(noFilter.success, false);
    assert.equal(valid.success, true);
});

test('RestoreApprovalMetadata accepts full approval with all optional fields', () => {
    const parsed = RestoreApprovalMetadata.safeParse({
        approval_required: true,
        approval_state: 'approved',
        approval_policy_id: 'policy-01',
        approval_requested_at: '2026-02-16T12:00:00.000Z',
        approval_requested_by: 'admin@example.com',
        approval_decided_at: '2026-02-16T12:05:00.000Z',
        approval_decided_by: 'manager@example.com',
        approval_decision: 'approve',
        approval_decision_reason: 'Authorized by SOC team',
        approval_external_ref: 'RITM001234',
        approval_snapshot_hash: 'a'.repeat(64),
        approval_valid_until: '2026-02-17T12:00:00.000Z',
        approval_revalidated_at: '2026-02-16T18:00:00.000Z',
        approval_revalidation_result: 'valid',
        approval_placeholder_mode: 'mvp_not_enforced',
    });

    assert.equal(parsed.success, true);
});

// Stage 6: Compound Schemas

test('RestoreMediaCandidate requires attachment_sys_id or media_id', () => {
    const neither = RestoreMediaCandidate.safeParse({
        candidate_id: 'candidate-01',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        size_bytes: 128,
        sha256_plain: 'b'.repeat(64),
    });

    assert.equal(neither.success, false);
});

test('RestoreMediaCandidate accepts with media_id only', () => {
    const parsed = RestoreMediaCandidate.safeParse({
        candidate_id: 'candidate-01',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        media_id: 'media-01',
        size_bytes: 128,
        sha256_plain: 'b'.repeat(64),
    });

    assert.equal(parsed.success, true);
});

test('RestoreMediaCandidate rejects metadata table mismatch', () => {
    const parsed = RestoreMediaCandidate.safeParse({
        candidate_id: 'candidate-01',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        attachment_sys_id: 'att-01',
        size_bytes: 128,
        sha256_plain: 'b'.repeat(64),
        metadata: {
            allowlist_version: 'rrs.metadata.allowlist.v1',
            metadata: {
                table: 'x_app.other_table',
                record_sys_id: 'rec-01',
            },
        },
    });

    assert.equal(parsed.success, false);
});

test('RestoreEncryptedValueEnvelope rejects all plaintext fields', () => {
    const diffPlain = RestoreEncryptedValueEnvelope.safeParse({
        diff_plain: { state: '3' },
    });
    const beforePlain = RestoreEncryptedValueEnvelope.safeParse({
        before_image_plain: { state: '1' },
    });
    const afterPlain = RestoreEncryptedValueEnvelope.safeParse({
        after_image_plain: { state: '2' },
    });

    assert.equal(diffPlain.success, false);
    assert.equal(beforePlain.success, false);
    assert.equal(afterPlain.success, false);
});

test('RestoreEncryptedValueEnvelope accepts encrypted-only fields', () => {
    const parsed = RestoreEncryptedValueEnvelope.safeParse({
        diff_enc: encryptedPayload('diff'),
        before_image_enc: encryptedPayload('before'),
        after_image_enc: encryptedPayload('after'),
    });

    assert.equal(parsed.success, true);
});

test('RestorePlanHashRowInput skip action does not require values', () => {
    const parsed = RestorePlanHashRowInput.safeParse({
        row_id: 'row-skip',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        action: 'skip',
        precondition_hash: HASH_A,
        metadata: metadataEnvelope(),
    });

    assert.equal(parsed.success, true);
});

test('RestorePlanHashRowInput non-skip action requires encrypted values', () => {
    const parsed = RestorePlanHashRowInput.safeParse({
        row_id: 'row-update',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        action: 'update',
        precondition_hash: HASH_A,
        metadata: metadataEnvelope(),
    });

    assert.equal(parsed.success, false);
});

test('RestorePlanHashRowInput rejects metadata table mismatch', () => {
    const parsed = RestorePlanHashRowInput.safeParse({
        row_id: 'row-01',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        action: 'update',
        precondition_hash: HASH_A,
        metadata: {
            allowlist_version: RESTORE_METADATA_ALLOWLIST_VERSION,
            metadata: {
                ...metadataEnvelope().metadata,
                table: 'x_app.other_table',
            },
        },
        values: {
            diff_enc: encryptedPayload('diff'),
        },
    });

    assert.equal(parsed.success, false);
});

test('canonicalJsonStringify sorts nested object keys deterministically', () => {
    const result = canonicalJsonStringify({
        z: { b: 2, a: 1 },
        a: [3, 1, 2],
        m: null,
    });

    assert.equal(result, '{"a":[3,1,2],"m":null,"z":{"a":1,"b":2}}');
});

test('canonicalJsonStringify handles primitive values', () => {
    assert.equal(canonicalJsonStringify(null), 'null');
    assert.equal(canonicalJsonStringify(true), 'true');
    assert.equal(canonicalJsonStringify(42), '42');
    assert.equal(canonicalJsonStringify('hello'), '"hello"');
});

test('computeRestorePlanHash produces different hashes for different inputs', () => {
    const inputA = RestorePlanHashInput.parse(basePlanHashInput());
    const inputB = RestorePlanHashInput.parse({
        ...basePlanHashInput(),
        action_counts: {
            ...actionCounts(),
            update: 2,
        },
    });

    const hashA = computeRestorePlanHash(inputA);
    const hashB = computeRestorePlanHash(inputB);

    assert.notEqual(hashA.plan_hash, hashB.plan_hash);
});

// Stage 7: Top-Level Schema Variants

test('RestoreJobStatus accepts all valid states', () => {
    const states = [
        'queued', 'running', 'paused',
        'completed', 'failed', 'cancelled',
    ];

    for (const status of states) {
        assert.equal(
            RestoreJobStatus.safeParse(status).success,
            true,
            `expected ${status} to be valid`,
        );
    }
});

test('RestoreJob accepts running and completed states', () => {
    const running = RestoreJob.safeParse({
        ...baseJob(),
        status: 'running',
        status_reason_code: 'none',
    });
    const completed = RestoreJob.safeParse({
        ...baseJob(),
        status: 'completed',
        status_reason_code: 'none',
    });

    assert.equal(running.success, true);
    assert.equal(completed.success, true);
});

test('RestoreWatermark accepts stale with preview_only', () => {
    const parsed = RestoreWatermark.safeParse({
        ...baseWatermark(),
        freshness: 'stale',
        executability: 'preview_only',
    });

    assert.equal(parsed.success, true);
});

test('RestoreWatermark accepts unknown freshness with blocked', () => {
    const parsed = RestoreWatermark.safeParse({
        ...baseWatermark(),
        freshness: 'unknown',
        executability: 'blocked',
        reason_code: 'blocked_freshness_unknown',
    });

    assert.equal(parsed.success, true);
});

test('RestoreWatermark rejects unknown freshness with executable', () => {
    const parsed = RestoreWatermark.safeParse({
        ...baseWatermark(),
        freshness: 'unknown',
        executability: 'executable',
    });

    assert.equal(parsed.success, false);
});

test('RestoreJournalEntry skipped outcome does not require before_image_enc', () => {
    const parsed = RestoreJournalEntry.safeParse({
        ...baseJournalEntry(),
        before_image_enc: undefined,
        outcome: 'skipped',
    });

    assert.equal(parsed.success, true);
});

test('RestoreJournalEntry failed outcome does not require before_image_enc', () => {
    const parsed = RestoreJournalEntry.safeParse({
        ...baseJournalEntry(),
        before_image_enc: undefined,
        outcome: 'failed',
        error_code: 'failed_internal_error',
    });

    assert.equal(parsed.success, true);
});

test('RestoreEvidenceArtifactHash accepts valid hash entry', () => {
    const parsed = RestoreEvidenceArtifactHash.safeParse({
        artifact_id: 'plan.json',
        sha256: 'c'.repeat(64),
        bytes: 2048,
    });

    assert.equal(parsed.success, true);
});

test('RestoreEvidenceSignature accepts rsa-pss-sha256 algorithm', () => {
    const parsed = RestoreEvidenceSignature.safeParse({
        signature_algorithm: 'rsa-pss-sha256',
        signer_key_id: 'signer-rsa-01',
        signature: 'rsa-signature-bytes',
        signature_verification: 'verified',
        signed_at: '2026-02-16T12:14:00.000Z',
    });

    assert.equal(parsed.success, true);
});

test('RestoreEvidenceSignature accepts all verification states', () => {
    const states = [
        'verified',
        'verification_pending',
        'verification_failed',
    ];

    for (const state of states) {
        const parsed = RestoreEvidenceSignature.safeParse({
            signature_algorithm: 'ed25519',
            signer_key_id: 'signer-01',
            signature: 'sig-bytes',
            signature_verification: state,
            signed_at: '2026-02-16T12:14:00.000Z',
        });

        assert.equal(
            parsed.success,
            true,
            `expected ${state} to be valid`,
        );
    }
});

test('RestoreEvidence accepts multiple artifact hashes', () => {
    const parsed = RestoreEvidence.safeParse({
        ...baseEvidence(),
        artifact_hashes: [
            { artifact_id: 'plan.json', sha256: HASH_A, bytes: 1024 },
            { artifact_id: 'journal.jsonl', sha256: HASH_B, bytes: 2048 },
            { artifact_id: 'manifest.json', sha256: HASH_C, bytes: 512 },
        ],
    });

    assert.equal(parsed.success, true);
});
