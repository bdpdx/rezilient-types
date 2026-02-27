import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import {
    buildEventBatchSchema,
    canonicalizeIsoDateTimeUtc,
    CDCDeleteData,
    CDCWriteData,
    CloudEventSchema,
    EncryptedPayload,
    ErrorReportData,
    EventBatchSchema,
    ExtensionsSchema,
    isIsoDateTimeUtc,
    MediaBlobChunking,
    MediaBlobDescriptor,
    MediaDeleteData,
    MediaManifestData,
    MediaMetaData,
    RepairReportData,
    SchemaChangeData,
    SchemaSnapshotData,
    serviceNowDateTime,
} from './schemas';

function baseEvent() {
    return {
        datacontenttype: 'application/json' as const,
        id: 'evt_01',
        source: 'sn://acme-dev.service-now.com',
        specversion: '1.0' as const,
        subject: 'x_app.ticket/abc123',
        time: '2026-02-14T00:00:00Z',
    };
}

function encryptedPayload(label: string) {
    return {
        alg: 'AES-256-CBC',
        module: 'x_rezrp_rezilient.encrypter',
        format: 'kmf',
        compression: 'none' as const,
        ciphertext: `cipher:${label}`,
    };
}

test('CloudEventSchema accepts cdc.write with ISO retention_days', () => {
    const parsed = CloudEventSchema.safeParse({
        ...baseEvent(),
        data: {
            changed_fields: ['state'],
            op: 'U',
            record_sys_id: 'abc123',
            schema_version: 3,
            snapshot_enc: encryptedPayload('cdc.write'),
            sys_updated_on: '2026-02-14 00:00:00',
            table: 'x_app.ticket',
        },
        extensions: {
            retention_days: 'P30D',
        },
        type: 'cdc.write',
    });

    assert.equal(parsed.success, true);
});

test('CloudEventSchema accepts canonical identity extensions', () => {
    const parsed = CloudEventSchema.safeParse({
        ...baseEvent(),
        data: {
            changed_fields: ['state'],
            op: 'U',
            record_sys_id: 'abc123',
            schema_version: 3,
            snapshot_enc: encryptedPayload('cdc.write'),
            sys_updated_on: '2026-02-14 00:00:00',
            table: 'x_app.ticket',
        },
        extensions: {
            instance_id: 'i_stage_001',
            source: 'sn://dev207082.service-now.com',
            tenant_id: 't_stage_001',
        },
        type: 'cdc.write',
    });

    assert.equal(parsed.success, true);
});

test('CloudEventSchema accepts millisecond UTC timestamps', () => {
    const parsed = CloudEventSchema.safeParse({
        ...baseEvent(),
        time: '2026-02-14T00:00:00.123Z',
        data: {
            changed_fields: ['state'],
            op: 'U',
            record_sys_id: 'abc123',
            schema_version: 3,
            snapshot_enc: encryptedPayload('cdc.write'),
            sys_updated_on: '2026-02-14 00:00:00',
            table: 'x_app.ticket',
        },
        type: 'cdc.write',
    });

    assert.equal(parsed.success, true);
});

test('canonicalizeIsoDateTimeUtc normalizes second precision to millis', () => {
    const secondPrecision = canonicalizeIsoDateTimeUtc(
        '2026-02-14T00:00:00Z',
    );
    const millisPrecision = canonicalizeIsoDateTimeUtc(
        '2026-02-14T00:00:00.123Z',
    );

    assert.equal(secondPrecision, '2026-02-14T00:00:00.000Z');
    assert.equal(millisPrecision, '2026-02-14T00:00:00.123Z');
});

test('canonicalizeIsoDateTimeUtc rejects malformed and non-UTC values', () => {
    assert.throws(
        () => canonicalizeIsoDateTimeUtc('2026-02-14T00:00:00+00:00'),
        /must be ISO datetime/,
    );
    assert.throws(
        () => canonicalizeIsoDateTimeUtc('2026-02-30T00:00:00Z'),
        /must be ISO datetime/,
    );
});

test('CloudEventSchema rejects plaintext schema.snapshot payloads', () => {
    const parsed = CloudEventSchema.safeParse({
        ...baseEvent(),
        data: {
            schema_hash: 'hash-1',
            schema_version: 1,
            snapshot: {
                fields: {
                    short_description: {
                        type: 'string',
                    },
                },
            },
            table: 'x_app.ticket',
        },
        subject: 'x_app.ticket',
        type: 'schema.snapshot',
    });

    assert.equal(parsed.success, false);
    if (parsed.success) {
        return;
    }

    const messages = parsed.error.issues.map((issue) => issue.message);

    assert(messages.includes('snapshot plaintext not allowed'));
    assert(messages.includes('snapshot_enc is required'));
});

test('CloudEventSchema enforces media compression enum strictness', () => {
    const parsed = CloudEventSchema.safeParse({
        ...baseEvent(),
        data: {
            op: 'I',
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
            attachment_sys_id: 'att_01',
            sys_created_on: '2026-02-14 00:00:00',
            sys_updated_on: '2026-02-14 00:00:00',
            size_bytes: 123,
            content_type: 'image/png',
            sha256_plain: 'deadbeef',
            media_id: 'media_01',
            blob_enc: {
                alg: 'AES-256-CBC',
                module: 'x_rezrp_rezilient.encrypter',
                format: 'kmf',
                compression: 'brotli',
                chunking: {
                    chunk_size_bytes: 262144,
                    chunk_count: 1,
                    format: 'length_prefixed',
                },
            },
            meta_enc: encryptedPayload('media.meta'),
        },
        subject: 'x_app.ticket/abc123/attachment/att_01',
        type: 'media.manifest',
    });

    assert.equal(parsed.success, false);
    if (parsed.success) {
        return;
    }

    const paths = parsed.error.issues.map((issue) => issue.path.join('.'));

    assert(paths.includes('data.blob_enc.compression'));
});

function encPayload() {
    return {
        alg: 'AES-256-CBC',
        module: 'x_rezrp_rezilient.encrypter',
        format: 'kmf',
        compression: 'none' as const,
        ciphertext: 'cipher:test',
    };
}

test('buildEventBatchSchema enforces configured max events', () => {
    const schema = buildEventBatchSchema(1);

    const parsed = schema.safeParse({
        batch_id: 'batch-01',
        events: [{ id: 1 }, { id: 2 }],
        sent_at: '2026-02-14T00:00:00Z',
        source: 'sn://acme-dev.service-now.com',
    });

    assert.equal(parsed.success, false);
    if (parsed.success) {
        return;
    }

    const paths = parsed.error.issues.map((issue) => issue.path.join('.'));

    assert(paths.includes('events'));
});

// Stage 1: Core Helpers and Simple Schemas

test('isIsoDateTimeUtc accepts valid second-precision timestamps', () => {
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00Z'), true);
    assert.equal(isIsoDateTimeUtc('2026-01-01T00:00:00Z'), true);
    assert.equal(isIsoDateTimeUtc('2026-12-31T23:59:59Z'), true);
});

test('isIsoDateTimeUtc accepts valid millisecond-precision timestamps', () => {
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00.000Z'), true);
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00.999Z'), true);
});

test('isIsoDateTimeUtc rejects non-UTC, offset, and malformed strings', () => {
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00+00:00'), false);
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00'), false);
    assert.equal(isIsoDateTimeUtc('2026-02-16'), false);
    assert.equal(isIsoDateTimeUtc('not-a-date'), false);
    assert.equal(isIsoDateTimeUtc(''), false);
    assert.equal(isIsoDateTimeUtc('2026-02-30T12:00:00Z'), false);
    assert.equal(isIsoDateTimeUtc('2026-02-16T12:00:00.1234Z'), false);
});

test('serviceNowDateTime accepts valid format', () => {
    const valid = serviceNowDateTime.safeParse('2026-02-16 12:00:00');

    assert.equal(valid.success, true);
});

test('serviceNowDateTime rejects ISO format and invalid strings', () => {
    const isoFormat = serviceNowDateTime.safeParse(
        '2026-02-16T12:00:00Z',
    );
    const partial = serviceNowDateTime.safeParse('2026-02-16');
    const garbage = serviceNowDateTime.safeParse('not-a-date');

    assert.equal(isoFormat.success, false);
    assert.equal(partial.success, false);
    assert.equal(garbage.success, false);
});

test('EncryptedPayload accepts minimal valid payload', () => {
    const parsed = EncryptedPayload.safeParse({
        alg: 'AES-256-CBC',
        ciphertext: 'encrypted-data',
    });

    assert.equal(parsed.success, true);
});

test('EncryptedPayload accepts all optional fields', () => {
    const parsed = EncryptedPayload.safeParse({
        v: 1,
        alg: 'AES-256-CBC',
        kid: 'key-01',
        module: 'x_rezrp_rezilient.encrypter',
        format: 'kmf',
        compression: 'gzip',
        ciphertext: 'encrypted-data',
        sha256: 'a'.repeat(64),
    });

    assert.equal(parsed.success, true);
});

test('EncryptedPayload rejects extra fields and empty ciphertext', () => {
    const extra = EncryptedPayload.safeParse({
        alg: 'AES-256-CBC',
        ciphertext: 'data',
        unknown_field: true,
    });
    const emptyCiphertext = EncryptedPayload.safeParse({
        alg: 'AES-256-CBC',
        ciphertext: '',
    });

    assert.equal(extra.success, false);
    assert.equal(emptyCiphertext.success, false);
});

// Stage 2: CDC and Schema Event Data Schemas

test('CDCDeleteData accepts valid delete with encrypted snapshot', () => {
    const parsed = CDCDeleteData.safeParse({
        op: 'D',
        record_sys_id: 'abc123',
        schema_version: 1,
        snapshot_enc: encPayload(),
        sys_updated_on: '2026-02-16 12:00:00',
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, true);
});

test('CDCDeleteData rejects plaintext snapshot', () => {
    const parsed = CDCDeleteData.safeParse({
        op: 'D',
        record_sys_id: 'abc123',
        schema_version: 1,
        snapshot: { state: '1' },
        snapshot_enc: encPayload(),
        sys_updated_on: '2026-02-16 12:00:00',
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, false);
});

test('CDCDeleteData rejects missing snapshot_enc', () => {
    const parsed = CDCDeleteData.safeParse({
        op: 'D',
        record_sys_id: 'abc123',
        schema_version: 1,
        sys_updated_on: '2026-02-16 12:00:00',
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, false);
});

test('CDCWriteData accepts insert and update operations', () => {
    const base = {
        record_sys_id: 'abc123',
        schema_version: 1,
        snapshot_enc: encPayload(),
        sys_updated_on: '2026-02-16 12:00:00',
        table: 'x_app.ticket',
    };

    const insert = CDCWriteData.safeParse({ ...base, op: 'I' });
    const update = CDCWriteData.safeParse({
        ...base,
        op: 'U',
        changed_fields: ['state', 'priority'],
    });

    assert.equal(insert.success, true);
    assert.equal(update.success, true);
});

test('CDCWriteData rejects plaintext snapshot', () => {
    const parsed = CDCWriteData.safeParse({
        op: 'U',
        record_sys_id: 'abc123',
        schema_version: 1,
        snapshot: { state: '1' },
        snapshot_enc: encPayload(),
        sys_updated_on: '2026-02-16 12:00:00',
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, false);
});

test('SchemaChangeData accepts all change kinds', () => {
    const base = { table: 'x_app.ticket' };

    const add = SchemaChangeData.safeParse({
        ...base,
        change: {
            element: 'u_priority',
            kind: 'add',
            new: { type: 'integer' },
        },
    });
    const drop = SchemaChangeData.safeParse({
        ...base,
        change: {
            element: 'u_obsolete',
            kind: 'drop',
            old: { type: 'string' },
        },
    });
    const modify = SchemaChangeData.safeParse({
        ...base,
        change: {
            element: 'u_status',
            kind: 'modify',
            old: { max_length: 40 },
            new: { max_length: 100 },
        },
    });

    assert.equal(add.success, true);
    assert.equal(drop.success, true);
    assert.equal(modify.success, true);
});

test('SchemaSnapshotData accepts valid encrypted snapshot', () => {
    const parsed = SchemaSnapshotData.safeParse({
        schema_hash: 'abc123def',
        schema_version: 3,
        snapshot_enc: encPayload(),
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, true);
});

test('SchemaSnapshotData rejects missing snapshot_enc', () => {
    const parsed = SchemaSnapshotData.safeParse({
        schema_hash: 'abc123def',
        schema_version: 3,
        table: 'x_app.ticket',
    });

    assert.equal(parsed.success, false);
});

// Stage 3: Media, Error, Repair, Extensions, and Batch

test('MediaBlobChunking accepts valid descriptor', () => {
    const parsed = MediaBlobChunking.safeParse({
        chunk_size_bytes: 4096,
        chunk_count: 10,
        format: 'length_prefixed',
    });

    assert.equal(parsed.success, true);
});

test('MediaBlobDescriptor accepts valid blob descriptor', () => {
    const parsed = MediaBlobDescriptor.safeParse({
        alg: 'AES-256-CBC',
        module: 'x_rezrp_rezilient.encrypter',
        format: 'kmf',
        compression: 'gzip',
        chunking: {
            chunk_size_bytes: 4096,
            chunk_count: 10,
            format: 'length_prefixed',
        },
    });

    assert.equal(parsed.success, true);
});

test('MediaManifestData accepts valid manifest', () => {
    const parsed = MediaManifestData.safeParse({
        op: 'I',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        attachment_sys_id: 'att-01',
        sys_created_on: '2026-02-16 12:00:00',
        sys_updated_on: '2026-02-16 12:00:00',
        size_bytes: 1024,
        content_type: 'image/png',
        sha256_plain: 'a'.repeat(64),
        media_id: 'media-01',
        blob_enc: {
            alg: 'AES-256-CBC',
            module: 'x_rezrp_rezilient.encrypter',
            format: 'kmf',
            compression: 'gzip',
            chunking: {
                chunk_size_bytes: 4096,
                chunk_count: 1,
                format: 'length_prefixed',
            },
        },
        meta_enc: encPayload(),
    });

    assert.equal(parsed.success, true);
});

test('MediaMetaData rejects insert operation', () => {
    const parsed = MediaMetaData.safeParse({
        op: 'I',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        attachment_sys_id: 'att-01',
        sys_created_on: '2026-02-16 12:00:00',
        sys_updated_on: '2026-02-16 12:00:00',
        size_bytes: 1024,
        content_type: 'image/png',
        sha256_plain: 'a'.repeat(64),
        media_id: 'media-01',
        blob_enc: {
            alg: 'AES-256-CBC',
            module: 'x_rezrp_rezilient.encrypter',
            format: 'kmf',
            compression: 'gzip',
            chunking: {
                chunk_size_bytes: 4096,
                chunk_count: 1,
                format: 'length_prefixed',
            },
        },
        meta_enc: encPayload(),
    });

    assert.equal(parsed.success, false);
});

test('MediaDeleteData accepts valid delete', () => {
    const parsed = MediaDeleteData.safeParse({
        op: 'D',
        table: 'x_app.ticket',
        record_sys_id: 'rec-01',
        attachment_sys_id: 'att-01',
        sys_updated_on: '2026-02-16 12:00:00',
    });

    assert.equal(parsed.success, true);
});

test('ErrorReportData accepts minimal required fields', () => {
    const parsed = ErrorReportData.safeParse({
        source: 'sn://acme.service-now.com',
        severity: 'error',
        message: 'Failed to process event',
        error_code: 'ERR_PROCESS',
        component: 'outbox',
    });

    assert.equal(parsed.success, true);
});

test('ErrorReportData accepts all optional fields', () => {
    const parsed = ErrorReportData.safeParse({
        source: 'sn://acme.service-now.com',
        severity: 'warning',
        message: 'Retrying event',
        error_code: 'ERR_RETRY',
        component: 'outbox',
        event_type: 'cdc.write',
        last_error: 'connection timeout',
        stage: 'delivery',
        payload_hash: 'hash123',
        attachment_hash: 'hash456',
        stack: 'Error at line 42',
        table: 'x_app.ticket',
        record_sys_id: 'abc123',
        attachment_sys_id: 'att-01',
        outbox_sys_id: 'outbox-01',
    });

    assert.equal(parsed.success, true);
});

test('RepairReportData accepts minimal required fields', () => {
    const parsed = RepairReportData.safeParse({
        source: 'sn://acme.service-now.com',
        component: 'outbox',
        stage: 'requeue',
        disposition: 'requeued',
        repair_action: 'requeue_with_backoff',
    });

    assert.equal(parsed.success, true);
});

test('ExtensionsSchema accepts all optional fields', () => {
    const parsed = ExtensionsSchema.safeParse({
        instance_id: 'i_stage_001',
        partition_key: 'x_app.ticket/abc123',
        producer: 'sn-agent-v2',
        retention: 'P30D',
        retention_days: 30,
        retention_ttl_ms: 2592000000,
        seq: 0,
        source: 'sn://dev207082.service-now.com',
        tenant_id: 't_stage_001',
    });

    assert.equal(parsed.success, true);
});

test('ExtensionsSchema rejects invalid retention and extra fields', () => {
    const badRetention = ExtensionsSchema.safeParse({
        retention: 'invalid',
    });
    const badIdentity = ExtensionsSchema.safeParse({
        instance_id: '',
    });
    const extraField = ExtensionsSchema.safeParse({
        unknown_field: true,
    });

    assert.equal(badRetention.success, false);
    assert.equal(badIdentity.success, false);
    assert.equal(extraField.success, false);
});

test('EventBatchSchema accepts valid batch and rejects empty events', () => {
    const valid = EventBatchSchema.safeParse({
        batch_id: 'batch-01',
        events: [{ any: 'event' }],
        sent_at: '2026-02-16T12:00:00.000Z',
        source: 'sn://acme.service-now.com',
    });
    const empty = EventBatchSchema.safeParse({
        events: [],
        sent_at: '2026-02-16T12:00:00.000Z',
        source: 'sn://acme.service-now.com',
    });

    assert.equal(valid.success, true);
    assert.equal(empty.success, false);
});
