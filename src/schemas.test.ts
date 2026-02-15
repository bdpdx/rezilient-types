import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { buildEventBatchSchema, CloudEventSchema } from './schemas';

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
