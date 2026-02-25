import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import { derivePartitionKey, mapTopic } from './partitioning';

test('derivePartitionKey honors explicit extensions.partition_key', () => {
    const key = derivePartitionKey({
        data: {
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
        },
        extensions: {
            partition_key: 'forced-key',
        },
        type: 'cdc.write',
    });

    assert.equal(key, 'forced-key');
});

test('derivePartitionKey throws for CDC events with missing fields', () => {
    assert.throws(
        () =>
            derivePartitionKey({
                data: {},
                subject: 'x_app.ticket/from-subject-fallback',
                type: 'cdc.write',
            }),
        /CDC event missing required partition key fields/,
    );
});

test('mapTopic routes error.report critical severity to error topic', () => {
    assert.equal(mapTopic('error.report', false, { severity: 'critical' }), 'rez.log.error');
    assert.equal(mapTopic('error.report', true, { severity: 'critical' }), 'rez.test.log.error');
});

test('mapTopic routes cdc.write and cdc.delete to CDC topics', () => {
    assert.equal(mapTopic('cdc.write', false), 'rez.cdc');
    assert.equal(mapTopic('cdc.delete', false), 'rez.cdc');
    assert.equal(mapTopic('cdc.write', true), 'rez.test.cdc');
    assert.equal(mapTopic('cdc.delete', true), 'rez.test.cdc');
});

test('mapTopic throws for unknown event types', () => {
    assert.throws(
        () => mapTopic('totally.bogus', false),
        /Unknown event type for topic mapping/,
    );
    assert.throws(
        () => mapTopic('totally.bogus', true),
        /Unknown event type for topic mapping/,
    );
});

test('mapTopic routes schema/media/repair topics correctly', () => {
    assert.equal(mapTopic('schema.change', true), 'rez.test.schema');
    assert.equal(mapTopic('media.delete', false), 'rez.media');
    assert.equal(mapTopic('repair.report', true), 'rez.test.repair');
});

test('derivePartitionKey for schema events returns table only', () => {
    const change = derivePartitionKey({
        data: { table: 'x_app.ticket' },
        type: 'schema.change',
    });
    const snapshot = derivePartitionKey({
        data: { table: 'x_app.ticket' },
        type: 'schema.snapshot',
    });

    assert.equal(change, 'x_app.ticket');
    assert.equal(snapshot, 'x_app.ticket');
});

test('derivePartitionKey for media events uses fallback chain', () => {
    const byAttachment = derivePartitionKey({
        data: {
            attachment_sys_id: 'att-01',
            media_id: 'media-01',
        },
        subject: 'x_app.ticket/att-01',
        type: 'media.manifest',
    });
    const byMediaId = derivePartitionKey({
        data: { media_id: 'media-01' },
        subject: 'x_app.ticket/att-01',
        type: 'media.meta',
    });
    const bySubject = derivePartitionKey({
        data: {},
        subject: 'x_app.ticket/att-01',
        type: 'media.delete',
    });
    const unknown = derivePartitionKey({
        data: {},
        type: 'media.manifest',
    });

    assert.equal(byAttachment, 'att-01');
    assert.equal(byMediaId, 'media-01');
    assert.equal(bySubject, 'x_app.ticket/att-01');
    assert.equal(unknown, 'unknown');
});

test('derivePartitionKey for error.report uses fallback chain', () => {
    const byAttachment = derivePartitionKey({
        data: { attachment_sys_id: 'att-01' },
        type: 'error.report',
    });
    const byTableRecord = derivePartitionKey({
        data: {
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
        },
        type: 'error.report',
    });
    const bySubject = derivePartitionKey({
        data: {},
        subject: 'x_app.ticket/fallback',
        type: 'error.report',
    });
    const bySource = derivePartitionKey({
        data: {},
        source: 'sn://acme.service-now.com',
        type: 'error.report',
    });
    const unknown = derivePartitionKey({
        data: {},
        type: 'error.report',
    });

    assert.equal(byAttachment, 'att-01');
    assert.equal(byTableRecord, 'x_app.ticket/abc123');
    assert.equal(bySubject, 'x_app.ticket/fallback');
    assert.equal(bySource, 'sn://acme.service-now.com');
    assert.equal(unknown, 'unknown');
});

test('derivePartitionKey for repair.report uses fallback chain', () => {
    const byOriginalEvent = derivePartitionKey({
        data: { original_event_id: 'evt-original' },
        type: 'repair.report',
    });
    const byTableRecord = derivePartitionKey({
        data: {
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
        },
        type: 'repair.report',
    });
    const bySubject = derivePartitionKey({
        data: {},
        subject: 'repair-subject',
        type: 'repair.report',
    });

    assert.equal(byOriginalEvent, 'evt-original');
    assert.equal(byTableRecord, 'x_app.ticket/abc123');
    assert.equal(bySubject, 'repair-subject');
});

test('derivePartitionKey for unknown type returns subject or unknown', () => {
    const withSubject = derivePartitionKey({
        data: {},
        subject: 'custom-subject',
        type: 'custom.type',
    });
    const withoutSubject = derivePartitionKey({
        data: {},
        type: 'custom.type',
    });

    assert.equal(withSubject, 'custom-subject');
    assert.equal(withoutSubject, 'unknown');
});

test('mapTopic routes error.report severity levels correctly', () => {
    assert.equal(
        mapTopic('error.report', false, { severity: 'error' }),
        'rez.log.error',
    );
    assert.equal(
        mapTopic('error.report', false, { severity: 'warning' }),
        'rez.log.warning',
    );
    assert.equal(
        mapTopic('error.report', false, { severity: 'info' }),
        'rez.log.info',
    );
    assert.equal(
        mapTopic('error.report', false, { severity: 'debug' }),
        'rez.log.debug',
    );
    assert.equal(
        mapTopic('error.report', true, { severity: 'warning' }),
        'rez.test.log.warning',
    );
});

test('mapTopic defaults to error topic for undefined and unknown severity', () => {
    assert.equal(
        mapTopic('error.report', false),
        'rez.log.error',
    );
    assert.equal(
        mapTopic('error.report', false, {}),
        'rez.log.error',
    );
    assert.equal(
        mapTopic('error.report', false, { severity: 'CRITICAL' }),
        'rez.log.error',
    );
    assert.equal(
        mapTopic('error.report', false, { severity: 'fatal' }),
        'rez.log.error',
    );
});

test('mapTopic routes all media types in both modes', () => {
    assert.equal(mapTopic('media.manifest', false), 'rez.media');
    assert.equal(mapTopic('media.meta', false), 'rez.media');
    assert.equal(mapTopic('media.delete', true), 'rez.test.media');
    assert.equal(mapTopic('media.manifest', true), 'rez.test.media');
});

test('derivePartitionKey for valid CDC events returns table/record', () => {
    const key = derivePartitionKey({
        data: {
            table: 'x_app.ticket',
            record_sys_id: 'abc123',
        },
        type: 'cdc.write',
    });

    assert.equal(key, 'x_app.ticket/abc123');
});
