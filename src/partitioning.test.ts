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

test('derivePartitionKey for CDC uses data.table/data.record_sys_id only', () => {
    const key = derivePartitionKey({
        data: {},
        subject: 'x_app.ticket/from-subject-fallback',
        type: 'cdc.write',
    });

    assert.equal(key, 'undefined/undefined');
});

test('mapTopic routes error.report critical severity to error topic', () => {
    assert.equal(mapTopic('error.report', false, { severity: 'critical' }), 'rez.error');
    assert.equal(mapTopic('error.report', true, { severity: 'critical' }), 'rez.test.error');
});

test('mapTopic routes control/schema/media/repair topics correctly', () => {
    assert.equal(mapTopic('snapshot.request', false), 'rez.control');
    assert.equal(mapTopic('schema.change', true), 'rez.test.schema');
    assert.equal(mapTopic('media.delete', false), 'rez.media');
    assert.equal(mapTopic('repair.report', true), 'rez.test.repair');
});
