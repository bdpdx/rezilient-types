import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import {
    AUDIT_CONTRACT_VERSION,
    AUDIT_EVENT_SCHEMA_VERSION,
    AUDIT_REPLAY_ORDER_VERSION,
    CrossServiceAuditEvent,
    CrossServiceAuditReplay,
    fromLegacyAuthAuditEvent,
    fromLegacyRestoreJobAuditEvent,
    sortCrossServiceAuditEventsForReplay,
} from './audit-contracts';

function baseEvent() {
    return CrossServiceAuditEvent.parse({
        contract_version: AUDIT_CONTRACT_VERSION,
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        event_id: 'evt-01',
        occurred_at: '2026-02-18T12:00:00.000Z',
        service: 'rrs' as const,
        lifecycle: 'execute' as const,
        action: 'started',
        outcome: 'started' as const,
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        source: 'sn://acme-dev.service-now.com',
        plan_id: 'plan-01',
        plan_hash: 'a'.repeat(64),
        job_id: 'job-01',
        metadata: {
            phase: 'execute',
        },
    });
}

test('CrossServiceAuditEvent accepts execute lifecycle with scope fields', () => {
    const parsed = CrossServiceAuditEvent.parse(baseEvent());

    assert.equal(parsed.contract_version, AUDIT_CONTRACT_VERSION);
    assert.equal(parsed.service, 'rrs');
    assert.equal(parsed.lifecycle, 'execute');
    assert.equal(parsed.job_id, 'job-01');
});

test('CrossServiceAuditEvent rejects plan lifecycle events without plan_id', () => {
    const event = {
        ...baseEvent(),
        lifecycle: 'plan' as const,
        job_id: undefined,
        plan_id: undefined,
        plan_hash: undefined,
    };

    assert.throws(() => CrossServiceAuditEvent.parse(event), /plan_id/);
});

test('CrossServiceAuditEvent rejects execute lifecycle events without job_id', () => {
    const event = {
        ...baseEvent(),
        job_id: undefined,
    };

    assert.throws(() => CrossServiceAuditEvent.parse(event), /job_id/);
});

test('CrossServiceAuditReplay enforces deterministic ordering', () => {
    const first = {
        ...baseEvent(),
        event_id: 'evt-01',
        occurred_at: '2026-02-18T12:00:00.000Z',
        service: 'acp' as const,
        lifecycle: 'auth' as const,
        action: 'token_minted',
        outcome: 'accepted' as const,
        job_id: undefined,
        plan_id: undefined,
        plan_hash: undefined,
        source: undefined,
        metadata: {
            token_type: 'access',
        },
    };
    const second = {
        ...baseEvent(),
        event_id: 'evt-02',
        occurred_at: '2026-02-18T12:00:00.000Z',
        service: 'rrs' as const,
    };

    const replay = CrossServiceAuditReplay.parse({
        contract_version: AUDIT_CONTRACT_VERSION,
        replay_order_version: AUDIT_REPLAY_ORDER_VERSION,
        generated_at: '2026-02-18T12:10:00.000Z',
        events: [first, second],
    });

    assert.equal(replay.events.length, 2);
});

test('CrossServiceAuditReplay rejects unsorted events', () => {
    const first = {
        ...baseEvent(),
        event_id: 'evt-02',
        occurred_at: '2026-02-18T12:01:00.000Z',
    };
    const second = {
        ...baseEvent(),
        event_id: 'evt-01',
        occurred_at: '2026-02-18T12:00:00.000Z',
    };

    assert.throws(
        () =>
            CrossServiceAuditReplay.parse({
                contract_version: AUDIT_CONTRACT_VERSION,
                replay_order_version: AUDIT_REPLAY_ORDER_VERSION,
                generated_at: '2026-02-18T12:10:00.000Z',
                events: [first, second],
            }),
        /sorted by occurred_at, then service, then event_id/,
    );
});

test('sortCrossServiceAuditEventsForReplay sorts by timestamp/service/event_id', () => {
    const unsorted = [
        CrossServiceAuditEvent.parse({
            ...baseEvent(),
            event_id: 'evt-03',
            occurred_at: '2026-02-18T12:01:00.000Z',
            service: 'rrs' as const,
        }),
        CrossServiceAuditEvent.parse({
            ...baseEvent(),
            event_id: 'evt-01',
            occurred_at: '2026-02-18T12:00:00.000Z',
            service: 'rrs' as const,
        }),
        CrossServiceAuditEvent.parse({
            ...baseEvent(),
            event_id: 'evt-02',
            occurred_at: '2026-02-18T12:00:00.000Z',
            service: 'acp' as const,
            lifecycle: 'auth' as const,
            action: 'token_validated',
            outcome: 'accepted' as const,
            job_id: undefined,
            plan_id: undefined,
            plan_hash: undefined,
            source: undefined,
        }),
    ];

    const sorted = sortCrossServiceAuditEventsForReplay(unsorted);

    assert.deepEqual(
        sorted.map((event) => `${event.occurred_at}:${event.service}:${event.event_id}`),
        [
            '2026-02-18T12:00:00.000Z:acp:evt-02',
            '2026-02-18T12:00:00.000Z:rrs:evt-01',
            '2026-02-18T12:01:00.000Z:rrs:evt-03',
        ],
    );
});

test('fromLegacyAuthAuditEvent maps deny events to auth lifecycle contract', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-01',
        event_type: 'token_mint_denied',
        occurred_at: '2026-02-18T12:00:00.000Z',
        actor: 'admin@example.com',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        client_id: 'client-01',
        service_scope: 'rrs',
        deny_reason_code: 'denied_invalid_client',
        metadata: {
            legacy: true,
        },
    });

    assert.equal(mapped.service, 'acp');
    assert.equal(mapped.lifecycle, 'auth');
    assert.equal(mapped.action, 'token_mint_denied');
    assert.equal(mapped.outcome, 'denied');
    assert.equal(mapped.reason_code, 'denied_invalid_client');
    assert.equal(mapped.actor?.type, 'user');
    assert.equal(mapped.metadata.client_id, 'client-01');
});

test('fromLegacyRestoreJobAuditEvent maps resumed job_started events to resume lifecycle', () => {
    const mapped = fromLegacyRestoreJobAuditEvent(
        {
            event_id: 'evt-restore-01',
            event_type: 'job_started',
            job_id: 'job-77',
            reason_code: 'none',
            created_at: '2026-02-18T12:05:00.000Z',
            details: {
                resumed_from_pause: true,
            },
        },
        {
            tenant_id: 'tenant-acme',
            instance_id: 'sn-dev-01',
            source: 'sn://acme-dev.service-now.com',
            plan_id: 'plan-77',
            plan_hash: 'b'.repeat(64),
        },
    );

    assert.equal(mapped.service, 'rrs');
    assert.equal(mapped.lifecycle, 'resume');
    assert.equal(mapped.action, 'resumed');
    assert.equal(mapped.outcome, 'started');
    assert.equal(mapped.job_id, 'job-77');
    assert.equal(mapped.plan_id, 'plan-77');
});
