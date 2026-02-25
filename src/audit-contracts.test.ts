import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import {
    AUDIT_CONTRACT_VERSION,
    AUDIT_EVENT_SCHEMA_VERSION,
    AUDIT_REPLAY_ORDER_VERSION,
    AuditActor,
    AuditCorrelation,
    CrossServiceAuditEvent,
    CrossServiceAuditReplay,
    LegacyRestoreAuditContext,
    compareCrossServiceAuditEventsForReplay,
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

test('CrossServiceAuditEvent canonicalizes plan_hash to lowercase', () => {
    const event = CrossServiceAuditEvent.parse({
        ...baseEvent(),
        plan_hash: 'A'.repeat(64),
    });

    assert.equal(event.plan_hash, 'a'.repeat(64));
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

test('fromLegacyAuthAuditEvent omits undefined client_id and service_scope from metadata', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-02',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal('client_id' in mapped.metadata, false);
    assert.equal('service_scope' in mapped.metadata, false);
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

// Stage 8: Schema Validation and Correlation

test('AuditActor accepts all type values and rejects extra fields', () => {
    const user = AuditActor.safeParse({
        type: 'user',
        id: 'admin@example.com',
        display: 'Admin User',
    });
    const service = AuditActor.safeParse({
        type: 'service',
        id: 'svc:backup',
    });
    const system = AuditActor.safeParse({
        type: 'system',
        id: 'cron-scheduler',
    });
    const extra = AuditActor.safeParse({
        type: 'user',
        id: 'admin@example.com',
        unknown: true,
    });

    assert.equal(user.success, true);
    assert.equal(service.success, true);
    assert.equal(system.success, true);
    assert.equal(extra.success, false);
});

test('AuditCorrelation accepts all optional fields and empty object', () => {
    const full = AuditCorrelation.safeParse({
        request_id: 'req-01',
        trace_id: 'trace-abc',
        parent_event_id: 'evt-parent',
    });
    const empty = AuditCorrelation.safeParse({});

    assert.equal(full.success, true);
    assert.equal(empty.success, true);
});

test('CrossServiceAuditEvent rejects instance_id without tenant_id', () => {
    assert.throws(
        () =>
            CrossServiceAuditEvent.parse({
                ...baseEvent(),
                tenant_id: undefined,
                instance_id: 'sn-dev-01',
                source: undefined,
            }),
        /tenant_id/,
    );
});

test('CrossServiceAuditEvent rejects source without tenant_id and instance_id', () => {
    assert.throws(
        () =>
            CrossServiceAuditEvent.parse({
                ...baseEvent(),
                tenant_id: undefined,
                instance_id: undefined,
                source: 'sn://acme.service-now.com',
            }),
        /tenant_id|instance_id/,
    );
});

test('CrossServiceAuditEvent rejects plan_hash without plan_id', () => {
    assert.throws(
        () =>
            CrossServiceAuditEvent.parse({
                ...baseEvent(),
                plan_id: undefined,
                plan_hash: 'a'.repeat(64),
            }),
        /plan_id/,
    );
});

test('CrossServiceAuditEvent rejects override lifecycle without job_id', () => {
    assert.throws(
        () =>
            CrossServiceAuditEvent.parse({
                ...baseEvent(),
                lifecycle: 'override',
                action: 'schema_override',
                job_id: undefined,
            }),
        /job_id/,
    );
});

test('CrossServiceAuditEvent rejects non-snake_case action', () => {
    assert.throws(
        () =>
            CrossServiceAuditEvent.parse({
                ...baseEvent(),
                action: 'InvalidAction',
            }),
        /snake_case/,
    );
});

test('CrossServiceAuditEvent accepts ingest lifecycle without job_id', () => {
    const parsed = CrossServiceAuditEvent.safeParse({
        ...baseEvent(),
        service: 'reg',
        lifecycle: 'ingest',
        action: 'batch_received',
        outcome: 'accepted',
        job_id: undefined,
        plan_id: undefined,
        plan_hash: undefined,
    });

    assert.equal(parsed.success, true);
});

test('CrossServiceAuditEvent accepts correlation field', () => {
    const parsed = CrossServiceAuditEvent.safeParse({
        ...baseEvent(),
        correlation: {
            request_id: 'req-01',
            trace_id: 'trace-abc',
        },
    });

    assert.equal(parsed.success, true);
});

test('compareCrossServiceAuditEventsForReplay returns 0 for identical sort keys', () => {
    const event = baseEvent();
    const result = compareCrossServiceAuditEventsForReplay(
        event,
        event,
    );

    assert.equal(result, 0);
});

test('compareCrossServiceAuditEventsForReplay sorts by occurred_at then service then event_id', () => {
    const earlier = {
        ...baseEvent(),
        occurred_at: '2026-02-18T11:00:00.000Z',
    };
    const later = {
        ...baseEvent(),
        occurred_at: '2026-02-18T13:00:00.000Z',
    };
    const acpEvent = {
        ...baseEvent(),
        service: 'acp' as const,
        lifecycle: 'auth' as const,
        action: 'token_validated',
        job_id: undefined,
        plan_id: undefined,
        plan_hash: undefined,
        source: undefined,
    };
    const rrsEvent = baseEvent();

    assert.equal(
        compareCrossServiceAuditEventsForReplay(earlier, later) < 0,
        true,
    );
    assert.equal(
        compareCrossServiceAuditEventsForReplay(acpEvent, rrsEvent) < 0,
        true,
    );
});

test('CrossServiceAuditReplay rejects duplicate service:event_id', () => {
    const event = baseEvent();

    assert.throws(
        () =>
            CrossServiceAuditReplay.parse({
                contract_version: AUDIT_CONTRACT_VERSION,
                replay_order_version: AUDIT_REPLAY_ORDER_VERSION,
                generated_at: '2026-02-18T12:10:00.000Z',
                events: [event, event],
            }),
        /unique by service:event_id/,
    );
});

test('LegacyRestoreAuditContext rejects plan_hash without plan_id', () => {
    const parsed = LegacyRestoreAuditContext.safeParse({
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        source: 'sn://acme-dev.service-now.com',
        plan_hash: 'a'.repeat(64),
    });

    assert.equal(parsed.success, false);
});

// Stage 9: Legacy Adapter Complete Coverage

test('fromLegacyAuthAuditEvent maps _started suffix to started outcome', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-03',
        event_type: 'rotation_started',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal(mapped.outcome, 'started');
});

test('fromLegacyAuthAuditEvent maps _completed suffix to completed outcome', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-04',
        event_type: 'rotation_completed',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal(mapped.outcome, 'completed');
});

test('fromLegacyAuthAuditEvent maps unmatched suffix to accepted outcome', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-05',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal(mapped.outcome, 'accepted');
});

test('fromLegacyAuthAuditEvent uses in_flight_reason_code when deny absent', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-06',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        in_flight_reason_code: 'paused_entitlement_disabled',
        metadata: {},
    });

    assert.equal(mapped.reason_code, 'paused_entitlement_disabled');
});

test('fromLegacyAuthAuditEvent prefers deny_reason_code over in_flight', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-07',
        event_type: 'token_mint_denied',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        deny_reason_code: 'denied_invalid_client',
        in_flight_reason_code: 'paused_entitlement_disabled',
        metadata: {},
    });

    assert.equal(mapped.reason_code, 'denied_invalid_client');
});

test('fromLegacyAuthAuditEvent filters reason codes with value none', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-08',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        deny_reason_code: 'none',
        in_flight_reason_code: 'none',
        metadata: {},
    });

    assert.equal(mapped.reason_code, undefined);
});

test('fromLegacyAuthAuditEvent infers service and system actor types', () => {
    const serviceActor = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-09',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        actor: 'svc:backup-service',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });
    const systemActor = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-10',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        actor: 'cron-scheduler',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal(serviceActor.actor?.type, 'service');
    assert.equal(systemActor.actor?.type, 'system');
});

test('fromLegacyAuthAuditEvent produces undefined actor when absent', () => {
    const mapped = fromLegacyAuthAuditEvent({
        event_id: 'evt-auth-11',
        event_type: 'token_minted',
        occurred_at: '2026-02-18T12:00:00.000Z',
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        metadata: {},
    });

    assert.equal(mapped.actor, undefined);
});

test('fromLegacyRestoreJobAuditEvent maps all seven event types', () => {
    type JobEventType =
        | 'job_created' | 'job_queued' | 'job_started'
        | 'job_paused' | 'job_completed' | 'job_failed'
        | 'job_cancelled';

    function makeEvent(eventType: JobEventType, details = {}) {
        return {
            event_id: `evt-${eventType}`,
            event_type: eventType,
            job_id: 'job-01',
            reason_code: 'none',
            created_at: '2026-02-18T12:00:00.000Z',
            details,
        };
    }

    const context = {
        tenant_id: 'tenant-acme',
        instance_id: 'sn-dev-01',
        source: 'sn://acme-dev.service-now.com',
        plan_id: 'plan-01',
        plan_hash: 'a'.repeat(64),
    };

    const created = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_created'),
        context,
    );
    assert.equal(created.lifecycle, 'plan');
    assert.equal(created.action, 'job_created');
    assert.equal(created.outcome, 'accepted');

    const queued = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_queued'),
        context,
    );
    assert.equal(queued.lifecycle, 'execute');
    assert.equal(queued.action, 'queued_for_lock');
    assert.equal(queued.outcome, 'queued');

    const started = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_started'),
        context,
    );
    assert.equal(started.lifecycle, 'execute');
    assert.equal(started.action, 'started');
    assert.equal(started.outcome, 'started');

    const paused = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_paused'),
        context,
    );
    assert.equal(paused.lifecycle, 'resume');
    assert.equal(paused.action, 'paused');
    assert.equal(paused.outcome, 'paused');

    const completed = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_completed'),
        context,
    );
    assert.equal(completed.lifecycle, 'execute');
    assert.equal(completed.outcome, 'completed');

    const failed = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_failed'),
        context,
    );
    assert.equal(failed.lifecycle, 'execute');
    assert.equal(failed.outcome, 'failed');

    const cancelled = fromLegacyRestoreJobAuditEvent(
        makeEvent('job_cancelled'),
        context,
    );
    assert.equal(cancelled.lifecycle, 'execute');
    assert.equal(cancelled.outcome, 'cancelled');
});

test('fromLegacyRestoreJobAuditEvent filters reason_code none', () => {
    const mapped = fromLegacyRestoreJobAuditEvent(
        {
            event_id: 'evt-reason-none',
            event_type: 'job_completed',
            job_id: 'job-01',
            reason_code: 'none',
            created_at: '2026-02-18T12:00:00.000Z',
            details: {},
        },
        {
            tenant_id: 'tenant-acme',
            instance_id: 'sn-dev-01',
            source: 'sn://acme-dev.service-now.com',
        },
    );

    assert.equal(mapped.reason_code, undefined);
});

test('fromLegacyRestoreJobAuditEvent passes through context without plan fields', () => {
    const mapped = fromLegacyRestoreJobAuditEvent(
        {
            event_id: 'evt-no-plan',
            event_type: 'job_completed',
            job_id: 'job-01',
            reason_code: 'none',
            created_at: '2026-02-18T12:00:00.000Z',
            details: {},
        },
        {
            tenant_id: 'tenant-acme',
            instance_id: 'sn-dev-01',
            source: 'sn://acme-dev.service-now.com',
        },
    );

    assert.equal(mapped.plan_id, undefined);
    assert.equal(mapped.plan_hash, undefined);
});
