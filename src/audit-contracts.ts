import { z } from 'zod';
import { isoDateTime } from './schemas';
import { Sha256Hex } from './restore-contracts';

const AUDIT_ACTION_REGEX = /^[a-z][a-z0-9_]*$/;

export const AUDIT_CONTRACT_VERSION = 'audit.contracts.v1';
export const AUDIT_EVENT_SCHEMA_VERSION = 'audit.event.v1';
export const AUDIT_REPLAY_ORDER_VERSION =
    'audit.replay.v1.occurred_at-service-event_id';

export const AuditService = z.enum([
    'acp',
    'reg',
    'rrs',
    'sn',
]);

export type AuditService = z.infer<typeof AuditService>;

export const AuditLifecycle = z.enum([
    'auth',
    'plan',
    'execute',
    'resume',
    'override',
    'delete',
    'ingest',
]);

export type AuditLifecycle = z.infer<typeof AuditLifecycle>;

export const AuditOutcome = z.enum([
    'attempted',
    'accepted',
    'denied',
    'queued',
    'started',
    'paused',
    'completed',
    'failed',
    'cancelled',
    'skipped',
]);

export type AuditOutcome = z.infer<typeof AuditOutcome>;

export const AuditActor = z
    .object({
        type: z.enum([
            'user',
            'service',
            'system',
        ]),
        id: z.string().min(1),
        display: z.string().min(1).optional(),
    })
    .strict();

export type AuditActor = z.infer<typeof AuditActor>;

export const AuditCorrelation = z
    .object({
        request_id: z.string().min(1).optional(),
        trace_id: z.string().min(1).optional(),
        parent_event_id: z.string().min(1).optional(),
    })
    .strict();

export type AuditCorrelation = z.infer<typeof AuditCorrelation>;

export const CrossServiceAuditEvent = z
    .object({
        contract_version: z.literal(AUDIT_CONTRACT_VERSION),
        schema_version: z.literal(AUDIT_EVENT_SCHEMA_VERSION),
        event_id: z.string().min(1),
        occurred_at: isoDateTime,
        service: AuditService,
        lifecycle: AuditLifecycle,
        action: z
            .string()
            .regex(AUDIT_ACTION_REGEX, 'action must be snake_case'),
        outcome: AuditOutcome,
        tenant_id: z.string().min(1).optional(),
        instance_id: z.string().min(1).optional(),
        source: z.string().min(1).optional(),
        plan_id: z.string().min(1).optional(),
        plan_hash: Sha256Hex.optional(),
        job_id: z.string().min(1).optional(),
        reason_code: z.string().min(1).optional(),
        actor: AuditActor.optional(),
        correlation: AuditCorrelation.optional(),
        metadata: z.record(z.string(), z.unknown()).default({}),
    })
    .strict()
    .superRefine((event, ctx) => {
        if (event.instance_id && !event.tenant_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'instance_id requires tenant_id',
                path: ['tenant_id'],
            });
        }

        if (event.source && (!event.tenant_id || !event.instance_id)) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'source requires tenant_id and instance_id',
                path: ['source'],
            });
        }

        if (event.plan_hash && !event.plan_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'plan_hash requires plan_id',
                path: ['plan_id'],
            });
        }

        if (event.lifecycle === 'plan' && !event.plan_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'plan lifecycle events require plan_id',
                path: ['plan_id'],
            });
        }

        if (
            (event.lifecycle === 'execute' ||
                event.lifecycle === 'resume' ||
                event.lifecycle === 'override' ||
                event.lifecycle === 'delete') &&
            !event.job_id
        ) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message:
                    'execute/resume/override/delete lifecycle events require job_id',
                path: ['job_id'],
            });
        }
    });

export type CrossServiceAuditEvent = z.infer<typeof CrossServiceAuditEvent>;

export function compareCrossServiceAuditEventsForReplay(
    left: CrossServiceAuditEvent,
    right: CrossServiceAuditEvent,
): number {
    const byOccurredAt = left.occurred_at.localeCompare(right.occurred_at);

    if (byOccurredAt !== 0) {
        return byOccurredAt;
    }

    const byService = left.service.localeCompare(right.service);

    if (byService !== 0) {
        return byService;
    }

    return left.event_id.localeCompare(right.event_id);
}

export function sortCrossServiceAuditEventsForReplay<
    T extends CrossServiceAuditEvent,
>(events: readonly T[]): T[] {
    return events
        .slice()
        .sort((left, right) => compareCrossServiceAuditEventsForReplay(left, right));
}

export const CrossServiceAuditReplay = z
    .object({
        contract_version: z.literal(AUDIT_CONTRACT_VERSION),
        replay_order_version: z.literal(AUDIT_REPLAY_ORDER_VERSION),
        generated_at: isoDateTime,
        events: z.array(CrossServiceAuditEvent).min(1),
    })
    .strict()
    .superRefine((payload, ctx) => {
        const seenIdentity = new Set<string>();

        for (let index = 0; index < payload.events.length; index += 1) {
            const event = payload.events[index];
            const identity = `${event.service}:${event.event_id}`;

            if (seenIdentity.has(identity)) {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message:
                        'events must be unique by service:event_id within replay payload',
                    path: ['events', index, 'event_id'],
                });
            }

            seenIdentity.add(identity);

            if (index === 0) {
                continue;
            }

            const previous = payload.events[index - 1];

            if (compareCrossServiceAuditEventsForReplay(previous, event) > 0) {
                ctx.addIssue({
                    code: z.ZodIssueCode.custom,
                    message:
                        'events must be sorted by occurred_at, then service, then event_id',
                    path: ['events', index],
                });
            }
        }
    });

export type CrossServiceAuditReplay = z.infer<typeof CrossServiceAuditReplay>;

export const LegacyAuthAuditEvent = z
    .object({
        event_id: z.string().min(1),
        event_type: z
            .string()
            .regex(AUDIT_ACTION_REGEX, 'legacy auth event_type must be snake_case'),
        occurred_at: isoDateTime,
        actor: z.string().min(1).optional(),
        tenant_id: z.string().min(1).optional(),
        instance_id: z.string().min(1).optional(),
        client_id: z.string().min(1).optional(),
        service_scope: z.enum(['reg', 'rrs']).optional(),
        deny_reason_code: z.string().min(1).optional(),
        in_flight_reason_code: z.string().min(1).optional(),
        metadata: z.record(z.string(), z.unknown()),
    })
    .strict();

export type LegacyAuthAuditEvent = z.infer<typeof LegacyAuthAuditEvent>;

export const LegacyRestoreJobAuditEvent = z
    .object({
        event_id: z.string().min(1),
        event_type: z.enum([
            'job_created',
            'job_queued',
            'job_started',
            'job_paused',
            'job_completed',
            'job_failed',
            'job_cancelled',
        ]),
        job_id: z.string().min(1),
        reason_code: z.string().min(1),
        created_at: isoDateTime,
        details: z.record(z.string(), z.unknown()),
    })
    .strict();

export type LegacyRestoreJobAuditEvent = z.infer<
    typeof LegacyRestoreJobAuditEvent
>;

export const LegacyRestoreAuditContext = z
    .object({
        tenant_id: z.string().min(1),
        instance_id: z.string().min(1),
        source: z.string().min(1),
        plan_id: z.string().min(1).optional(),
        plan_hash: Sha256Hex.optional(),
    })
    .strict()
    .superRefine((context, ctx) => {
        if (context.plan_hash && !context.plan_id) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'plan_hash requires plan_id in legacy context',
                path: ['plan_id'],
            });
        }
    });

export type LegacyRestoreAuditContext = z.infer<typeof LegacyRestoreAuditContext>;

function inferActorType(actor: string): AuditActor['type'] {
    if (actor.includes('@')) {
        return 'user';
    }

    if (actor.startsWith('svc:') || actor.startsWith('service:')) {
        return 'service';
    }

    return 'system';
}

function mapLegacyAuthOutcome(eventType: string): AuditOutcome {
    if (eventType.endsWith('_denied')) {
        return 'denied';
    }

    if (eventType.endsWith('_started')) {
        return 'started';
    }

    if (eventType.endsWith('_completed')) {
        return 'completed';
    }

    return 'accepted';
}

function mapLegacyRestoreLifecycle(
    event: LegacyRestoreJobAuditEvent,
): {
    lifecycle: AuditLifecycle;
    action: string;
    outcome: AuditOutcome;
} {
    switch (event.event_type) {
        case 'job_created':
            return {
                lifecycle: 'plan',
                action: 'job_created',
                outcome: 'accepted',
            };
        case 'job_queued':
            return {
                lifecycle: 'execute',
                action: 'queued_for_lock',
                outcome: 'queued',
            };
        case 'job_started': {
            const resumedFromPause = event.details.resumed_from_pause === true;

            if (resumedFromPause) {
                return {
                    lifecycle: 'resume',
                    action: 'resumed',
                    outcome: 'started',
                };
            }

            return {
                lifecycle: 'execute',
                action: 'started',
                outcome: 'started',
            };
        }
        case 'job_paused':
            return {
                lifecycle: 'resume',
                action: 'paused',
                outcome: 'paused',
            };
        case 'job_completed':
            return {
                lifecycle: 'execute',
                action: 'completed',
                outcome: 'completed',
            };
        case 'job_failed':
            return {
                lifecycle: 'execute',
                action: 'failed',
                outcome: 'failed',
            };
        case 'job_cancelled':
            return {
                lifecycle: 'execute',
                action: 'cancelled',
                outcome: 'cancelled',
            };
    }
}

export function fromLegacyAuthAuditEvent(
    legacyEvent: LegacyAuthAuditEvent,
): CrossServiceAuditEvent {
    const parsed = LegacyAuthAuditEvent.parse(legacyEvent);
    const reasonCode =
        parsed.deny_reason_code && parsed.deny_reason_code !== 'none'
            ? parsed.deny_reason_code
            : parsed.in_flight_reason_code &&
                parsed.in_flight_reason_code !== 'none'
            ? parsed.in_flight_reason_code
            : undefined;

    return CrossServiceAuditEvent.parse({
        contract_version: AUDIT_CONTRACT_VERSION,
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        event_id: parsed.event_id,
        occurred_at: parsed.occurred_at,
        service: 'acp',
        lifecycle: 'auth',
        action: parsed.event_type,
        outcome: mapLegacyAuthOutcome(parsed.event_type),
        tenant_id: parsed.tenant_id,
        instance_id: parsed.instance_id,
        reason_code: reasonCode,
        actor: parsed.actor
            ? {
                type: inferActorType(parsed.actor),
                id: parsed.actor,
            }
            : undefined,
        metadata: {
            ...parsed.metadata,
            legacy_event_type: parsed.event_type,
            ...(parsed.client_id !== undefined
                ? { client_id: parsed.client_id }
                : {}),
            ...(parsed.service_scope !== undefined
                ? { service_scope: parsed.service_scope }
                : {}),
        },
    });
}

export function fromLegacyRestoreJobAuditEvent(
    legacyEvent: LegacyRestoreJobAuditEvent,
    context: LegacyRestoreAuditContext,
): CrossServiceAuditEvent {
    const parsedEvent = LegacyRestoreJobAuditEvent.parse(legacyEvent);
    const parsedContext = LegacyRestoreAuditContext.parse(context);
    const mapped = mapLegacyRestoreLifecycle(parsedEvent);

    return CrossServiceAuditEvent.parse({
        contract_version: AUDIT_CONTRACT_VERSION,
        schema_version: AUDIT_EVENT_SCHEMA_VERSION,
        event_id: parsedEvent.event_id,
        occurred_at: parsedEvent.created_at,
        service: 'rrs',
        lifecycle: mapped.lifecycle,
        action: mapped.action,
        outcome: mapped.outcome,
        tenant_id: parsedContext.tenant_id,
        instance_id: parsedContext.instance_id,
        source: parsedContext.source,
        plan_id: parsedContext.plan_id,
        plan_hash: parsedContext.plan_hash,
        job_id: parsedEvent.job_id,
        reason_code:
            parsedEvent.reason_code !== 'none'
                ? parsedEvent.reason_code
                : undefined,
        metadata: {
            ...parsedEvent.details,
            legacy_event_type: parsedEvent.event_type,
        },
    });
}
