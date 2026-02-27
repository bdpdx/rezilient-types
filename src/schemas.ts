import { z } from 'zod';

const ISO_UTC_SECOND_REGEX =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
const ISO_UTC_MILLIS_REGEX =
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

function normalizeIsoUtcInput(value: string): string | null {
    if (ISO_UTC_SECOND_REGEX.test(value)) {
        return `${value.slice(0, -1)}.000Z`;
    }

    if (ISO_UTC_MILLIS_REGEX.test(value)) {
        return value;
    }

    return null;
}

function parseIsoUtcCanonical(value: string): string | null {
    const normalized = normalizeIsoUtcInput(value);

    if (!normalized) {
        return null;
    }

    const parsed = Date.parse(normalized);

    if (!Number.isFinite(parsed)) {
        return null;
    }

    const canonical = new Date(parsed).toISOString();

    if (canonical !== normalized) {
        return null;
    }

    return canonical;
}

export function isIsoDateTimeUtc(value: string): boolean {
    return parseIsoUtcCanonical(value) !== null;
}

export function canonicalizeIsoDateTimeUtc(value: string): string {
    const canonical = parseIsoUtcCanonical(value);

    if (!canonical) {
        throw new Error(
            'must be ISO datetime (UTC Z) with second or millisecond precision',
        );
    }

    return canonical;
}

export const isoDateTime = z
    .string()
    .refine(isIsoDateTimeUtc, {
        message:
            'must be ISO datetime (UTC Z) with second or millisecond precision',
    });

export const serviceNowDateTime = z
    .string()
    .regex(
        /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/,
        'must be ServiceNow timestamp (YYYY-MM-DD HH:mm:ss)',
    );

export const EncryptedPayload = z
    .object({
        v: z.number().int().positive().optional(),
        alg: z.string().min(1),
        kid: z.string().min(1).optional(),
        module: z.string().min(1).optional(),
        format: z.string().min(1).optional(),
        compression: z.enum(['gzip', 'none']).optional(),
        ciphertext: z.string().min(1),
        sha256: z.string().min(1).optional(),
    })
    .strict();

export type EncryptedPayload = z.infer<typeof EncryptedPayload>;

export const CDCDeleteData = z
    .object({
        op: z.literal('D'),
        record_sys_id: z.string().min(1),
        schema_version: z.number().int().positive(),
        snapshot: z.record(z.string(), z.unknown()).optional(),
        snapshot_enc: EncryptedPayload.optional(),
        sys_updated_on: serviceNowDateTime,
        table: z.string().min(1),
    })
    .strict()
    .superRefine((d, ctx) => {
        if (d.snapshot !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot plaintext not allowed',
                path: ['snapshot'],
            });
        }

        if (!d.snapshot_enc) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot_enc is required',
                path: ['snapshot_enc'],
            });
        }
    });

export type CDCDeleteData = z.infer<typeof CDCDeleteData>;

export const CDCWriteData = z
    .object({
        changed_fields: z.array(z.string()).optional(),
        op: z.enum(['I', 'U']),
        record_sys_id: z.string().min(1),
        schema_version: z.number().int().positive(),
        snapshot: z.record(z.string(), z.unknown()).optional(),
        snapshot_enc: EncryptedPayload.optional(),
        sys_updated_on: serviceNowDateTime,
        table: z.string().min(1),
    })
    .strict()
    .superRefine((d, ctx) => {
        if (d.snapshot !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot plaintext not allowed',
                path: ['snapshot'],
            });
        }

        if (!d.snapshot_enc) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot_enc is required',
                path: ['snapshot_enc'],
            });
        }
    });

export type CDCWriteData = z.infer<typeof CDCWriteData>;

export const ExtensionsSchema = z
    .object({
        instance_id: z.string().min(1).optional(),
        partition_key: z.string().min(1).optional(),
        producer: z.string().min(1).optional(),
        retention: z.string().regex(/^P\d+D$/i).optional(),
        retention_days: z
            .union([
                z.number().int().positive(),
                z.string().regex(/^P\d+D$/i),
            ])
            .optional(),
        retention_ttl_ms: z.number().int().positive().optional(),
        seq: z.number().int().nonnegative().optional(),
        source: z.string().min(1).optional(),
        tenant_id: z.string().min(1).optional(),
    })
    .strict();

export type CloudEventExtensions = z.infer<typeof ExtensionsSchema>;

export const CloudEventBase = z
    .object({
        data: z.record(z.string(), z.unknown()),
        datacontenttype: z.literal('application/json'),
        extensions: ExtensionsSchema.optional(),
        id: z.string().min(1),
        source: z.string().min(1),
        specversion: z.literal('1.0'),
        subject: z.string().min(1),
        time: isoDateTime,
        type: z.enum([
            'cdc.delete',
            'cdc.write',
            'schema.change',
            'schema.snapshot',
            'media.manifest',
            'media.meta',
            'media.delete',
            'error.report',
            'repair.report',
        ]),
    })
    .strict();

export type CloudEventBase = z.infer<typeof CloudEventBase>;

export const SchemaChangeData = z
    .object({
        change: z
            .object({
                element: z.string().min(1),
                kind: z.enum(['add', 'drop', 'modify']),
                new: z.record(z.string(), z.unknown()).optional(),
                old: z.record(z.string(), z.unknown()).optional(),
            })
            .strict(),
        table: z.string().min(1),
    })
    .strict();

export type SchemaChangeData = z.infer<typeof SchemaChangeData>;

export const SchemaSnapshotData = z
    .object({
        schema_hash: z.string().min(1),
        schema_version: z.number().int().positive(),
        snapshot: z.record(z.string(), z.unknown()).optional(),
        snapshot_enc: EncryptedPayload.optional(),
        table: z.string().min(1),
    })
    .strict()
    .superRefine((d, ctx) => {
        if (d.snapshot !== undefined) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot plaintext not allowed',
                path: ['snapshot'],
            });
        }

        if (!d.snapshot_enc) {
            ctx.addIssue({
                code: z.ZodIssueCode.custom,
                message: 'snapshot_enc is required',
                path: ['snapshot_enc'],
            });
        }
    });

export type SchemaSnapshotData = z.infer<typeof SchemaSnapshotData>;

export const MediaBlobChunking = z
    .object({
        chunk_size_bytes: z.number().int().positive(),
        chunk_count: z.number().int().positive(),
        format: z.literal('length_prefixed'),
    })
    .strict();

export type MediaBlobChunking = z.infer<typeof MediaBlobChunking>;

export const MediaBlobDescriptor = z
    .object({
        alg: z.string().min(1),
        module: z.string().min(1),
        format: z.string().min(1),
        compression: z.enum(['gzip', 'none']),
        chunking: MediaBlobChunking,
    })
    .strict();

export type MediaBlobDescriptor = z.infer<typeof MediaBlobDescriptor>;

export const MediaManifestData = z
    .object({
        op: z.enum(['I', 'U']),
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        attachment_sys_id: z.string().min(1),
        sys_created_on: serviceNowDateTime,
        sys_updated_on: serviceNowDateTime,
        size_bytes: z.number().int().nonnegative(),
        content_type: z.string().min(1),
        sha256_plain: z.string().min(1),
        media_id: z.string().min(1),
        blob_enc: MediaBlobDescriptor,
        meta_enc: EncryptedPayload,
    })
    .strict();

export type MediaManifestData = z.infer<typeof MediaManifestData>;

export const MediaMetaData = MediaManifestData.extend({
    op: z.literal('U'),
}).strict();

export type MediaMetaData = z.infer<typeof MediaMetaData>;

export const MediaDeleteData = z
    .object({
        op: z.literal('D'),
        table: z.string().min(1),
        record_sys_id: z.string().min(1),
        attachment_sys_id: z.string().min(1),
        sys_updated_on: serviceNowDateTime,
    })
    .strict();

export type MediaDeleteData = z.infer<typeof MediaDeleteData>;

export const ErrorReportData = z
    .object({
        source: z.string().min(1),
        severity: z.enum(['debug', 'info', 'warning', 'error', 'critical']),
        message: z.string().min(1),
        error_code: z.string().min(1),
        component: z.string().min(1),
        event_type: z.string().min(1).optional(),
        last_error: z.string().min(1).optional(),
        stage: z.string().min(1).optional(),
        payload_hash: z.string().min(1).optional(),
        attachment_hash: z.string().min(1).optional(),
        stack: z.string().min(1).optional(),
        table: z.string().min(1).optional(),
        record_sys_id: z.string().min(1).optional(),
        attachment_sys_id: z.string().min(1).optional(),
        outbox_sys_id: z.string().min(1).optional(),
    })
    .strict();

export type ErrorReportData = z.infer<typeof ErrorReportData>;

export const RepairReportData = z
    .object({
        source: z.string().min(1),
        component: z.string().min(1),
        stage: z.string().min(1),
        disposition: z.string().min(1),
        repair_action: z.string().min(1),
        original_event_id: z.string().min(1).optional(),
        event_type: z.string().min(1).optional(),
        error: z.string().min(1).optional(),
        target_topic: z.string().min(1).optional(),
        message: z.string().min(1).optional(),
        table: z.string().min(1).optional(),
        record_sys_id: z.string().min(1).optional(),
        attachment_sys_id: z.string().min(1).optional(),
        outbox_sys_id: z.string().min(1).optional(),
        attempts: z.number().int().nonnegative().optional(),
    })
    .strict();

export type RepairReportData = z.infer<typeof RepairReportData>;

export const CloudEventSchema = z.discriminatedUnion('type', [
    CloudEventBase.extend({
        data: CDCDeleteData,
        type: z.literal('cdc.delete'),
    }),
    CloudEventBase.extend({
        data: CDCWriteData,
        type: z.literal('cdc.write'),
    }),
    CloudEventBase.extend({
        data: SchemaChangeData,
        type: z.literal('schema.change'),
    }),
    CloudEventBase.extend({
        data: SchemaSnapshotData,
        type: z.literal('schema.snapshot'),
    }),
    CloudEventBase.extend({
        data: MediaManifestData,
        type: z.literal('media.manifest'),
    }),
    CloudEventBase.extend({
        data: MediaMetaData,
        type: z.literal('media.meta'),
    }),
    CloudEventBase.extend({
        data: MediaDeleteData,
        type: z.literal('media.delete'),
    }),
    CloudEventBase.extend({
        data: ErrorReportData,
        type: z.literal('error.report'),
    }),
    CloudEventBase.extend({
        data: RepairReportData,
        type: z.literal('repair.report'),
    }),
]);

export const CloudEventEnvelope = CloudEventSchema;

export type CloudEvent = z.infer<typeof CloudEventSchema>;

export const buildEventBatchSchema = (maxEventsPerBatch?: number) =>
    z
        .object({
            batch_id: z.string().min(1).optional(),
            events: z.array(z.any()).min(1).max(maxEventsPerBatch ?? 500),
            sent_at: isoDateTime,
            source: z.string().min(1),
        })
        .strict();

export const EventBatchSchema = buildEventBatchSchema();

export type EventBatch = z.infer<ReturnType<typeof buildEventBatchSchema>>;
