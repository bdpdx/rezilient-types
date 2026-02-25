export function derivePartitionKey(event: any): string {
    if (event?.extensions?.partition_key) {
        return event.extensions.partition_key;
    }

    const type = event?.type;
    const data = event?.data || {};

    switch (type) {
        case 'cdc.delete':
        case 'cdc.write':
            if (!data.table || !data.record_sys_id) {
                throw new Error(
                    'CDC event missing required partition key fields: ' +
                    `table=${data.table}, ` +
                    `record_sys_id=${data.record_sys_id}`,
                );
            }
            return `${data.table}/${data.record_sys_id}`;
        case 'schema.change':
        case 'schema.snapshot':
            return `${data.table}`;
        case 'media.manifest':
        case 'media.meta':
        case 'media.delete':
            return String(
                data.attachment_sys_id ||
                    data.media_id ||
                    event?.subject ||
                    'unknown',
            );
        case 'error.report':
            if (data.attachment_sys_id) {
                return String(data.attachment_sys_id);
            }
            if (data.table && data.record_sys_id) {
                return `${data.table}/${data.record_sys_id}`;
            }
            return event?.subject || event?.source || 'unknown';
        case 'repair.report':
            if (data.original_event_id) {
                return String(data.original_event_id);
            }
            if (data.table && data.record_sys_id) {
                return `${data.table}/${data.record_sys_id}`;
            }
            return event?.subject || event?.source || 'unknown';
        default:
            return event?.subject || 'unknown';
    }
}

function normalizeErrorSeverity(
    raw: unknown,
): 'error' | 'warning' | 'info' | 'debug' {
    const value = String(raw || '').toLowerCase();

    if (value === 'critical') {
        return 'error';
    }
    if (
        value === 'error' ||
        value === 'warning' ||
        value === 'info' ||
        value === 'debug'
    ) {
        return value;
    }

    return 'error';
}

function mapErrorTopic(severity: unknown, useTestTopics: boolean): string {
    const normalized = normalizeErrorSeverity(severity);
    const prefix = useTestTopics ? 'rez.test.log.' : 'rez.log.';

    if (normalized === 'error') {
        return `${prefix}error`;
    }

    return `${prefix}${normalized}`;
}

export function mapTopic(type: string, useTestTopics = false, data?: any): string {
    if (useTestTopics) {
        if (type === 'schema.change' || type === 'schema.snapshot') {
            return 'rez.test.schema';
        }
        if (
            type === 'media.manifest' ||
            type === 'media.meta' ||
            type === 'media.delete'
        ) {
            return 'rez.test.media';
        }
        if (type === 'error.report') {
            return mapErrorTopic(data?.severity, true);
        }
        if (type === 'repair.report') {
            return 'rez.test.repair';
        }

        if (type === 'cdc.write' || type === 'cdc.delete') {
            return 'rez.test.cdc';
        }

        throw new Error(
            `Unknown event type for topic mapping: ${type}`,
        );
    }

    if (type === 'schema.change' || type === 'schema.snapshot') {
        return 'rez.schema';
    }
    if (type === 'media.manifest' || type === 'media.meta' || type === 'media.delete') {
        return 'rez.media';
    }
    if (type === 'error.report') {
        return mapErrorTopic(data?.severity, false);
    }
    if (type === 'repair.report') {
        return 'rez.repair';
    }

    if (type === 'cdc.write' || type === 'cdc.delete') {
        return 'rez.cdc';
    }

    throw new Error(
        `Unknown event type for topic mapping: ${type}`,
    );
}
