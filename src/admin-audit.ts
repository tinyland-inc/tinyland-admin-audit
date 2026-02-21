/**
 * Admin Audit Middleware - Phase 2.2
 *
 * Enhanced admin activity logging with full observability integration:
 * - Phase 1: IP hashing (GDPR-compliant)
 * - Phase 1: Device detection
 * - Phase 2: Distributed tracing (trace_id, span_id)
 * - Phase 2: Session context
 * - Phase 2: Before/after state tracking
 * - Loki integration for centralized logging
 *
 * @module admin-audit
 */

import { getAdminAuditConfig } from './config.js';
import type { AuditRequestEvent } from './config.js';
import type {
  AdminAction,
  AdminAuditLog,
  AdminAuditOptions,
  DeviceType,
  ResourceType,
} from './types.js';

/**
 * Extract client context from request event (Phase 1 integration)
 */
export function extractClientContext(event: AuditRequestEvent) {
  const config = getAdminAuditConfig();

  let clientIp: string;
  try {
    clientIp = event.getClientAddress();
  } catch (_error) {
    clientIp = '127.0.0.1';
  }

  const userAgent = event.request.headers.get('user-agent') || 'unknown';

  return {
    clientIp,
    clientIpHash: config.hashIp(clientIp),
    clientIpMasked: config.maskIp(clientIp),
    userAgent,
    deviceType: config.detectDeviceType(userAgent) as DeviceType,
  };
}

/**
 * Calculate fields that changed between before/after states
 */
export function calculateChangedFields(
  before?: Record<string, any>,
  after?: Record<string, any>,
): string[] {
  if (!before || !after) return [];

  const changedFields: string[] = [];
  const allKeys = new Set([...Object.keys(before), ...Object.keys(after)]);

  for (const key of allKeys) {
    if (JSON.stringify(before[key]) !== JSON.stringify(after[key])) {
      changedFields.push(key);
    }
  }

  return changedFields;
}

/**
 * Log an admin action with full observability context
 *
 * @example
 * ```typescript
 * await logAdminAction(event, 'UPDATE', 'user', {
 *   resourceId: 'user123',
 *   resourceName: 'jane@example.com',
 *   before: { role: 'user', status: 'active' },
 *   after: { role: 'admin', status: 'active' },
 *   metadata: { reason: 'Promotion request approved' }
 * });
 * ```
 */
export async function logAdminAction(
  event: AuditRequestEvent,
  action: AdminAction,
  resourceType: ResourceType,
  options: AdminAuditOptions = {},
): Promise<void> {
  const config = getAdminAuditConfig();
  const logger = config.createLogger('admin-audit');

  const { locals, request, url } = event;

  // Require authenticated user
  if (!locals.user) {
    logger.warn('Admin action attempted without authentication', {
      action,
      resource_type: resourceType,
      request_path: url.pathname,
    });
    return;
  }

  // Extract client context (Phase 1)
  const clientContext = extractClientContext(event);

  // Generate trace IDs (Phase 2)
  const traceId = config.generateId();
  const spanId = config.generateId();

  // Calculate changes
  const fieldsChanged = calculateChangedFields(options.before, options.after);

  // Build audit log entry
  const auditLog: AdminAuditLog = {
    // Identity
    timestamp: new Date().toISOString(),
    trace_id: traceId,
    span_id: spanId,

    // Admin user
    admin_user_id: locals.user.id,
    admin_username: locals.user.username || locals.user.email || locals.user.handle || 'unknown',
    admin_role: locals.user.role || 'unknown',

    // Action
    action,
    resource_type: resourceType,
    resource_id: options.resourceId,
    resource_name: options.resourceName,

    // Changes
    ...(options.before || options.after
      ? {
          changes: {
            before: options.before || {},
            after: options.after || {},
            fields_changed: fieldsChanged,
          },
        }
      : {}),

    // Client context (Phase 1)
    client_ip_hash: clientContext.clientIpHash,
    client_ip_masked: clientContext.clientIpMasked,
    user_agent: clientContext.userAgent,
    device_type: clientContext.deviceType,

    // Session
    session_id: locals.session?.id || 'no-session',
    browser_fingerprint: locals.session?.browserFingerprint,

    // Request
    request_path: url.pathname,
    request_method: request.method,

    // Result
    success: true,
    duration_ms: options.durationMs,

    // Metadata
    metadata: options.metadata,
  };

  // Log to Loki with structured context
  logger.info(
    `Admin ${action}: ${resourceType}${options.resourceId ? `/${options.resourceId}` : ''}`,
    {
      'admin.action': action,
      'admin.user_id': auditLog.admin_user_id,
      'admin.username': auditLog.admin_username,
      'admin.role': auditLog.admin_role,

      'resource.type': resourceType,
      'resource.id': options.resourceId,
      'resource.name': options.resourceName,

      'changes.fields_changed':
        fieldsChanged.length > 0 ? fieldsChanged.join(', ') : undefined,
      'changes.count': fieldsChanged.length || undefined,

      'client.ip_hash': clientContext.clientIpHash,
      'client.device_type': clientContext.deviceType,

      'session.id': auditLog.session_id,
      trace_id: traceId,
      span_id: spanId,

      'http.method': request.method,
      'http.path': url.pathname,

      duration_ms: options.durationMs,
    },
  );
}

/**
 * Log a failed admin action
 */
export async function logAdminActionFailure(
  event: AuditRequestEvent,
  action: AdminAction,
  resourceType: ResourceType,
  error: Error | string,
  options: AdminAuditOptions = {},
): Promise<void> {
  const config = getAdminAuditConfig();
  const logger = config.createLogger('admin-audit');

  const { locals, request, url } = event;

  if (!locals.user) return;

  const clientContext = extractClientContext(event);
  const traceId = config.generateId();
  const spanId = config.generateId();

  const errorMessage = error instanceof Error ? error.message : error;

  const auditLog: AdminAuditLog = {
    timestamp: new Date().toISOString(),
    trace_id: traceId,
    span_id: spanId,

    admin_user_id: locals.user.id,
    admin_username: locals.user.username || locals.user.email || locals.user.handle || 'unknown',
    admin_role: locals.user.role || 'unknown',

    action,
    resource_type: resourceType,
    resource_id: options.resourceId,
    resource_name: options.resourceName,

    client_ip_hash: clientContext.clientIpHash,
    client_ip_masked: clientContext.clientIpMasked,
    user_agent: clientContext.userAgent,
    device_type: clientContext.deviceType,

    session_id: locals.session?.id || 'no-session',
    browser_fingerprint: locals.session?.browserFingerprint || 'no-fingerprint',

    request_path: url.pathname,
    request_method: request.method,

    success: false,
    error_message: errorMessage,
    duration_ms: options.durationMs,

    metadata: options.metadata,
  };

  logger.error(
    `Admin ${action} FAILED: ${resourceType}${options.resourceId ? `/${options.resourceId}` : ''}`,
    {
      'admin.action': action,
      'admin.user_id': auditLog.admin_user_id,
      'admin.username': auditLog.admin_username,
      'admin.role': auditLog.admin_role,

      'resource.type': resourceType,
      'resource.id': options.resourceId,
      'resource.name': options.resourceName,

      'client.ip_hash': clientContext.clientIpHash,
      'client.device_type': clientContext.deviceType,

      'session.id': auditLog.session_id,
      trace_id: traceId,
      span_id: spanId,

      'http.method': request.method,
      'http.path': url.pathname,

      'error.message': errorMessage,
      'error.type': error instanceof Error ? error.name : 'string',
      duration_ms: options.durationMs,

      level: 'error',
    },
  );
}

/**
 * Helper: Log user management actions
 */
export async function logUserManagement(
  event: AuditRequestEvent,
  action: 'CREATE' | 'UPDATE' | 'DELETE' | 'INVITE',
  userId: string,
  userName: string,
  before?: Record<string, any>,
  after?: Record<string, any>,
): Promise<void> {
  return logAdminAction(event, action, 'user', {
    resourceId: userId,
    resourceName: userName,
    before,
    after,
  });
}

/**
 * Helper: Log permission changes
 */
export async function logPermissionChange(
  event: AuditRequestEvent,
  userId: string,
  userName: string,
  oldRole: string,
  newRole: string,
): Promise<void> {
  return logAdminAction(event, 'PERMISSION_CHANGE', 'permission', {
    resourceId: userId,
    resourceName: userName,
    before: { role: oldRole },
    after: { role: newRole },
    metadata: {
      permission_type: 'role_change',
      old_role: oldRole,
      new_role: newRole,
    },
  });
}

/**
 * Helper: Log content management actions
 */
export async function logContentManagement(
  event: AuditRequestEvent,
  action: 'CREATE' | 'UPDATE' | 'DELETE',
  contentType: 'post' | 'event' | 'profile' | 'video' | 'product' | 'program',
  contentId: string,
  contentTitle: string,
  before?: Record<string, any>,
  after?: Record<string, any>,
): Promise<void> {
  return logAdminAction(event, action, contentType, {
    resourceId: contentId,
    resourceName: contentTitle,
    before,
    after,
  });
}
