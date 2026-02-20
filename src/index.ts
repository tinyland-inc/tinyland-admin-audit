/**
 * @tummycrypt/tinyland-admin-audit
 *
 * Admin audit logging with GDPR-compliant IP hashing and device detection.
 * Framework-agnostic via dependency injection configuration.
 *
 * @example
 * ```typescript
 * import {
 *   configureAdminAudit,
 *   logAdminAction,
 *   type AuditRequestEvent,
 * } from '@tummycrypt/tinyland-admin-audit';
 *
 * // Configure with your framework's implementations
 * configureAdminAudit({
 *   createLogger: (name) => myLoggerFactory(name),
 *   hashIp: (ip) => myHashFunction(ip),
 *   maskIp: (ip) => myMaskFunction(ip),
 *   detectDeviceType: (ua) => myDeviceDetector(ua),
 * });
 *
 * // Use in request handlers
 * await logAdminAction(event, 'UPDATE', 'user', {
 *   resourceId: 'user-123',
 *   before: { role: 'member' },
 *   after: { role: 'admin' },
 * });
 * ```
 *
 * @module index
 */

// Configuration & DI
export {
  configureAdminAudit,
  getAdminAuditConfig,
  resetAdminAuditConfig,
} from './config.js';

export type {
  Logger,
  AuditRequestEvent,
  AdminAuditPackageConfig,
} from './config.js';

// Types
export type {
  AdminAction,
  ResourceType,
  DeviceType,
  AdminAuditLog,
  AdminAuditOptions,
} from './types.js';

// Core audit functions
export {
  extractClientContext,
  calculateChangedFields,
  logAdminAction,
  logAdminActionFailure,
  logUserManagement,
  logPermissionChange,
  logContentManagement,
} from './admin-audit.js';
