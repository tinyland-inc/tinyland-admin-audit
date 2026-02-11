/**
 * Type definitions for admin audit logging.
 *
 * @module types
 */

/**
 * Admin action types for audit logging
 */
export type AdminAction =
  | 'CREATE'
  | 'UPDATE'
  | 'DELETE'
  | 'VIEW'
  | 'EXPORT'
  | 'IMPORT'
  | 'LOGIN'
  | 'LOGOUT'
  | 'PERMISSION_CHANGE'
  | 'INVITE'
  | 'REVOKE';

/**
 * Resource types that can be audited
 */
export type ResourceType =
  | 'user'
  | 'profile'
  | 'post'
  | 'event'
  | 'video'
  | 'product'
  | 'program'
  | 'invitation'
  | 'settings'
  | 'permission'
  | 'session'
  | 'file';

/**
 * Device type classification
 */
export type DeviceType = 'mobile' | 'tablet' | 'desktop' | 'unknown';

/**
 * Admin audit log entry (Phase 2 enhanced)
 */
export interface AdminAuditLog {
  // Identity
  timestamp: string;
  trace_id: string;          // Distributed tracing
  span_id: string;

  // Admin user context
  admin_user_id: string;
  admin_username: string;
  admin_role: string;

  // Action details
  action: AdminAction;
  resource_type: ResourceType;
  resource_id?: string;
  resource_name?: string;

  // Changes (before/after state)
  changes?: {
    before: Record<string, any>;
    after: Record<string, any>;
    fields_changed: string[];
  };

  // Client context (Phase 1)
  client_ip_hash: string;          // GDPR-compliant hashed IP
  client_ip_masked?: string;       // Display-only (192.168.*.*)
  user_agent: string;
  device_type: DeviceType;

  // Session context
  session_id: string;
  browser_fingerprint?: string;

  // Request details
  request_path: string;
  request_method: string;

  // Result
  success: boolean;
  error_message?: string;
  duration_ms?: number;

  // Additional metadata
  metadata?: Record<string, any>;
}

/**
 * Options for logging admin actions
 */
export interface AdminAuditOptions {
  resourceId?: string;
  resourceName?: string;
  before?: Record<string, any>;
  after?: Record<string, any>;
  metadata?: Record<string, any>;
  durationMs?: number;
}
