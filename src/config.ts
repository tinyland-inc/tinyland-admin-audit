/**
 * Dependency injection configuration for tinyland-admin-audit.
 *
 * Allows consumers to provide their own logger, IP hashing, device detection,
 * and ID generation without coupling to any framework.
 *
 * @module config
 */

import crypto from 'crypto';

/** Logger interface for audit operations */
export interface Logger {
  info(message: string, meta?: Record<string, any>): void;
  warn(message: string, meta?: Record<string, any>): void;
  error(message: string, meta?: Record<string, any>): void;
}

/**
 * Framework-agnostic request event abstraction.
 *
 * Replaces SvelteKit's RequestEvent to decouple from any specific framework.
 * Consumers map their framework's request object to this interface.
 */
export interface AuditRequestEvent {
  getClientAddress(): string;
  request: {
    headers: {
      get(name: string): string | null;
    };
    method: string;
  };
  url: {
    pathname: string;
  };
  locals: {
    user?: {
      id: string;
      username?: string;
      email?: string;
      handle?: string;
      role?: string;
    };
    session?: {
      id?: string;
      browserFingerprint?: string;
    };
  };
}

/** Package configuration options */
export interface AdminAuditPackageConfig {
  /** Factory to create a named logger. Defaults to console. */
  createLogger: (name: string) => Logger;
  /** Hash an IP address (GDPR-compliant). Defaults to passthrough. */
  hashIp: (ip: string) => string;
  /** Mask an IP address for display. Defaults to replacing last octet with ***. */
  maskIp: (ip: string) => string;
  /** Detect device type from user agent string. Defaults to 'unknown'. */
  detectDeviceType: (userAgent: string) => string;
  /** Generate a unique ID (for trace/span IDs). Defaults to crypto.randomUUID(). */
  generateId: () => string;
}

const defaultConfig: AdminAuditPackageConfig = {
  createLogger: () => ({
    info: console.log,
    warn: console.warn,
    error: console.error,
  }),
  hashIp: (ip: string) => ip,
  maskIp: (ip: string) => ip.replace(/\d+$/, '***'),
  detectDeviceType: () => 'unknown',
  generateId: () => crypto.randomUUID(),
};

let config: AdminAuditPackageConfig = { ...defaultConfig };

/** Configure the admin audit package with custom dependencies */
export function configureAdminAudit(overrides: Partial<AdminAuditPackageConfig>): void {
  config = { ...config, ...overrides };
}

/** Get the resolved configuration */
export function getAdminAuditConfig(): AdminAuditPackageConfig {
  return config;
}

/** Reset configuration to defaults (primarily for testing) */
export function resetAdminAuditConfig(): void {
  config = { ...defaultConfig };
}
