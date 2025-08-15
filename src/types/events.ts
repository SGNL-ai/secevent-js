/**
 * Security Event Types
 * Implements CAEP and SSF event types according to their specifications
 */

import { SubjectIdentifier, ComplexSubject } from './subject';

/**
 * Base Security Event interface
 */
export interface SecurityEvent {
  [eventType: string]: EventData | unknown;
}

export interface EventData {
  subject?: SubjectIdentifier | ComplexSubject;
  [key: string]: unknown;
}

/**
 * CAEP Event Types
 */

/**
 * Session Revoked Event
 * Indicates that the session identified by the subject has been revoked
 */
export interface SessionRevokedEvent extends EventData {
  event_timestamp: number;
  reason?: string;
}

/**
 * Token Claims Change Event
 * Indicates that the claims in the token have changed
 */
export interface TokenClaimsChangeEvent extends EventData {
  event_timestamp: number;
  claims?: Record<string, unknown>;
}

/**
 * Credential Change Event
 * Indicates that the user's credential has been changed
 */
export interface CredentialChangeEvent extends EventData {
  event_timestamp: number;
  credential_type?: string;
  change_type?: 'create' | 'update' | 'delete';
  reason?: string;
  x509_issuer?: string;
  x509_serial?: string;
  fido2_aaguid?: string;
  friendly_name?: string;
}

/**
 * Assurance Level Change Event
 * Indicates that the user's assurance level has changed
 */
export interface AssuranceLevelChangeEvent extends EventData {
  event_timestamp: number;
  current_level?: string;
  previous_level?: string;
  change_direction?: 'increase' | 'decrease';
  initiating_entity?: 'policy' | 'user' | 'admin';
}

/**
 * Device Compliance Change Event
 * Indicates that the device's compliance status has changed
 */
export interface DeviceComplianceChangeEvent extends EventData {
  event_timestamp: number;
  current_status?: 'compliant' | 'not_compliant';
  previous_status?: 'compliant' | 'not_compliant';
  compliance_policies?: string[];
}

/**
 * SSF Event Types
 */

/**
 * Stream Updated Event
 * Indicates that the stream configuration has been updated
 */
export interface StreamUpdatedEvent extends EventData {
  effective_time?: number;
}

/**
 * Verification Event
 * Used to verify the stream connection
 */
export interface VerificationEvent extends EventData {
  state?: string;
}

/**
 * CAEP Event URIs
 */
export const CAEP_EVENT_TYPES = {
  SESSION_REVOKED: 'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
  TOKEN_CLAIMS_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
  CREDENTIAL_CHANGE: 'https://schemas.openid.net/secevent/caep/event-type/credential-change',
  ASSURANCE_LEVEL_CHANGE:
    'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
  DEVICE_COMPLIANCE_CHANGE:
    'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
} as const;

/**
 * SSF Event URIs
 */
export const SSF_EVENT_TYPES = {
  STREAM_UPDATED: 'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
  VERIFICATION: 'https://schemas.openid.net/secevent/ssf/event-type/verification',
} as const;

/**
 * RISC Event URIs
 */
export const RISC_EVENT_TYPES = {
  ACCOUNT_CREDENTIAL_CHANGE_REQUIRED:
    'https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required',
  ACCOUNT_PURGED: 'https://schemas.openid.net/secevent/risc/event-type/account-purged',
  ACCOUNT_DISABLED: 'https://schemas.openid.net/secevent/risc/event-type/account-disabled',
  ACCOUNT_ENABLED: 'https://schemas.openid.net/secevent/risc/event-type/account-enabled',
  IDENTIFIER_CHANGED: 'https://schemas.openid.net/secevent/risc/event-type/identifier-changed',
  IDENTIFIER_RECYCLED: 'https://schemas.openid.net/secevent/risc/event-type/identifier-recycled',
  OPT_IN: 'https://schemas.openid.net/secevent/risc/event-type/opt-in',
  OPT_OUT_INITIATED: 'https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated',
  OPT_OUT_CANCELLED: 'https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled',
  OPT_OUT_EFFECTIVE: 'https://schemas.openid.net/secevent/risc/event-type/opt-out-effective',
  RECOVERY_ACTIVATED: 'https://schemas.openid.net/secevent/risc/event-type/recovery-activated',
  RECOVERY_INFORMATION_CHANGED:
    'https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed',
  SESSIONS_REVOKED: 'https://schemas.openid.net/secevent/risc/event-type/sessions-revoked',
} as const;

/**
 * All event type URIs
 */
export const EVENT_TYPES = {
  ...CAEP_EVENT_TYPES,
  ...SSF_EVENT_TYPES,
  ...RISC_EVENT_TYPES,
} as const;

export type EventTypeUri = (typeof EVENT_TYPES)[keyof typeof EVENT_TYPES];

/**
 * Helper class for creating events
 */
export class Events {
  static sessionRevoked(
    subject: SubjectIdentifier | ComplexSubject,
    timestamp: number,
    reason?: string,
  ): SecurityEvent {
    return {
      [CAEP_EVENT_TYPES.SESSION_REVOKED]: {
        subject,
        event_timestamp: timestamp,
        reason,
      } as SessionRevokedEvent,
    };
  }

  static tokenClaimsChange(
    subject: SubjectIdentifier | ComplexSubject,
    timestamp: number,
    claims?: Record<string, unknown>,
  ): SecurityEvent {
    return {
      [CAEP_EVENT_TYPES.TOKEN_CLAIMS_CHANGE]: {
        subject,
        event_timestamp: timestamp,
        claims,
      } as TokenClaimsChangeEvent,
    };
  }

  static credentialChange(
    subject: SubjectIdentifier | ComplexSubject,
    timestamp: number,
    options?: Partial<CredentialChangeEvent>,
  ): SecurityEvent {
    return {
      [CAEP_EVENT_TYPES.CREDENTIAL_CHANGE]: {
        subject,
        event_timestamp: timestamp,
        ...options,
      } as CredentialChangeEvent,
    };
  }

  static assuranceLevelChange(
    subject: SubjectIdentifier | ComplexSubject,
    timestamp: number,
    options?: Partial<AssuranceLevelChangeEvent>,
  ): SecurityEvent {
    return {
      [CAEP_EVENT_TYPES.ASSURANCE_LEVEL_CHANGE]: {
        subject,
        event_timestamp: timestamp,
        ...options,
      } as AssuranceLevelChangeEvent,
    };
  }

  static deviceComplianceChange(
    subject: SubjectIdentifier | ComplexSubject,
    timestamp: number,
    options?: Partial<DeviceComplianceChangeEvent>,
  ): SecurityEvent {
    return {
      [CAEP_EVENT_TYPES.DEVICE_COMPLIANCE_CHANGE]: {
        subject,
        event_timestamp: timestamp,
        ...options,
      } as DeviceComplianceChangeEvent,
    };
  }

  static streamUpdated(effectiveTime?: number): SecurityEvent {
    return {
      [SSF_EVENT_TYPES.STREAM_UPDATED]: {
        effective_time: effectiveTime,
      } as StreamUpdatedEvent,
    };
  }

  static verification(state?: string): SecurityEvent {
    return {
      [SSF_EVENT_TYPES.VERIFICATION]: {
        state,
      } as VerificationEvent,
    };
  }
}
