/**
 * Security Event Token (SET) Types
 * Core types for SEC Event tokens as defined in RFC 8417
 */

import { JWTPayload } from 'jose';
import { SecurityEvent } from './events';

/**
 * Security Event Token payload
 * Extends JWT payload with SET-specific claims
 */
export interface SecEventPayload extends JWTPayload {
  /**
   * Events claim containing one or more security events
   */
  events: SecurityEvent;

  /**
   * Transaction identifier
   */
  txn?: string;

  /**
   * Token identifier (jti is inherited from JWTPayload)
   */
  jti: string;

  /**
   * Issued at timestamp (iat is inherited from JWTPayload)
   */
  iat: number;

  /**
   * Issuer (iss is inherited from JWTPayload)
   */
  iss: string;

  /**
   * Audience (aud is inherited from JWTPayload)
   */
  aud?: string | string[];

  /**
   * Subject (sub is inherited from JWTPayload)
   * Note: In SET, the subject is typically in the event, not the JWT subject
   */
  sub?: string;

  /**
   * Additional custom claims
   */
  [key: string]: unknown;
}

/**
 * Options for creating a Security Event Token
 */
export interface SecEventOptions {
  /**
   * Issuer of the token
   */
  issuer: string;

  /**
   * Audience for the token
   */
  audience?: string | string[];

  /**
   * Token ID (defaults to UUID)
   */
  jti?: string;

  /**
   * Issued at timestamp (defaults to current time)
   */
  iat?: number;

  /**
   * Transaction ID
   */
  txn?: string;

  /**
   * Additional custom claims
   */
  additionalClaims?: Record<string, unknown>;
}

/**
 * Signed Security Event Token
 */
export interface SignedSecEvent {
  /**
   * The JWT string representation
   */
  jwt: string;

  /**
   * The decoded payload
   */
  payload: SecEventPayload;
}

/**
 * SEC Event validation options
 */
export interface ValidationOptions {
  /**
   * Expected issuer
   */
  issuer?: string | string[];

  /**
   * Expected audience
   */
  audience?: string | string[];

  /**
   * Clock tolerance in seconds
   */
  clockTolerance?: number;

  /**
   * Current time (defaults to Date.now())
   */
  currentDate?: Date;

  /**
   * Required claims
   */
  requiredClaims?: string[];

  /**
   * Maximum token age in seconds
   */
  maxTokenAge?: number;
}

/**
 * Validation result
 */
export interface ValidationResult {
  /**
   * Whether validation succeeded
   */
  valid: boolean;

  /**
   * Decoded payload if valid
   */
  payload?: SecEventPayload;

  /**
   * Error message if invalid
   */
  error?: string;

  /**
   * Detailed validation errors
   */
  errors?: string[];
}

/**
 * ID Generator interface
 */
export interface IdGenerator {
  /**
   * Generate a unique ID
   */
  generate(): string;
}

/**
 * Signing key configuration
 */
export interface SigningKey {
  /**
   * Key ID
   */
  kid?: string;

  /**
   * Algorithm
   */
  alg: string;

  /**
   * The actual key (can be string, Buffer, or KeyLike)
   */
  key: unknown;
}