/**
 * @sgnl-ai/secevent - Security Event Token Library
 * A comprehensive JavaScript/TypeScript implementation of RFC 8417, CAEP, and SSF
 *
 * Copyright (c) 2024 SGNL.ai
 * Licensed under the MIT License
 */

// Core types
export * from './types/subject';
export * from './types/events';
export * from './types/secevent';

// Builder
export { SecEventBuilder, createBuilder } from './builder/builder';
export type { BuilderOptions } from './builder/builder';

// Parser
export { SecEventParser, createParser } from './parser/parser';
export type { ParserOptions } from './parser/parser';

// ID Generation
export {
  UuidGenerator,
  TimestampGenerator,
  PrefixedGenerator,
  CustomGenerator,
  defaultIdGenerator,
} from './id/generator';

// Signing
export { KeyManager, SigningUtils, Algorithm, defaultKeyManager } from './signing/signer';

// Re-export commonly used functions
export { SubjectIdentifiers } from './types/subject';
export { Events } from './types/events';
export { EVENT_TYPES, CAEP_EVENT_TYPES, SSF_EVENT_TYPES, RISC_EVENT_TYPES } from './types/events';

/**
 * Quick start example:
 *
 * ```typescript
 * import {
 *   createBuilder,
 *   SubjectIdentifiers,
 *   Events,
 *   SigningUtils,
 *   Algorithm
 * } from '@sgnl-ai/secevent';
 *
 * // Create a signing key
 * const signingKey = SigningUtils.createSymmetricKey('your-secret', Algorithm.HS256);
 *
 * // Build and sign a SET
 * const secEvent = await createBuilder()
 *   .withIssuer('https://example.com')
 *   .withAudience('https://app.example.com')
 *   .withEvent(
 *     Events.sessionRevoked(
 *       SubjectIdentifiers.email('user@example.com'),
 *       Date.now() / 1000,
 *       'suspicious_activity'
 *     )
 *   )
 *   .sign(signingKey);
 *
 * console.log(secEvent.jwt);
 * ```
 */
