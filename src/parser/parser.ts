/**
 * Security Event Token Parser and Validator
 * Parses and validates SETs according to RFC 8417
 */

import { jwtVerify, decodeJwt, JWTVerifyOptions, JWTPayload, createRemoteJWKSet } from 'jose';
import {
  SecEventPayload,
  ValidationOptions,
  ValidationResult,
  SigningKey,
} from '../types/secevent';
import { SecurityEvent } from '../types/events';

/**
 * Parser configuration
 */
export interface ParserOptions {
  /**
   * JWKS URL for key verification
   */
  jwksUrl?: string;

  /**
   * Static verification keys
   */
  verificationKeys?: SigningKey[];

  /**
   * Default validation options
   */
  defaultValidationOptions?: ValidationOptions;
}

/**
 * Security Event Token Parser
 */
export class SecEventParser {
  private jwks?: ReturnType<typeof createRemoteJWKSet>;

  constructor(private options: ParserOptions = {}) {
    if (options.jwksUrl) {
      this.jwks = createRemoteJWKSet(new URL(options.jwksUrl));
    }
  }

  /**
   * Parse a JWT without verification
   */
  decode(jwt: string): SecEventPayload {
    const payload = decodeJwt(jwt) as unknown as SecEventPayload;
    this.validatePayloadStructure(payload);
    return payload;
  }

  /**
   * Parse and verify a signed SET
   */
  async verify(
    jwt: string,
    verificationKey?: SigningKey | SigningKey[],
    options?: ValidationOptions,
  ): Promise<ValidationResult> {
    try {
      const mergedOptions = {
        ...this.options.defaultValidationOptions,
        ...options,
      };

      // Determine verification key(s)
      const keys = verificationKey
        ? Array.isArray(verificationKey)
          ? verificationKey
          : [verificationKey]
        : this.options.verificationKeys;

      if (!keys && !this.jwks) {
        throw new Error('No verification key or JWKS URL provided');
      }

      // Verify JWT signature
      let payload: JWTPayload;
      const jwtOptions: JWTVerifyOptions = {};

      if (mergedOptions.issuer) {
        jwtOptions.issuer = mergedOptions.issuer;
      }
      if (mergedOptions.audience) {
        jwtOptions.audience = mergedOptions.audience;
      }
      if (mergedOptions.clockTolerance) {
        jwtOptions.clockTolerance = mergedOptions.clockTolerance;
      }
      if (mergedOptions.currentDate) {
        jwtOptions.currentDate = mergedOptions.currentDate;
      }
      if (mergedOptions.maxTokenAge) {
        jwtOptions.maxTokenAge = `${mergedOptions.maxTokenAge}s`;
      }

      if (this.jwks) {
        const result = await jwtVerify(jwt, this.jwks, jwtOptions);
        payload = result.payload;
      } else if (keys) {
        // Try each key until one works
        let lastError: Error | undefined;
        for (const key of keys) {
          try {
            const result = await jwtVerify(
              jwt,
              key.key as Parameters<typeof jwtVerify>[1],
              jwtOptions,
            );
            payload = result.payload;
            break;
          } catch (error) {
            lastError = error as Error;
          }
        }
        if (!payload!) {
          throw lastError || new Error('Verification failed with all provided keys');
        }
      } else {
        throw new Error('No verification method available');
      }

      // Validate SET-specific requirements
      const secEventPayload = payload as unknown as SecEventPayload;
      const validationErrors = this.validateSecEvent(secEventPayload, mergedOptions);

      if (validationErrors.length > 0) {
        return {
          valid: false,
          errors: validationErrors,
          error: validationErrors.join('; '),
        };
      }

      return {
        valid: true,
        payload: secEventPayload,
      };
    } catch (error) {
      return {
        valid: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Validate SET payload structure
   */
  private validatePayloadStructure(payload: SecEventPayload): void {
    if (!payload.events || typeof payload.events !== 'object') {
      throw new Error('Missing or invalid events claim');
    }

    if (!payload.iss || typeof payload.iss !== 'string') {
      throw new Error('Missing or invalid issuer claim');
    }

    if (!payload.jti || typeof payload.jti !== 'string') {
      throw new Error('Missing or invalid jti claim');
    }

    if (typeof payload.iat !== 'number') {
      throw new Error('Missing or invalid iat claim');
    }
  }

  /**
   * Validate SET-specific requirements
   */
  private validateSecEvent(
    payload: SecEventPayload,
    options: ValidationOptions,
  ): string[] {
    const errors: string[] = [];

    // Basic structure validation
    try {
      this.validatePayloadStructure(payload);
    } catch (error) {
      errors.push(error instanceof Error ? error.message : 'Invalid payload structure');
    }

    // Check required claims
    if (options.requiredClaims) {
      for (const claim of options.requiredClaims) {
        if (!(claim in payload)) {
          errors.push(`Missing required claim: ${claim}`);
        }
      }
    }

    // Validate events
    if (payload.events) {
      const eventCount = Object.keys(payload.events).length;
      if (eventCount === 0) {
        errors.push('No events present in events claim');
      }

      // Check for valid event URIs
      for (const eventUri of Object.keys(payload.events)) {
        if (!this.isValidEventUri(eventUri)) {
          errors.push(`Invalid event URI format: ${eventUri}`);
        }
      }
    }

    // RFC 8417 states that the "sub" claim should not be used in the JWT itself
    // The subject should be in the events
    if (payload.sub) {
      // This is a warning, not necessarily an error
      // Some implementations might still use it
    }

    return errors;
  }

  /**
   * Check if an event URI is valid
   */
  private isValidEventUri(uri: string): boolean {
    try {
      const url = new URL(uri);
      return url.protocol === 'https:' || url.protocol === 'http:';
    } catch {
      return false;
    }
  }

  /**
   * Extract events from a decoded payload
   */
  extractEvents(payload: SecEventPayload): SecurityEvent {
    return payload.events;
  }

  /**
   * Extract a specific event type from a payload
   */
  extractEvent<T = unknown>(payload: SecEventPayload, eventType: string): T | undefined {
    return payload.events[eventType] as T | undefined;
  }

  /**
   * Check if a payload contains a specific event type
   */
  hasEvent(payload: SecEventPayload, eventType: string): boolean {
    return eventType in payload.events;
  }

  /**
   * Get all event types in a payload
   */
  getEventTypes(payload: SecEventPayload): string[] {
    return Object.keys(payload.events);
  }
}

/**
 * Factory function for creating a parser
 */
export function createParser(options?: ParserOptions): SecEventParser {
  return new SecEventParser(options);
}