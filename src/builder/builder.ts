/**
 * Security Event Token Builder
 * Provides a fluent API for constructing SETs
 */

import { SignJWT } from 'jose';
import {
  SecEventPayload,
  SignedSecEvent,
  IdGenerator,
  SigningKey,
} from '../types/secevent';
import { SecurityEvent } from '../types/events';
import { defaultIdGenerator } from '../id/generator';

/**
 * Builder configuration options
 */
export interface BuilderOptions {
  /**
   * Default issuer for all tokens
   */
  defaultIssuer?: string;

  /**
   * Default audience for all tokens
   */
  defaultAudience?: string | string[];

  /**
   * ID generator for JTI values
   */
  idGenerator?: IdGenerator;

  /**
   * Default signing key
   */
  signingKey?: SigningKey;
}

/**
 * Security Event Token Builder
 */
export class SecEventBuilder {
  private issuer?: string;
  private audience?: string | string[];
  private jti?: string;
  private iat?: number;
  private txn?: string;
  private events: SecurityEvent = {};
  private additionalClaims: Record<string, unknown> = {};
  private signingKey?: SigningKey;

  constructor(private options: BuilderOptions = {}) {
    if (options.defaultIssuer !== undefined) {
      this.issuer = options.defaultIssuer;
    }
    if (options.defaultAudience !== undefined) {
      this.audience = options.defaultAudience;
    }
    if (options.signingKey !== undefined) {
      this.signingKey = options.signingKey;
    }
  }

  /**
   * Set the issuer
   */
  withIssuer(issuer: string): this {
    this.issuer = issuer;
    return this;
  }

  /**
   * Set the audience
   */
  withAudience(audience: string | string[]): this {
    this.audience = audience;
    return this;
  }

  /**
   * Set the token ID
   */
  withJti(jti: string): this {
    this.jti = jti;
    return this;
  }

  /**
   * Set the issued at timestamp
   */
  withIat(iat: number): this {
    this.iat = iat;
    return this;
  }

  /**
   * Set the transaction ID
   */
  withTxn(txn: string): this {
    this.txn = txn;
    return this;
  }

  /**
   * Add an event to the token
   */
  withEvent(event: SecurityEvent): this {
    this.events = { ...this.events, ...event };
    return this;
  }

  /**
   * Add multiple events to the token
   */
  withEvents(...events: SecurityEvent[]): this {
    events.forEach((event) => {
      this.events = { ...this.events, ...event };
    });
    return this;
  }

  /**
   * Add a custom claim
   */
  withClaim(key: string, value: unknown): this {
    this.additionalClaims[key] = value;
    return this;
  }

  /**
   * Add multiple custom claims
   */
  withClaims(claims: Record<string, unknown>): this {
    this.additionalClaims = { ...this.additionalClaims, ...claims };
    return this;
  }

  /**
   * Set the signing key
   */
  withSigningKey(key: SigningKey): this {
    this.signingKey = key;
    return this;
  }

  /**
   * Build the payload without signing
   */
  buildPayload(): SecEventPayload {
    if (!this.issuer) {
      throw new Error('Issuer is required');
    }

    if (Object.keys(this.events).length === 0) {
      throw new Error('At least one event is required');
    }

    const idGenerator = this.options.idGenerator || defaultIdGenerator;

    const payload: SecEventPayload = {
      iss: this.issuer,
      jti: this.jti || idGenerator.generate(),
      iat: this.iat || Math.floor(Date.now() / 1000),
      events: this.events,
      ...this.additionalClaims,
    };

    if (this.audience) {
      payload.aud = this.audience;
    }

    if (this.txn) {
      payload.txn = this.txn;
    }

    return payload;
  }

  /**
   * Build and sign the token
   */
  async sign(signingKey?: SigningKey): Promise<SignedSecEvent> {
    const key = signingKey || this.signingKey;
    if (!key) {
      throw new Error('Signing key is required');
    }

    const payload = this.buildPayload();

    let jwt = new SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({
        alg: key.alg,
        typ: 'secevent+jwt',
        ...(key.kid && { kid: key.kid }),
      })
      .setIssuedAt(payload.iat)
      .setIssuer(payload.iss)
      .setJti(payload.jti);

    if (payload.aud) {
      jwt = jwt.setAudience(payload.aud);
    }

    const token = await jwt.sign(key.key as Parameters<typeof jwt.sign>[0]);

    return {
      jwt: token,
      payload,
    };
  }

  /**
   * Reset the builder
   */
  reset(): this {
    if (this.options.defaultIssuer !== undefined) {
      this.issuer = this.options.defaultIssuer;
    } else {
      delete this.issuer;
    }
    if (this.options.defaultAudience !== undefined) {
      this.audience = this.options.defaultAudience;
    } else {
      delete this.audience;
    }
    delete this.jti;
    delete this.iat;
    delete this.txn;
    this.events = {};
    this.additionalClaims = {};
    if (this.options.signingKey !== undefined) {
      this.signingKey = this.options.signingKey;
    } else {
      delete this.signingKey;
    }
    return this;
  }

  /**
   * Create a new builder with the same configuration
   */
  clone(): SecEventBuilder {
    const builder = new SecEventBuilder(this.options);
    if (this.issuer !== undefined) {
      builder.issuer = this.issuer;
    }
    if (this.audience !== undefined) {
      builder.audience = this.audience;
    }
    if (this.jti !== undefined) {
      builder.jti = this.jti;
    }
    if (this.iat !== undefined) {
      builder.iat = this.iat;
    }
    if (this.txn !== undefined) {
      builder.txn = this.txn;
    }
    builder.events = { ...this.events };
    builder.additionalClaims = { ...this.additionalClaims };
    if (this.signingKey !== undefined) {
      builder.signingKey = this.signingKey;
    }
    return builder;
  }
}

/**
 * Factory function for creating a builder
 */
export function createBuilder(options?: BuilderOptions): SecEventBuilder {
  return new SecEventBuilder(options);
}