/**
 * Tests for SecEventBuilder
 */

import { SecEventBuilder, createBuilder } from '../src/builder/builder';
import { SubjectIdentifiers } from '../src/types/subject';
import { Events, CAEP_EVENT_TYPES } from '../src/types/events';
import { SigningUtils, Algorithm } from '../src/signing/signer';
import { UuidGenerator, PrefixedGenerator } from '../src/id/generator';

describe('SecEventBuilder', () => {
  let builder: SecEventBuilder;

  beforeEach(() => {
    builder = createBuilder();
  });

  describe('Basic building', () => {
    it('should build a basic SET payload', () => {
      const subject = SubjectIdentifiers.email('user@example.com');
      const event = Events.sessionRevoked(subject, Date.now() / 1000);

      const payload = builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event)
        .buildPayload();

      expect(payload.iss).toBe('https://example.com');
      expect(payload.aud).toBe('https://app.example.com');
      expect(CAEP_EVENT_TYPES.SESSION_REVOKED in payload.events).toBe(true);
      expect(payload.jti).toBeDefined();
      expect(payload.iat).toBeDefined();
    });

    it('should support multiple events', () => {
      const subject = SubjectIdentifiers.email('user@example.com');
      const event1 = Events.sessionRevoked(subject, Date.now() / 1000);
      const event2 = Events.tokenClaimsChange(subject, Date.now() / 1000);

      const payload = builder
        .withIssuer('https://example.com')
        .withEvents(event1, event2)
        .buildPayload();

      expect(Object.keys(payload.events)).toHaveLength(2);
      expect(CAEP_EVENT_TYPES.SESSION_REVOKED in payload.events).toBe(true);
      expect(CAEP_EVENT_TYPES.TOKEN_CLAIMS_CHANGE in payload.events).toBe(true);
    });

    it('should throw error if no issuer is provided', () => {
      const event = Events.verification('test-state');

      expect(() => {
        builder.withEvent(event).buildPayload();
      }).toThrow('Issuer is required');
    });

    it('should throw error if no events are provided', () => {
      expect(() => {
        builder.withIssuer('https://example.com').buildPayload();
      }).toThrow('At least one event is required');
    });
  });

  describe('Custom claims', () => {
    it('should support adding custom claims', () => {
      const event = Events.streamUpdated();

      const payload = builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withClaim('custom', 'value')
        .withClaims({ foo: 'bar', nested: { value: 123 } })
        .buildPayload();

      expect(payload.custom).toBe('value');
      expect(payload.foo).toBe('bar');
      expect(payload.nested).toEqual({ value: 123 });
    });

    it('should support transaction ID', () => {
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withTxn('txn-12345')
        .buildPayload();

      expect(payload.txn).toBe('txn-12345');
    });
  });

  describe('ID generation', () => {
    it('should use custom ID generator', () => {
      const customGenerator = new PrefixedGenerator('test', new UuidGenerator());
      const customBuilder = createBuilder({
        idGenerator: customGenerator,
      });

      const event = Events.verification();
      const payload = customBuilder
        .withIssuer('https://example.com')
        .withEvent(event)
        .buildPayload();

      expect(payload.jti).toMatch(/^test-/);
    });

    it('should use provided JTI', () => {
      const event = Events.verification();
      const payload = builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withJti('custom-jti')
        .buildPayload();

      expect(payload.jti).toBe('custom-jti');
    });
  });

  describe('Builder configuration', () => {
    it('should use default issuer and audience', () => {
      const configuredBuilder = createBuilder({
        defaultIssuer: 'https://default.issuer.com',
        defaultAudience: 'https://default.audience.com',
      });

      const event = Events.verification();
      const payload = configuredBuilder.withEvent(event).buildPayload();

      expect(payload.iss).toBe('https://default.issuer.com');
      expect(payload.aud).toBe('https://default.audience.com');
    });

    it('should override defaults', () => {
      const configuredBuilder = createBuilder({
        defaultIssuer: 'https://default.issuer.com',
      });

      const event = Events.verification();
      const payload = configuredBuilder
        .withIssuer('https://override.issuer.com')
        .withEvent(event)
        .buildPayload();

      expect(payload.iss).toBe('https://override.issuer.com');
    });
  });

  describe('Signing', () => {
    it('should sign a token with symmetric key', async () => {
      const signingKey = SigningUtils.createSymmetricKey('test-secret', Algorithm.HS256);
      const event = Events.verification('test-state');

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      expect(signedEvent.jwt).toBeDefined();
      expect(typeof signedEvent.jwt).toBe('string');
      expect(signedEvent.jwt.split('.')).toHaveLength(3); // JWT format
      expect(signedEvent.payload).toBeDefined();
    });

    it('should throw error if no signing key is provided', async () => {
      const event = Events.verification();

      await expect(
        builder.withIssuer('https://example.com').withEvent(event).sign(),
      ).rejects.toThrow('Signing key is required');
    });
  });

  describe('Builder utilities', () => {
    it('should reset the builder', () => {
      const event = Events.verification();
      builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event)
        .withTxn('txn-123');

      builder.reset();

      expect(() => builder.buildPayload()).toThrow('Issuer is required');
    });

    it('should clone the builder', () => {
      const event = Events.verification();
      builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event);

      const cloned = builder.clone();
      const payload1 = builder.buildPayload();
      const payload2 = cloned.buildPayload();

      expect(payload1.iss).toBe(payload2.iss);
      expect(payload1.aud).toBe(payload2.aud);
      // JTI should be different due to generation
      expect(payload1.jti).not.toBe(payload2.jti);
    });
  });
});
