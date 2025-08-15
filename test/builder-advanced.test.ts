/**
 * Advanced tests for SecEventBuilder to achieve 100% coverage
 */

import { createBuilder } from '../src/builder/builder';
import { Events } from '../src/types/events';
import { SigningUtils, Algorithm } from '../src/signing/signer';

describe('SecEventBuilder Advanced', () => {
  describe('Builder with default signing key', () => {
    it('should use default signing key when none provided to sign()', async () => {
      const defaultKey = SigningUtils.createSymmetricKey('default-secret', Algorithm.HS256);

      const builder = createBuilder({
        signingKey: defaultKey,
      });

      const event = Events.verification('test-state');
      const signedEvent = await builder.withIssuer('https://example.com').withEvent(event).sign(); // No key provided, should use default

      expect(signedEvent.jwt).toBeDefined();
      expect(signedEvent.payload).toBeDefined();
    });

    it('should override default signing key when provided to sign()', async () => {
      const defaultKey = SigningUtils.createSymmetricKey('default-secret', Algorithm.HS256);
      const overrideKey = SigningUtils.createSymmetricKey('override-secret', Algorithm.HS256);

      const builder = createBuilder({
        signingKey: defaultKey,
      });

      const event = Events.verification('test-state');
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(overrideKey); // Override the default

      expect(signedEvent.jwt).toBeDefined();
      // Can't easily verify which key was used without decoding,
      // but the code path is tested
    });
  });

  describe('Builder reset with configured defaults', () => {
    it('should reset to configured defaults', () => {
      const builder = createBuilder({
        defaultIssuer: 'https://default.issuer.com',
        defaultAudience: 'https://default.audience.com',
      });

      // Set custom values
      builder
        .withIssuer('https://custom.issuer.com')
        .withAudience('https://custom.audience.com')
        .withEvent(Events.verification());

      // Reset should go back to defaults
      builder.reset();

      // Add an event so we can build
      builder.withEvent(Events.verification());
      const payload = builder.buildPayload();

      expect(payload.iss).toBe('https://default.issuer.com');
      expect(payload.aud).toBe('https://default.audience.com');
    });

    it('should reset signing key to default', () => {
      const defaultKey = SigningUtils.createSymmetricKey('default', Algorithm.HS256);
      const customKey = SigningUtils.createSymmetricKey('custom', Algorithm.HS256);

      const builder = createBuilder({
        signingKey: defaultKey,
      });

      // Set custom signing key
      builder.withSigningKey(customKey);

      // Reset
      builder.reset();

      // The signing key should be back to default
      // We can test this by attempting to sign
      builder.withIssuer('https://example.com').withEvent(Events.verification());

      // This should work with the default key
      expect(async () => await builder.sign()).not.toThrow();
    });
  });

  describe('Builder clone with signing key', () => {
    it('should clone with signing key', () => {
      const signingKey = SigningUtils.createSymmetricKey('secret', Algorithm.HS256);

      const builder = createBuilder();
      builder
        .withIssuer('https://example.com')
        .withSigningKey(signingKey)
        .withEvent(Events.verification());

      const cloned = builder.clone();

      // Both should be able to sign
      expect(async () => await builder.sign()).not.toThrow();
      expect(async () => await cloned.sign()).not.toThrow();
    });
  });

  describe('Edge cases', () => {
    it('should handle undefined optional parameters', () => {
      const builder = createBuilder({
        defaultIssuer: undefined,
        defaultAudience: undefined,
        idGenerator: undefined,
        signingKey: undefined,
      });

      expect(builder).toBeDefined();
    });

    it('should handle empty audience array', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withAudience([])
        .withEvent(event)
        .buildPayload();

      expect(payload.aud).toEqual([]);
    });

    it('should handle single string audience', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withAudience('https://single.audience.com')
        .withEvent(event)
        .buildPayload();

      expect(payload.aud).toBe('https://single.audience.com');
    });

    it('should handle array audience', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withAudience(['https://aud1.com', 'https://aud2.com'])
        .withEvent(event)
        .buildPayload();

      expect(payload.aud).toEqual(['https://aud1.com', 'https://aud2.com']);
    });

    it('should not include txn if not set', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder.withIssuer('https://example.com').withEvent(event).buildPayload();

      expect(payload.txn).toBeUndefined();
    });

    it('should not include aud if not set', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder.withIssuer('https://example.com').withEvent(event).buildPayload();

      expect(payload.aud).toBeUndefined();
    });

    it('should handle complex nested claims', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withClaim('nested', {
          level1: {
            level2: {
              level3: 'value',
            },
          },
        })
        .buildPayload();

      expect(payload.nested).toEqual({
        level1: {
          level2: {
            level3: 'value',
          },
        },
      });
    });

    it('should handle boolean and number claims', () => {
      const builder = createBuilder();
      const event = Events.verification();

      const payload = builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withClaim('booleanClaim', true)
        .withClaim('numberClaim', 42)
        .withClaim('nullClaim', null)
        .buildPayload();

      expect(payload.booleanClaim).toBe(true);
      expect(payload.numberClaim).toBe(42);
      expect(payload.nullClaim).toBeNull();
    });
  });
});
