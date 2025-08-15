/**
 * Advanced tests for SecEventParser to achieve 100% coverage
 */

import { SecEventParser, createParser } from '../src/parser/parser';
import { SecEventBuilder } from '../src/builder/builder';
import { Events } from '../src/types/events';
import { SigningUtils, Algorithm } from '../src/signing/signer';

// Mock jose module
jest.mock('jose', () => {
  const actual = jest.requireActual('jose');
  return {
    ...actual,
    createRemoteJWKSet: jest.fn(() => {
      return jest.fn().mockResolvedValue({
        // Mock JWKS response
      });
    }),
  };
});

describe('SecEventParser Advanced', () => {
  let parser: SecEventParser;
  let builder: SecEventBuilder;
  const signingKey = SigningUtils.createSymmetricKey('test-secret', Algorithm.HS256, 'test-key');

  beforeEach(() => {
    parser = createParser();
    builder = new SecEventBuilder();
  });

  describe('JWKS URL Support', () => {
    it('should create parser with JWKS URL', () => {
      const parserWithJwks = createParser({
        jwksUrl: 'https://example.com/.well-known/jwks.json',
      });

      expect(parserWithJwks).toBeDefined();
    });

    it('should verify with JWKS when no key provided', async () => {
      const parserWithJwks = createParser({
        jwksUrl: 'https://example.com/.well-known/jwks.json',
      });

      const event = Events.verification('test');
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      // This will fail because the mock JWKS doesn't have the right key
      // but it tests the code path
      const result = await parserWithJwks.verify(signedEvent.jwt);
      expect(result.valid).toBe(false);
    });
  });

  describe('Error Handling', () => {
    it('should handle invalid JWT in decode', () => {
      expect(() => parser.decode('not-a-jwt')).toThrow();
    });

    it('should handle JWT without events claim', () => {
      // Create a JWT without events claim
      const invalidJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwianRpIjoiMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

      expect(() => parser.decode(invalidJwt)).toThrow('Missing or invalid events claim');
    });

    it('should handle JWT without issuer', () => {
      const invalidJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJldmVudHMiOnt9LCJqdGkiOiIxMjMiLCJpYXQiOjE1MTYyMzkwMjJ9.invalid';

      expect(() => parser.decode(invalidJwt)).toThrow();
    });

    it('should handle JWT without jti', () => {
      const invalidJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJldmVudHMiOnt9LCJpc3MiOiJ0ZXN0IiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid';

      expect(() => parser.decode(invalidJwt)).toThrow();
    });

    it('should handle JWT without iat', () => {
      const invalidJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJldmVudHMiOnt9LCJpc3MiOiJ0ZXN0IiwianRpIjoiMTIzIn0.invalid';

      expect(() => parser.decode(invalidJwt)).toThrow();
    });
  });

  describe('Validation Options', () => {
    it('should validate with clock tolerance', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        clockTolerance: 60,
      });

      expect(result.valid).toBe(true);
    });

    it('should validate with current date', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        currentDate: new Date(),
      });

      expect(result.valid).toBe(true);
    });

    it('should validate with max token age', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        maxTokenAge: 3600, // 1 hour
      });

      expect(result.valid).toBe(true);
    });

    it('should fail with expired max token age', async () => {
      const event = Events.verification();
      // Create a token with old iat
      const oldIat = Math.floor(Date.now() / 1000) - 7200; // 2 hours ago
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withIat(oldIat)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        maxTokenAge: 3600, // 1 hour
      });

      expect(result.valid).toBe(false);
    });
  });

  describe('Multiple Verification Keys', () => {
    it('should try all keys until one works', async () => {
      const correctKey = SigningUtils.createSymmetricKey('correct', Algorithm.HS256);
      const wrongKey1 = SigningUtils.createSymmetricKey('wrong1', Algorithm.HS256);
      const wrongKey2 = SigningUtils.createSymmetricKey('wrong2', Algorithm.HS256);

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(correctKey);

      const result = await parser.verify(signedEvent.jwt, [wrongKey1, wrongKey2, correctKey]);

      expect(result.valid).toBe(true);
    });

    it('should fail if no keys work', async () => {
      const signingKeyUsed = SigningUtils.createSymmetricKey('signing', Algorithm.HS256);
      const wrongKey1 = SigningUtils.createSymmetricKey('wrong1', Algorithm.HS256);
      const wrongKey2 = SigningUtils.createSymmetricKey('wrong2', Algorithm.HS256);

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKeyUsed);

      const result = await parser.verify(signedEvent.jwt, [wrongKey1, wrongKey2]);

      expect(result.valid).toBe(false);
      expect(result.error).toContain('signature verification failed');
    });
  });

  describe('Event Validation', () => {
    it('should validate events with no event URIs', async () => {
      // Manually create a token with empty events
      const emptyEventsJwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6InNlY2V2ZW50K2p3dCJ9.eyJpc3MiOiJodHRwczovL2V4YW1wbGUuY29tIiwianRpIjoiMTIzIiwiaWF0IjoxNTE2MjM5MDIyLCJldmVudHMiOnt9fQ.invalid';

      const result = await parser.verify(emptyEventsJwt, signingKey);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('signature');
    });

    it('should validate event URI format', async () => {
      // Create token with invalid event URI
      const invalidEventJwt = await builder
        .withIssuer('https://example.com')
        .withEvent({ 'not-a-url': { data: 'test' } })
        .sign(signingKey);

      const result = await parser.verify(invalidEventJwt.jwt, signingKey);
      expect(result.valid).toBe(false);
      expect(result.errors?.[0]).toContain('Invalid event URI format');
    });

    it('should allow sub claim (with warning)', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .withClaim('sub', 'subject-123')
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey);
      // Should still be valid, sub is allowed but not recommended
      expect(result.valid).toBe(true);
    });
  });

  describe('Parser with configured verification keys', () => {
    it('should use configured keys when no key provided to verify', async () => {
      const key1 = SigningUtils.createSymmetricKey('key1', Algorithm.HS256);
      const key2 = SigningUtils.createSymmetricKey('key2', Algorithm.HS256);

      const configuredParser = createParser({
        verificationKeys: [key1, key2],
      });

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(key2);

      const result = await configuredParser.verify(signedEvent.jwt);
      expect(result.valid).toBe(true);
    });

    it('should fail when no configured keys match', async () => {
      const key1 = SigningUtils.createSymmetricKey('key1', Algorithm.HS256);
      const key2 = SigningUtils.createSymmetricKey('key2', Algorithm.HS256);
      const signingKeyUsed = SigningUtils.createSymmetricKey('different', Algorithm.HS256);

      const configuredParser = createParser({
        verificationKeys: [key1, key2],
      });

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKeyUsed);

      const result = await configuredParser.verify(signedEvent.jwt);
      expect(result.valid).toBe(false);
    });
  });

  describe('No verification method available', () => {
    it('should error when no key or JWKS provided', async () => {
      const parserNoKeys = createParser();

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parserNoKeys.verify(signedEvent.jwt);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('No verification key or JWKS URL provided');
    });
  });

  describe('Event extraction edge cases', () => {
    it('should return undefined for non-existent event', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);
      const extracted = parser.extractEvent(decoded, 'https://example.com/non-existent');

      expect(extracted).toBeUndefined();
    });

    it('should return false for hasEvent with non-existent event', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);
      const hasEvent = parser.hasEvent(decoded, 'https://example.com/non-existent');

      expect(hasEvent).toBe(false);
    });

    it('should return empty array for getEventTypes with no events', () => {
      // Manually create payload with empty events
      const payload = {
        iss: 'test',
        jti: '123',
        iat: Date.now() / 1000,
        events: {},
      };

      const eventTypes = parser.getEventTypes(
        payload as Parameters<typeof parser.getEventTypes>[0],
      );
      expect(eventTypes).toEqual([]);
    });
  });

  describe('Validation with array issuer/audience', () => {
    it('should validate with array of issuers', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        issuer: ['https://other.com', 'https://example.com'],
      });

      expect(result.valid).toBe(true);
    });

    it('should validate with array audience', async () => {
      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withAudience(['https://app1.com', 'https://app2.com'])
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        audience: ['https://app1.com', 'https://app3.com'],
      });

      expect(result.valid).toBe(true);
    });
  });
});
