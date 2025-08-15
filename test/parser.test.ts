/**
 * Tests for SecEventParser
 */

import { SecEventParser, createParser } from '../src/parser/parser';
import { SecEventBuilder } from '../src/builder/builder';
import { SubjectIdentifiers } from '../src/types/subject';
import { Events } from '../src/types/events';
import { SigningUtils, Algorithm } from '../src/signing/signer';

describe('SecEventParser', () => {
  let parser: SecEventParser;
  let builder: SecEventBuilder;
  const signingKey = SigningUtils.createSymmetricKey('test-secret', Algorithm.HS256, 'test-key');

  beforeEach(() => {
    parser = createParser();
    builder = new SecEventBuilder();
  });

  describe('Decode', () => {
    it('should decode a valid SET without verification', async () => {
      const subject = SubjectIdentifiers.email('user@example.com');
      const event = Events.sessionRevoked(subject, Date.now() / 1000, 'test-reason');

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);

      expect(decoded.iss).toBe('https://example.com');
      expect(decoded.aud).toBe('https://app.example.com');
      expect(decoded.events).toBeDefined();
      expect(decoded.jti).toBeDefined();
      expect(decoded.iat).toBeDefined();
    });

    it('should throw error for invalid JWT format', () => {
      expect(() => parser.decode('invalid-jwt')).toThrow();
    });

    it('should throw error for JWT without events claim', () => {
      // Create a JWT without events claim using jose directly
      const jwt =
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0IiwianRpIjoiMTIzIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalid';

      expect(() => parser.decode(jwt)).toThrow();
    });
  });

  describe('Verify', () => {
    it('should verify a valid SET with correct key', async () => {
      const subject = SubjectIdentifiers.issuerSubject('https://example.com', 'user123');
      const event = Events.tokenClaimsChange(subject, Date.now() / 1000, {
        role: 'admin',
      });

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
      expect(result.payload?.iss).toBe('https://example.com');
      expect(result.error).toBeUndefined();
    });

    it('should fail verification with wrong key', async () => {
      const event = Events.verification('test-state');

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const wrongKey = SigningUtils.createSymmetricKey('wrong-secret', Algorithm.HS256);
      const result = await parser.verify(signedEvent.jwt, wrongKey);

      expect(result.valid).toBe(false);
      expect(result.error).toBeDefined();
    });

    it('should validate issuer if specified', async () => {
      const event = Events.streamUpdated();

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        issuer: 'https://different.com',
      });

      expect(result.valid).toBe(false);
      expect(result.error?.toLowerCase()).toContain('iss');
    });

    it('should validate audience if specified', async () => {
      const event = Events.verification();

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withAudience('https://app.example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        audience: 'https://different.com',
      });

      expect(result.valid).toBe(false);
      expect(result.error?.toLowerCase()).toContain('aud');
    });

    it('should validate required claims', async () => {
      const event = Events.verification();

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await parser.verify(signedEvent.jwt, signingKey, {
        requiredClaims: ['txn'], // txn not present
      });

      expect(result.valid).toBe(false);
      expect(result.errors).toContain('Missing required claim: txn');
    });

    it('should handle multiple verification keys', async () => {
      const event = Events.verification();
      const correctKey = SigningUtils.createSymmetricKey('correct', Algorithm.HS256);
      const wrongKey1 = SigningUtils.createSymmetricKey('wrong1', Algorithm.HS256);
      const wrongKey2 = SigningUtils.createSymmetricKey('wrong2', Algorithm.HS256);

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(correctKey);

      const result = await parser.verify(signedEvent.jwt, [wrongKey1, correctKey, wrongKey2]);

      expect(result.valid).toBe(true);
    });
  });

  describe('Event extraction', () => {
    it('should extract events from payload', async () => {
      const subject = SubjectIdentifiers.opaque('user-id-123');
      const event1 = Events.sessionRevoked(subject, Date.now() / 1000);
      const event2 = Events.credentialChange(subject, Date.now() / 1000, {
        credential_type: 'password',
        change_type: 'update',
      });

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvents(event1, event2)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);
      const events = parser.extractEvents(decoded);

      expect(Object.keys(events)).toHaveLength(2);
    });

    it('should extract specific event type', async () => {
      const subject = SubjectIdentifiers.phoneNumber('+1234567890');
      const timestamp = Date.now() / 1000;
      const event = Events.assuranceLevelChange(subject, timestamp, {
        current_level: 'high',
        previous_level: 'low',
        change_direction: 'increase',
      });

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);
      const extractedEvent = parser.extractEvent(
        decoded,
        'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
      );

      expect(extractedEvent).toBeDefined();
      expect((extractedEvent as Record<string, unknown>).current_level).toBe('high');
    });

    it('should check for event presence', async () => {
      const event = Events.deviceComplianceChange(
        SubjectIdentifiers.uri('device://12345'),
        Date.now() / 1000,
        {
          current_status: 'compliant',
          previous_status: 'not_compliant',
        },
      );

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvent(event)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);

      expect(
        parser.hasEvent(
          decoded,
          'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
        ),
      ).toBe(true);
      expect(
        parser.hasEvent(decoded, 'https://schemas.openid.net/secevent/caep/event-type/other'),
      ).toBe(false);
    });

    it('should get all event types', async () => {
      const subject = SubjectIdentifiers.aliases(
        SubjectIdentifiers.email('user@example.com'),
        SubjectIdentifiers.phoneNumber('+1234567890'),
      );

      const event1 = Events.sessionRevoked(subject, Date.now() / 1000);
      const event2 = Events.verification('state');

      const signedEvent = await builder
        .withIssuer('https://example.com')
        .withEvents(event1, event2)
        .sign(signingKey);

      const decoded = parser.decode(signedEvent.jwt);
      const eventTypes = parser.getEventTypes(decoded);

      expect(eventTypes).toHaveLength(2);
      expect(eventTypes).toContain(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      );
      expect(eventTypes).toContain(
        'https://schemas.openid.net/secevent/ssf/event-type/verification',
      );
    });
  });

  describe('Parser configuration', () => {
    it('should use default validation options', async () => {
      const configuredParser = createParser({
        defaultValidationOptions: {
          issuer: 'https://expected.com',
          audience: 'https://expected-aud.com',
        },
      });

      const event = Events.verification();
      const signedEvent = await builder
        .withIssuer('https://expected.com')
        .withAudience('https://expected-aud.com')
        .withEvent(event)
        .sign(signingKey);

      const result = await configuredParser.verify(signedEvent.jwt, signingKey);

      expect(result.valid).toBe(true);
    });

    it('should use configured verification keys', async () => {
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
  });
});
