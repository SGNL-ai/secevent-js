/**
 * Tests for Event Types and Helpers
 */

import { Events, EVENT_TYPES, CAEP_EVENT_TYPES, SSF_EVENT_TYPES } from '../src/types/events';
import { SubjectIdentifiers } from '../src/types/subject';

describe('Events', () => {
  const timestamp = Math.floor(Date.now() / 1000);
  const subject = SubjectIdentifiers.email('user@example.com');

  describe('CAEP Events', () => {
    it('should create session revoked event', () => {
      const event = Events.sessionRevoked(subject, timestamp, 'security_policy');

      expect(CAEP_EVENT_TYPES.SESSION_REVOKED in event).toBe(true);
      const data = event[CAEP_EVENT_TYPES.SESSION_REVOKED] as any;
      expect(data.subject).toEqual(subject);
      expect(data.event_timestamp).toBe(timestamp);
      expect(data.reason).toBe('security_policy');
    });

    it('should create token claims change event', () => {
      const claims = { role: 'admin', department: 'engineering' };
      const event = Events.tokenClaimsChange(subject, timestamp, claims);

      expect(CAEP_EVENT_TYPES.TOKEN_CLAIMS_CHANGE in event).toBe(true);
      const data = event[CAEP_EVENT_TYPES.TOKEN_CLAIMS_CHANGE] as any;
      expect(data.subject).toEqual(subject);
      expect(data.event_timestamp).toBe(timestamp);
      expect(data.claims).toEqual(claims);
    });

    it('should create credential change event', () => {
      const event = Events.credentialChange(subject, timestamp, {
        credential_type: 'password',
        change_type: 'update',
        reason: 'periodic_rotation',
      });

      expect(CAEP_EVENT_TYPES.CREDENTIAL_CHANGE in event).toBe(true);
      const data = event[CAEP_EVENT_TYPES.CREDENTIAL_CHANGE] as any;
      expect(data.subject).toEqual(subject);
      expect(data.event_timestamp).toBe(timestamp);
      expect(data.credential_type).toBe('password');
      expect(data.change_type).toBe('update');
      expect(data.reason).toBe('periodic_rotation');
    });

    it('should create assurance level change event', () => {
      const event = Events.assuranceLevelChange(subject, timestamp, {
        current_level: 'high',
        previous_level: 'medium',
        change_direction: 'increase',
        initiating_entity: 'policy',
      });

      expect(CAEP_EVENT_TYPES.ASSURANCE_LEVEL_CHANGE in event).toBe(true);
      const data = event[CAEP_EVENT_TYPES.ASSURANCE_LEVEL_CHANGE] as any;
      expect(data.current_level).toBe('high');
      expect(data.previous_level).toBe('medium');
      expect(data.change_direction).toBe('increase');
      expect(data.initiating_entity).toBe('policy');
    });

    it('should create device compliance change event', () => {
      const deviceSubject = SubjectIdentifiers.uri('device://abc123');
      const event = Events.deviceComplianceChange(deviceSubject, timestamp, {
        current_status: 'compliant',
        previous_status: 'not_compliant',
        compliance_policies: ['encryption', 'antivirus', 'os_version'],
      });

      expect(CAEP_EVENT_TYPES.DEVICE_COMPLIANCE_CHANGE in event).toBe(true);
      const data = event[CAEP_EVENT_TYPES.DEVICE_COMPLIANCE_CHANGE] as any;
      expect(data.current_status).toBe('compliant');
      expect(data.previous_status).toBe('not_compliant');
      expect(data.compliance_policies).toEqual(['encryption', 'antivirus', 'os_version']);
    });
  });

  describe('SSF Events', () => {
    it('should create stream updated event', () => {
      const effectiveTime = timestamp + 3600;
      const event = Events.streamUpdated(effectiveTime);

      expect(SSF_EVENT_TYPES.STREAM_UPDATED in event).toBe(true);
      const data = event[SSF_EVENT_TYPES.STREAM_UPDATED] as any;
      expect(data.effective_time).toBe(effectiveTime);
    });

    it('should create stream updated event without effective time', () => {
      const event = Events.streamUpdated();

      expect(SSF_EVENT_TYPES.STREAM_UPDATED in event).toBe(true);
      const data = event[SSF_EVENT_TYPES.STREAM_UPDATED] as any;
      expect(data.effective_time).toBeUndefined();
    });

    it('should create verification event', () => {
      const state = 'random-state-value-12345';
      const event = Events.verification(state);

      expect(SSF_EVENT_TYPES.VERIFICATION in event).toBe(true);
      const data = event[SSF_EVENT_TYPES.VERIFICATION] as any;
      expect(data.state).toBe(state);
    });

    it('should create verification event without state', () => {
      const event = Events.verification();

      expect(SSF_EVENT_TYPES.VERIFICATION in event).toBe(true);
      const data = event[SSF_EVENT_TYPES.VERIFICATION] as any;
      expect(data.state).toBeUndefined();
    });
  });

  describe('Complex Subjects', () => {
    it('should support complex subject with multiple identifiers', () => {
      const complexSubject = {
        user: SubjectIdentifiers.email('user@example.com'),
        device: SubjectIdentifiers.uri('device://mobile-123'),
        session: SubjectIdentifiers.opaque('session-abc-def'),
      };

      const event = Events.sessionRevoked(complexSubject, timestamp, 'device_compromised');

      expect(event).toHaveProperty(CAEP_EVENT_TYPES.SESSION_REVOKED);
      const data = event[CAEP_EVENT_TYPES.SESSION_REVOKED] as any;
      expect(data.subject).toEqual(complexSubject);
      expect(data.subject.user.format).toBe('email');
      expect(data.subject.device.format).toBe('uri');
      expect(data.subject.session.format).toBe('opaque');
    });

    it('should support aliases identifier', () => {
      const aliases = SubjectIdentifiers.aliases(
        SubjectIdentifiers.email('user@example.com'),
        SubjectIdentifiers.phoneNumber('+1234567890'),
        SubjectIdentifiers.issuerSubject('https://idp.example.com', 'user-123'),
      );

      const event = Events.credentialChange(aliases, timestamp, {
        credential_type: 'fido2',
        change_type: 'create',
        fido2_aaguid: 'aaguid-value',
        friendly_name: 'YubiKey 5',
      });

      const data = event[CAEP_EVENT_TYPES.CREDENTIAL_CHANGE] as any;
      expect(data.subject.format).toBe('aliases');
      expect(data.subject.identifiers).toHaveLength(3);
    });
  });

  describe('Event Constants', () => {
    it('should have correct CAEP event URIs', () => {
      expect(CAEP_EVENT_TYPES.SESSION_REVOKED).toBe(
        'https://schemas.openid.net/secevent/caep/event-type/session-revoked',
      );
      expect(CAEP_EVENT_TYPES.TOKEN_CLAIMS_CHANGE).toBe(
        'https://schemas.openid.net/secevent/caep/event-type/token-claims-change',
      );
      expect(CAEP_EVENT_TYPES.CREDENTIAL_CHANGE).toBe(
        'https://schemas.openid.net/secevent/caep/event-type/credential-change',
      );
      expect(CAEP_EVENT_TYPES.ASSURANCE_LEVEL_CHANGE).toBe(
        'https://schemas.openid.net/secevent/caep/event-type/assurance-level-change',
      );
      expect(CAEP_EVENT_TYPES.DEVICE_COMPLIANCE_CHANGE).toBe(
        'https://schemas.openid.net/secevent/caep/event-type/device-compliance-change',
      );
    });

    it('should have correct SSF event URIs', () => {
      expect(SSF_EVENT_TYPES.STREAM_UPDATED).toBe(
        'https://schemas.openid.net/secevent/ssf/event-type/stream-updated',
      );
      expect(SSF_EVENT_TYPES.VERIFICATION).toBe(
        'https://schemas.openid.net/secevent/ssf/event-type/verification',
      );
    });

    it('should have all events in EVENT_TYPES', () => {
      expect(EVENT_TYPES).toMatchObject(CAEP_EVENT_TYPES);
      expect(EVENT_TYPES).toMatchObject(SSF_EVENT_TYPES);
    });
  });
});