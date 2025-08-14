/**
 * Tests for Subject Identifiers
 */

import {
  SubjectIdentifiers,
  isAccountIdentifier,
  isEmailIdentifier,
  isIssuerSubjectIdentifier,
  isOpaqueIdentifier,
  isPhoneNumberIdentifier,
  isDidIdentifier,
  isUriIdentifier,
  isAliasesIdentifier,
} from '../src/types/subject';

describe('SubjectIdentifiers', () => {
  describe('Factory methods', () => {
    it('should create account identifier', () => {
      const subject = SubjectIdentifiers.account('acct:user@example.com');
      expect(subject.format).toBe('account');
      expect(subject.uri).toBe('acct:user@example.com');
    });

    it('should create email identifier', () => {
      const subject = SubjectIdentifiers.email('user@example.com');
      expect(subject.format).toBe('email');
      expect(subject.email).toBe('user@example.com');
    });

    it('should create issuer-subject identifier', () => {
      const subject = SubjectIdentifiers.issuerSubject('https://idp.example.com', 'user-123');
      expect(subject.format).toBe('iss_sub');
      expect(subject.iss).toBe('https://idp.example.com');
      expect(subject.sub).toBe('user-123');
    });

    it('should create opaque identifier', () => {
      const subject = SubjectIdentifiers.opaque('random-id-12345');
      expect(subject.format).toBe('opaque');
      expect(subject.id).toBe('random-id-12345');
    });

    it('should create phone number identifier', () => {
      const subject = SubjectIdentifiers.phoneNumber('+1234567890');
      expect(subject.format).toBe('phone_number');
      expect(subject.phone_number).toBe('+1234567890');
    });

    it('should create DID identifier', () => {
      const subject = SubjectIdentifiers.did('did:example:123456789abcdefghi');
      expect(subject.format).toBe('did');
      expect(subject.url).toBe('did:example:123456789abcdefghi');
    });

    it('should create URI identifier', () => {
      const subject = SubjectIdentifiers.uri('https://example.com/users/123');
      expect(subject.format).toBe('uri');
      expect(subject.uri).toBe('https://example.com/users/123');
    });

    it('should create aliases identifier', () => {
      const email = SubjectIdentifiers.email('user@example.com');
      const phone = SubjectIdentifiers.phoneNumber('+1234567890');
      const opaque = SubjectIdentifiers.opaque('user-id-123');

      const aliases = SubjectIdentifiers.aliases(email, phone, opaque);
      expect(aliases.format).toBe('aliases');
      expect(aliases.identifiers).toHaveLength(3);
      expect(aliases.identifiers[0]).toEqual(email);
      expect(aliases.identifiers[1]).toEqual(phone);
      expect(aliases.identifiers[2]).toEqual(opaque);
    });
  });

  describe('Type guards', () => {
    it('should identify account identifier', () => {
      const account = SubjectIdentifiers.account('acct:user@example.com');
      const email = SubjectIdentifiers.email('user@example.com');

      expect(isAccountIdentifier(account)).toBe(true);
      expect(isAccountIdentifier(email)).toBe(false);
    });

    it('should identify email identifier', () => {
      const email = SubjectIdentifiers.email('user@example.com');
      const phone = SubjectIdentifiers.phoneNumber('+1234567890');

      expect(isEmailIdentifier(email)).toBe(true);
      expect(isEmailIdentifier(phone)).toBe(false);
    });

    it('should identify issuer-subject identifier', () => {
      const issSub = SubjectIdentifiers.issuerSubject('https://idp.example.com', 'user-123');
      const opaque = SubjectIdentifiers.opaque('user-123');

      expect(isIssuerSubjectIdentifier(issSub)).toBe(true);
      expect(isIssuerSubjectIdentifier(opaque)).toBe(false);
    });

    it('should identify opaque identifier', () => {
      const opaque = SubjectIdentifiers.opaque('random-id');
      const uri = SubjectIdentifiers.uri('https://example.com/user');

      expect(isOpaqueIdentifier(opaque)).toBe(true);
      expect(isOpaqueIdentifier(uri)).toBe(false);
    });

    it('should identify phone number identifier', () => {
      const phone = SubjectIdentifiers.phoneNumber('+1234567890');
      const email = SubjectIdentifiers.email('user@example.com');

      expect(isPhoneNumberIdentifier(phone)).toBe(true);
      expect(isPhoneNumberIdentifier(email)).toBe(false);
    });

    it('should identify DID identifier', () => {
      const did = SubjectIdentifiers.did('did:example:123');
      const uri = SubjectIdentifiers.uri('https://example.com');

      expect(isDidIdentifier(did)).toBe(true);
      expect(isDidIdentifier(uri)).toBe(false);
    });

    it('should identify URI identifier', () => {
      const uri = SubjectIdentifiers.uri('https://example.com/user');
      const did = SubjectIdentifiers.did('did:example:123');

      expect(isUriIdentifier(uri)).toBe(true);
      expect(isUriIdentifier(did)).toBe(false);
    });

    it('should identify aliases identifier', () => {
      const aliases = SubjectIdentifiers.aliases(
        SubjectIdentifiers.email('user@example.com'),
        SubjectIdentifiers.phoneNumber('+1234567890'),
      );
      const email = SubjectIdentifiers.email('user@example.com');

      expect(isAliasesIdentifier(aliases)).toBe(true);
      expect(isAliasesIdentifier(email)).toBe(false);
    });
  });

  describe('Complex subjects', () => {
    it('should support complex subject structure', () => {
      const complexSubject = {
        user: SubjectIdentifiers.email('user@example.com'),
        device: SubjectIdentifiers.uri('device://mobile-123'),
        session: SubjectIdentifiers.opaque('session-abc'),
        application: SubjectIdentifiers.uri('app://my-app'),
        tenant: SubjectIdentifiers.issuerSubject('https://tenant.example.com', 'tenant-456'),
      };

      expect(complexSubject.user.format).toBe('email');
      expect(complexSubject.device.format).toBe('uri');
      expect(complexSubject.session.format).toBe('opaque');
      expect(complexSubject.application.format).toBe('uri');
      expect(complexSubject.tenant.format).toBe('iss_sub');
    });

    it('should allow partial complex subjects', () => {
      const partialSubject = {
        user: SubjectIdentifiers.email('user@example.com'),
        session: SubjectIdentifiers.opaque('session-123'),
      };

      expect(partialSubject.user).toBeDefined();
      expect(partialSubject.session).toBeDefined();
      expect(partialSubject.device).toBeUndefined();
    });

    it('should support custom properties in complex subjects', () => {
      const customSubject = {
        user: SubjectIdentifiers.email('user@example.com'),
        customField: SubjectIdentifiers.uri('custom://resource'),
      };

      expect(customSubject.customField).toBeDefined();
      expect(customSubject.customField.format).toBe('uri');
    });
  });

  describe('Edge cases', () => {
    it('should handle empty aliases', () => {
      const aliases = SubjectIdentifiers.aliases();
      expect(aliases.format).toBe('aliases');
      expect(aliases.identifiers).toHaveLength(0);
    });

    it('should handle single alias', () => {
      const single = SubjectIdentifiers.email('user@example.com');
      const aliases = SubjectIdentifiers.aliases(single);
      expect(aliases.identifiers).toHaveLength(1);
      expect(aliases.identifiers[0]).toEqual(single);
    });

    it('should handle international phone numbers', () => {
      const intlPhone = SubjectIdentifiers.phoneNumber('+44 20 7123 4567');
      expect(intlPhone.phone_number).toBe('+44 20 7123 4567');
    });

    it('should handle various URI schemes', () => {
      const httpUri = SubjectIdentifiers.uri('http://example.com/user');
      const httpsUri = SubjectIdentifiers.uri('https://example.com/user');
      const customUri = SubjectIdentifiers.uri('custom://app/user/123');

      expect(httpUri.uri).toBe('http://example.com/user');
      expect(httpsUri.uri).toBe('https://example.com/user');
      expect(customUri.uri).toBe('custom://app/user/123');
    });

    it('should handle various DID methods', () => {
      const didKey = SubjectIdentifiers.did('did:key:z6MkpTHR8N8TLt9K3r4u7K7hdfKGqQ4HvLWSdja5VrCkdCNy');
      const didWeb = SubjectIdentifiers.did('did:web:example.com:user:alice');
      const didEthr = SubjectIdentifiers.did('did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8e');

      expect(didKey.url).toContain('did:key:');
      expect(didWeb.url).toContain('did:web:');
      expect(didEthr.url).toContain('did:ethr:');
    });
  });
});