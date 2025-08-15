/**
 * Subject Identifier Types
 * Implements various subject identifier formats as defined in RFC 8417 and related specs
 */

export interface SubjectIdentifier {
  format: string;
  [key: string]: unknown;
}

/**
 * Account Identifier
 * Identifies a subject using an account at a service provider
 */
export interface AccountIdentifier extends SubjectIdentifier {
  format: 'account';
  uri: string;
}

/**
 * Email Identifier
 * Identifies a subject using an email address
 */
export interface EmailIdentifier extends SubjectIdentifier {
  format: 'email';
  email: string;
}

/**
 * Issuer and Subject Identifier
 * Identifies a subject using an issuer and subject pair
 */
export interface IssuerSubjectIdentifier extends SubjectIdentifier {
  format: 'iss_sub';
  iss: string;
  sub: string;
}

/**
 * Opaque Identifier
 * Identifies a subject using an opaque identifier
 */
export interface OpaqueIdentifier extends SubjectIdentifier {
  format: 'opaque';
  id: string;
}

/**
 * Phone Number Identifier
 * Identifies a subject using a phone number
 */
export interface PhoneNumberIdentifier extends SubjectIdentifier {
  format: 'phone_number';
  phone_number: string;
}

/**
 * Decentralized Identifier (DID)
 * Identifies a subject using a W3C Decentralized Identifier
 */
export interface DidIdentifier extends SubjectIdentifier {
  format: 'did';
  url: string;
}

/**
 * URI Identifier
 * Identifies a subject using a URI
 */
export interface UriIdentifier extends SubjectIdentifier {
  format: 'uri';
  uri: string;
}

/**
 * Aliases Identifier
 * Groups multiple identifiers for the same subject
 */
export interface AliasesIdentifier extends SubjectIdentifier {
  format: 'aliases';
  identifiers: SubjectIdentifier[];
}

/**
 * Complex Subject with multiple identifier types
 */
export interface ComplexSubject {
  user?: SubjectIdentifier;
  device?: SubjectIdentifier;
  session?: SubjectIdentifier;
  application?: SubjectIdentifier;
  tenant?: SubjectIdentifier;
  org?: SubjectIdentifier;
  [key: string]: SubjectIdentifier | undefined;
}

/**
 * Type guard functions
 */
export function isAccountIdentifier(subject: SubjectIdentifier): subject is AccountIdentifier {
  return subject.format === 'account';
}

export function isEmailIdentifier(subject: SubjectIdentifier): subject is EmailIdentifier {
  return subject.format === 'email';
}

export function isIssuerSubjectIdentifier(
  subject: SubjectIdentifier,
): subject is IssuerSubjectIdentifier {
  return subject.format === 'iss_sub';
}

export function isOpaqueIdentifier(subject: SubjectIdentifier): subject is OpaqueIdentifier {
  return subject.format === 'opaque';
}

export function isPhoneNumberIdentifier(
  subject: SubjectIdentifier,
): subject is PhoneNumberIdentifier {
  return subject.format === 'phone_number';
}

export function isDidIdentifier(subject: SubjectIdentifier): subject is DidIdentifier {
  return subject.format === 'did';
}

export function isUriIdentifier(subject: SubjectIdentifier): subject is UriIdentifier {
  return subject.format === 'uri';
}

export function isAliasesIdentifier(subject: SubjectIdentifier): subject is AliasesIdentifier {
  return subject.format === 'aliases';
}

/**
 * Factory functions for creating subject identifiers
 */
export class SubjectIdentifiers {
  static account(uri: string): AccountIdentifier {
    return { format: 'account', uri };
  }

  static email(email: string): EmailIdentifier {
    return { format: 'email', email };
  }

  static issuerSubject(iss: string, sub: string): IssuerSubjectIdentifier {
    return { format: 'iss_sub', iss, sub };
  }

  static opaque(id: string): OpaqueIdentifier {
    return { format: 'opaque', id };
  }

  static phoneNumber(phone_number: string): PhoneNumberIdentifier {
    return { format: 'phone_number', phone_number };
  }

  static did(url: string): DidIdentifier {
    return { format: 'did', url };
  }

  static uri(uri: string): UriIdentifier {
    return { format: 'uri', uri };
  }

  static aliases(...identifiers: SubjectIdentifier[]): AliasesIdentifier {
    return { format: 'aliases', identifiers };
  }
}
