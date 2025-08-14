# @sgnl/secevent

[![npm version](https://img.shields.io/npm/v/@sgnl/secevent.svg)](https://www.npmjs.com/package/@sgnl/secevent)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue.svg)](https://www.typescriptlang.org/)

A comprehensive JavaScript/TypeScript library for Security Event Tokens (SET) implementing [RFC 8417](https://datatracker.ietf.org/doc/html/rfc8417), Continuous Access Evaluation Protocol (CAEP), and Shared Signals Framework (SSF).

Built by [SGNL.ai](https://sgnl.ai) as part of our commitment to advancing continuous access evaluation and the shared signals framework.

## Features

- 🔐 **Full RFC 8417 Compliance**: Complete implementation of Security Event Tokens specification
- 🚀 **CAEP Events**: Support for all standard CAEP event types (session-revoked, token-claims-change, credential-change, etc.)
- 🔄 **SSF Events**: Stream management with verification and stream-updated events
- 📝 **TypeScript First**: Full type safety with comprehensive TypeScript definitions
- 🏗️ **Builder Pattern**: Intuitive API for constructing security events
- ✅ **Validation & Parsing**: Robust JWT verification and SET-specific validation
- 🔑 **Flexible Signing**: Support for symmetric and asymmetric keys with multiple algorithms
- 🎯 **Subject Identifiers**: All standard formats (email, phone, issuer-subject, URI, DID, etc.)
- ⚡ **Zero Dependencies**: Minimal footprint with only essential dependencies

## Installation

```bash
npm install @sgnl/secevent
```

or

```bash
yarn add @sgnl/secevent
```

## Quick Start

### Creating and Signing a Security Event Token

```typescript
import { 
  createBuilder, 
  SubjectIdentifiers, 
  Events, 
  SigningUtils,
  Algorithm 
} from '@sgnl/secevent';

// Create a signing key
const signingKey = SigningUtils.createSymmetricKey('your-secret-key', Algorithm.HS256);

// Build and sign a session revoked event
const secEvent = await createBuilder()
  .withIssuer('https://idp.example.com')
  .withAudience('https://app.example.com')
  .withEvent(
    Events.sessionRevoked(
      SubjectIdentifiers.email('user@example.com'),
      Math.floor(Date.now() / 1000),
      'suspicious_activity'
    )
  )
  .sign(signingKey);

console.log(secEvent.jwt);
```

### Parsing and Verifying a Security Event Token

```typescript
import { createParser, SigningUtils, Algorithm } from '@sgnl/secevent';

// Create a parser
const parser = createParser();

// Verification key (same as signing key for symmetric algorithms)
const verificationKey = SigningUtils.createSymmetricKey('your-secret-key', Algorithm.HS256);

// Verify and parse the token
const result = await parser.verify(secEvent.jwt, verificationKey, {
  issuer: 'https://idp.example.com',
  audience: 'https://app.example.com'
});

if (result.valid) {
  console.log('Token is valid!');
  console.log('Events:', result.payload.events);
} else {
  console.error('Validation failed:', result.error);
}
```

## Supported Event Types

### CAEP Events

- **Session Revoked**: Indicates a user session has been terminated
- **Token Claims Change**: Notifies about changes in token claims
- **Credential Change**: Signals credential updates (password, MFA, etc.)
- **Assurance Level Change**: Indicates changes in authentication assurance level
- **Device Compliance Change**: Reports device compliance status changes

### SSF Events

- **Stream Updated**: Configuration changes for event streams
- **Verification**: Stream connection verification

### RISC Events

- Account disabled/enabled
- Credential change required
- Recovery activated
- And more...

## Subject Identifiers

The library supports all standard subject identifier formats:

```typescript
import { SubjectIdentifiers } from '@sgnl/secevent';

// Email
const emailSubject = SubjectIdentifiers.email('user@example.com');

// Phone Number
const phoneSubject = SubjectIdentifiers.phoneNumber('+1234567890');

// Issuer + Subject
const issSubject = SubjectIdentifiers.issuerSubject(
  'https://idp.example.com',
  'user-123'
);

// Opaque Identifier
const opaqueSubject = SubjectIdentifiers.opaque('unique-id-123');

// Decentralized Identifier (DID)
const didSubject = SubjectIdentifiers.did('did:example:123456789');

// Aliases (multiple identifiers for same subject)
const aliasedSubject = SubjectIdentifiers.aliases(
  emailSubject,
  phoneSubject,
  issSubject
);
```

## Complex Subjects

For scenarios requiring multiple subject contexts:

```typescript
const complexSubject = {
  user: SubjectIdentifiers.email('user@example.com'),
  device: SubjectIdentifiers.uri('device://mobile-123'),
  session: SubjectIdentifiers.opaque('session-abc-def'),
  tenant: SubjectIdentifiers.issuerSubject('https://tenant.example.com', 'tenant-456')
};

const event = Events.sessionRevoked(complexSubject, Date.now() / 1000);
```

## Advanced Usage

### Custom ID Generation

```typescript
import { createBuilder, PrefixedGenerator, UuidGenerator } from '@sgnl/secevent';

const builder = createBuilder({
  idGenerator: new PrefixedGenerator('evt', new UuidGenerator())
});

// JTI will be like: evt-550e8400-e29b-41d4-a716-446655440000
```

### Using Asymmetric Keys

```typescript
import { SigningUtils, Algorithm } from '@sgnl/secevent';

// Generate a key pair
const { publicKey, privateKey } = await SigningUtils.generateKeyPair(Algorithm.RS256);

// Sign with private key
const signingKey = {
  key: privateKey,
  alg: Algorithm.RS256,
  kid: 'key-1'
};

const secEvent = await builder.sign(signingKey);

// Verify with public key
const verificationKey = {
  key: publicKey,
  alg: Algorithm.RS256,
  kid: 'key-1'
};

const result = await parser.verify(secEvent.jwt, verificationKey);
```

### JWKS URL Support

```typescript
import { createParser } from '@sgnl/secevent';

// Parser with JWKS URL for automatic key resolution
const parser = createParser({
  jwksUrl: 'https://idp.example.com/.well-known/jwks.json'
});

// No need to provide verification key
const result = await parser.verify(jwt);
```

### Multiple Events in One Token

```typescript
const secEvent = await createBuilder()
  .withIssuer('https://idp.example.com')
  .withEvents(
    Events.sessionRevoked(subject, timestamp),
    Events.credentialChange(subject, timestamp, {
      credential_type: 'password',
      change_type: 'update'
    })
  )
  .sign(signingKey);
```

## API Reference

### Builder

- `createBuilder(options?)`: Create a new SET builder
- `.withIssuer(issuer)`: Set the token issuer
- `.withAudience(audience)`: Set the token audience
- `.withEvent(event)`: Add a single event
- `.withEvents(...events)`: Add multiple events
- `.withJti(jti)`: Set custom token ID
- `.withTxn(txn)`: Set transaction ID
- `.withClaim(key, value)`: Add custom claim
- `.sign(key?)`: Sign and return the token

### Parser

- `createParser(options?)`: Create a new SET parser
- `.decode(jwt)`: Decode without verification
- `.verify(jwt, key?, options?)`: Verify and parse token
- `.extractEvents(payload)`: Extract all events
- `.extractEvent(payload, type)`: Extract specific event type
- `.hasEvent(payload, type)`: Check for event presence
- `.getEventTypes(payload)`: Get all event type URIs

## Testing

The library includes comprehensive test coverage:

```bash
# Run tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## Development

```bash
# Install dependencies
npm install

# Build the library
npm run build

# Run linting
npm run lint

# Type checking
npm run typecheck

# Format code
npm run format
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## Security

This library is designed for building secure systems. If you discover a security vulnerability, please email security@sgnl.ai.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- 🐛 Issues: [GitHub Issues](https://github.com/SGNL-ai/secevent-js/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/SGNL-ai/secevent-js/discussions)

## Acknowledgments

This library is inspired by and compatible with:
- [OpenID Shared Signals Framework](https://openid.net/specs/openid-sse-framework-1_0.html)
- [OpenID CAEP Specification](https://openid.net/specs/openid-caep-1_0.html)
- [RFC 8417 - Security Event Token](https://datatracker.ietf.org/doc/html/rfc8417)

Built with ❤️ by [SGNL.ai](https://sgnl.ai)