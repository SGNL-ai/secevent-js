# secevent-js Examples

Example scripts demonstrating the secevent-js library capabilities.

## Basic Usage (`basic-usage.js`)

Interactive examples for parsing and generating Security Event Tokens.

```bash
node examples/basic-usage.js
```

**Features:**
- Parse any JWT Security Event Token
- Generate custom SETs with user input  
- Interactive menu system
- Sample tokens included

## CAEP.dev Integration (`caep-dev.js`)

Complete integration with CAEP.dev's Shared Signals Framework (SSF) APIs for testing Security Event Token interoperability.

```bash
# Run directly - will prompt for token if not in environment
node examples/caep-dev.js

# Or set token in environment
export CAEP_DEV_TOKEN="your-token-here"
node examples/caep-dev.js
```

**Features:**
- Automatic stream creation and configuration
- Event polling with full JWT parsing
- Library method demonstrations
- Clear output formatting

### Getting a CAEP.dev Token

1. Visit https://caep.dev
2. Sign in or create an account
3. Open browser developer tools (Network tab)
4. Perform any action on the site
5. Look for API requests to `ssf.caep.dev`
6. Copy the Bearer token from the Authorization header

### API Integration Points

**Stream Management:**
- POST /ssf/streams - Create a new stream
- GET /ssf/streams - Get stream configuration
- PATCH /ssf/streams - Update stream configuration
- DELETE /ssf/streams/{id} - Delete a stream

**Event Polling:**
- POST /ssf/streams/poll - Poll for events
  - Returns events as JWTs in a `sets` object
  - Keys are JTIs, values are JWT strings

### Example Output

```
Checking for existing streams...
Found existing stream: e9ff2fba-27c4-4340-afd1-d3834730af44
Stream is already configured for polling.

Polling for events...
Received 3 events!

============================================================
Security Event Token #1
============================================================

Parsed with secevent-js library:
  • Event Types: https://schemas.openid.net/secevent/caep/event-type/session-revoked
  • Has Session Revoked: true
  • JTI: NjI3MGI2NTEtNmE0ZC00OGFjLWE1MGQtOTE2ZTVlNDZkZWQ0
  • Issuer: https://ssf.caep.dev/
  • Audience: https://caepable.web.app
  • Issued At: 2025-01-15T01:58:40.000Z

Event Details (extracted via library):
  • Event Timestamp: 2025-01-15T01:58:40.000Z
  • Subject Format: email
  • Subject Email: user@example.com

Full JWT Payload (JSON):
{
  "aud": "https://caepable.web.app",
  "events": {
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked": {
      "event_timestamp": 1755223120,
      "subject": {
        "email": "user@example.com",
        "format": "email"
      }
    }
  },
  "iat": 1755223120,
  "iss": "https://ssf.caep.dev/",
  "jti": "NjI3MGI2NTEtNmE0ZC00OGFjLWE1MGQtOTE2ZTVlNDZkZWQ0"
}
```

### Troubleshooting

**"The CAEP transmitter currently doesn't support long polling"**  
CAEP.dev doesn't support long polling. The client uses `returnImmediately: true` to poll for available events.

**"This configured stream only supports the push delivery method"**  
The stream is configured for push delivery. The client will automatically update it to polling mode.

**"CAEP stream already exists"**  
You can only have one stream per account. The client will use the existing stream.

## Development Tips

### Import the Library

```javascript
const { 
  createParser, 
  createBuilder, 
  Events, 
  SubjectIdentifiers,
  CAEP_EVENT_TYPES 
} = require('@sgnl/secevent');
```

### Parse a Token

```javascript
const parser = createParser();
const decoded = parser.decode(jwt);
const eventTypes = parser.getEventTypes(decoded);
```

### Build a Token

```javascript
const builder = createBuilder();
const subject = SubjectIdentifiers.email('user@example.com');
const event = Events.sessionRevoked(subject, Date.now() / 1000);

const payload = builder
  .withIssuer('https://issuer.example.com')
  .withAudience('https://app.example.com')
  .withEvent(event)
  .buildPayload();
```

## Related Documentation

- [CAEP.dev](https://caep.dev) - Interactive CAEP testing platform
- [RFC 8417](https://datatracker.ietf.org/doc/html/rfc8417) - Security Event Token (SET)
- [OpenID Shared Signals Framework](https://openid.net/specs/openid-sse-framework-1_0.html)