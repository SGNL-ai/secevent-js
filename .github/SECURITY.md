# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible for receiving such patches depends on the CVSS v3.0 Rating:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | ✅ Active support  |
| < 1.0   | ❌ Not supported   |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

If you've found a security vulnerability in @sgnl/secevent, please report it to us through coordinated disclosure.

Please send an email to security@sgnl.ai with:

- Type of issue (e.g., buffer overflow, SQL injection, cross-site scripting, etc.)
- Full paths of source file(s) related to the manifestation of the issue
- The location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

We'll acknowledge your email within 48 hours and provide a detailed response within 96 hours indicating the next steps in handling your submission.

## Preferred Languages

We prefer all communications to be in English.

## Disclosure Policy

When we receive a security report, we will:

1. Confirm the problem and determine the affected versions
2. Audit code to find any similar problems
3. Prepare fixes for all supported versions
4. Release new security fix versions

## Comments on this Policy

If you have suggestions on how this process could be improved, please submit a pull request or open an issue to discuss.

## Security Best Practices for Users

When using @sgnl/secevent in your applications:

1. **Keep the library updated**: Always use the latest version to get security patches
2. **Validate inputs**: Always validate and sanitize inputs before processing
3. **Use strong keys**: Use cryptographically strong keys for signing tokens
4. **Rotate keys regularly**: Implement key rotation policies
5. **Verify signatures**: Always verify token signatures before trusting the content
6. **Handle errors securely**: Don't expose sensitive information in error messages
7. **Use HTTPS**: Always transmit security tokens over encrypted connections
8. **Implement rate limiting**: Protect your endpoints from abuse

## Known Security Considerations

### JWT Security
- This library uses the `jose` library for JWT operations
- Always verify the issuer and audience claims
- Be aware of algorithm confusion attacks - always specify allowed algorithms

### Key Management
- Never commit keys to version control
- Use environment variables or secure key management systems
- Rotate keys regularly

### Event Validation
- Always validate event types against a whitelist
- Verify event timestamps are within acceptable ranges
- Validate subject identifiers format

## Security Acknowledgments

We'd like to thank the following security researchers for responsibly disclosing vulnerabilities:

<!-- Add contributors here as vulnerabilities are reported and fixed -->

---

*This security policy is adapted from the [Node.js Security Policy](https://github.com/nodejs/node/blob/main/SECURITY.md)*