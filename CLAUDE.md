# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is @sgnl/secevent - a comprehensive JavaScript/TypeScript library for Security Event Tokens (SET) implementing RFC 8417, CAEP (Continuous Access Evaluation Protocol), and SSF (Shared Signals Framework). Built by SGNL.ai as a port of the Go secevent library.

## Development Commands

### Setup
```bash
npm install
```

### Testing
```bash
npm test                 # Run all tests with Jest
npm run test:watch       # Run tests in watch mode
npm run test:coverage    # Run tests with coverage report (target: 80%+)
```

### Code Quality
```bash
npm run lint            # Run ESLint
npm run lint:fix        # Auto-fix linting issues
npm run typecheck       # Run TypeScript type checking
npm run format          # Format code with Prettier
npm run format:check    # Check code formatting
```

### Build
```bash
npm run build           # Build the library with tsup
npm run build:watch     # Build in watch mode
npm run dev             # Same as build:watch
```

### Documentation
```bash
npm run docs            # Generate TypeDoc documentation
```

## Project Structure

- `src/` - TypeScript source code
  - `types/` - Core type definitions (subject, events, secevent)
  - `builder/` - SecEventBuilder for constructing SETs
  - `parser/` - SecEventParser for parsing and validating SETs
  - `signing/` - Key management and signing utilities
  - `id/` - ID generation strategies (UUID, timestamp, etc.)
  - `index.ts` - Main exports
- `test/` - Jest test files (80%+ coverage requirement)
- `dist/` - Built output (generated, gitignored)

## Key Implementation Guidelines

1. **Standards Compliance**: Strictly follow RFC 8417, CAEP, and SSF specifications
2. **Testing**: Use Jest with 80% minimum coverage. Test files should comprehensively test all functionality
3. **Type Safety**: Full TypeScript with strict mode - never use `any` type
4. **Error Handling**: Provide clear, actionable error messages for all validation failures
5. **Builder Pattern**: Use fluent API for constructing security events
6. **Signing**: Support both symmetric (HS256) and asymmetric (RS256, ES256) algorithms via jose library

## Important Conventions

- All event URIs must match the OpenID specifications exactly
- Use the `Events` helper class for creating standard events
- Use the `SubjectIdentifiers` helper class for creating subject identifiers
- JWT typ header should be "secevent+jwt"
- Always validate event URIs are proper URLs (https:// or http://)
- Support complex subjects with multiple identifier types
- Use async/await for all asynchronous operations
- Follow existing patterns when adding new event types or subject formats