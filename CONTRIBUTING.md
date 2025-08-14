# Contributing to @sgnl/secevent

Thank you for your interest in contributing to the Security Event Token library! We welcome contributions from the community and are grateful for your support in advancing security event standards.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Accept responsibility and apologize for mistakes
- Focus on what is best for the community

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR-USERNAME/secevent-js.git
   cd secevent-js
   ```
3. **Install dependencies**:
   ```bash
   npm install
   ```
4. **Create a branch** for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

### Code Quality

Before submitting a PR, ensure your code passes all quality checks:

```bash
# Type checking
npm run typecheck

# Linting
npm run lint

# Format code
npm run format

# Run all checks
npm run lint && npm run typecheck && npm test
```

### Building

```bash
# Build the library
npm run build

# Build in watch mode
npm run build:watch
```

## Contribution Guidelines

### Issues

- **Search existing issues** before creating a new one
- **Use issue templates** when available
- **Provide clear descriptions** with steps to reproduce for bugs
- **Include relevant information**: Node version, OS, error messages

### Pull Requests

1. **Keep PRs focused**: One feature or fix per PR
2. **Write meaningful commit messages**: Follow conventional commits
   - `feat:` New feature
   - `fix:` Bug fix
   - `docs:` Documentation changes
   - `test:` Test additions or changes
   - `refactor:` Code refactoring
   - `chore:` Maintenance tasks

3. **Update documentation** for new features
4. **Add tests** for new functionality (maintain 80%+ coverage)
5. **Update the README** if needed
6. **Ensure CI passes** before requesting review

### Code Style

- Follow the existing code style (enforced by ESLint and Prettier)
- Use TypeScript's strict mode features
- Write self-documenting code with clear variable names
- Add JSDoc comments for public APIs
- Avoid using `any` type - use proper typing

### Testing Requirements

- All new features must have tests
- Maintain minimum 80% code coverage
- Write both unit and integration tests where appropriate
- Test edge cases and error conditions
- Use descriptive test names that explain what is being tested

## Project Structure

```
secevent-js/
├── src/                 # Source code
│   ├── types/          # TypeScript type definitions
│   ├── builder/        # SET builder implementation
│   ├── parser/         # SET parser and validator
│   ├── signing/        # Signing and key management
│   ├── id/             # ID generation strategies
│   └── index.ts        # Main exports
├── test/               # Test files
├── docs/               # Documentation
└── examples/           # Usage examples
```

## Implementing New Features

### Adding New Event Types

1. Define the event interface in `src/types/events.ts`
2. Add the event URI to the appropriate constants
3. Create a helper method in the `Events` class
4. Add comprehensive tests in `test/events.test.ts`
5. Update documentation with examples

### Adding New Subject Identifier Formats

1. Define the identifier interface in `src/types/subject.ts`
2. Create a type guard function
3. Add a factory method to `SubjectIdentifiers`
4. Add tests in `test/subject.test.ts`
5. Update README with usage examples

## Release Process

Releases are managed by maintainers following semantic versioning:

- **MAJOR**: Breaking API changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

## Getting Help

- 📧 Email: support@sgnl.ai
- 💬 GitHub Discussions: Ask questions and share ideas
- 🐛 GitHub Issues: Report bugs or request features

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in our README and release notes. Thank you for helping make security event handling better for everyone!

---

**Thank you for contributing to @sgnl/secevent!** 🎉