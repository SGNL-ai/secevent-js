# Release Process

This document describes the release process for @sgnl-ai/secevent.

## Prerequisites

Before releasing, ensure you have:
1. Maintainer access to the repository
2. npm publishing rights for @sgnl scope
3. GPG key for signing commits (recommended)
4. Clean working directory with all changes committed

## Automated Release Process (Recommended)

We use GitHub Actions for automated releases. There are two ways to trigger a release:

### Method 1: Tag-based Release

1. Update the version in `package.json`:
   ```bash
   npm version patch  # For bug fixes (1.0.0 -> 1.0.1)
   npm version minor  # For new features (1.0.0 -> 1.1.0)
   npm version major  # For breaking changes (1.0.0 -> 2.0.0)
   ```

2. Push the tag to GitHub:
   ```bash
   git push origin main
   git push origin --tags
   ```

3. The GitHub Action will automatically:
   - Run all tests
   - Build the library
   - Create a GitHub release with changelog
   - Publish to npm
   - Publish to GitHub Packages

### Method 2: Manual Workflow Trigger

1. Go to Actions → Release workflow
2. Click "Run workflow"
3. Enter the version number (e.g., 1.2.3)
4. The workflow will handle everything automatically

## Manual Release Process

If you need to release manually:

### 1. Pre-release Checklist

- [ ] All tests pass: `npm test`
- [ ] Linting passes: `npm run lint`
- [ ] TypeScript compiles: `npm run typecheck`
- [ ] Coverage is above 80%: `npm run test:coverage`
- [ ] Documentation is updated
- [ ] CHANGELOG is updated

### 2. Version Bump

```bash
# For stable releases
npm version patch  # 1.0.0 -> 1.0.1
npm version minor  # 1.0.0 -> 1.1.0
npm version major  # 1.0.0 -> 2.0.0

# For pre-releases
npm version prerelease --preid=beta  # 1.0.0 -> 1.0.1-beta.0
npm version prerelease --preid=alpha # 1.0.0 -> 1.0.1-alpha.0
```

### 3. Build and Test

```bash
npm run build
npm test
```

### 4. Publish to npm

```bash
# For stable releases
npm publish --access public

# For pre-releases
npm publish --tag beta --access public  # For beta
npm publish --tag alpha --access public # For alpha
```

### 5. Create GitHub Release

1. Go to [Releases](https://github.com/SGNL-ai/secevent-js/releases)
2. Click "Draft a new release"
3. Choose the tag you just created
4. Title: `v{version}` (e.g., v1.0.0)
5. Generate release notes automatically
6. Attach built files from `dist/` if needed
7. Mark as pre-release if applicable
8. Publish release

## Release Types

### Stable Release
- Production-ready version
- Follows semantic versioning strictly
- Published to npm with `latest` tag
- Full changelog and release notes

### Beta Release
- Feature-complete but needs testing
- Version format: `x.y.z-beta.n`
- Published to npm with `beta` tag
- Users install with: `npm install @sgnl-ai/secevent@beta`

### Alpha Release
- Early development version
- Version format: `x.y.z-alpha.n`
- Published to npm with `alpha` tag
- Users install with: `npm install @sgnl-ai/secevent@alpha`

## Version Numbering

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (x.0.0): Breaking API changes
- **MINOR** (0.x.0): New features, backward compatible
- **PATCH** (0.0.x): Bug fixes, backward compatible

### Breaking Changes Include:
- Removing or renaming exported functions/classes
- Changing function signatures
- Changing behavior in backward-incompatible ways
- Dropping Node.js version support

### Non-Breaking Changes Include:
- Adding new exported functions/classes
- Adding optional parameters
- Deprecating features (with warnings)
- Bug fixes
- Performance improvements

## Post-Release

After releasing:

1. **Announce the release**:
   - Update internal documentation
   - Post in relevant channels
   - Update dependent projects

2. **Monitor for issues**:
   - Watch GitHub issues
   - Monitor npm downloads
   - Check for security alerts

3. **Hotfix Process**:
   If critical issues are found:
   ```bash
   git checkout -b hotfix/issue-description
   # Fix the issue
   npm version patch
   git push origin main --tags
   ```

## Rollback Process

If a release has critical issues:

1. **npm deprecate the bad version**:
   ```bash
   npm deprecate @sgnl-ai/secevent@1.2.3 "Critical bug in this version, please upgrade"
   ```

2. **Release a fix immediately**:
   ```bash
   git revert <commit-hash>  # If needed
   npm version patch
   npm publish --access public
   ```

3. **Communicate**:
   - Create a GitHub issue explaining the problem
   - Update release notes
   - Notify users through appropriate channels

## Troubleshooting

### npm publish fails
- Check npm authentication: `npm whoami`
- Verify permissions: `npm access ls-collaborators @sgnl-ai/secevent`
- Check registry: `npm config get registry`

### GitHub Actions fail
- Check secrets are configured (NPM_TOKEN, etc.)
- Verify branch protections allow the workflow
- Check workflow permissions in repository settings

### Version conflicts
- Ensure package.json version matches git tag
- Run `git fetch --tags` to sync tags
- Delete local tag if needed: `git tag -d v1.2.3`

## Security Considerations

- Never commit sensitive tokens
- Use npm 2FA for publishing
- Sign commits with GPG when possible
- Review dependencies before releasing
- Run `npm audit` before each release

## Questions?

Contact the maintainers or open an issue for help with the release process.