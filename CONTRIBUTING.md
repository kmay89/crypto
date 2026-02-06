# Contributing to Quantum Vault

Thank you for your interest in contributing. Please read these guidelines before submitting changes.

## Principles

1. **Security first.** Every change must maintain or improve the security posture.
2. **Zero tracking.** Do not add analytics, cookies, tracking pixels, or any form of data collection. Pull requests that introduce tracking will be rejected.
3. **Minimal dependencies.** The only external runtime dependency is `@noble/post-quantum`. Do not add frameworks, bundlers, or libraries unless there is an extraordinary reason.
4. **Client-side only.** All cryptographic operations must remain entirely in the browser. No server-side processing.

## Security Vulnerability Reporting

If you discover a security vulnerability, **do not open a public issue.** Instead, use the contact information in [security.txt](/.well-known/security.txt) to report it responsibly.

## Submitting Changes

1. Fork the repository and create a feature branch.
2. Make your changes with clear, descriptive commit messages.
3. Run the [PREFLIGHT.md](./PREFLIGHT.md) checklist before submitting.
4. Open a pull request with a clear description of what changed and why.

## Code Standards

- **No inline scripts.** All JavaScript belongs in `main.js`. The CSP enforces this.
- **No `console.log()`** or debug statements in production code.
- **No `eval()`, `new Function()`,** or dynamic code execution.
- **Pin dependency versions** — never use `@latest` or version ranges for CDN imports.
- **External links** must use `rel="noopener noreferrer"`.

## What We Accept

- Bug fixes
- Security improvements
- Accessibility improvements
- Documentation improvements
- Performance optimizations (that don't compromise security)
- Post-quantum algorithm updates (when new NIST standards are published)

## What We Do Not Accept

- Analytics or tracking of any kind
- Advertising or monetization
- Server-side dependencies
- Cosmetic-only changes without functional improvement
- Breaking changes to the `.pqenc` file format without version bump

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](./LICENSE).
