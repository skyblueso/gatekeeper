# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Gatekeeper, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **GitHub Security Advisories** (preferred): Use [GitHub's private vulnerability reporting](https://github.com/brodskysimcha-netizen/gatekeeper/security/advisories/new)
2. **Email**: Contact simcha@osint613.com with subject line "Gatekeeper Security Report"

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial assessment**: Within 1 week
- **Fix timeline**: Depends on severity, typically within 2 weeks for critical issues

### Scope

The following are in scope:
- Bypass of detection patterns (false negatives that miss real threats)
- Scanner itself introducing security risks (e.g., code execution during scan)
- Evasion techniques that defeat the scanner's analysis

The following are out of scope:
- False positives (use GitHub Issues for these)
- Feature requests
- Issues in dependencies
