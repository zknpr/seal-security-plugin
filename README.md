# SEAL Security Plugin for Claude Code

Comprehensive Web3 security framework plugin based on the [SEAL (Security Alliance) Frameworks](https://frameworks.securityalliance.org). Provides real-time security guidance, platform-specific hardening checklists, and hooks that block dangerous commands and secret exposure.

## Install

```bash
claude plugin install seal-security@github:zknpr/seal-security-plugin
```

## What's Included

### Skills

| Skill | Trigger | Description |
|---|---|---|
| `security-guidance` | "security review", "audit", "harden", "opsec", or when touching infra/wallets/CI/CD | Comprehensive security advisor with deep reference files for every SEAL domain |
| `security-checklist` | "checklist", "harden [platform]", "lock down" | 20+ platform-specific hardening checklists |

### Hooks

| Hook | Trigger | Behavior |
|---|---|---|
| `security-guard` | Every `Bash` command | 15 rules catching pipe-to-shell, chmod 777, force push, secret exposure, docker privileged, SSL disable, etc. |
| `secret-scanner` | Every `Write`/`Edit` operation | 11 patterns detecting private keys, mnemonics, AWS creds, SSH keys, JWTs, webhook URLs, DB connection strings |

#### Hook Behavior

- **BLOCKED** (prevents execution): Private keys, mnemonics, AWS keys, SSH keys, PGP keys, pipe-to-shell, chmod 777, force push to main, rm -rf system dirs
- **WARNING** (shows message, allows execution): API key assignments, JWTs, webhooks, npm install without --ignore-scripts, env dumps, SSL verification disable
- `.env` files are warned but never blocked (they're expected to contain secrets)
- Each **warning** is shown only once per session per file/command (no nagging); **blocked** actions are always enforced, on every occurrence
- Add a `seal-allow-secret` comment on a line to opt that line out of secret scanning (for known-fake values in test fixtures)
- Debug logging is **opt-in**: set `SEAL_DEBUG=1` to write hook logs under `~/.claude/` (off by default)

## Covered Security Domains

Based on the full [SEAL Security Frameworks](https://frameworks.securityalliance.org):

| Domain | Coverage |
|---|---|
| **Operational Security** | Account hardening for 15 platforms (Discord, GitHub, Telegram, Twitter/X, Signal, Slack, Vercel, Zoom, etc.) |
| **Infrastructure** | DNS/DNSSEC, registrar security, CAA records, email security (SPF/DKIM/DMARC), endpoint hardening |
| **Wallet Security** | Hardware wallet selection, seed phrase management, multisig best practices, signing verification, EIP-7702 risks |
| **DevSecOps** | CI/CD pipeline hardening, repository security, development environment isolation, code signing, sandboxing |
| **Security Testing** | Unit/integration/fuzz/static analysis/formal verification for smart contracts |
| **Monitoring** | On-chain monitoring guidelines, tools (BlockScout, Hypernative, Tenderly), alert thresholds, channel reliability |
| **Incident Response** | Severity levels (P1-P5), roles, communication templates, 7 playbooks (malware, DPRK, wallet drainers, ELUSIVE COMET, SEAL 911 War Room) |
| **Supply Chain** | Dependency awareness, lockfile integrity, version pinning, Web3-specific threats, vendor risk, incident response |
| **AI Security** | Prompt injection defenses, Web3-specific AI risks, ElizaOS agent memory attacks |

## Platform Checklists Available

Discord, GitHub, Telegram, Twitter/X, Signal, Slack, Vercel, GoDaddy, Notion, Mercury, Sentry, Render, Linear, Trello, Zoom, DNS/Domain Security, Hardware Wallet Setup, Multisig Setup, CI/CD Pipeline, Dependency Management, On-Chain Monitoring, Incident Response Readiness

## Notable Incidents Referenced

| Incident | Loss | Category |
|---|---|---|
| Bybit (DPRK, Feb 2025) | $1.5B | State-sponsored |
| Wormhole | $325M | Contract upgrade |
| Beanstalk | $182M | Flash loan governance |
| Parity | $150M | Proxy pattern bug |
| Cream Finance | $130M | Oracle manipulation |
| Mango Markets | $112M | Oracle manipulation |
| Vyper reentrancy 2023 | $69M | Compiler vulnerability |
| Ledger Connect Kit 2023 | $600K+ | Supply chain |

## Key Principles (Non-Negotiable)

1. **FIDO2/WebAuthn everywhere** — TOTP is second choice, SMS is NEVER acceptable
2. **2+ independent verification channels** for all critical operations
3. **Default-deny egress** — explicit allowlist only
4. **Never sign blindly** — verify origin, contract, function, parameters, gas
5. **Hardware wallet is source of truth** — simulations can be spoofed
6. **Frozen installs in CI** — `npm ci`, never `*` or `latest`
7. **Assume compromise when in doubt** — move funds first, investigate second
8. **Every alert must map to a documented response**
9. **Post-mortem within 1 week** — learning, not blame
10. **"When in doubt, choose the higher severity"**

## Source

All guidance is derived from the [SEAL Security Frameworks](https://frameworks.securityalliance.org) maintained by the [Security Alliance](https://securityalliance.org), a not-for-profit organization dedicated to Web3 security.

## License

MIT
