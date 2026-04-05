---
name: security-checklist
description: Quick operational security checklists for specific platforms and services. Use when hardening Discord, GitHub, Telegram, Twitter/X, Signal, Slack, Vercel, GoDaddy, Notion, Sentry, Render, Linear, Mercury, Trello, Zoom, DNS, wallets, CI/CD, or multisig setups. Triggers on "checklist", "harden [platform]", "secure [platform]", "lock down", "audit [platform]".
---

# Security Checklists (SEAL Framework)

Provide the specific checklist for the platform or service the user asks about. Read `~/.claude/seal-security-framework.md` for the full framework, but deliver focused, actionable checklists.

## Platform Checklists

### Discord
- [ ] 2FA with authenticator app (NOT SMS)
- [ ] Disable SMS backup auth
- [ ] Cold Admin accounts on factory-reset devices
- [ ] Role hierarchy: Cold Admin > Team > Moderator > Verified
- [ ] Max 2-3 admins with Administrator permission
- [ ] Anti-raid/anti-nuke/anti-impersonation bots deployed
- [ ] AutoMod rules configured
- [ ] Safety Setup: CAPTCHA + raid protection enabled
- [ ] Monthly role review
- [ ] Quarterly bot/integration review
- [ ] Bi-annual full security audit

### GitHub
- [ ] Non-SMS 2FA for all members
- [ ] Push protection enabled
- [ ] Signed commits (GPG) required
- [ ] Branch protection: 2+ approvals required
- [ ] Force pushes blocked
- [ ] Fork PR workflows disabled in Actions
- [ ] Dependabot alerts enabled
- [ ] Secret scanning + push protection enabled
- [ ] Org-level rulesets configured
- [ ] Personal access tokens restricted
- [ ] No deploy keys — use GitHub Apps

### Telegram
- [ ] Two-Step Verification enabled
- [ ] Passkeys configured
- [ ] Local passcode set
- [ ] Phone number hidden from everyone
- [ ] Peer-to-peer calls disabled (IP leak prevention)
- [ ] Automatic media download disabled
- [ ] Secret Chats used for sensitive E2EE conversations
- [ ] Content protection enabled for groups
- [ ] Slow mode + aggressive anti-spam

### Twitter/X
- [ ] SMS 2FA disabled
- [ ] Authenticator app or security key enabled
- [ ] Phone number deleted from account
- [ ] Password reset protection enabled
- [ ] Connected apps reviewed and unnecessary ones revoked
- [ ] Email address uses "+" suffix for obscurity

### Signal
- [ ] Registration Lock enabled
- [ ] Phone number hidden
- [ ] Disappearing messages: 1 week
- [ ] Relay calls: always (prevents IP exposure)
- [ ] Screen lock: 1 minute timeout

### Slack
- [ ] 2FA with authenticator apps only
- [ ] Admin approval for new invitations
- [ ] Jailbroken/rooted devices blocked

### Vercel
- [ ] 2FA enabled
- [ ] Deployment protection enabled
- [ ] Sensitive environment variables enforced
- [ ] Git Fork Protection enabled
- [ ] Build logs protection enabled

### GoDaddy
- [ ] Non-SMS 2FA enabled
- [ ] Delegate access reviewed
- [ ] DNSSEC enabled

### Notion
- [ ] 2-step verification (authenticator, not SMS)
- [ ] Support access disabled
- [ ] Publishing/export/guest invites disabled

### Mercury
- [ ] 2FA enabled
- [ ] ACH authorization enabled
- [ ] Dual admin approval required

### Sentry
- [ ] 2FA enabled
- [ ] Org-wide 2FA required
- [ ] Join requests disabled

### Render
- [ ] 2FA enabled
- [ ] CLI tokens/API keys/SSH keys reviewed
- [ ] Audit logs enabled (org/enterprise plan)

### Linear
- [ ] Passkeys configured
- [ ] Invite links disabled
- [ ] Email domains restricted
- [ ] Third-party applications controlled

### Trello
- [ ] 2-step verification enabled
- [ ] Connected applications reviewed
- [ ] Sessions reviewed

### Zoom (ELUSIVE COMET Defense)
- [ ] Remote control DISABLED (Settings > Meeting > In Meeting > Remote control > OFF)
- [ ] Screen sharing set to host only
- [ ] Zoom accessibility permissions NOT granted on macOS
- [ ] Prefer browser-based Zoom when possible
- [ ] SSO/OAuth authentication used
- [ ] macOS: TCC permissions revoked (`tccutil reset Accessibility us.zoom.xos`)
- [ ] Zoom desktop client removed if not essential
- [ ] Waiting rooms enabled
- [ ] Meeting passcodes required
- [ ] Google Meet or Jitsi used for sensitive discussions (treasury, key ceremonies)

### DNS / Domain Security
- [ ] Enterprise registrar (MarkMonitor, AWS Route53, or Cloudflare)
- [ ] FIDO2/WebAuthn on registrar account
- [ ] DNSSEC enabled and DS record published
- [ ] CAA records configured (restrict CA issuance)
- [ ] EPP locks enabled (clientTransferProhibited, etc.)
- [ ] Registry lock enabled (if available)
- [ ] Security contact email on separate domain
- [ ] WHOIS privacy enabled
- [ ] Auto-renewal ON, max registration period
- [ ] SPF + DKIM + DMARC configured
- [ ] Certificate Transparency monitoring (crt.sh)
- [ ] DNS monitoring alerts configured (registrar change, NS change, DNSSEC broken)

### Hardware Wallet Setup
- [ ] Purchased direct from manufacturer
- [ ] Tamper-resistant packaging verified
- [ ] Secure Element EAL6+ present
- [ ] Open source firmware
- [ ] Strong PIN (6+ digits)
- [ ] Keys generated on device
- [ ] Clear Signing supported
- [ ] Backup device configured
- [ ] Seed phrase stored securely (3-piece split or Shamir's)

### Multisig Setup
- [ ] Minimum 3 signers configured
- [ ] 50% threshold (or higher)
- [ ] 7+ signers for $1M+ assets
- [ ] All signers use hardware wallets
- [ ] Signers geographically distributed
- [ ] Role diversity among signers
- [ ] At least one external signer
- [ ] Tested on testnet first
- [ ] Timelock implemented
- [ ] Veto quorum configured
- [ ] Disaster recovery plan documented
- [ ] Out-of-band verification protocol established (2+ channels)
- [ ] Regular drills scheduled

### CI/CD Pipeline
- [ ] All PRs run CI (unit, integration, dependency vuln checks)
- [ ] Leaked credential scanning enabled
- [ ] Deterministic builds with frozen lockfiles
- [ ] Isolated build/test environments
- [ ] Strict access controls on pipeline config
- [ ] Fork PRs: no secrets, restricted tokens, no deploy
- [ ] Protected branches: secrets only in protected environments
- [ ] Default-deny egress on runners
- [ ] Ephemeral runners (no persistent state)
- [ ] GitHub Actions pinned to SHA (not tag)
- [ ] Artifact signing and provenance generation
- [ ] OIDC federation instead of static cloud keys

### Dependency Management
- [ ] Lockfiles committed to version control
- [ ] CI uses frozen installs (`npm ci`, `--frozen-lockfile`)
- [ ] Install scripts audited for new packages
- [ ] Security-critical packages pinned to exact versions
- [ ] No `*` or `latest` in any dependency
- [ ] Vulnerability scanning in CI (npm audit, cargo-audit, etc.)
- [ ] Lockfile changes reviewed in PRs
- [ ] GitHub Actions pinned to SHA
- [ ] Level 1 Critical deps (crypto, wallet, smart contract libs) audited on every update

### On-Chain Monitoring
- [ ] Monitoring objectives defined (what and why)
- [ ] Large fund transfer alerts (absolute + relative thresholds)
- [ ] Token minting/burning alerts
- [ ] Ownership/admin change alerts
- [ ] Contract upgrade alerts
- [ ] Unusual gas pattern alerts
- [ ] 2+ independent monitoring providers
- [ ] Alert channels: PagerDuty/OpsGenie (not just Slack/Discord)
- [ ] Every alert has a documented response runbook
- [ ] Alerts tested periodically
- [ ] Alert-on-alert-tampering configured

### Incident Response Readiness
- [ ] Severity levels defined (P1-P5)
- [ ] Incident roles assigned (Leader, Scribe, Comms, SMEs, Decision Makers)
- [ ] Communication channels established (encrypted)
- [ ] Pre-approved communication templates ready
- [ ] SEAL 911 contact information available
- [ ] Escalation order documented
- [ ] Post-mortem template ready
- [ ] Runbooks created for known incident types
- [ ] Drills conducted quarterly
