# Account Security Reference (SEAL Framework)

## Universal Rules
- **FIDO2/WebAuthn** is the gold standard for 2FA
- **TOTP** (authenticator apps) is acceptable when hardware keys aren't supported
- **SMS 2FA is NEVER acceptable** — SIM swap attacks are trivial
- Review and revoke unnecessary connected apps/sessions regularly
- Use unique email addresses per service (+ suffix trick)
- Dedicated admin accounts on hardened devices for high-value platforms

## Discord
**Threat model**: Server takeover, impersonation, phishing, raid attacks, nuke bots

**Critical settings:**
- 2FA: authenticator app, disable SMS backup
- Cold Admin: factory-reset device, only used for admin actions
- Role hierarchy: Cold Admin > Team > Moderator > Verified
- Max 2-3 Administrator-level accounts
- Disable @everyone mentions from non-admins
- Enable member screening with CAPTCHA

**Bot security:**
- Anti-raid bots: detect mass join/message patterns
- Anti-nuke bots: prevent mass channel/role deletion
- Anti-impersonation: flag similar usernames/avatars
- AutoMod: filter known phishing patterns, suspicious links

**Review schedule:**
- Monthly: role assignments, member access
- Quarterly: bot permissions, integrations, webhook URLs
- Bi-annually: full server security audit

## GitHub
**Threat model**: Supply chain attacks, secret leakage, unauthorized code changes, Actions abuse

**Repository security:**
- Branch protection: require 2+ approvals for main/production
- Block force pushes to protected branches
- Require signed commits (GPG)
- Enable CODEOWNERS for critical paths
- Dismiss stale approvals on new pushes

**Actions security:**
- Disable fork PR workflows (prevents secret exfiltration)
- Restrict Actions to verified/selected actions only
- Pin actions to SHA, not tags
- Use `permissions:` to restrict GITHUB_TOKEN scope
- Never echo secrets in logs

**Org-level:**
- Require 2FA for all members
- Restrict personal access token creation
- Enable secret scanning + push protection
- Enable Dependabot security updates
- Use GitHub Apps instead of deploy keys
- Org-level rulesets for consistent policy

## Telegram
**Threat model**: SIM swap, IP exposure, Man-in-the-Group, social engineering

**Critical settings:**
- Two-Step Verification (password + recovery email)
- Passkeys for device auth
- Local passcode (separate from device PIN)
- Phone number: visible to Nobody
- Calls: Never for peer-to-peer (prevents IP leak via STUN/TURN)
- Auto-download: disabled for all media types

**Group security:**
- Content protection: prevent forwarding/screenshots in sensitive groups
- Slow mode: rate limit messages during attacks
- Aggressive anti-spam settings
- Admin-only message sending for announcement channels

**Man-in-the-Group attack:**
Attacker joins group, copies name/photo of a trusted member, sends messages that appear to come from that person. Mitigation: unique usernames, admin verification, member screening.

## Twitter/X
**Threat model**: Account takeover, SIM swap, phishing, social engineering

- Delete phone number entirely (prevents SMS-based attacks)
- Disable SMS 2FA, use authenticator app or security key
- Enable password reset protection (prevents unauthorized resets)
- Review connected apps regularly, revoke unused
- Use email with + suffix (user+twitter@domain.com) for leak detection

## Signal
**Threat model**: Registration hijacking, IP exposure, message persistence

- Registration Lock: prevents re-registration without PIN
- Hide phone number from non-contacts
- Disappearing messages: 1 week default for all chats
- Relay calls always: routes through Signal servers, preventing IP exposure
- Screen lock: 1 minute (prevent physical access to messages)

## Slack
- 2FA: authenticator apps only (no SMS)
- Admin-approved invitations only
- Block jailbroken/rooted devices from accessing workspace
- Review connected apps and bot tokens regularly

## Vercel
- 2FA required
- Deployment protection enabled (prevent unauthorized deploys)
- Sensitive env vars enforced (not visible in build logs)
- Git Fork Protection (prevent fork-based secret exfiltration)
- Build logs protection (prevent secret leakage in logs)

## GoDaddy
- Non-SMS 2FA
- Review delegate access (remove unused)
- DNSSEC enabled for all domains
- Note: GoDaddy is NOT recommended for critical domains (see Infrastructure section)

## Mercury (Banking)
- 2FA mandatory
- ACH authorization enabled (prevent unauthorized transfers)
- Dual admin approval for sensitive operations

## Notion
- 2-step verification with authenticator (not SMS)
- Disable support access (prevents Notion support from accessing your data)
- Disable publishing, export, and guest invites

## Sentry
- 2FA mandatory, require org-wide 2FA enforcement
- Disable join requests (prevent unauthorized access)

## Render
- 2FA enabled
- Regular review of CLI tokens, API keys, SSH keys
- Audit logs (requires org/enterprise plan)

## Linear
- Passkeys preferred
- Disable invite links
- Restrict to specific email domains
- Control and review third-party applications

## Trello
- 2-step verification enabled
- Review connected applications and active sessions regularly
