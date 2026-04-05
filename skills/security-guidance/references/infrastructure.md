# Infrastructure Security Reference (SEAL Framework)

## Domain & DNS Security

### Why It Matters
In Web3, compromised domains lead to irreversible financial losses. Users interact with dApps through domain names — a hijacked domain silently redirects to a wallet drainer.

**Notable incidents:**
- Curve Finance 2025 & 2022: DNS hijacking
- Puffer Finance 2024: domain compromise
- Compound Finance 2024: domain compromise
- Galxe 2023: $270K stolen, 1,100 wallets drained via DNS hijack

### DNS Resolution Flow
1. Local cache check
2. Recursive resolver query
3. Root nameserver
4. TLD nameserver
5. Authoritative nameserver

### DNS Attack Vectors
- **Social engineering at registrars**: Call support, impersonate owner, transfer domain
- **Expired domain sniping**: Register domains that lapse
- **DNS hijacking**: Modify DNS records via compromised registrar/NS
- **MX tampering**: Redirect email to intercept password resets
- **DNS tunneling**: Exfiltrate data via DNS queries
- **DNS cache poisoning**: Inject false records into resolver caches

### DNSSEC Configuration
1. Enable DNSSEC signing at your DNS provider
2. Publish DS record at your registrar
3. **Algorithm**: 13 (ECDSAP256SHA256) recommended
4. **Digest Type**: 2 (SHA-256)
5. Verify: `dig +dnssec yourdomain.com`

### CAA Records
Restrict which Certificate Authorities can issue certs for your domain:
```dns
example.com. CAA 0 issue "letsencrypt.org"
example.com. CAA 0 iodef "mailto:security@example.com"
```
- Prevents unauthorized certificate issuance
- Alert on issuance attempts via iodef

### Email Security Stack
```dns
; SPF - Define authorized senders
example.com. TXT "v=spf1 include:_spf.google.com -all"

; DKIM - Sign outgoing mail (configured at email provider)

; DMARC - Policy enforcement
_dmarc.example.com. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
```

**SMTP DANE**: TLSA records secured via DNSSEC — ensures encrypted email transport
**MTA-STS**: Enforce TLS between mail servers (start with `mode: testing`, then `mode: enforce`)
**TLS-RPT**: Delivery failure reporting to detect interception attempts

### Registrar Security

**Recommended (enterprise-grade):**
- MarkMonitor
- AWS Route53
- Cloudflare Registrar

**AVOID for critical domains:**
- GoDaddy
- Namecheap
- Any consumer-grade registrar

**EPP Lock Status Codes:**
- `clientTransferProhibited` — prevents unauthorized transfers
- `clientUpdateProhibited` — prevents DNS record changes
- `clientDeleteProhibited` — prevents domain deletion
- `serverTransferProhibited` — registrar-side transfer lock
- `serverUpdateProhibited` — registry-level update lock

**Authentication:**
- **FIDO2/WebAuthn**: STRONGLY RECOMMENDED
- **TOTP**: Discouraged (phishable)
- **SMS**: DO NOT USE (SIM swap trivial)

**Other controls:**
- Dedicated security contact email on a DIFFERENT domain
- WHOIS privacy / RDAP as modern replacement
- Auto-renewal ON with max registration period
- Domain expiration monitoring alerts

### DNS Monitoring

**Critical alerts (immediate response):**
- Registrar changed
- Nameserver changed
- DNSSEC validation broken
- CAA records removed
- Unexpected TTL drops (attacker preparing for fast DNS switch)

**High priority (investigate within hours):**
- A/AAAA record changes (when NS unchanged)
- MX record changes
- DMARC policy weakened
- Unexpected certificate issuance

**Tools:**
- Certificate Transparency: crt.sh, Cert Spotter
- Passive DNS: PassiveTotal, SecurityTrails
- GitOps DNS: OctoDNS, DNSControl (infrastructure as code)

### DNS Incident Response
1. **Verify**: Confirm the DNS change is unauthorized
2. **Access registrar**: Use emergency credentials on hardened device
3. **Contact security team**: Parallel notification
4. **Document**: Screenshot everything, timestamps
5. **Contain**: Apply registry lock, update nameservers, warn users via social media
6. **Recover**: Full DNS record audit, credential reset for all registrar accounts
7. **Post-incident**: Root cause analysis, implement additional controls

### Endpoint Security — Zoom Hardening

**Threat: ELUSIVE COMET** — social engineering via Zoom remote control

**Mandatory controls:**
- Disable remote control: Settings > Meeting > In Meeting > Remote control > OFF
- Screen sharing: host only
- Never grant Zoom accessibility permissions on macOS
- Prefer browser-based Zoom (no remote control capability)
- Use SSO/OAuth authentication
- macOS: `tccutil reset Accessibility us.zoom.xos`
- Remove Zoom desktop client when possible

**For sensitive operations:**
- Use Google Meet or Jitsi for treasury discussions, key ceremonies
- Deploy PPPC profiles fleet-wide via MDM/Jamf

**Detection signals:**
- Request to share entire screen (not specific window)
- Participant named "Zoom" appearing
- Remote control dialog box
- Urgency pressure from unknown contacts
- "Investors" insisting on Zoom specifically
- Accessibility permission request
