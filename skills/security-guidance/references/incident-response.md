# Incident Response Reference (SEAL Framework)

## Severity Levels

| Level | Description | Response Time | Who's Involved |
|---|---|---|---|
| **P1 Critical** | Funds loss, active exploitation, critical outage | Immediate | Decision Makers + full IRT |
| **P2 High** | Significant production impact, potential fund loss | Immediate | IRT + relevant SMEs |
| **P3 Moderate** | Medium consequence, unlikely fund loss | Within hours | On-call + relevant SMEs |
| **P4 Low** | Minor consequence, no financial risk | Flexible scheduling | Assigned team member |
| **P5 Info** | Informational only | No urgent action | Log and review |

**"When in doubt, choose the higher severity. A false P1 creates noise. A missed P1 costs funds."**

## Incident Roles

| Role | Responsibility |
|---|---|
| **Detector** | Identifies incident, notifies responders, transfers responsibility |
| **Incident Leader** | Manages response, assigns tasks, makes decisions, escalates |
| **Scribe** | Documents everything in Incident Log (UTC timestamps). Should NOT also do remediation. |
| **Communication Manager** | Drafts updates, coordinates PR, oversees community channels |
| **SMEs** | Technical specialists summoned by incident type |
| **Decision Makers** | Senior leadership for high-stakes determinations |

## Response Process

### 1. Detection
Sources: monitoring alerts, community reports, bug bounties, audits, partner notifications

### 2. Coordination
- Start video conference immediately for P1/P2
- Create private channel: `#incident-[brief-description]`
- Notify all responders with severity and brief description
- **Explicit role handoff** — no ambiguity about who's leading

### 3. Investigation
- Collect all relevant logs
- Assess impact (users affected, funds at risk)
- Confirm or adjust severity level
- Evaluate mitigation options

### 4. Resolution
- **Temporary mitigation first** if faster (pause contracts, disable frontend)
- Then plan permanent fix
- Document every action taken with timestamps

### 5. Monitoring
- Immediate verification that fix works
- **1-week minimum observation period**
- Evaluate whether new alerts are needed

### 6. Post-Incident Review
- **Within 1 week** of resolution
- Full timeline reconstruction
- Root cause analysis (5 Whys)
- Action items with **owners and deadlines**
- Focus on **learning, not blame**

## P1 Escalation Order
1. **SEAL 911** (if active exploit) — industry-wide emergency response
2. **Decision Makers** (internal)
3. **Security Partners** (auditors, IR retainer firms)
4. **Legal** (if fund loss or regulatory implications)

## Communication

### Before Posting Checklist
- [ ] Approved by Incident Leader or Decision Maker
- [ ] Facts verified — no speculation about root cause
- [ ] Includes what users should do (or not do)
- [ ] States when next update will come

### Communication Building Blocks

**Acknowledgment:**
"We're aware of an issue affecting [service/feature] and are actively investigating."

**Funds Safe:**
"User funds are safe and have not been affected."

**Funds at Risk:**
"We are investigating a potential security issue. Out of caution, we recommend users [specific action]."

**Do Not Interact:**
"Do not interact with [specific thing] until further notice."

**Service Paused:**
"We have temporarily paused [service/feature] while we investigate."

**Next Update:**
"We'll provide an update within [timeframe] or sooner if the situation changes."

**Resolution:**
"The issue has been resolved. [Brief description of fix]."

**Post-Mortem:**
"We'll publish a detailed post-mortem within [timeframe]."

### Channel-Specific Guidance
- **Twitter**: Short initial tweet, details in thread, pin updates
- **Discord**: @everyone ONLY for P1, create dedicated thread
- **Telegram**: Pin critical messages, consider disabling chat during active incident

### Tone
- Be direct and factual
- Avoid jargon
- Don't speculate on root cause until confirmed
- Don't assign blame
- Acknowledge impact
- Avoid excessive apologies (one sincere acknowledgment is enough)

## Playbooks

### Malware Infection
1. **Disconnect** from internet immediately
2. **Turn off** the infected computer
3. **Secure crypto assets**: Create new wallet on CLEAN device, transfer assets (tokens/NFTs/admin roles first, native token last)
4. **Notify colleagues** using pre-written template
5. **Secure accounts**: Log out all sessions, change passwords, reset 2FA — on a CLEAN device
6. **Notify authorities**: IC3.gov, Chainabuse.com, SEAL 911, local police
7. **Get new computer**: Factory reset or new hardware. NEVER restore from backup.
8. **Stay vigilant**: Attackers often follow up with additional attacks

### DPRK (North Korea) Attacks
**Scale**: $1.34B stolen in 2024, $1.5B from Bybit in Feb 2025

**Attack Methods:**
1. **Fake video conference**: Impersonate investor, send link to non-standard video call platform, "error" triggers malware install
2. **Fake PDF**: Malicious executable that opens expected PDF as cover while installing backdoor

**Response**: Assume ALL private keys, files, and accounts are compromised. Move funds immediately. Treat as P1.

### Wallet Drainer Attacks
**Model**: Drainer-as-a-Service franchise (developer sells tools to affiliates)

**Tactics:**
- Request token approval (unlimited approve)
- Request DEX signatures (Permit2, etc.)
- Request EIP-7702 wallet upgrade
- Directly request seed phrase

**Response**: Revoke all approvals immediately, move funds to new wallet

### ELUSIVE COMET (Zoom Remote Control)
1. Attacker impersonates journalist/investor/podcast host
2. Schedules Zoom call, pressures full-screen sharing
3. User named "Zoom" requests remote control access
4. Installs malware, steals keys/sessions, hijacks social accounts

**Defense**: Disable Zoom remote control, prefer browser Zoom, never grant accessibility permissions

### SEAL 911 War Room
**Parallel tracks:**
- **Analysis**: Scope impact, gather transactions, investigate attack vector
- **Protocol**: Pause contracts, execute defensive scripts, white hat frontrunning
- **Web**: Disable deposits, enable blacklisting, redirect frontend
- **Communications**: Prepare statements, notify downstream protocols, notify block explorers

**Roles**: Operations, Scribe, Strategy Lead, Protocol Lead, Web/Infra Lead, External Communicator

**White Hat Frontrunning**: pcaversaccio's script for standard and EIP-7702 flows via Flashbots

### Decentralized Incident Response (DeIRF)
**Principles**: Zero-trust default, shared responsibility, minimum viable process, open tooling, evidence first

**Containment options:**
- Smart contract pause
- Multisig freeze
- Host quarantine
- DNS reroute to safe page

**Post-incident:**
- Retrospective within 72 hours
- Update all runbooks
- Reward reporters
- Public disclosure timeline

**Ongoing:**
- Quarterly red team drills
- Rotate secrets regularly
- Review identity proofs every 6 months

## Post-Mortem Template

### Structure
1. **Metadata**: Date, severity, duration, responders
2. **Summary**: 2-4 paragraphs describing what happened
3. **Impact**: Users affected, financial impact, reputation impact
4. **Timeline**: Minute-by-minute from detection to resolution
5. **Root Cause**: Primary cause + contributing factors + 5 Whys
6. **What Went Well**: Things that worked
7. **What Went Wrong**: Things that failed
8. **Where We Got Lucky**: Near-misses that could have been worse
9. **Action Items**: Every item has owner + deadline
10. **Lessons for Runbooks**: What to update

### Key Questions
- Did we detect quickly enough?
- Was the right severity assigned?
- Were the right people involved early enough?
- Did we have an appropriate runbook?
- What would we do differently?

## Incident Log Template

**Name**: `YYYY-MM-DD-brief-description`
**Update in real-time, UTC 24-hour format**

Fields:
- Status (active/mitigated/resolved)
- Severity (P1-P5)
- Start/Resolution time
- Affected services
- Roles assigned
- Communication channels
- Timeline (every action with timestamp)
- Root cause analysis
- Actions taken
- Communications sent
- Post-incident checklist
