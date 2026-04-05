# Monitoring Reference (SEAL Framework)

## First Principles
1. **Know what you're monitoring and WHY** — every monitored metric has a reason
2. **Act on your alerts** — every alert maps to a concrete documented response
3. **Monitor with redundancy** — 2+ independent providers for critical systems
4. **Alert on alert tampering** — if monitoring itself is compromised, you're blind
5. **Test alerts periodically** — untested alerts are assumptions, not controls

## Monitoring Objectives

What to monitor on-chain:
- **Large fund transfers** (both absolute and relative thresholds)
- **Token minting/burning** events
- **Ownership/admin changes** (owner transfers, role grants)
- **Contract upgrades** (proxy implementation changes)
- **Access control modifications** (new roles, permission changes)
- **Unusual gas patterns** (potential MEV or attack activity)

## Monitoring Strategies

| Strategy | Focus |
|---|---|
| Transaction monitoring | Track specific address activity, value flows |
| Contract event monitoring | Listen for emitted events (Transfer, Approval, OwnershipTransferred) |
| Bridge monitoring | Cross-chain message verification, liquidity changes |
| Oracle/governance monitoring | Price feed deviations, governance proposals, vote patterns |
| Node/network monitoring | Block propagation, RPC availability, peer count |

## Alert Thresholds

### Setting Thresholds
1. **Establish baselines**: Average transaction volumes, typical token minting rates, normal gas usage
2. **Historical analysis**: Use past data to understand normal patterns
3. **Absolute thresholds**: e.g., any transfer > $1M
4. **Relative thresholds**: e.g., > 5x normal hourly volume
5. **Adaptive thresholds**: Adjust based on changing patterns over time

### Multi-Layered Approach
- **Primary thresholds**: Critical alerts requiring immediate action (P1/P2)
- **Secondary thresholds**: Informational alerts for investigation (P3/P4)
- Combine multiple metrics to reduce false positives

### Anomaly Detection
Impossible to predict every alert type. Anomaly detection monitors transactions in real-time and compares to learned behavioral patterns.

**Example**: If 4% of tokens normally change ownership daily and suddenly 20% change in 10 minutes, that's anomalous even without a specific rule.

**Tools for anomaly detection:**
- **Hypernative**: ML-based behavioral modeling
- **Tenderly**: Custom alert rules for threshold approximation

## Monitoring Tools

### Open Source / Self-Hosted

| Tool | Purpose | Cost |
|---|---|---|
| **BlockScout** | Blockchain explorer with custom monitoring/alerts | Free (MIT), managed from $250/mo |
| **Prometheus + Grafana** | Infrastructure metrics, node health, RPC availability | Free, chain-agnostic |

### Commercial / Hosted

| Tool | Key Feature | Chains | Pricing |
|---|---|---|---|
| **Etherscan Watch List** | 50 addresses, email notifications | Ethereum family | Free tier available |
| **Guardrail** | Real-time DeFi security, automated threat response (pause, flag) | 30+ | Commercial |
| **Hexagate (Chainalysis)** | ML anomaly detection, GateSigner pre-signing simulation | 75+ | Free for partner chains |
| **Hypernative** | ML behavioral modeling, pre-crime threat detection | 70+ | Commercial |
| **Tenderly** | 12 alert types, 8 destinations, transaction simulation | 100+ | Free tier available |

### Tenderly Alert Destinations
Slack, Discord, Telegram, email, webhooks, PagerDuty, Sentry, Web3 Actions

## Reliability Considerations

### Self-Hosted vs Managed

| Factor | Self-Hosted | Managed |
|---|---|---|
| Control | Full control over infrastructure | Vendor controls |
| Operational burden | You own uptime, upgrades, maintenance | Vendor handles ops |
| Vendor risk | None | Platform downtime affects you |
| Cost | Infrastructure + engineering time | Subscription fee |

### Key Metrics to Track
- **Uptime SLA**: What's guaranteed?
- **Time-to-alert**: From on-chain event to notification
- **Alert delivery guarantees**: At-least-once vs best-effort

### Redundancy Recommendation
For protocols with significant value:
- Run **at least 2 independent monitoring setups**
- Ideally: **one self-hosted + one managed**
- Both covering the **same critical invariants**
- Cross-check: if one fires and the other doesn't, investigate immediately

## Alert Channel Reliability

| Channel | Reliability | Use For |
|---|---|---|
| **PagerDuty / OpsGenie** | High (escalation, on-call, delivery receipts) | P1/P2 critical alerts |
| **Slack / Discord / Telegram** | Medium (easy to miss, no delivery guarantees) | P3/P4 informational, team visibility |
| **Email** | Low (latency, spam filtering, easy to miss) | Never as sole channel for critical alerts |
| **Webhooks** | High (programmable, reliable) | Automated response triggers |

**Rule**: Critical alerts (P1/P2) MUST go through PagerDuty/OpsGenie with escalation policies. Slack/Discord/Telegram are supplementary only.
