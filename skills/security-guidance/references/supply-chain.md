# Supply Chain Security Reference (SEAL Framework)

## What Is Supply Chain?
Everything between your source code and your users: code dependencies, frontend delivery, build tooling, infrastructure providers, hardware, and the human supply chain.

**Not theoretical** — npm, wallet connector, and compiler attacks have caused hundreds of millions in losses.

## Dependency Awareness

### Every Dependency = Code You Didn't Write But Are Responsible For

**Direct dependencies**: Packages you explicitly install
**Transitive dependencies**: Packages your dependencies depend on (often 10-100x more)

### Lockfile Integrity
- **Always commit lockfiles** to version control
- **Frozen installs in CI**:
  - `npm ci` (not `npm install`)
  - `pnpm install --frozen-lockfile`
  - `yarn --frozen-lockfile`
  - `pip install --require-hashes`
  - `cargo install --locked`
- **Review lockfile changes in PRs** — a lockfile change is a code change

### Install Scripts
- Audit install scripts before adding new packages
- Disable by default in high-assurance environments: `ignore-scripts=true` in `.npmrc`
- Allowlist specific packages that need install scripts

### Version Pinning
- **Exact version** for security-critical packages (crypto, auth, wallet)
- **Patch range** (`~1.2.3`) for general dependencies
- **NEVER use `*` or `latest`** — ever
- **GitHub Actions**: Pin to full SHA, not tag
  - Good: `uses: actions/checkout@a81bbbf8298c0fa03ea29cdc473d45769f953675`
  - Bad: `uses: actions/checkout@v4`

### Trust Signals Before Adding a Package
- Maintainer activity and count (bus factor)
- Download trends (sudden spikes = suspicious)
- Scope/permissions requested
- OIDC Trusted Publishers (eliminates long-lived publish tokens)
- Check for known vulnerabilities

### Typosquatting Defense
- Verify package names character by character
- Use scoped packages when available (`@org/package`)
- Review any unfamiliar packages before install
- Common tricks: `lodash` vs `1odash`, `express` vs `expres`

### Vulnerability Scanning

| Ecosystem | Tool | Command |
|---|---|---|
| Node.js | npm audit | `npm audit` |
| Rust | cargo-audit | `cargo audit` |
| Python | pip-audit | `pip-audit` |
| Go | govulncheck | `govulncheck ./...` |
| Ruby | bundler-audit | `bundle audit check --update` |
| Java | OWASP Dependency-Check | Via Maven/Gradle plugin |
| PHP | local-php-security-checker | Via Composer |
| Solidity | Slither + Aderyn | Run in CI |

### Common Pitfalls
- Blindly merging Dependabot/Renovate PRs without reviewing changes
- Using `*` or `latest` in any dependency spec
- Ignoring transitive dependency vulnerabilities
- Installing packages from GitHub URLs (bypasses registry checks)
- Not reviewing changelogs between versions
- Publishing packages with long-lived tokens (use OIDC instead)

## Web3-Specific Supply Chain Threats

### Frontend Attacks

**npm Package Compromise:**
- npm registry 2025: widespread package poisoning
- Solana web3.js 2024: official package compromised
- ua-parser-js 2021: crypto miner injected into widely-used package
- event-stream 2018: targeted attack on cryptocurrency wallet

**Wallet Connector Hijacking:**
- Ledger Connect Kit 2023: $600K+ stolen via compromised wallet connector library
- Affected every dApp using the Ledger connector

**CDN/Hosting Compromise:**
- Compromised CDN serves malicious JavaScript
- Users interact with legitimate-looking site that drains wallets

### Smart Contract Risks

**Compiler Tampering:**
- Vyper reentrancy 2023: $69M lost due to compiler bug
- Compiler bugs affect ALL contracts deployed with that version

**Malicious Libraries/Plugins:**
- Imported libraries can contain hidden backdoors
- Always audit security-critical imports

**Unverified Deployments:**
- Deploying contracts from unverified source
- Always verify on-chain bytecode matches audited source

### Governance Attacks
- Tornado Cash 2023: governance takeover via malicious proposal
- Beanstalk 2022: $182M via flash loan governance capture

### Infrastructure Risks
- Infura outage 2020: single RPC provider failure cascaded
- **Oracle manipulation**: Mango Markets $112M, Cream Finance $130M, bZx $1M
- Block explorer API dependence and verification vulnerabilities

### Hardware Supply Chain
- Trezor Safe 3: voltage glitching vulnerability 2025
- Ledger database breach 2020: physical addresses leaked, targeted phishing

## Risk Classification

| Level | Examples | Required Scrutiny |
|---|---|---|
| **Level 1 Critical** | Smart contract libraries, wallet interaction, crypto modules | Highest — audit every update, verify source |
| **Level 2 High-Risk** | Auth modules, API middleware, database connectors, oracle integration | Full review on updates |
| **Level 3 Moderate** | UI frameworks, utility libraries, analytics | Standard automated scanning |
| **Level 4 Low-Risk** | Test frameworks, linting tools, docs generators | Basic hygiene |

## Vendor Risk Management

### Vendor Categories
- **Infrastructure**: RPC providers, indexing services, hosting/CDN, domain registrars
- **Security services**: Auditors, bug bounty platforms, monitoring providers
- **Human supply chain**: Contractors, freelancers, **DPRK IT workers** (active threat)

### Assessment Frequency
- High-trust vendors: **Reassess quarterly**
- All vendors: **Reassess annually minimum**

### Common Pitfalls
- Assuming "decentralized" means no vendor risk
- Single-provider dependency (no fallback)
- Skipping due diligence for well-known brands
- No exit strategy (can you migrate away quickly?)

## Supply Chain Incident Response

### Key Differences from Direct Compromise
- You don't control the affected code
- Detection often comes from external sources
- May need to wait for upstream fix
- Blast radius is ecosystem-wide (all consumers of the package)

### Detection Signals
- Community alerts (Twitter, security advisories)
- Unexpected dependency updates in lockfile
- Behavioral anomalies (new network connections, modified output)
- Integrity check failures
- Registry security advisories

### Response Scenarios

**Frontend dependency compromised:**
1. Deploy clean frontend from known-good source
2. Invalidate CDN caches globally
3. Warn users via all channels
4. Check for wallet drainer activity in on-chain monitoring

**Smart contract dependency compromised:**
1. Determine if the vulnerable code is deployed on-chain
2. If deployed: consider pausing affected contracts
3. Plan migration to fixed version
4. Audit all deployments using the affected dependency

**CI/CD pipeline compromised:**
1. **Assume ALL secrets are compromised** — rotate everything
2. Audit all recent deployments from affected pipeline
3. Review pipeline logs for unauthorized changes
4. Rebuild from clean, verified source
