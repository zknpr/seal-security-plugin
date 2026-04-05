# DevSecOps Reference (SEAL Framework)

## Core Principle
Security embedded from planning through delivery. Automated checks stop unsafe changes before production. Sandboxed execution contains risk.

## CI/CD Pipeline Security

### Every PR Must Run
- Unit tests
- Integration tests
- Dependency vulnerability checks
- Misconfiguration scanning
- Leaked credential detection

### Build Security
- **Deterministic builds** with strict dependencies and build containers
- **Frozen lockfiles** in CI: `npm ci`, `pnpm install --frozen-lockfile`, `yarn --frozen-lockfile`
- Integrated security scanning tools (SAST, DAST)
- **Isolated build/test environments** — never on developer machines
- Strict access controls for pipeline configurations

### Trust Zones
- **Zone A (Untrusted PR validation)**: No long-lived secrets, restricted CI token, no deploy/publish permissions
- **Zone B (Trusted branch/release)**: Controlled secret access, protected environments, provenance + signing

### GitHub Actions Hardening
- Pin actions to SHA (not tag): `uses: actions/checkout@a81bbbf...`
- Restrict `GITHUB_TOKEN` permissions: `permissions: contents: read`
- Disable fork PR workflows to prevent secret exfiltration
- Never echo secrets in logs
- Use `actions/attest-build-provenance` for supply chain integrity

## Repository Hardening

- MFA required for all repository members
- Protected branches with 2+ required reviews
- Block force pushes to protected branches
- Require signed commits (GPG)
- Enable CODEOWNERS for critical paths
- Dismiss stale approvals on new pushes
- Regular dependency updates with vulnerability scanning
- Secret scanning + push protection enabled

## Development Environment Security

- IDEs: plugins/extensions from trusted sources only
- **Restricted mode** for untrusted projects (VS Code, JetBrains)
- Keep IDEs and plugins up-to-date
- Integrated static code analysis (Slither, Aderyn, ESLint security rules)
- **Principle of least privilege** for dev environment access
- **Isolate dev from production** — no production credentials in dev

## Code Signing

- **GPG-signed commits** required for all PRs
- Mandatory code review before merge
- MFA with **Yubikeys** for signing operations
- Regular GPG key rotation
- Verify signature chain in CI

## Security Testing Integration

| Type | Purpose | When |
|---|---|---|
| SAST | Analyze code without executing | Every PR |
| DAST | Test running application | Pre-deploy |
| IAST | Instrument running app for deeper analysis | Staging |
| Fuzz testing | Random/unexpected inputs | CI/CD |

### Smart Contract Testing
- **Unit tests**: Always. High code + branch coverage
- **Integration tests**: Always. Fork testing against mainnet state
- **Fuzz tests**: Always. Most unit tests should also be fuzz tests
- **Static analysis**: Always. Slither + Aderyn
- **Formal verification**: When math-heavy or matching another system
- **Mutation testing**: Evaluate test suite quality

## Data Security & Contract Upgrade Checklist

### Pre-Upgrade
- [ ] Data backup and disaster recovery tested
- [ ] Secure storage and encryption verified
- [ ] Third-party integrations reviewed
- [ ] Access control verified
- [ ] Full test suite passes on upgrade code
- [ ] Security audit completed
- [ ] Upgrade governance process followed

### Proxy Patterns
- **UUPS** (Universal Upgradeable Proxy Standard)
- **Transparent Proxy** — admin-only upgrade path
- **Diamond** (EIP-2535) — modular facets
- **Beacon** — single upgrade point for multiple proxies

### Real-World Upgrade Failures
| Incident | Loss | Root Cause |
|---|---|---|
| Wormhole | $325M | Upgrade vulnerability |
| Nomad | $190M | Upgrade validation failure |
| Parity | $150M | Proxy ownership bug (funds locked permanently) |

## Isolation & Sandboxing

### Core Security Properties
1. **Isolation**: Workload cannot access host resources or adjacent tenants
2. **Least privilege**: Runtime identity scoped to minimum required actions
3. **Constrained side effects**: Filesystem, network, API access explicitly bounded
4. **Ephemerality**: Runtime is short-lived and reset between jobs
5. **Auditability**: Execution logged for incident response

### Enforcement Planes

| Plane | Risks | Required Controls |
|---|---|---|
| Process/syscall | Container escape, host tampering | seccomp, no --privileged, capability drops, AppArmor/SELinux |
| Filesystem | Credential theft, workspace poisoning | Read-only rootfs, isolated workspace, explicit writable mounts |
| Identity | Token abuse, cloud account takeover | Short-lived creds, OIDC federation, scoped IAM |
| Network | Data exfiltration, lateral movement | Default-deny egress, destination allowlist, proxy/inspection |
| Resources | DoS, budget burn | CPU/memory/pids/time limits, quotas, max concurrency |

### Runtime Isolation Levels

| Runtime | Isolation Strength | Best For |
|---|---|---|
| Standard containers | Moderate | Low-risk build/test with strict hardening |
| Hardened containers (rootless + seccomp) | Moderate-strong | Most CI validation |
| Sandboxed containers (gVisor/Kata) | Strong | Untrusted code in shared infra |
| MicroVMs (Firecracker) | Strong | High-risk multi-tenant runners |
| Full VMs | Strongest | Regulated workloads or signing paths |

### Capability-Based Isolation Tiers
- **Tier 1 Validate**: Read repo, execute tests. No deploy, no publish, no production secrets.
- **Tier 2 Build**: Pull from approved registries, upload intermediate artifacts. No release signing keys.
- **Tier 3 Release**: Publish signed artifact, write release metadata, deploy to approved targets only.

### Network Isolation
1. **Default deny egress** — add explicit allow rules only for required destinations
2. Separate trust zones for untrusted / trusted / release pipelines
3. Block cloud metadata endpoints (169.254.169.254) from untrusted jobs
4. Centralize outbound through policy-enforcing gateways/proxies

### Resource Isolation
- CPU/memory limits per job
- Process count (pids) limits
- Filesystem/artifact size limits
- Execution timeout limits
- Concurrency limits per workflow/repository

### 30/60/90 Day Implementation Plan

**Day 30:**
- Split trust zones (untrusted PRs vs protected branches)
- Set CI tokens to least-privilege / read-only defaults
- Disable secrets in fork/untrusted PRs
- Add job timeouts and resource limits

**Day 60:**
- Default-deny egress on all runners
- Deploy seccomp/AppArmor profiles
- Migrate to OIDC short-lived roles (eliminate static cloud keys)

**Day 90:**
- Artifact signing and provenance verification
- Policy-as-code gates for all deployments
- Tabletop exercise: simulate CI/CD pipeline compromise

### Common Failure Modes
- Treating "containerized" as automatically secure
- Running untrusted PR code on persistent/privileged runners
- Reusing static secrets across environments
- Allowing unrestricted egress from build environments
- Granting broad default CI token permissions
