# Wallet Security Reference (SEAL Framework)

## Wallet Types

### Cold vs Hot
- **Cold wallets**: Hardware, paper, air-gapped, brain, account abstraction, multisig
  - For long-term, high-security storage
  - Even cold wallets become "hot" when connected via USB
- **Hot wallets**: Browser extensions, mobile apps
  - For daily transactions only
  - Minimize balance — transfer from cold as needed

### Custodial vs Non-Custodial
- **Custodial** (CEX): Third-party manages keys. Recovery possible. Counterparty risk (exchange hack, freeze, insolvency).
- **Non-custodial**: You control keys. No counterparty risk. Full responsibility for backup and recovery.

## Hardware Wallet Selection Criteria
1. **Large screen** — verify transaction details on device
2. **Touch screen PIN** — prevent keylogger capture
3. **Brute force protection** — device wipe after failed attempts
4. **Open source firmware** — auditable
5. **Secure Element (EAL6+)** — tamper-resistant chip
6. **Brand diversification** — use different brands for multisig signers
7. Purchase **direct from manufacturer** only
8. Verify **tamper-resistant packaging**
9. Strong PIN: **6+ digits**
10. Generate **new keys on device** (never import)
11. **Clear Signing** support required
12. Maintain a **backup device**

## Seed Phrase Management

### Secure Storage
- **3-piece split method**: divide seed into 3 overlapping pieces, each stored separately
- **Tamper-evident bags**: detect physical access attempts
- **Metal backup**: fire/water resistant seed storage

### PROHIBITED
- Digital storage (files, notes apps)
- Cloud backup (iCloud, Google Drive, Dropbox)
- Photos of seed phrase
- Email or messaging apps
- Password managers (for seed phrases specifically)

### Advanced Methods
- **Shamir's Secret Sharing**: Split into N shares, require K to reconstruct
- **Trezor Multi-Share Backup**: Device-native Shamir implementation

### Maintenance
- **Audit every 6 months**: verify physical integrity, access, tamper evidence
- Key rotation on ANY suspicion of compromise
- **Succession planning**: trusted contacts, code words, documented procedures
- Emergency access plan: who can access funds if you're incapacitated

## Multisig Best Practices

### General Rules
- **Minimum 3 signers**
- **50% threshold** (e.g., 2-of-3, 3-of-5)
- **7+ signers for $1M+ assets**
- **Hardware wallets mandatory** for all signers
- Strategic signer distribution (geographic, organizational)
- Role diversity (not all same team/company)
- Include external parties for independence

### Communication
- **Out-of-band verification** for all transactions
- **2+ communication channels** (e.g., Signal + in-person)
- Never rely solely on the platform where the transaction was initiated

### Operations
- Signer rotation procedures documented
- Regular training and simulation drills
- Key revocation process for departing signers

### Setup
- **Test on testnet first**
- Implement **timelocks** for large transactions
- **Veto quorum** — ability to block suspicious transactions
- **RBAC** — role-based access control for different operation types
- **Disaster recovery plan** documented and tested

### Contract-Level Security
- Invariant enforcement (balance checks, rate limiting)
- Address whitelisting for large transfers
- Module restrictions

## Signing & Verification

### Core Principles
1. **NEVER sign blindly** — understand every transaction before signing
2. **Verify Don't Trust** — independently verify all parameters
3. **Simulate Before Signing** — but simulations CAN be spoofed
4. **Hardware Wallet is Source of Truth** — what the device shows is what you sign
5. **Demand Clear Signing** — reject if device can't display human-readable details

### Standard Transactions (EOA)
Verify before signing:
1. Origin URL (is this the real website?)
2. Smart contract address (cross-reference official docs + block explorer)
3. Function name and parameters (is this what you intend?)
4. Gas fees (abnormally high gas = potential attack)

### Multisig Transactions (Safe)
**Phase 1 — Off-chain signing (EIP-712):**
1. Compare SafeTxHash from local tool with hardware wallet display
2. Verify all transaction parameters match expected values
3. All signers verify on 2+ independent devices

**Phase 2 — On-chain execution:**
1. Decode calldata independently
2. Confirm all parameters match Phase 1
3. **Beware DELEGATECALL** — executes foreign code in your contract's context
4. At least 2 signers must simulate the transaction

**Verification tools:**
- safe-tx-hashes-util (CLI)
- OpenZeppelin Safe Utils
- Cyfrin Safe TX Hashes
- Tenderly simulation
- SwissKnife calldata decoder

### EIP-7702 Transactions
- **Type 0x04**: Allows EOAs to temporarily act as smart contracts
- **Benefits**: Transaction batching, gas sponsorship, privilege de-escalation
- **Risks**:
  - Phishing for SetCode delegation (attacker gains code execution in your account)
  - Multi-chain replay attacks when chain ID = 0 (delegation valid on ALL chains)
- **Rules**: Only delegate to contracts vetted by your wallet provider
- **Revocation**: Set delegation to zero address (0x0)

## Smart Contract Interaction Security

### Token Approvals
- Set **exact amounts** (not unlimited/max uint256)
- **Revoke unused approvals** regularly
- Audit all active approvals periodically
- Tools: Revoke.cash, Etherscan token approval checker

### Permit (EIP-2612)
- Gasless approval — **higher risk** because no on-chain transaction to notice
- Review permit parameters carefully before signing
- Check spender address and amount

### MEV Protection
- Slippage tolerance: 0.5-1% for liquid pairs
- Use **Flashbots Protect** or **MEV Blocker** for private transaction submission
- Avoid broadcasting transactions to public mempool for large trades

### Attack Patterns to Watch
- **Address poisoning**: Attacker sends tiny tx from similar-looking address, hoping you copy-paste it
- **Clipboard malware**: Replaces copied addresses with attacker's address
- **Fake airdrops**: Tokens that execute malicious code when you try to sell/transfer
- **Ice phishing**: Trick into signing approval to attacker-controlled address

## Wallet Tools & Resources

### Selection
- ethereum.org/wallets — official wallet finder
- Wallet Scrutiny — open source verification
- Wallet Security Ranking — comparative security analysis
- Wallet Beat — feature comparison

### Browser Security
- **Rabby Wallet** — security-focused browser wallet
- **MetaMask** with security Snaps (Tenderly, Forta)

### Transaction Simulation
- Tenderly — simulate before signing
- Alchemy — transaction preview

### Monitoring
- Safe Watcher — multisig monitoring
- DeFi DNS Whitelist — known-good domain list
- Little Snitch / Lulu (macOS) — outbound connection monitoring
- Glasswire (Windows) — network monitoring

### Verification
- safe-tx-hashes-util �� Safe transaction hash verification
- Cyfrin Safe TX Hashes — independent hash verification
- Safe Utils (OpenZeppelin) — multisig utilities
