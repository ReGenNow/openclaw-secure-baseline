# OpenClaw Secure Baseline

A **practical security baseline** for running messaging automation safely on personal devices, home labs, and small business environments.

## What This Solves

Messaging bots connected to platforms like iMessage, WhatsApp, Telegram, and Signal face real risks:

- **Spam-triggered automation** — unknown senders causing unintended actions
- **Bot presence detection** — auto-replies revealing your bot exists
- **Enumeration attacks** — different error messages leaking sender status
- **Accidental exposure** — control gateways reachable from LAN/internet
- **Weak defaults** — insecure authentication left enabled

This baseline prevents all of these.

## Core Principles

| Principle | Implementation |
|-----------|----------------|
| **Default Deny** | Unknown senders are blocked, not queued |
| **Silent Drop** | No reply to unknown senders (prevents oracle) |
| **Owner-Initiated Pairing** | Codes generated only when owner acts |
| **Least Privilege** | Approved senders get minimal capabilities |
| **Defense in Depth** | Multiple independent security layers |

## Components

### Message Gatekeeper
Zero-trust sender validation with:
- Sender registry (approved/pending/blocked)
- Owner-initiated pairing flow
- Capability-based access control (RBAC)
- Privacy-safe audit logging (HMAC hashes)

### Gateway Security Check
Regression guard that verifies:
- Gateway bound to localhost only
- Insecure auth flags disabled
- No Docker/proxy exposure

## Quick Start

```bash
# 1. Copy the gatekeeper to your project
cp src/message_gatekeeper.py /your/project/security/

# 2. Set up the CLI wrapper
cp scripts/gatekeeper /your/project/security/
chmod +x /your/project/security/gatekeeper

# 3. Configure your gateway (see examples/)
# Ensure bind = "loopback" and insecure flags = false

# 4. Schedule the security check
cp scripts/gateway-security-check.sh /your/project/security/
chmod +x /your/project/security/gateway-security-check.sh
```

## Documentation

- [`SECURITY.md`](SECURITY.md) — Security policy and principles
- [`docs/security/HARDENING.md`](docs/security/HARDENING.md) — Step-by-step hardening guide

## What This Is NOT

- Not a vulnerability disclosure
- Not an exploit repository
- Not enterprise compliance documentation
- Not a penetration testing guide

## Scope & Assumptions

This baseline assumes:
- Host OS is trusted
- Admin credentials are not compromised
- Physical access is controlled

Threats outside this scope are intentionally excluded.

## Philosophy

> Automation should be secured like an API, not treated like a chat UI.

## License

MIT License — see [LICENSE](LICENSE)
