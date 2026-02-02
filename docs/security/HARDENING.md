# Message Gatekeeper Hardening Guide

This guide provides step-by-step instructions for implementing zero-trust sender validation to prevent unauthorized message-triggered automation.

---

## Overview

The Message Gatekeeper sits between your messaging platforms and automation bot:

```
┌─────────────────────────────────────────────────────────────────┐
│                    MESSAGING PLATFORMS                          │
│            (iMessage, WhatsApp, Telegram, Signal)               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   MESSAGE GATEKEEPER                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │   Sender    │  │  Pairing    │  │ Capability  │             │
│  │  Registry   │  │   System    │  │    RBAC     │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
│  ┌─────────────┐  ┌─────────────┐                              │
│  │   Audit     │  │   Abuse     │                              │
│  │   Logging   │  │  Controls   │                              │
│  └─────────────┘  └─────────────┘                              │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼ (allowed only)
┌─────────────────────────────────────────────────────────────────┐
│                    AUTOMATION BOT                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## Sender States

The gatekeeper maintains four sender states:

| State | Description | Action |
|-------|-------------|--------|
| `unknown` | Never seen before | Silent drop, log attempt |
| `pending` | Owner initiated pairing | Awaiting code confirmation |
| `approved` | Verified and trusted | Process with capabilities |
| `blocked` | Explicitly denied | Silent drop |

---

## Pairing Flow (Owner-Initiated)

**Critical**: Pairing codes are NEVER generated automatically in response to unknown messages.

### Step 1: Unknown Sender Contacts Bot

```
Unknown sender → Message arrives
                → Gatekeeper: check_sender()
                → Result: {allowed: false, status: "unknown"}
                → Action: SILENT DROP (no reply)
                → Log: attempt recorded for owner review
```

### Step 2: Owner Reviews Unknown Attempts

```bash
./gatekeeper list-unknown --since 24h
```

Owner decides which senders to trust based on context.

### Step 3: Owner Initiates Pairing

```bash
./gatekeeper initiate <platform> <sender_id> --name "Contact Name"
```

This generates a time-limited pairing code (e.g., `ALPHA-1234`).

### Step 4: Code Shared Out-of-Band

Owner shares the code via:
- Phone call
- Email
- In-person
- Any channel OTHER than the messaging platform

**Never auto-send pairing codes** — this defeats the security model.

### Step 5: Sender Confirms

Sender provides the code to the bot. If valid:
- Sender moves to `approved` state
- Default capabilities applied
- Future messages processed

---

## Capability Model (RBAC)

Not all approved senders should have equal power.

### Default Capabilities (Least Privilege)

```python
DEFAULT_CAPABILITIES = {
    "can_chat": True,       # Basic conversation
    "can_status": True,     # Query status/info
    "can_run_jobs": False,  # Execute automation
    "can_files": False,     # Access files
    "can_network": False,   # Network operations
    "can_admin": False,     # Admin commands
}
```

### Granting Elevated Access

At pairing time:
```bash
./gatekeeper initiate telegram user_123 --name "Admin" --can-run-jobs --can-admin
```

After approval:
```bash
./gatekeeper set-caps telegram user_123 --can-run-jobs true
```

### Checking Capabilities in Your Bot

```python
result = gatekeeper.check_sender(platform, sender_id)

if not result.allowed:
    return  # Silent drop

# Check capability before action
if action == "run_job":
    if not result.capabilities.get("can_run_jobs"):
        reply("Permission denied")
        return

    # Execute action...
```

---

## Gateway Hardening

### Required Configuration

Your gateway configuration must include:

```json
{
  "gateway": {
    "bind": "loopback",
    "controlUi": {
      "allowInsecureAuth": false,
      "dangerouslyDisableDeviceAuth": false
    }
  }
}
```

### Bind Modes

| Mode | Result | Security |
|------|--------|----------|
| `loopback` | `127.0.0.1` | Safe |
| `lan` | `0.0.0.0` | **DANGEROUS** |

Always use `loopback`.

### Verification

Run the security check:

```bash
./gateway-security-check.sh
```

Expected output:
```
[PASS] Config bind = loopback
[PASS] allowInsecureAuth = false
[PASS] dangerouslyDisableDeviceAuth = false
[PASS] Gateway bound to localhost only
```

---

## Audit Logging

### What to Log

- Security decisions (allow/deny)
- Pairing lifecycle events
- Capability changes
- Block/unblock actions

### Privacy Protection

**Never log:**
- Raw sender identifiers
- Pairing codes
- Message content
- Secrets

**Always log:**
- HMAC-hashed sender IDs
- Timestamps
- Action types
- Sanitized metadata

### Example Log Entry

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "action": "CHECK_ALLOWED",
  "platform": "telegram",
  "sender_hash": "a1b2c3d4e5f6g7h8",
  "status": "approved"
}
```

---

## Regression Guard

Configuration mistakes are the #1 cause of security failures.

### What the Guard Checks

1. **Config values**: bind mode, auth flags
2. **Actual listener**: not bound to wildcard
3. **Docker exposure**: no `0.0.0.0:PORT` publishing

### Scheduling

Run at boot and/or daily:

```bash
# Example cron entry
0 6 * * * /path/to/gateway-security-check.sh >> /var/log/gateway-security.log 2>&1
```

### Fail-Fast Behavior

If any check fails, the script exits with code 1. Use this to block startup if needed.

---

## File Security

### Sensitive Files (NEVER commit)

| File | Contains | Permissions |
|------|----------|-------------|
| `.gatekeeper-secret` | HMAC key | `0600` |
| `sender-registry.json` | Phone numbers, IDs | `0600` |
| `gatekeeper-audit.log` | Activity log | `0644` |
| `*.lock` | Lock files | `0644` |

### Required .gitignore

```gitignore
# Secrets and runtime state
.gatekeeper-secret
sender-registry.json
sender-registry.lock
*-audit.log

# OS artifacts
.DS_Store
__pycache__/
```

---

## Platform-Specific Notes

### Phone Number Normalization

For iMessage, WhatsApp, Signal:
- Store in E.164 format: `+15551234567`
- Strip formatting before lookup
- Always include country code

### Telegram IDs

- Prefer numeric user ID over username
- Usernames can change; IDs are stable
- Format: `user_123456789`

---

## Operational Checklist

### Daily/Weekly

- [ ] Review `list-unknown` for legitimate contacts
- [ ] Check security guard logs for failures

### Monthly

- [ ] Audit approved sender list
- [ ] Review elevated capabilities
- [ ] Remove unused approvals

### After Updates

- [ ] Run security check
- [ ] Verify config wasn't reset
- [ ] Check listener binding

---

## Troubleshooting

### "Gateway still bound to 0.0.0.0"

1. Check correct config file is loaded
2. Restart the gateway service
3. Verify with `lsof -nP -iTCP:<PORT> -sTCP:LISTEN`

### "Pairing code not working"

1. Check code hasn't expired (24h default)
2. Check attempt limit not exceeded (5 default)
3. Verify sender ID format matches

### "Approved sender being rejected"

1. Check sender isn't also in blocked list
2. Verify sender ID normalization
3. Check registry file permissions

---

## Summary

A properly hardened setup ensures:

- Unknown senders cannot trigger automation
- Control plane is not network-accessible
- Privileges are minimal by default
- Regressions are detected early

This is the baseline for safe messaging automation.
