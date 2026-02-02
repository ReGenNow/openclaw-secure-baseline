# Security Policy & Hardening Guide

This document describes the **recommended security baseline** for running messaging automation safely on personal devices, home networks, and small business environments.

The goal is **practical protection against real-world abuse** (spam, bot enumeration, accidental exposure), not enterprise or nation-state threat models.

---

## Threat Model

This project is designed to mitigate the following common risks:

- Unsolicited SMS/chat spam triggering automation
- Bot enumeration via auto-replies or pairing prompts
- Accidental LAN or internet exposure of control gateways
- Privilege escalation through weak defaults
- Configuration regressions over time

This project **does not** attempt to defend against:

- OS-level compromise
- Malware running as the same user
- Stolen admin credentials
- Physical device access

Those are outside the intended scope.

---

## Security Principles

We follow a **zero-trust messaging model**:

- Messaging platforms are treated as **untrusted network input**
- No sender is trusted by default
- Automation is gated behind explicit authorization
- Secrets remain private; design is safe to be public

This aligns with Kerckhoffs's principle:

> Security should not depend on secrecy of the design.

---

## Required Baseline (Strongly Recommended)

### 1. Gateway Network Binding

The control gateway **MUST** bind to loopback only.

**Allowed:**
- `127.0.0.1:<PORT>`
- `[::1]:<PORT>`

**Disallowed:**
- `0.0.0.0:<PORT>`
- `*:<PORT>`
- `:::<PORT>`

This prevents LAN or internet access to the control plane.

---

### 2. Insecure Authentication Flags

The following options **must be disabled**:

```json
"allowInsecureAuth": false
"dangerouslyDisableDeviceAuth": false
```

Leaving these enabled creates an easy escalation path.

---

### 3. Default-Deny Messaging

- Unknown senders are silently dropped
- No auto-replies
- No pairing prompts
- No status hints

This prevents bot presence detection and enumeration.

---

### 4. Owner-Initiated Pairing Only

Pairing must be started by the owner, not by inbound messages.

**Secure flow:**

1. Unknown sender → logged only
2. Owner reviews unknown attempts
3. Owner explicitly initiates pairing
4. Pairing code shared out-of-band
5. Sender approves with code

Auto-generated pairing replies to unknown senders are **not allowed**.

---

### 5. Capability-Based Access (RBAC)

Approved senders should have least-privilege capabilities.

**Example baseline:**

```
can_chat: true
can_status: true
can_run_jobs: false
can_files: false
can_network: false
can_admin: false
```

Elevated permissions must be granted intentionally.

---

### 6. Confirmation for Risky Actions

Actions with side effects (jobs, files, network, money) should require:

- Explicit confirmation
- Short-lived tokens
- Single-use approval

This prevents accidental execution and prompt-injection style abuse.

---

### 7. Audit Logging (Privacy-Safe)

- All security decisions should be logged
- Sender identifiers must be hashed (HMAC recommended)
- Secrets must never be logged
- Message bodies should be avoided unless strictly necessary

---

## Regression Protection (Strongly Recommended)

Configuration mistakes are the most common cause of security failures.

A boot-time or scheduled security self-check should verify:

- Gateway bind is loopback-only
- Insecure auth flags are disabled
- No Docker or proxy port publishing exists
- The correct config file is loaded

**Fail fast** if any check does not pass.

---

## What Is Safe to Publish

- Architecture and threat model
- Hardening checklist
- Gatekeeper logic
- Security scripts
- Capability model

## What Must Remain Private

- Secret keys
- Pairing codes
- Sender identifiers
- Internal network topology
- Deployment-specific credentials

---

## Reporting Security Issues

If you discover a security issue:

- Do not open a public issue with sensitive details
- Contact the project maintainer privately
- Include steps to reproduce and impact assessment

Responsible disclosure is appreciated.

---

## Disclaimer

This project provides a practical security baseline suitable for personal and small-scale deployments.

It is **not** a substitute for enterprise security reviews, formal audits, or regulatory compliance requirements.

---

## Summary

If you follow the baseline in this document:

- Messaging cannot trigger automation without approval
- Control gateways are not reachable from the network
- Privileges are limited by default
- Common real-world abuse is prevented

This is the intended security posture.
