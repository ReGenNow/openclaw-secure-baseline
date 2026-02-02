#!/usr/bin/env python3
"""
Message Gatekeeper - Zero-trust sender validation for messaging platforms.

Enforces default-deny for unknown senders across all platforms with
OWNER-INITIATED pairing using memorable codes.

SECURITY MODEL:
- Unknown senders are logged and denied (no auto-reply with codes)
- Owner must explicitly initiate pairing via CLI
- Pairing codes are never sent automatically to prevent bot presence oracle

Environment Variables:
    GATEKEEPER_REGISTRY     Path to sender registry JSON file
    GATEKEEPER_AUDIT_LOG    Path to audit log file
    GATEKEEPER_SECRET       Path to HMAC secret file
    GATEKEEPER_EXPIRY_HOURS Pairing code expiry (default: 24)

Usage:
    ./gatekeeper check <platform> <sender_id>
    ./gatekeeper initiate <platform> <sender_id> [--name "Name"]
    ./gatekeeper approve <platform> <sender_id> <code>
    ./gatekeeper block <platform> <sender_id> [--reason "..."]
    ./gatekeeper unblock <platform> <sender_id>
    ./gatekeeper set-caps <platform> <sender_id> --can-run-jobs true
    ./gatekeeper list-pending
    ./gatekeeper list-approved [--platform telegram]
    ./gatekeeper list-blocked
    ./gatekeeper list-unknown [--since 1h]
    ./gatekeeper stats
    ./gatekeeper expire
"""

import os
import sys
import json
import hmac
import hashlib
import secrets
import argparse
import re
import fcntl
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional, Dict, List
from enum import Enum

# NATO phonetic alphabet words for memorable codes
NATO_WORDS = [
    "ALPHA", "BRAVO", "CHARLIE", "DELTA", "ECHO", "FOXTROT",
    "GOLF", "HOTEL", "INDIA", "JULIET", "KILO", "LIMA",
    "MIKE", "NOVEMBER", "OSCAR", "PAPA", "QUEBEC", "ROMEO"
]

SUPPORTED_PLATFORMS = ["imessage", "whatsapp", "telegram", "signal"]
MAX_APPROVAL_ATTEMPTS = 5
MAX_PENDING_PER_PLATFORM = 100
MAX_UNKNOWN_LOG_ENTRIES = 1000

# Default capabilities for new approved senders (least privilege)
DEFAULT_CAPABILITIES = {
    "can_chat": True,
    "can_status": True,
    "can_run_jobs": False,
    "can_files": False,
    "can_network": False,
    "can_admin": False,
}


def get_default_paths():
    """Get default file paths from environment or sensible defaults."""
    base_dir = Path(os.environ.get("GATEKEEPER_BASE_DIR", Path.home() / ".gatekeeper"))
    return {
        "registry": Path(os.environ.get("GATEKEEPER_REGISTRY", base_dir / "sender-registry.json")),
        "audit_log": Path(os.environ.get("GATEKEEPER_AUDIT_LOG", base_dir / "gatekeeper-audit.log")),
        "secret": Path(os.environ.get("GATEKEEPER_SECRET", base_dir / ".gatekeeper-secret")),
        "expiry_hours": int(os.environ.get("GATEKEEPER_EXPIRY_HOURS", "24")),
    }


class SenderStatus(Enum):
    APPROVED = "approved"
    PENDING = "pending"
    BLOCKED = "blocked"
    UNKNOWN = "unknown"


@dataclass
class CheckResult:
    """Result of checking a sender's authorization status."""
    allowed: bool
    status: str
    requires_pairing: bool
    pairing_code: Optional[str] = None
    message: str = ""
    sender_name: Optional[str] = None
    capabilities: Optional[Dict[str, bool]] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


class MessageGatekeeper:
    """Zero-trust message sender validation with owner-initiated pairing."""

    def __init__(self, registry_path: Optional[Path] = None,
                 audit_log_path: Optional[Path] = None,
                 secret_path: Optional[Path] = None,
                 expiry_hours: Optional[int] = None):
        paths = get_default_paths()
        self.registry_path = registry_path or paths["registry"]
        self.audit_log_path = audit_log_path or paths["audit_log"]
        self.secret_path = secret_path or paths["secret"]
        self.expiry_hours = expiry_hours or paths["expiry_hours"]
        self._registry = None
        self._hmac_secret = None
        self._lock_fd = None

    def _get_hmac_secret(self) -> bytes:
        """Get or create HMAC secret for audit log hashing."""
        if self._hmac_secret is not None:
            return self._hmac_secret

        if self.secret_path.exists():
            self._hmac_secret = self.secret_path.read_bytes()
        else:
            self._hmac_secret = secrets.token_bytes(32)
            self.secret_path.parent.mkdir(parents=True, exist_ok=True)
            self.secret_path.write_bytes(self._hmac_secret)
            os.chmod(self.secret_path, 0o600)

        return self._hmac_secret

    def _acquire_lock(self):
        """Acquire exclusive lock on registry file."""
        lock_path = self.registry_path.with_suffix('.lock')
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_fd = open(lock_path, 'w')
        fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_EX)

    def _release_lock(self):
        """Release registry file lock."""
        if self._lock_fd:
            fcntl.flock(self._lock_fd.fileno(), fcntl.LOCK_UN)
            self._lock_fd.close()
            self._lock_fd = None

    @property
    def registry(self) -> Dict:
        """Lazy-load registry."""
        if self._registry is None:
            self._registry = self._load_registry()
        return self._registry

    def _load_registry(self) -> Dict:
        """Load registry from disk or create empty one."""
        if self.registry_path.exists():
            try:
                with open(self.registry_path, 'r') as f:
                    data = json.load(f)
                    if "unknown_log" not in data:
                        data["unknown_log"] = []
                    return data
            except (json.JSONDecodeError, IOError) as e:
                self._audit("REGISTRY_LOAD_ERROR", error=str(e))
                return self._empty_registry()
        return self._empty_registry()

    def _empty_registry(self) -> Dict:
        """Create empty registry structure."""
        now = datetime.now(timezone.utc).isoformat()
        return {
            "meta": {
                "version": "1.1",
                "created": now,
                "last_modified": now
            },
            "approved": {platform: {} for platform in SUPPORTED_PLATFORMS},
            "pending": {platform: {} for platform in SUPPORTED_PLATFORMS},
            "blocked": {platform: {} for platform in SUPPORTED_PLATFORMS},
            "unknown_log": []
        }

    def _save_registry(self):
        """Save registry atomically with file locking."""
        self.registry["meta"]["last_modified"] = datetime.now(timezone.utc).isoformat()
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)

        self._acquire_lock()
        try:
            temp_path = self.registry_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(self.registry, f, indent=2)
            os.chmod(temp_path, 0o600)
            temp_path.rename(self.registry_path)
        finally:
            self._release_lock()

    def _audit(self, action: str, platform: str = None, sender_id: str = None, **extra):
        """Write audit log entry with HMAC-hashed sender ID."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action
        }
        if platform:
            entry["platform"] = platform
        if sender_id:
            entry["sender_hash"] = self._hash_sender(platform or "", sender_id)
        entry.update(extra)

        self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.audit_log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def _hash_sender(self, platform: str, sender_id: str) -> str:
        """HMAC-hash sender ID for privacy (not dictionary-reversible)."""
        secret = self._get_hmac_secret()
        msg = f"{platform}:{sender_id}".encode()
        return hmac.new(secret, msg, hashlib.sha256).hexdigest()[:16]

    def _normalize_sender(self, platform: str, sender_id: str) -> str:
        """Normalize sender ID format per platform (E.164 for phones)."""
        sender_id = sender_id.strip()

        if platform in ["imessage", "whatsapp", "signal"]:
            if sender_id.startswith('+'):
                return '+' + re.sub(r'[^\d]', '', sender_id[1:])
            digits = re.sub(r'[^\d]', '', sender_id)
            if len(digits) >= 10:
                return '+' + digits
            return sender_id

        if platform == "telegram":
            if sender_id.isdigit():
                return f"user_{sender_id}"
            if sender_id.startswith('user_'):
                return sender_id
            if sender_id.startswith('@'):
                return sender_id.lower()
            return sender_id

        return sender_id

    def _generate_pairing_code(self) -> str:
        """Generate memorable pairing code: WORD-NNNN (cryptographic RNG)."""
        word = secrets.choice(NATO_WORDS)
        number = secrets.randbelow(9000) + 1000
        return f"{word}-{number}"

    def _validate_platform(self, platform: str) -> str:
        """Validate and normalize platform name."""
        platform = platform.lower().strip()
        if platform not in SUPPORTED_PLATFORMS:
            raise ValueError(f"Unsupported platform: {platform}. Supported: {', '.join(SUPPORTED_PLATFORMS)}")
        return platform

    def _log_unknown_sender(self, platform: str, sender_id: str):
        """Log unknown sender attempt (for owner review)."""
        now = datetime.now(timezone.utc).isoformat()
        self.registry["unknown_log"].append({
            "platform": platform,
            "sender_id": sender_id,
            "timestamp": now
        })
        if len(self.registry["unknown_log"]) > MAX_UNKNOWN_LOG_ENTRIES:
            self.registry["unknown_log"] = self.registry["unknown_log"][-MAX_UNKNOWN_LOG_ENTRIES:]
        self._save_registry()

    def check_sender(self, platform: str, sender_id: str) -> CheckResult:
        """
        Check if sender is authorized.

        SECURITY: Unknown senders are logged but NO pairing code is generated.
        Owner must explicitly call initiate_pairing() to start pairing.
        """
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        # Check blocked first
        blocked = self.registry["blocked"].get(platform, {})
        if sender_id in blocked:
            self._audit("CHECK_BLOCKED", platform, sender_id)
            return CheckResult(
                allowed=False,
                status=SenderStatus.BLOCKED.value,
                requires_pairing=False,
                message="Not authorized"
            )

        # Check approved
        approved = self.registry["approved"].get(platform, {})
        if sender_id in approved:
            self._audit("CHECK_ALLOWED", platform, sender_id, status="approved")
            caps = approved[sender_id].get("capabilities", DEFAULT_CAPABILITIES.copy())
            return CheckResult(
                allowed=True,
                status=SenderStatus.APPROVED.value,
                requires_pairing=False,
                sender_name=approved[sender_id].get("name"),
                capabilities=caps,
                message="Sender is approved"
            )

        # Check pending
        pending = self.registry["pending"].get(platform, {})
        if sender_id in pending:
            entry = pending[sender_id]
            expires_at = datetime.fromisoformat(entry["expires_at"])

            if datetime.now(timezone.utc) > expires_at:
                del self.registry["pending"][platform][sender_id]
                self._save_registry()
                self._audit("PAIRING_EXPIRED", platform, sender_id)
            else:
                self._audit("CHECK_PENDING", platform, sender_id)
                return CheckResult(
                    allowed=False,
                    status=SenderStatus.PENDING.value,
                    requires_pairing=True,
                    pairing_code=entry["pairing_code"],
                    message=f"Pairing pending. Code: {entry['pairing_code']}"
                )

        # Unknown sender - LOG ONLY, no auto-pairing
        self._log_unknown_sender(platform, sender_id)
        self._audit("CHECK_UNKNOWN", platform, sender_id)

        return CheckResult(
            allowed=False,
            status=SenderStatus.UNKNOWN.value,
            requires_pairing=True,
            message="Not authorized"
        )

    def initiate_pairing(self, platform: str, sender_id: str, name: str = None,
                         capabilities: Dict[str, bool] = None) -> Dict:
        """
        OWNER-INITIATED pairing. Creates pending entry with code.
        """
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        if sender_id in self.registry["approved"].get(platform, {}):
            return {"success": False, "error": "Sender is already approved"}

        if sender_id in self.registry["blocked"].get(platform, {}):
            return {"success": False, "error": "Sender is blocked. Unblock first."}

        pending = self.registry["pending"].get(platform, {})
        if len(pending) >= MAX_PENDING_PER_PLATFORM:
            return {"success": False, "error": f"Too many pending requests. Run 'expire' to clean up."}

        if sender_id in pending:
            entry = pending[sender_id]
            return {
                "success": True,
                "message": "Pairing already pending",
                "pairing_code": entry["pairing_code"],
                "expires_at": entry["expires_at"],
                "sender_id": sender_id,
                "platform": platform
            }

        pairing_code = self._generate_pairing_code()
        expires_at = datetime.now(timezone.utc) + timedelta(hours=self.expiry_hours)
        caps = capabilities if capabilities else DEFAULT_CAPABILITIES.copy()

        if platform not in self.registry["pending"]:
            self.registry["pending"][platform] = {}

        self.registry["pending"][platform][sender_id] = {
            "pairing_code": pairing_code,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "approval_attempts": 0,
            "name": name,
            "capabilities": caps
        }
        self._save_registry()
        self._audit("PAIRING_INITIATED", platform, sender_id, name=name)

        return {
            "success": True,
            "message": "Pairing initiated. Share this code with the sender.",
            "pairing_code": pairing_code,
            "expires_at": expires_at.isoformat(),
            "sender_id": sender_id,
            "platform": platform,
            "name": name
        }

    def approve_sender(self, platform: str, sender_id: str, pairing_code: str) -> Dict:
        """Approve a sender with their pairing code."""
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        pending = self.registry["pending"].get(platform, {})

        if sender_id not in pending:
            self._audit("APPROVAL_FAILED", platform, sender_id, reason="not_pending")
            return {"success": False, "error": "No pending pairing request"}

        entry = pending[sender_id]

        if datetime.now(timezone.utc) > datetime.fromisoformat(entry["expires_at"]):
            del self.registry["pending"][platform][sender_id]
            self._save_registry()
            self._audit("APPROVAL_FAILED", platform, sender_id, reason="expired")
            return {"success": False, "error": "Pairing request expired"}

        attempts = entry.get("approval_attempts", 0)
        if attempts >= MAX_APPROVAL_ATTEMPTS:
            del self.registry["pending"][platform][sender_id]
            self._save_registry()
            self._audit("APPROVAL_FAILED", platform, sender_id, reason="max_attempts")
            return {"success": False, "error": "Too many failed attempts"}

        if entry["pairing_code"].upper() != pairing_code.upper():
            entry["approval_attempts"] = attempts + 1
            self._save_registry()
            remaining = MAX_APPROVAL_ATTEMPTS - entry["approval_attempts"]
            self._audit("APPROVAL_FAILED", platform, sender_id, reason="wrong_code", attempts_remaining=remaining)
            return {"success": False, "error": f"Invalid code. {remaining} attempts remaining."}

        # Success
        now = datetime.now(timezone.utc).isoformat()
        name = entry.get("name")
        caps = entry.get("capabilities", DEFAULT_CAPABILITIES.copy())

        if platform not in self.registry["approved"]:
            self.registry["approved"][platform] = {}

        self.registry["approved"][platform][sender_id] = {
            "approved_at": now,
            "paired_at": entry["created_at"],
            "capabilities": caps
        }
        if name:
            self.registry["approved"][platform][sender_id]["name"] = name

        del self.registry["pending"][platform][sender_id]
        self._save_registry()
        self._audit("SENDER_APPROVED", platform, sender_id, name=name)

        return {
            "success": True,
            "message": f"Approved" + (f" as '{name}'" if name else ""),
            "sender_id": sender_id,
            "platform": platform
        }

    def block_sender(self, platform: str, sender_id: str, reason: str = None) -> Dict:
        """Block a sender from sending messages."""
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        now = datetime.now(timezone.utc).isoformat()

        if platform not in self.registry["blocked"]:
            self.registry["blocked"][platform] = {}

        self.registry["blocked"][platform][sender_id] = {
            "blocked_at": now,
            "reason": reason or "Manual block"
        }

        if sender_id in self.registry["approved"].get(platform, {}):
            del self.registry["approved"][platform][sender_id]
        if sender_id in self.registry["pending"].get(platform, {}):
            del self.registry["pending"][platform][sender_id]

        self._save_registry()
        self._audit("SENDER_BLOCKED", platform, sender_id, reason=reason)

        return {
            "success": True,
            "message": "Sender blocked",
            "sender_id": sender_id,
            "platform": platform,
            "reason": reason
        }

    def unblock_sender(self, platform: str, sender_id: str) -> Dict:
        """Unblock a previously blocked sender."""
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        blocked = self.registry["blocked"].get(platform, {})

        if sender_id not in blocked:
            return {"success": False, "error": "Sender is not blocked"}

        del self.registry["blocked"][platform][sender_id]
        self._save_registry()
        self._audit("SENDER_UNBLOCKED", platform, sender_id)

        return {
            "success": True,
            "message": "Sender unblocked. Use 'initiate' to start pairing.",
            "sender_id": sender_id,
            "platform": platform
        }

    def set_capabilities(self, platform: str, sender_id: str, capabilities: Dict[str, bool]) -> Dict:
        """Update capabilities for an approved sender."""
        platform = self._validate_platform(platform)
        sender_id = self._normalize_sender(platform, sender_id)

        approved = self.registry["approved"].get(platform, {})

        if sender_id not in approved:
            return {"success": False, "error": "Sender is not approved"}

        current_caps = approved[sender_id].get("capabilities", DEFAULT_CAPABILITIES.copy())
        current_caps.update(capabilities)
        approved[sender_id]["capabilities"] = current_caps
        self._save_registry()

        self._audit("CAPABILITIES_UPDATED", platform, sender_id, capabilities=list(capabilities.keys()))

        return {
            "success": True,
            "message": "Capabilities updated",
            "sender_id": sender_id,
            "platform": platform,
            "capabilities": current_caps
        }

    def list_pending(self) -> List[Dict]:
        """List all pending pairing requests."""
        result = []
        now = datetime.now(timezone.utc)

        for platform, senders in self.registry["pending"].items():
            for sender_id, entry in senders.items():
                expires_at = datetime.fromisoformat(entry["expires_at"])
                remaining = expires_at - now

                result.append({
                    "platform": platform,
                    "sender_id": sender_id,
                    "name": entry.get("name"),
                    "pairing_code": entry["pairing_code"],
                    "created_at": entry["created_at"],
                    "expires_at": entry["expires_at"],
                    "expires_in": str(remaining).split('.')[0] if remaining.total_seconds() > 0 else "EXPIRED",
                    "attempts": entry.get("approval_attempts", 0)
                })

        return sorted(result, key=lambda x: x["expires_at"])

    def list_approved(self, platform: str = None) -> List[Dict]:
        """List approved senders."""
        result = []
        platforms = [platform] if platform else SUPPORTED_PLATFORMS

        for plat in platforms:
            if platform:
                plat = self._validate_platform(plat)

            for sender_id, entry in self.registry["approved"].get(plat, {}).items():
                result.append({
                    "platform": plat,
                    "sender_id": sender_id,
                    "name": entry.get("name"),
                    "approved_at": entry["approved_at"]
                })

        return sorted(result, key=lambda x: (x["platform"], x.get("name") or x["sender_id"]))

    def list_blocked(self) -> List[Dict]:
        """List all blocked senders."""
        result = []

        for platform, senders in self.registry["blocked"].items():
            for sender_id, entry in senders.items():
                result.append({
                    "platform": platform,
                    "sender_id": sender_id,
                    "reason": entry.get("reason"),
                    "blocked_at": entry["blocked_at"]
                })

        return sorted(result, key=lambda x: x["blocked_at"], reverse=True)

    def list_unknown(self, since_hours: float = None) -> List[Dict]:
        """List unknown sender attempts."""
        result = []
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=since_hours) if since_hours else None

        for entry in self.registry.get("unknown_log", []):
            ts = datetime.fromisoformat(entry["timestamp"])
            if cutoff and ts < cutoff:
                continue

            result.append({
                "platform": entry["platform"],
                "sender_id": entry["sender_id"],
                "timestamp": entry["timestamp"],
                "age": str(now - ts).split('.')[0]
            })

        return sorted(result, key=lambda x: x["timestamp"], reverse=True)

    def expire_pending(self) -> int:
        """Remove expired pending requests."""
        now = datetime.now(timezone.utc)
        expired_count = 0

        for platform in SUPPORTED_PLATFORMS:
            pending = self.registry["pending"].get(platform, {})
            expired = []

            for sender_id, entry in pending.items():
                expires_at = datetime.fromisoformat(entry["expires_at"])
                if now > expires_at:
                    expired.append(sender_id)

            for sender_id in expired:
                del self.registry["pending"][platform][sender_id]
                self._audit("PAIRING_EXPIRED", platform, sender_id)
                expired_count += 1

        if expired_count > 0:
            self._save_registry()

        return expired_count

    def stats(self) -> Dict:
        """Get statistics about the registry."""
        approved_count = sum(len(s) for s in self.registry["approved"].values())
        pending_count = sum(len(s) for s in self.registry["pending"].values())
        blocked_count = sum(len(s) for s in self.registry["blocked"].values())
        unknown_count = len(self.registry.get("unknown_log", []))

        by_platform = {}
        for platform in SUPPORTED_PLATFORMS:
            by_platform[platform] = {
                "approved": len(self.registry["approved"].get(platform, {})),
                "pending": len(self.registry["pending"].get(platform, {})),
                "blocked": len(self.registry["blocked"].get(platform, {}))
            }

        return {
            "total": {
                "approved": approved_count,
                "pending": pending_count,
                "blocked": blocked_count,
                "unknown_attempts": unknown_count
            },
            "by_platform": by_platform,
            "registry_version": self.registry["meta"]["version"],
            "last_modified": self.registry["meta"]["last_modified"]
        }


def format_table(rows: List[Dict], columns: List[str]) -> str:
    """Format data as ASCII table."""
    if not rows:
        return "(no data)"

    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, "") or "")
            widths[col] = max(widths[col], min(len(val), 40))

    lines = []
    header = " | ".join(col.upper().ljust(widths[col]) for col in columns)
    lines.append(header)
    lines.append("-+-".join("-" * widths[col] for col in columns))

    for row in rows:
        cells = []
        for col in columns:
            val = str(row.get(col, "") or "")
            if len(val) > 40:
                val = val[:37] + "..."
            cells.append(val.ljust(widths[col]))
        lines.append(" | ".join(cells))

    return "\n".join(lines)


def parse_duration(s: str) -> float:
    """Parse duration string like '1h', '30m', '2d' to hours."""
    s = s.strip().lower()
    if s.endswith('h'):
        return float(s[:-1])
    if s.endswith('m'):
        return float(s[:-1]) / 60
    if s.endswith('d'):
        return float(s[:-1]) * 24
    return float(s)


def main():
    parser = argparse.ArgumentParser(
        description="Message Gatekeeper - Zero-trust sender validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # check
    check_p = subparsers.add_parser("check", help="Check if sender is allowed")
    check_p.add_argument("platform", help="Platform (imessage, whatsapp, telegram, signal)")
    check_p.add_argument("sender_id", help="Sender identifier")

    # initiate
    init_p = subparsers.add_parser("initiate", help="Initiate pairing (owner action)")
    init_p.add_argument("platform", help="Platform")
    init_p.add_argument("sender_id", help="Sender identifier")
    init_p.add_argument("--name", help="Friendly name for sender")
    init_p.add_argument("--can-run-jobs", action="store_true", help="Grant job execution")
    init_p.add_argument("--can-files", action="store_true", help="Grant file access")
    init_p.add_argument("--can-admin", action="store_true", help="Grant admin capability")

    # approve
    approve_p = subparsers.add_parser("approve", help="Approve with pairing code")
    approve_p.add_argument("platform", help="Platform")
    approve_p.add_argument("sender_id", help="Sender identifier")
    approve_p.add_argument("code", help="Pairing code")

    # block
    block_p = subparsers.add_parser("block", help="Block a sender")
    block_p.add_argument("platform", help="Platform")
    block_p.add_argument("sender_id", help="Sender identifier")
    block_p.add_argument("--reason", help="Reason for blocking")

    # unblock
    unblock_p = subparsers.add_parser("unblock", help="Unblock a sender")
    unblock_p.add_argument("platform", help="Platform")
    unblock_p.add_argument("sender_id", help="Sender identifier")

    # set-caps
    caps_p = subparsers.add_parser("set-caps", help="Set capabilities for approved sender")
    caps_p.add_argument("platform", help="Platform")
    caps_p.add_argument("sender_id", help="Sender identifier")
    caps_p.add_argument("--can-run-jobs", type=lambda x: x.lower() == 'true', help="true/false")
    caps_p.add_argument("--can-files", type=lambda x: x.lower() == 'true', help="true/false")
    caps_p.add_argument("--can-network", type=lambda x: x.lower() == 'true', help="true/false")
    caps_p.add_argument("--can-admin", type=lambda x: x.lower() == 'true', help="true/false")

    # list commands
    subparsers.add_parser("list-pending", help="List pending pairing requests")
    approved_p = subparsers.add_parser("list-approved", help="List approved senders")
    approved_p.add_argument("--platform", help="Filter by platform")
    subparsers.add_parser("list-blocked", help="List blocked senders")
    unknown_p = subparsers.add_parser("list-unknown", help="List unknown sender attempts")
    unknown_p.add_argument("--since", help="Filter by time (e.g., 1h, 30m, 2d)")

    # maintenance
    subparsers.add_parser("stats", help="Show registry statistics")
    subparsers.add_parser("expire", help="Remove expired pending requests")

    # Global options
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--table", action="store_true", help="Output as table")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    gatekeeper = MessageGatekeeper()

    try:
        if args.command == "check":
            result = gatekeeper.check_sender(args.platform, args.sender_id)
            output = result.to_dict()

        elif args.command == "initiate":
            caps = DEFAULT_CAPABILITIES.copy()
            if getattr(args, 'can_run_jobs', False):
                caps["can_run_jobs"] = True
            if getattr(args, 'can_files', False):
                caps["can_files"] = True
            if getattr(args, 'can_admin', False):
                caps["can_admin"] = True
            output = gatekeeper.initiate_pairing(args.platform, args.sender_id, args.name, caps)

        elif args.command == "approve":
            output = gatekeeper.approve_sender(args.platform, args.sender_id, args.code)

        elif args.command == "block":
            output = gatekeeper.block_sender(args.platform, args.sender_id, args.reason)

        elif args.command == "unblock":
            output = gatekeeper.unblock_sender(args.platform, args.sender_id)

        elif args.command == "set-caps":
            caps = {}
            if args.can_run_jobs is not None:
                caps["can_run_jobs"] = args.can_run_jobs
            if args.can_files is not None:
                caps["can_files"] = args.can_files
            if args.can_network is not None:
                caps["can_network"] = args.can_network
            if args.can_admin is not None:
                caps["can_admin"] = args.can_admin
            if not caps:
                print(json.dumps({"error": "No capabilities specified"}), file=sys.stderr)
                sys.exit(1)
            output = gatekeeper.set_capabilities(args.platform, args.sender_id, caps)

        elif args.command == "list-pending":
            data = gatekeeper.list_pending()
            if args.table or (not args.json and sys.stdout.isatty()):
                print(format_table(data, ["platform", "sender_id", "name", "pairing_code", "expires_in", "attempts"]))
                sys.exit(0)
            output = data

        elif args.command == "list-approved":
            data = gatekeeper.list_approved(args.platform)
            if args.table or (not args.json and sys.stdout.isatty()):
                print(format_table(data, ["platform", "sender_id", "name", "approved_at"]))
                sys.exit(0)
            output = data

        elif args.command == "list-blocked":
            data = gatekeeper.list_blocked()
            if args.table or (not args.json and sys.stdout.isatty()):
                print(format_table(data, ["platform", "sender_id", "reason", "blocked_at"]))
                sys.exit(0)
            output = data

        elif args.command == "list-unknown":
            since = parse_duration(args.since) if args.since else None
            data = gatekeeper.list_unknown(since)
            if args.table or (not args.json and sys.stdout.isatty()):
                print(format_table(data, ["platform", "sender_id", "age", "timestamp"]))
                sys.exit(0)
            output = data

        elif args.command == "stats":
            output = gatekeeper.stats()

        elif args.command == "expire":
            count = gatekeeper.expire_pending()
            output = {"expired_count": count, "message": f"Removed {count} expired pending request(s)"}

        print(json.dumps(output, indent=2))

        if isinstance(output, dict):
            if output.get("allowed") is False:
                sys.exit(1)
            if output.get("success") is False:
                sys.exit(1)

    except ValueError as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"Unexpected error: {e}"}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
