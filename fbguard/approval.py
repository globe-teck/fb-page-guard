"""Signed authorship and separate-identity approval for plans.

Each person or agent that takes part has its own identity and Ed25519 key pair.
The private key stays with its owner. A trusted-keys file lists
`identity ed25519:<public key>` lines and is what apply checks against.

- The author (normally the agent) signs the plan when it is made.
- A different identity reviews the plan and signs an approval for that exact plan.
- apply sends nothing unless both signatures check out against the trusted keys
  and the approver is a different identity, with a different key, from the author.

This only separates people if the author cannot read an approver's private key
and cannot edit the trusted-keys file. See "Known limits" in the README.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

IDENTITY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,63}")  # used with fullmatch: no trailing "\n" slips through
PLAN_CONTEXT = b"fbguard-plan-v1\n"
APPROVAL_CONTEXT = b"fbguard-approval-v1\n"
UNSIGNED_FIELDS = frozenset({"fingerprint", "author_sig"})


class ApprovalError(PermissionError):
    pass


class KeyFileError(ValueError):
    """Bad key material or trusted-keys file."""


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        from cryptography.hazmat.primitives import serialization
    except ImportError as e:  # pragma: no cover - exercised only without the extra
        raise KeyFileError("pip install cryptography to sign or check approvals") from e
    return ed25519, serialization


def check_identity(identity: str) -> str:
    if not isinstance(identity, str) or not IDENTITY_RE.fullmatch(identity):
        raise KeyFileError("identity must be 1-64 characters: letters, digits, . _ @ -")
    return identity


def same_identity(a: str, b: str) -> bool:
    if not isinstance(a, str) or not isinstance(b, str):
        raise ApprovalError("identities must be strings")
    return a.casefold() == b.casefold()


def _str_field(obj: Mapping[str, Any], name: str, what: str) -> str:
    """Return obj[name] if it is a non-empty string; refuse anything else with ApprovalError."""
    value = obj.get(name)
    if not isinstance(value, str) or not value:
        raise ApprovalError(f"{what} {name!r} must be a non-empty string")
    return value


def require_object(value: Any, what: str) -> Mapping[str, Any]:
    """Plans and approvals are JSON objects; refuse anything else with ApprovalError, not a traceback."""
    if not isinstance(value, Mapping):
        raise ApprovalError(f"{what} must be a JSON object, not {type(value).__name__}")
    return value


def plan_body(plan: Mapping[str, Any]) -> Dict[str, Any]:
    require_object(plan, "plan")
    return {k: v for k, v in plan.items() if k not in UNSIGNED_FIELDS}


def plan_digest(plan: Mapping[str, Any]) -> str:
    """Full sha256 of the plan as signed (the 12-character fingerprint is its prefix)."""
    return hashlib.sha256(json.dumps(plan_body(plan), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _approval_message(digest: str, approver: str) -> bytes:
    return APPROVAL_CONTEXT + f"{digest}\n{approver}".encode()


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _unb64(s: str) -> bytes:
    try:
        return base64.b64decode(s.encode(), validate=True)
    except (ValueError, TypeError, AttributeError) as e:
        raise ApprovalError("signature or key is not valid base64") from e


# ---- keys ------------------------------------------------------------------
def generate(identity: str, key_out: Path) -> str:
    """Write a new private key (mode 0600, refuses to overwrite) and return its trusted-keys line."""
    check_identity(identity)
    ed25519, serialization = _ed25519()
    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    key_out = Path(key_out)
    key_out.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(key_out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return f"{identity} ed25519:{_b64(pub)}"


class Signer:
    """An identity plus its private key, loaded from a file only its owner can read."""

    def __init__(self, identity: str, key_path: Path):
        self.identity = check_identity(identity)
        key_path = Path(key_path)
        if os.name == "posix" and stat.S_IMODE(key_path.stat().st_mode) & 0o077:
            raise KeyFileError(f"{key_path} is readable by others; chmod 600 it")
        ed25519, serialization = _ed25519()
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise KeyFileError("signing key must be Ed25519")
        self._key = key

    def public_b64(self) -> str:
        _, serialization = _ed25519()
        return _b64(self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign(self, message: bytes) -> str:
        return _b64(self._key.sign(message))


class TrustedKeys:
    """identity -> Ed25519 public key. Duplicate identities and keys shared by two identities are refused."""

    def __init__(self, entries: Mapping[str, str]):
        self._keys: Dict[str, Tuple[str, bytes]] = {}
        seen: Dict[bytes, str] = {}
        for ident, pub in entries.items():
            check_identity(ident)
            raw = _unb64(pub)
            if len(raw) != 32:
                raise KeyFileError(f"public key for {ident} is not a 32-byte Ed25519 key")
            fold = ident.casefold()
            if fold in self._keys:
                raise KeyFileError(f"identity {ident} is listed twice")
            if raw in seen:
                raise KeyFileError(f"identities {seen[raw]} and {ident} share one key")
            seen[raw] = ident
            self._keys[fold] = (ident, raw)

    @classmethod
    def load(cls, path: Path) -> "TrustedKeys":
        entries: Dict[str, str] = {}
        for n, line in enumerate(Path(path).read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or not parts[1].startswith("ed25519:"):
                raise KeyFileError(f"{path}:{n}: expected 'identity ed25519:<base64>'")
            if parts[0].casefold() in {k.casefold() for k in entries}:
                raise KeyFileError(f"identity {parts[0]} is listed twice")
            entries[parts[0]] = parts[1][len("ed25519:"):]
        return cls(entries)

    def key_for(self, identity: str) -> bytes:
        try:
            return self._keys[str(identity).casefold()][1]
        except KeyError:
            raise ApprovalError(f"{identity!r} is not in the trusted keys") from None

    def verify(self, identity: str, message: bytes, sig: str) -> None:
        ed25519, _ = _ed25519()
        from cryptography.exceptions import InvalidSignature
        try:
            ed25519.Ed25519PublicKey.from_public_bytes(self.key_for(identity)).verify(_unb64(str(sig)), message)
        except InvalidSignature:
            raise ApprovalError(f"signature by {identity!r} does not verify") from None


# ---- plans and approvals ----------------------------------------------------
def sign_plan(plan: Dict[str, Any], signer: Signer) -> None:
    """Sign a plan that already carries author == signer.identity."""
    if plan.get("author") != signer.identity:
        raise ApprovalError("plan author does not match the signer")
    plan["author_sig"] = signer.sign(PLAN_CONTEXT + plan_digest(plan).encode())


def check_author(plan: Mapping[str, Any], trusted: TrustedKeys) -> str:
    require_object(plan, "plan")
    if not plan.get("author") or not plan.get("author_sig"):
        raise ApprovalError("plan has no signed author; make it with a signing identity")
    author = _str_field(plan, "author", "plan")
    sig = _str_field(plan, "author_sig", "plan")
    trusted.verify(author, PLAN_CONTEXT + plan_digest(plan).encode(), sig)
    return author


def _refuse_self(author: str, approver: str, trusted: TrustedKeys) -> None:
    if same_identity(author, approver) or trusted.key_for(author) == trusted.key_for(approver):
        raise ApprovalError(f"{approver} wrote this plan and cannot approve it; a different identity must approve")


def approve(plan: Mapping[str, Any], fingerprint_seen: str, signer: Signer, trusted: TrustedKeys) -> dict:
    """Return an approval for this exact plan, signed by a reviewer who is not its author."""
    require_object(plan, "plan")
    digest = plan_digest(plan)
    if fingerprint_seen != plan.get("fingerprint") or not digest.startswith(str(fingerprint_seen)):
        raise ApprovalError("the fingerprint you approved is not this plan's; re-read the plan")
    author = check_author(plan, trusted)
    if _b64(trusted.key_for(signer.identity)) != signer.public_b64():
        raise ApprovalError(f"your key does not match the trusted key for {signer.identity}")
    _refuse_self(author, signer.identity, trusted)
    return {"approver": signer.identity, "fingerprint": plan["fingerprint"], "plan_sha256": digest,
            "sig": signer.sign(_approval_message(digest, signer.identity))}


def check_approval(plan: Mapping[str, Any], approval: Optional[Mapping[str, Any]], trusted: TrustedKeys) -> Tuple[str, str]:
    """Raise unless a different trusted identity signed an approval of this exact plan. Returns (author, approver)."""
    require_object(plan, "plan")
    if not isinstance(approval, Mapping):
        raise ApprovalError("a signed approval from a different identity is required")
    author = check_author(plan, trusted)
    digest = plan_digest(plan)
    if not approval.get("approver") or not approval.get("sig"):
        raise ApprovalError("approval is missing the approver or signature")
    approver = _str_field(approval, "approver", "approval")
    sig = _str_field(approval, "sig", "approval")
    if approval.get("plan_sha256") != digest:
        raise ApprovalError("approval does not match this plan")
    _refuse_self(author, approver, trusted)
    trusted.verify(approver, _approval_message(digest, approver), sig)
    return author, approver
