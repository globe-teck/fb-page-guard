"""Low-level Graph API plumbing: URLs, HTTP, error parsing and secret redaction.

Standard library only. The transport is injectable so tests never touch the network.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Mapping, Optional, Tuple

GRAPH_VERSION = "v21.0"
GRAPH_BASE = "https://graph.facebook.com"

# Error codes Meta documents as throttling, and as temporary service errors.
RATE_LIMIT_CODES = {4, 17, 32, 613, 80001, 80004}
TRANSIENT_CODES = {1, 2}

_SECRET_PARAMS = ("access_token", "client_secret", "fb_exchange_token", "input_token", "code", "appsecret_proof")
_REDACT_RE = re.compile(r"(?i)\b(" + "|".join(_SECRET_PARAMS) + r")=([^&\s\"']+)")
_BEARER_RE = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._\-]+")
_TOKENISH_RE = re.compile(r"\bEA[A-Za-z0-9]{20,}\b")  # Meta access tokens start with "EA"

# A transport takes (method, url, body_bytes_or_None) and returns (status, body_bytes).
Transport = Callable[[str, str, Optional[bytes]], Tuple[int, bytes]]


def redact(text: str) -> str:
    """Mask token-like values so they can be logged or shown safely."""
    text = _REDACT_RE.sub(lambda m: f"{m.group(1)}=***", str(text))
    text = _BEARER_RE.sub(r"\1***", text)
    return _TOKENISH_RE.sub("EA***", text)


class GraphError(RuntimeError):
    """A Graph API error with its numeric code. The message is always redacted."""

    def __init__(self, message: str, code: Optional[int] = None, subcode: Optional[int] = None,
                 status: Optional[int] = None):
        super().__init__(redact(message))
        self.code = code
        self.subcode = subcode
        self.status = status

    @property
    def retryable(self) -> bool:
        return self.code in RATE_LIMIT_CODES or self.code in TRANSIENT_CODES

    def __str__(self) -> str:
        bits = [super().__str__()]
        if self.code is not None:
            bits.append(f"(code {self.code}" + (f", subcode {self.subcode})" if self.subcode else ")"))
        return " ".join(bits)


def build_url(path: str, params: Optional[Mapping[str, Any]] = None, version: str = GRAPH_VERSION) -> str:
    path = path.lstrip("/")
    url = f"{GRAPH_BASE}/{version}/{path}"
    if params:
        url += "?" + urllib.parse.urlencode({k: v for k, v in params.items() if v is not None})
    return url


def parse_response(status: int, body: bytes) -> dict:
    try:
        data = json.loads(body.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GraphError(f"non-JSON response (HTTP {status})", status=status)
    if isinstance(data, dict) and "error" in data:
        err = data["error"] or {}
        raise GraphError(err.get("message", "unknown error"), err.get("code"), err.get("error_subcode"), status)
    if status >= 400:
        raise GraphError(f"HTTP {status}", status=status)
    if isinstance(data, bool):  # some edges return a bare true/false
        return {"success": data}
    return data


def urllib_transport(method: str, url: str, body: Optional[bytes]) -> Tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except urllib.error.URLError as e:
        raise GraphError(f"network error: {e.reason}", code=2)


def request(method: str, path: str, params: Optional[Mapping[str, Any]] = None,
            transport: Transport = urllib_transport, version: str = GRAPH_VERSION) -> dict:
    """One Graph call. GET puts params in the query string; POST/DELETE send a form body."""
    method = method.upper()
    params = dict(params or {})
    if method == "GET":
        status, body = transport("GET", build_url(path, params, version), None)
    else:
        data = urllib.parse.urlencode({k: v for k, v in params.items() if v is not None}).encode()
        status, body = transport(method, build_url(path, None, version), data)
    return parse_response(status, body)
