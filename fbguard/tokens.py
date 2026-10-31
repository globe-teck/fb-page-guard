"""One-time token bootstrap and encrypted token storage.

Flow: short-lived user token -> long-lived user token -> Page token taken from
/me/accounts (a Page token derived from a long-lived user token does not expire)
-> checked with /debug_token -> stored encrypted with Fernet.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, Optional

from . import graph

REQUIRED_TASKS = frozenset({"MANAGE", "CREATE_CONTENT"})


class SetupError(RuntimeError):
    pass


def exchange_long_lived(app_id: str, app_secret: str, short_token: str, transport=graph.urllib_transport) -> str:
    data = graph.request("GET", "oauth/access_token", {
        "grant_type": "fb_exchange_token", "client_id": app_id,
        "client_secret": app_secret, "fb_exchange_token": short_token,
    }, transport)
    tok = data.get("access_token")
    if not tok:
        raise SetupError("no access_token in the exchange response")
    return tok


def find_page(user_token: str, page_id: str, transport=graph.urllib_transport) -> dict:
    """Return the /me/accounts entry for page_id, following pagination."""
    params = {"fields": "id,name,access_token,tasks", "limit": 100, "access_token": user_token}
    path = "me/accounts"
    for _ in range(20):
        data = graph.request("GET", path, params, transport)
        for page in data.get("data", []):
            if str(page.get("id")) == str(page_id):
                return page
        after = ((data.get("paging") or {}).get("cursors") or {}).get("after")
        if not after or not (data.get("paging") or {}).get("next"):
            break
        params = dict(params, after=after)
    raise SetupError(f"page {page_id} is not in /me/accounts for this user; check the Page role and the granted scopes")


def check_tasks(page: dict, required: Iterable[str] = REQUIRED_TASKS) -> None:
    missing = set(required) - set(page.get("tasks") or [])
    if missing:
        raise SetupError("page token lacks tasks: " + ", ".join(sorted(missing)))


def debug_token(token: str, app_id: str, app_secret: str, transport=graph.urllib_transport) -> dict:
    data = graph.request("GET", "debug_token", {"input_token": token, "access_token": f"{app_id}|{app_secret}"}, transport)
    info = data.get("data") or {}
    if not info.get("is_valid"):
        raise SetupError("debug_token says the Page token is not valid")
    return info


def summarize(page: dict, info: dict) -> str:
    """Non-secret confirmation text."""
    exp = info.get("expires_at")
    return "\n".join([
        f"page: {page.get('name')} ({page.get('id')})",
        f"token type: {info.get('type')}",
        f"valid: {info.get('is_valid')}",
        f"expires: {'never' if not exp else exp}",
        f"scopes: {', '.join(info.get('scopes') or [])}",
        f"tasks: {', '.join(page.get('tasks') or [])}",
    ])


class TokenStore:
    """Fernet-encrypted file holding one token. The key comes from an env var, never from disk next to it."""

    def __init__(self, path: Path, key_env: str = "FBG_TOKEN_KEY"):
        self.path = Path(path)
        self.key_env = key_env

    def _fernet(self):
        try:
            from cryptography.fernet import Fernet
        except ImportError as e:  # pragma: no cover - exercised only without the extra
            raise SetupError("pip install cryptography to use the encrypted token store") from e
        key = os.environ.get(self.key_env)
        if not key:
            raise SetupError(f"{self.key_env} is not set")
        return Fernet(key.encode())

    def save(self, token: str) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(self._fernet().encrypt(token.encode()))
        os.replace(tmp, self.path)

    def load(self) -> str:
        if not self.path.exists():
            raise SetupError(f"no token file at {self.path}; run the setup first")
        return self._fernet().decrypt(self.path.read_bytes()).decode()


def bootstrap(app_id: str, app_secret: str, short_token: str, page_id: str, store: Optional[TokenStore],
              transport=graph.urllib_transport) -> str:
    """Run the whole flow and return the non-secret summary. Saves the Page token if a store is given."""
    long_user = exchange_long_lived(app_id, app_secret, short_token, transport)
    page = find_page(long_user, page_id, transport)
    check_tasks(page)
    info = debug_token(page["access_token"], app_id, app_secret, transport)
    if store is not None:
        store.save(page["access_token"])
    return summarize(page, info)
