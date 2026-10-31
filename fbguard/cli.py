"""Command line: fbguard {setup,keygen,health,info,posts,plan-update,plan-post,approve,apply}.

Config comes from the environment: FBG_PAGE_ID, FBG_TOKEN_FILE (default
./.secrets/page_token.enc), FBG_TOKEN_KEY (Fernet key), FBG_CHANGELOG
(default ./changelog.jsonl). Setup also reads FBG_APP_ID, FBG_APP_SECRET and
FBG_SHORT_TOKEN, prompting with hidden input when one is missing.

Identities: FBG_IDENTITY and FBG_SIGNING_KEY (path to that identity's private
key) for whoever runs plan-* or approve; FBG_TRUSTED_KEYS (path to the
trusted-keys file) for approve and apply. The approver must be a different
identity, with a different key, from the plan's author.
"""
from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import os
import sys
from pathlib import Path

from . import approval as appr, graph, tokens
from .client import ApprovalError, PageClient, PlanError



def _read_json(path: str, what: str) -> dict:
    """Load a plan or approval file; anything but a JSON object is a clean error, not a traceback."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except UnicodeDecodeError:
        raise ApprovalError(f"{what} file {path} is not UTF-8") from None
    except ValueError as e:
        raise ApprovalError(f"{what} file {path} is not valid JSON ({e.msg}, line {e.lineno})") from None
    appr.require_object(value, what)
    return value

def _env(name: str, secret: bool = True) -> str:
    val = os.environ.get(name)
    if val:
        return val
    if not sys.stdin.isatty():
        raise SystemExit(f"{name} is not set")
    return getpass.getpass(f"{name}: ") if secret else input(f"{name}: ")


def _store() -> tokens.TokenStore:
    return tokens.TokenStore(Path(os.environ.get("FBG_TOKEN_FILE", ".secrets/page_token.enc")))


def _need(name: str) -> str:
    val = os.environ.get(name)
    if not val:
        raise SystemExit(f"{name} is not set")
    return val


def _signer() -> appr.Signer:
    return appr.Signer(_need("FBG_IDENTITY"), Path(_need("FBG_SIGNING_KEY")))


def _trusted() -> appr.TrustedKeys:
    return appr.TrustedKeys.load(Path(_need("FBG_TRUSTED_KEYS")))


def _client(signer=None, trusted=None) -> PageClient:
    return PageClient(_env("FBG_PAGE_ID", secret=False), _store().load(),
                      Path(os.environ.get("FBG_CHANGELOG", "changelog.jsonl")),
                      signer=signer, trusted=trusted)


def _kv(pairs):
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"expected field=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="fbguard", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("setup", help="exchange tokens once and store the Page token encrypted")
    p = sub.add_parser("keygen", help="make a signing key for one identity and print its trusted-keys line")
    p.add_argument("--identity", required=True); p.add_argument("--key-out", required=True)
    sub.add_parser("health")
    sub.add_parser("info")
    p = sub.add_parser("posts"); p.add_argument("--limit", type=int, default=10)
    p = sub.add_parser("plan-update", help="plan a Page field change (nothing is sent)")
    p.add_argument("set", nargs="+", metavar="field=value"); p.add_argument("--out", required=True)
    p = sub.add_parser("plan-post", help="plan a post (nothing is sent)")
    p.add_argument("message"); p.add_argument("--link"); p.add_argument("--at", help="ISO time with offset")
    p.add_argument("--out", required=True)
    p = sub.add_parser("approve", help="sign an approval of a plan someone else wrote (nothing is sent)")
    p.add_argument("plan"); p.add_argument("--fingerprint", required=True)
    p.add_argument("--out", required=True)
    p = sub.add_parser("apply", help="send a plan approved by a different identity")
    p.add_argument("plan"); p.add_argument("--approval", required=True, metavar="APPROVAL_FILE")
    a = ap.parse_args(argv)
    try:
        if a.cmd == "setup":
            print(tokens.bootstrap(_env("FBG_APP_ID", secret=False), _env("FBG_APP_SECRET"),
                                   _env("FBG_SHORT_TOKEN"), _env("FBG_PAGE_ID", secret=False), _store()))
            return 0
        if a.cmd == "keygen":
            print(appr.generate(a.identity, Path(a.key_out)))
            print(f"Private key written to {a.key_out} (mode 0600). Add the line above to the trusted-keys file.")
            return 0
        if a.cmd == "approve":
            plan = _read_json(a.plan, "plan")
            out = appr.approve(plan, a.fingerprint, _signer(), _trusted())
            fd = os.open(a.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps(out, indent=2, sort_keys=True) + "\n")
            print(f"Approved {plan['fingerprint']} as {out['approver']} (author: {plan['author']}). Nothing sent.")
            print(f"  fbguard apply {a.plan} --approval {a.out}")
            return 0
        if a.cmd in ("health", "info", "posts"):
            c = _client()
            res = {"health": c.health, "info": c.info, "posts": lambda: c.posts(a.limit)}[a.cmd]()
            print(json.dumps(res, indent=2))
            return 0
        if a.cmd in ("plan-update", "plan-post"):
            c = _client(signer=_signer())
            if a.cmd == "plan-update":
                plan = c.plan_update(_kv(a.set))
            else:
                at = dt.datetime.fromisoformat(a.at.replace("Z", "+00:00")) if a.at else None
                plan = c.plan_post(a.message, a.link, at)
            Path(a.out).write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n")
            print(json.dumps(plan, indent=2, sort_keys=True))
            print(f"\nNothing sent. Author: {plan['author']}. A different identity reviews it and approves "
                  f"fingerprint {plan['fingerprint']}:")
            print(f"  fbguard approve {a.out} --fingerprint {plan['fingerprint']} --out approval.json")
            return 0
        if a.cmd == "apply":
            plan = _read_json(a.plan, "plan")
            approval = _read_json(a.approval, "approval")
            print(json.dumps(_client(trusted=_trusted()).apply(plan, approval), indent=2))
            return 0
    except (PlanError, ApprovalError, appr.KeyFileError, tokens.SetupError, graph.GraphError,
            FileExistsError, FileNotFoundError) as e:
        print(f"error: {graph.redact(str(e))}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
