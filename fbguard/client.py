"""Approval-gated Page client.

Reads run freely. Every write is two steps:
  1. plan_*()  builds an exact change (with the current values for the diff) and a
     short fingerprint of it, and the author's identity signs it. Nothing is sent.
  2. A different identity reviews the plan and signs an approval of it
     (approval.approve).
  3. apply(plan, approval) sends it, but only if the author and approver
     signatures verify against the trusted keys, the approver is not the author,
     the plan is unchanged since it was signed, and the Page still has the
     values the plan was made against.
Each applied write is appended to a JSONL changelog with the before values.
Post plans can only be applied when a changelog is configured.
"""
from __future__ import annotations

import datetime as dt
import json
import time
from pathlib import Path
from typing import Any, Callable, Dict, Mapping, Optional

from . import approval as appr, graph
from .approval import ApprovalError

ABOUT_MAX_LEN = 100
# Fields this client will change. Anything else is refused rather than passed through.
UPDATABLE_FIELDS = frozenset({"about", "description", "website", "phone", "emails", "general_info", "impressum"})
READ_ONLY_FIELDS = frozenset({"username", "name", "id", "category_list", "followers_count", "fan_count"})
INFO_FIELDS = "id,name,username,about,description,website,phone,emails,category_list,followers_count"
SCHEDULE_MIN = dt.timedelta(minutes=10)
SCHEDULE_MAX = dt.timedelta(days=30)
MAX_RETRIES = 5
BACKOFF_CAP = 300.0


class PlanError(ValueError):
    pass


def fingerprint(plan: Mapping[str, Any]) -> str:
    """12-character prefix of the plan's sha256 (covers the author, not the signatures)."""
    return appr.plan_digest(plan)[:12]


class PageClient:
    def __init__(self, page_id: str, token: str, changelog: Optional[Path] = None,
                 transport: Optional[graph.Transport] = None,
                 sleep: Callable[[float], None] = time.sleep,
                 now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.timezone.utc),
                 signer: Optional[appr.Signer] = None, trusted: Optional[appr.TrustedKeys] = None):
        self.page_id = str(page_id)
        self._token = token
        self.changelog = Path(changelog) if changelog else None
        self.transport = transport  # None means the real network transport
        self.sleep = sleep
        self.now = now
        self.signer = signer    # who authors plans made by this client
        self.trusted = trusted  # trusted keys that apply() checks signatures against

    # ---- plumbing -------------------------------------------------------
    def _call(self, method: str, path: str, params: Optional[Mapping[str, Any]] = None) -> dict:
        params = dict(params or {}, access_token=self._token)
        delay = 2.0
        for attempt in range(MAX_RETRIES + 1):
            try:
                return graph.request(method, path, params, self.transport or graph.urllib_transport)
            except graph.GraphError as e:
                if not e.retryable or attempt == MAX_RETRIES:
                    raise
                self.sleep(min(delay, BACKOFF_CAP))
                delay *= 2
        raise AssertionError("unreachable")

    def _log(self, plan: Mapping[str, Any], result: Mapping[str, Any], approver: str) -> None:
        if not self.changelog:
            return
        self.changelog.parent.mkdir(parents=True, exist_ok=True)
        entry = {"ts": self.now().isoformat(timespec="seconds"), "page": self.page_id,
                 "action": plan["action"], "fingerprint": plan["fingerprint"],
                 "author": plan.get("author"), "approver": approver,
                 "before": plan.get("before"), "after": plan.get("fields") or plan.get("post"),
                 "result": result}
        with open(self.changelog, "a", encoding="utf-8") as f:
            f.write(graph.redact(json.dumps(entry, sort_keys=True)) + "\n")

    # ---- reads ----------------------------------------------------------
    def info(self, fields: str = INFO_FIELDS) -> dict:
        return self._call("GET", self.page_id, {"fields": fields})

    def posts(self, limit: int = 10) -> dict:
        return self._call("GET", f"{self.page_id}/published_posts",
                          {"fields": "id,message,created_time,permalink_url", "limit": limit})

    def health(self) -> dict:
        page = self.info("id,name")
        return {"ok": str(page.get("id")) == self.page_id, "name": page.get("name")}

    # ---- plans ----------------------------------------------------------
    def _finish(self, plan: Dict[str, Any]) -> dict:
        if self.signer is None:
            raise PlanError("plans must be signed by their author; set a signing identity")
        plan["author"] = self.signer.identity
        plan["fingerprint"] = fingerprint(plan)
        appr.sign_plan(plan, self.signer)
        return plan

    def plan_update(self, fields: Mapping[str, Any]) -> dict:
        if not fields:
            raise PlanError("nothing to change")
        ro = sorted(set(fields) & READ_ONLY_FIELDS)
        if ro:
            raise PlanError(f"read-only through the API, change by hand in Page settings: {', '.join(ro)}")
        unknown = sorted(set(fields) - UPDATABLE_FIELDS)
        if unknown:
            raise PlanError(f"not an allowed field: {', '.join(unknown)}")
        if "about" in fields and len(str(fields["about"])) > ABOUT_MAX_LEN:
            raise PlanError(f"about is {len(str(fields['about']))} characters; the limit is {ABOUT_MAX_LEN}")
        current = self.info(",".join(sorted(fields)))
        before = {k: current.get(k) for k in sorted(fields)}
        changed = {k: v for k, v in sorted(fields.items()) if before.get(k) != v}
        if not changed:
            raise PlanError("the Page already has these values")
        return self._finish({"action": "update", "page": self.page_id, "fields": changed,
                             "before": {k: before[k] for k in changed}})

    def plan_post(self, message: str, link: Optional[str] = None,
                  publish_at: Optional[dt.datetime] = None) -> dict:
        if not (message or "").strip():
            raise PlanError("empty post")
        post: Dict[str, Any] = {"message": message}
        if link:
            if not link.startswith("https://"):
                raise PlanError("link must be https://")
            post["link"] = link
        if publish_at is not None:
            if publish_at.tzinfo is None:
                raise PlanError("publish_at needs a timezone")
            ahead = publish_at - self.now()
            if not (SCHEDULE_MIN <= ahead <= SCHEDULE_MAX):
                raise PlanError("scheduled posts must be 10 minutes to 30 days ahead")
            post["published"] = "false"
            post["scheduled_publish_time"] = int(publish_at.timestamp())
        return self._finish({"action": "post", "page": self.page_id, "post": post})

    # ---- apply ----------------------------------------------------------
    def _already_applied(self, fp: str) -> bool:
        if not self.changelog or not self.changelog.exists():
            return False
        with open(self.changelog, encoding="utf-8") as f:
            for line in f:
                try:
                    rec = json.loads(line)
                    if isinstance(rec, dict) and rec.get("fingerprint") == fp:
                        return True
                except ValueError:
                    continue
        return False

    def apply(self, plan: Mapping[str, Any], approval: Optional[Mapping[str, Any]]) -> dict:
        appr.require_object(plan, "plan")
        if plan.get("page") != self.page_id:
            raise ApprovalError("plan is for a different Page")
        if fingerprint(plan) != plan.get("fingerprint"):
            raise ApprovalError("plan was edited after it was fingerprinted; make a new plan")
        if self.trusted is None:
            raise ApprovalError("no trusted keys configured; cannot check who wrote or approved this plan")
        _, approver = appr.check_approval(plan, approval, self.trusted)
        if plan["action"] == "update":
            live = self.info(",".join(sorted(plan["fields"])))
            drift = {k: live.get(k) for k in plan["before"] if live.get(k) != plan["before"][k]}
            if drift:
                raise ApprovalError(f"the Page changed since the plan was made ({', '.join(sorted(drift))}); re-plan")
            result = self._call("POST", self.page_id, plan["fields"])
        elif plan["action"] == "post":
            if not self.changelog:
                raise ApprovalError("a changelog is required to apply post plans (it is how duplicate posts are refused); "
                                    "pass changelog=<path> to PageClient")
            if self._already_applied(plan["fingerprint"]):
                raise ApprovalError("already applied: this plan's fingerprint is in the changelog; make a new plan")
            result = self._call("POST", f"{self.page_id}/feed", plan["post"])
        else:
            raise ApprovalError(f"unknown action {plan['action']!r}")
        self._log(plan, result, approver)
        return result
