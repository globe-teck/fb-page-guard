import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path

from fbguard import approval as appr, graph
from fbguard.client import ApprovalError, PageClient, PlanError, fingerprint
from tests.fake import FakeGraph
from tests.keys import Identities

NOW = dt.datetime(2030, 1, 7, 15, 0, tzinfo=dt.timezone.utc)
TOKEN = "EAA" + "T" * 40


class ClientTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "changelog.jsonl"
        self.fake = FakeGraph()
        self.sleeps = []
        self.ids = Identities("agent", "reviewer")
        self.trusted = self.ids.trusted()
        self.c = PageClient("1234567890", TOKEN, self.log, self.fake, self.sleeps.append, lambda: NOW,
                            signer=self.ids.signer("agent"), trusted=self.trusted)

    def tearDown(self):
        self.tmp.cleanup()
        self.ids.cleanup()

    def ok(self, plan):
        """A valid approval of plan by a different identity."""
        return appr.approve(plan, plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)

    def writes(self):
        return [c for c in self.fake.calls if c[0] != "GET"]

    def test_plan_sends_nothing_and_records_before_values(self):
        plan = self.c.plan_update({"about": "New about"})
        self.assertEqual(self.writes(), [])
        self.assertEqual(plan["before"], {"about": "Old about"})
        self.assertEqual(plan["fields"], {"about": "New about"})
        self.assertEqual(plan["fingerprint"], fingerprint(plan))

    def test_unchanged_fields_are_dropped_and_noop_refused(self):
        plan = self.c.plan_update({"about": "New", "website": "https://example.com"})
        self.assertEqual(list(plan["fields"]), ["about"])
        with self.assertRaises(PlanError):
            self.c.plan_update({"website": "https://example.com"})

    def test_refuses_read_only_unknown_and_long_about(self):
        for fields in ({"username": "x"}, {"category_list": "x"}, {"cover": "x"}, {"about": "a" * 101}, {}):
            with self.assertRaises(PlanError):
                self.c.plan_update(fields)

    def test_apply_needs_matching_approval(self):
        plan = self.c.plan_update({"about": "New about"})
        for bad in (None, "000000000000", plan["fingerprint"], {"approver": "reviewer", "sig": "AAAA"}):
            with self.assertRaises(ApprovalError):
                self.c.apply(plan, bad)
        self.assertEqual(self.writes(), [])
        self.c.apply(plan, self.ok(plan))
        self.assertEqual(self.fake.fields["about"], "New about")

    def test_second_apply_of_post_plan_is_refused_and_nothing_sent(self):
        plan = self.c.plan_post("Hello world")
        ok = self.ok(plan)
        self.c.apply(plan, ok)
        self.assertEqual(len(self.fake.posts), 1)
        before = list(self.fake.calls)
        with self.assertRaisesRegex(ApprovalError, "already applied"):
            self.c.apply(plan, ok)
        self.assertEqual(len(self.fake.posts), 1)
        self.assertEqual([c for c in self.fake.calls[len(before):] if c[0] != "GET"], [])

    def test_post_plan_refused_without_changelog_and_nothing_sent(self):
        c = PageClient("1234567890", TOKEN, None, self.fake, self.sleeps.append, lambda: NOW,
                       signer=self.ids.signer("agent"), trusted=self.trusted)
        plan = c.plan_post("Hello world")
        with self.assertRaisesRegex(ApprovalError, "changelog is required"):
            c.apply(plan, self.ok(plan))
        self.assertEqual(self.fake.posts, [])
        self.assertEqual(self.writes(), [])

    def test_edited_plan_is_refused_even_with_old_fingerprint(self):
        plan = self.c.plan_update({"about": "New about"})
        ok = self.ok(plan)
        plan["fields"]["about"] = "Something else"
        with self.assertRaises(ApprovalError):
            self.c.apply(plan, ok)
        plan["fingerprint"] = fingerprint(plan)  # even with a recomputed fingerprint
        with self.assertRaises(ApprovalError):
            self.c.apply(plan, ok)
        self.assertEqual(self.writes(), [])

    def test_drift_since_plan_is_refused(self):
        plan = self.c.plan_update({"about": "New about"})
        ok = self.ok(plan)
        self.fake.fields["about"] = "Someone edited it by hand"
        with self.assertRaises(ApprovalError):
            self.c.apply(plan, ok)
        self.assertEqual(self.writes(), [])

    def test_plan_for_other_page_is_refused(self):
        plan = self.c.plan_update({"about": "New about"})
        other = PageClient("999", TOKEN, None, self.fake, self.sleeps.append, lambda: NOW, trusted=self.trusted)
        with self.assertRaises(ApprovalError):
            other.apply(plan, self.ok(plan))

    def test_changelog_has_before_after_and_no_token(self):
        plan = self.c.plan_update({"about": "New about"})
        self.c.apply(plan, self.ok(plan))
        text = self.log.read_text()
        self.assertNotIn(TOKEN, text)
        entry = json.loads(text.splitlines()[0])
        self.assertEqual(entry["before"], {"about": "Old about"})
        self.assertEqual(entry["after"], {"about": "New about"})
        self.assertEqual(entry["action"], "update")
        self.assertEqual((entry["author"], entry["approver"]), ("agent", "reviewer"))

    def test_post_plan_and_apply(self):
        plan = self.c.plan_post("Hello", link="https://example.com/x")
        self.assertEqual(self.writes(), [])
        res = self.c.apply(plan, self.ok(plan))
        self.assertEqual(res["id"], "1234567890_1")
        self.assertEqual(self.fake.posts[0]["message"], "Hello")

    def test_post_validation(self):
        with self.assertRaises(PlanError):
            self.c.plan_post("   ")
        with self.assertRaises(PlanError):
            self.c.plan_post("x", link="http://example.com")
        with self.assertRaises(PlanError):
            self.c.plan_post("x", publish_at=NOW + dt.timedelta(minutes=5))
        with self.assertRaises(PlanError):
            self.c.plan_post("x", publish_at=NOW + dt.timedelta(days=31))
        with self.assertRaises(PlanError):
            self.c.plan_post("x", publish_at=dt.datetime(2030, 1, 8, 9, 0))
        plan = self.c.plan_post("x", publish_at=NOW + dt.timedelta(days=1))
        self.assertEqual(plan["post"]["published"], "false")
        self.assertEqual(plan["post"]["scheduled_publish_time"], int((NOW + dt.timedelta(days=1)).timestamp()))

    def test_rate_limit_retries_with_backoff(self):
        self.fake.fail_next = [(400, {"message": "too many", "code": 4}), (400, {"message": "too many", "code": 32})]
        self.assertTrue(self.c.health()["ok"])
        self.assertEqual(self.sleeps, [2.0, 4.0])

    def test_permission_error_is_not_retried(self):
        self.fake.fail_next = [(403, {"message": "(#200) not allowed", "code": 200})]
        with self.assertRaises(graph.GraphError):
            self.c.info()
        self.assertEqual(self.sleeps, [])

    def test_gives_up_after_max_retries(self):
        self.fake.fail_next = [(400, {"message": "busy", "code": 17})] * 10
        with self.assertRaises(graph.GraphError):
            self.c.info()
        self.assertEqual(len(self.sleeps), 5)


if __name__ == "__main__":
    unittest.main()
