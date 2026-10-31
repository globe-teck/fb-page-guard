"""L5: the author of a plan must not be able to approve it."""
import datetime as dt
import os
import tempfile
import unittest
from pathlib import Path

from fbguard import approval as appr
from fbguard.client import ApprovalError, PageClient, PlanError
from tests.fake import FakeGraph
from tests.keys import Identities

NOW = dt.datetime(2030, 1, 7, 15, 0, tzinfo=dt.timezone.utc)
TOKEN = "EAA" + "T" * 40


class SeparateApproverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "changelog.jsonl"
        self.fake = FakeGraph()
        self.ids = Identities("agent", "reviewer", "outsider")
        # outsider has a key but is not in the trusted file
        self.ids.trusted_file.write_text("\n".join([self.ids.lines["agent"], self.ids.lines["reviewer"]]) + "\n")
        self.trusted = self.ids.trusted()
        self.agent = self.ids.signer("agent")
        self.c = PageClient("1234567890", TOKEN, self.log, self.fake, lambda s: None, lambda: NOW,
                            signer=self.agent, trusted=self.trusted)
        self.plan = self.c.plan_update({"about": "New about"})

    def tearDown(self):
        self.tmp.cleanup()
        self.ids.cleanup()

    def writes(self):
        return [c for c in self.fake.calls if c[0] != "GET"]

    def assertRefused(self, approval, regex=None):
        with self.assertRaisesRegex(ApprovalError, regex or ""):
            self.c.apply(self.plan, approval)
        self.assertEqual(self.writes(), [])

    def assertRefusedPlan(self, plan, approval):
        with self.assertRaises(ApprovalError):
            self.c.apply(plan, approval)
        self.assertEqual(self.writes(), [])

    def test_plan_records_and_signs_its_author(self):
        self.assertEqual(self.plan["author"], "agent")
        self.assertEqual(appr.check_author(self.plan, self.trusted), "agent")

    def test_author_cannot_approve_own_plan(self):
        with self.assertRaisesRegex(ApprovalError, "cannot approve"):
            appr.approve(self.plan, self.plan["fingerprint"], self.agent, self.trusted)

    def test_hand_made_self_approval_is_refused_at_apply(self):
        digest = appr.plan_digest(self.plan)
        forged = {"approver": "agent", "plan_sha256": digest,
                  "sig": self.agent.sign(appr._approval_message(digest, "agent"))}
        self.assertRefused(forged, "cannot approve")

    def test_case_variant_of_author_is_the_same_identity(self):
        digest = appr.plan_digest(self.plan)
        forged = {"approver": "AGENT", "plan_sha256": digest,
                  "sig": self.agent.sign(appr._approval_message(digest, "AGENT"))}
        self.assertRefused(forged, "cannot approve")

    def test_author_signing_under_reviewer_name_is_refused(self):
        digest = appr.plan_digest(self.plan)
        forged = {"approver": "reviewer", "plan_sha256": digest,
                  "sig": self.agent.sign(appr._approval_message(digest, "reviewer"))}
        self.assertRefused(forged, "does not verify")

    def test_untrusted_approver_is_refused(self):
        outsider = self.ids.signer("outsider")
        digest = appr.plan_digest(self.plan)
        forged = {"approver": "outsider", "plan_sha256": digest,
                  "sig": outsider.sign(appr._approval_message(digest, "outsider"))}
        self.assertRefused(forged, "not in the trusted keys")

    def test_one_key_under_two_identities_is_refused(self):
        alias = self.ids.lines["agent"].replace("agent ", "agent-alias ", 1)
        self.ids.trusted_file.write_text(self.ids.lines["agent"] + "\n" + alias + "\n")
        with self.assertRaisesRegex(appr.KeyFileError, "share one key"):
            appr.TrustedKeys.load(self.ids.trusted_file)

    def test_duplicate_identity_is_refused(self):
        self.ids.trusted_file.write_text(self.ids.lines["agent"] + "\n" +
                                         self.ids.lines["reviewer"].replace("reviewer ", "Agent ", 1) + "\n")
        with self.assertRaisesRegex(appr.KeyFileError, "listed twice"):
            appr.TrustedKeys.load(self.ids.trusted_file)

    def test_relabelled_author_breaks_the_author_signature(self):
        reviewer_ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        self.plan["author"] = "outsider"
        self.assertRefused(reviewer_ok)

    def test_approval_of_another_plan_is_refused(self):
        other = self.c.plan_update({"about": "Different"})
        ok_other = appr.approve(other, other["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        self.assertRefused(ok_other, "does not match")

    def test_reviewer_must_type_the_fingerprint_of_this_plan(self):
        with self.assertRaisesRegex(ApprovalError, "not this plan"):
            appr.approve(self.plan, "000000000000", self.ids.signer("reviewer"), self.trusted)

    def test_reviewer_key_must_match_trusted_key(self):
        impostor = appr.Signer("reviewer", self.ids.key_path("outsider"))
        with self.assertRaisesRegex(ApprovalError, "does not match the trusted key"):
            appr.approve(self.plan, self.plan["fingerprint"], impostor, self.trusted)

    def test_unsigned_plan_is_refused(self):
        unsigned = PageClient("1234567890", TOKEN, self.log, self.fake, lambda s: None, lambda: NOW)
        with self.assertRaisesRegex(PlanError, "signed"):
            unsigned.plan_update({"about": "x"})
        del self.plan["author_sig"]
        self.assertRefused({"approver": "reviewer", "plan_sha256": "x", "sig": "x"}, "no signed author")

    def test_apply_without_trusted_keys_is_refused(self):
        c = PageClient("1234567890", TOKEN, self.log, self.fake, lambda s: None, lambda: NOW)
        ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        with self.assertRaisesRegex(ApprovalError, "no trusted keys"):
            c.apply(self.plan, ok)
        self.assertEqual(self.writes(), [])

    def test_different_identity_approval_is_applied(self):
        ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        self.c.apply(self.plan, ok)
        self.assertEqual(self.fake.fields["about"], "New about")

    def test_signing_key_readable_by_others_is_refused(self):
        if os.name != "posix":
            self.skipTest("POSIX modes")
        os.chmod(self.ids.key_path("reviewer"), 0o644)
        with self.assertRaisesRegex(appr.KeyFileError, "readable by others"):
            self.ids.signer("reviewer")

    def test_non_string_approver_or_sig_is_a_clean_refusal(self):
        ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        for bad in (["reviewer"], {"id": "reviewer"}, 7, 1.5, True, b"reviewer"):
            with self.subTest(approver=bad):
                self.assertRefused(dict(ok, approver=bad), "approver.*must be a non-empty string")
            with self.subTest(sig=bad):
                self.assertRefused(dict(ok, sig=bad), "sig.*must be a non-empty string")
        with self.assertRaisesRegex(ApprovalError, "must be strings"):
            appr.same_identity("agent", ["agent"])

    def test_non_string_plan_author_is_a_clean_refusal(self):
        ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        for bad in (["agent"], {"a": 1}, 3):
            with self.subTest(author=bad):
                plan = dict(self.plan, author=bad)
                # apply refuses it earlier (fingerprint); the checker itself must also refuse cleanly
                self.assertRefusedPlan(plan, ok)
                with self.assertRaisesRegex(ApprovalError, "author.*must be a non-empty string"):
                    appr.check_approval(plan, ok, self.trusted)

    def test_non_object_plan_is_a_clean_refusal(self):
        ok = appr.approve(self.plan, self.plan["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        for bad in ([self.plan], "plan", 7, None, True):
            with self.subTest(plan=bad):
                self.assertRefusedPlan(bad, ok)
                with self.assertRaisesRegex(ApprovalError, "plan must be a JSON object"):
                    appr.check_approval(bad, ok, self.trusted)
                with self.assertRaisesRegex(ApprovalError, "plan must be a JSON object"):
                    appr.approve(bad, "x", self.ids.signer("reviewer"), self.trusted)
                with self.assertRaisesRegex(ApprovalError, "plan must be a JSON object"):
                    appr.plan_digest(bad)

    def test_identity_with_a_trailing_newline_is_refused(self):
        for bad in ("agent\n", "agent\r\n", "\nagent", "age\nnt", "agent "):
            with self.subTest(identity=bad):
                with self.assertRaises(appr.KeyFileError):
                    appr.check_identity(bad)
                with self.assertRaises(appr.KeyFileError):
                    appr.Signer(bad, self.ids.key_path("agent"))
        self.assertEqual(appr.check_identity("agent"), "agent")

    def test_changelog_line_that_is_not_an_object_does_not_crash(self):
        self.log.write_text('[1, 2]\n"x"\n7\nnot json\n')
        post = self.c.plan_post("Hello")
        ok = appr.approve(post, post["fingerprint"], self.ids.signer("reviewer"), self.trusted)
        self.c.apply(post, ok)
        with self.assertRaisesRegex(ApprovalError, "already applied"):
            self.c.apply(post, ok)

    def test_keygen_refuses_to_overwrite(self):
        with self.assertRaises(FileExistsError):
            appr.generate("agent", self.ids.key_path("agent"))


if __name__ == "__main__":
    unittest.main()
