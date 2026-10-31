import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from fbguard import cli
from tests.fake import FakeGraph
from tests.keys import Identities


def env_for(ids, d, who):
    return {"FBG_PAGE_ID": "1234567890", "FBG_CHANGELOG": f"{d}/log.jsonl",
            "FBG_IDENTITY": who, "FBG_SIGNING_KEY": str(ids.key_path(who)),
            "FBG_TRUSTED_KEYS": str(ids.trusted_file)}


class CliTest(unittest.TestCase):
    def test_plan_then_apply_round_trip(self):
        fake = FakeGraph()
        ids = Identities("agent", "reviewer")
        self.addCleanup(ids.cleanup)
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, env_for(ids, d, "agent")), \
             mock.patch("fbguard.tokens.TokenStore.load", return_value="EAA" + "t" * 30), \
             mock.patch("fbguard.graph.urllib_transport", fake):
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["plan-update", "about=Hello", "--out", f"{d}/p.json"]), 0)
            self.assertIn("Nothing sent", out.getvalue())
            self.assertEqual([c for c in fake.calls if c[0] != "GET"], [])
            fp = json.loads(Path(f"{d}/p.json").read_text())["fingerprint"]
            # The agent that wrote the plan tries to approve it.
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["approve", f"{d}/p.json", "--fingerprint", fp, "--out", f"{d}/a.json"]), 2)
            self.assertIn("cannot approve", err.getvalue())
            self.assertFalse(Path(f"{d}/a.json").exists())
            # A different identity approves it, then the agent applies it.
            with mock.patch.dict(os.environ, env_for(ids, d, "reviewer")), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["approve", f"{d}/p.json", "--fingerprint", fp, "--out", f"{d}/a.json"]), 0)
            self.assertEqual([c for c in fake.calls if c[0] != "GET"], [])
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["apply", f"{d}/p.json", "--approval", f"{d}/a.json"]), 0)
            self.assertEqual(fake.fields["about"], "Hello")
            self.assertTrue(Path(f"{d}/log.jsonl").exists())

    def test_plan_or_approval_that_is_not_a_json_object_is_a_clean_error(self):
        fake = FakeGraph()
        ids = Identities("agent", "reviewer")
        self.addCleanup(ids.cleanup)
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, env_for(ids, d, "agent")), \
             mock.patch("fbguard.tokens.TokenStore.load", return_value="EAA" + "t" * 30), \
             mock.patch("fbguard.graph.urllib_transport", fake):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["plan-update", "about=Hello", "--out", f"{d}/p.json"]), 0)
            fp = json.loads(Path(f"{d}/p.json").read_text())["fingerprint"]
            with mock.patch.dict(os.environ, env_for(ids, d, "reviewer")), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["approve", f"{d}/p.json", "--fingerprint", fp, "--out", f"{d}/a.json"]), 0)
            bad = {"list": "[1, 2]", "string": '"plan"', "number": "7", "null": "null", "bool": "true",
                   "not json": "{nope", "empty": ""}
            for name, text in bad.items():
                Path(f"{d}/bad.json").write_text(text)
                for argv, what in ((["apply", f"{d}/bad.json", "--approval", f"{d}/a.json"], "plan"),
                                   (["apply", f"{d}/p.json", "--approval", f"{d}/bad.json"], "approval")):
                    with self.subTest(case=name, file=what):
                        err = io.StringIO()
                        with redirect_stderr(err), redirect_stdout(io.StringIO()):
                            self.assertEqual(cli.main(argv), 2)
                        self.assertRegex(err.getvalue(), rf"^error: {what} (must be a JSON object|file .* is not valid JSON)")
                        self.assertNotIn("Traceback", err.getvalue())
                with self.subTest(case=name, cmd="approve"):
                    err = io.StringIO()
                    with mock.patch.dict(os.environ, env_for(ids, d, "reviewer")), redirect_stderr(err), \
                         redirect_stdout(io.StringIO()):
                        self.assertEqual(cli.main(["approve", f"{d}/bad.json", "--fingerprint", fp, "--out", f"{d}/a2.json"]), 2)
                    self.assertIn("error: plan", err.getvalue())
            Path(f"{d}/bad.json").write_bytes(b"\xff\xfe{}")
            err = io.StringIO()
            with redirect_stderr(err), redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["apply", f"{d}/bad.json", "--approval", f"{d}/a.json"]), 2)
            self.assertIn("not UTF-8", err.getvalue())
            self.assertEqual([c for c in fake.calls if c[0] != "GET"], [])
            self.assertFalse(Path(f"{d}/a2.json").exists())

    def test_keygen_prints_only_the_public_line(self):
        with tempfile.TemporaryDirectory() as d:
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(cli.main(["keygen", "--identity", "reviewer", "--key-out", f"{d}/r.key"]), 0)
            self.assertTrue(out.getvalue().startswith("reviewer ed25519:"))
            self.assertNotIn("PRIVATE", out.getvalue())
            self.assertEqual(os.stat(f"{d}/r.key").st_mode & 0o777, 0o600)


    def test_plan_post_accepts_trailing_z(self):
        import datetime as dt
        fake = FakeGraph()
        when = (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).replace(microsecond=0)
        at = when.strftime("%Y-%m-%dT%H:%M:%SZ")
        ids = Identities("agent")
        self.addCleanup(ids.cleanup)
        with tempfile.TemporaryDirectory() as d, \
             mock.patch.dict(os.environ, env_for(ids, d, "agent")), \
             mock.patch("fbguard.tokens.TokenStore.load", return_value="EAA" + "t" * 30), \
             mock.patch("fbguard.graph.urllib_transport", fake):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(cli.main(["plan-post", "Hi", "--at", at, "--out", f"{d}/p.json"]), 0)
            plan = json.loads(Path(f"{d}/p.json").read_text())
            self.assertEqual(plan["post"]["scheduled_publish_time"], int(when.timestamp()))
            self.assertEqual([c for c in fake.calls if c[0] != "GET"], [])


if __name__ == "__main__":
    unittest.main()
