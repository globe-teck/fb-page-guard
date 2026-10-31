import json
import os
import stat
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from fbguard import tokens

SHORT, LONG, PAGE_TOK, SECRET = "EAAshort" + "s" * 30, "EAAlong" + "l" * 30, "EAApage" + "p" * 30, "app-secret-value"  # pragma: allowlist secret (fake test values)


def fake_transport(pages, valid=True):
    calls = []

    def t(method, url, body):
        u = urllib.parse.urlparse(url)
        path = u.path.split("/", 2)[2]
        q = dict(urllib.parse.parse_qsl(u.query))
        calls.append((path, q))
        if path == "oauth/access_token":
            assert q["fb_exchange_token"] == SHORT and q["client_secret"] == SECRET
            return 200, json.dumps({"access_token": LONG}).encode()
        if path == "me/accounts":
            assert q["access_token"] == LONG
            if "after" not in q:
                return 200, json.dumps({"data": pages[:1], "paging": {"cursors": {"after": "c1"}, "next": "x"}}).encode()
            return 200, json.dumps({"data": pages[1:]}).encode()
        if path == "debug_token":
            return 200, json.dumps({"data": {"is_valid": valid, "type": "PAGE", "expires_at": 0,
                                             "scopes": ["pages_manage_posts"]}}).encode()
        return 404, b'{"error":{"message":"nope","code":803}}'
    t.calls = calls
    return t


PAGES = [{"id": "111", "name": "Other", "access_token": "EAAother" + "o" * 30, "tasks": ["MANAGE"]},
         {"id": "222", "name": "Example Page", "access_token": PAGE_TOK, "tasks": ["MANAGE", "CREATE_CONTENT"]}]


class TokenTest(unittest.TestCase):
    def test_bootstrap_follows_pagination_and_summary_has_no_secrets(self):
        t = fake_transport(PAGES)
        out = tokens.bootstrap("42", SECRET, SHORT, "222", None, t)
        self.assertIn("Example Page (222)", out)
        self.assertIn("expires: never", out)
        for s in (SHORT, LONG, PAGE_TOK, SECRET):
            self.assertNotIn(s, out)
        self.assertTrue(any(q.get("after") == "c1" for _, q in t.calls))

    def test_missing_page_and_missing_tasks(self):
        with self.assertRaises(tokens.SetupError):
            tokens.bootstrap("42", SECRET, SHORT, "999", None, fake_transport(PAGES))
        with self.assertRaises(tokens.SetupError):
            tokens.bootstrap("42", SECRET, SHORT, "111", None, fake_transport(PAGES))

    def test_invalid_token_is_refused(self):
        with self.assertRaises(tokens.SetupError):
            tokens.bootstrap("42", SECRET, SHORT, "222", None, fake_transport(PAGES, valid=False))


try:
    from cryptography.fernet import Fernet
except ImportError:  # pragma: no cover
    Fernet = None


@unittest.skipIf(Fernet is None, "cryptography not installed")
class StoreTest(unittest.TestCase):
    def test_round_trip_encrypted_0600(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["FBG_TEST_KEY"] = Fernet.generate_key().decode()
            try:
                store = tokens.TokenStore(Path(d) / "s" / "tok.enc", "FBG_TEST_KEY")
                store.save(PAGE_TOK)
                raw = store.path.read_bytes()
                self.assertNotIn(PAGE_TOK.encode(), raw)
                self.assertEqual(stat.S_IMODE(store.path.stat().st_mode), 0o600)
                self.assertEqual(store.load(), PAGE_TOK)
            finally:
                del os.environ["FBG_TEST_KEY"]

    def test_missing_key_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as d:
            store = tokens.TokenStore(Path(d) / "tok.enc", "FBG_UNSET_KEY_FOR_TEST")
            with self.assertRaises(tokens.SetupError):
                store.save("x")


if __name__ == "__main__":
    unittest.main()
