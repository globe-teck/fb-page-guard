import unittest

from fbguard import graph


class GraphTest(unittest.TestCase):
    def test_redacts_query_params_bearer_and_token_shapes(self):
        s = graph.redact("x?access_token=EAAB123&client_secret=s3cr3t Bearer abc.def EAA" + "x" * 30)
        self.assertNotIn("EAAB123", s)
        self.assertNotIn("s3cr3t", s)
        self.assertNotIn("abc.def", s)
        self.assertNotIn("x" * 30, s)

    def test_error_parsing_keeps_code_and_redacts(self):
        with self.assertRaises(graph.GraphError) as cm:
            graph.parse_response(400, b'{"error":{"message":"bad access_token=EAAsecret","code":190,"error_subcode":463}}')
        e = cm.exception
        self.assertEqual((e.code, e.subcode), (190, 463))
        self.assertNotIn("EAAsecret", str(e))
        self.assertFalse(e.retryable)

    def test_rate_limit_codes_are_retryable(self):
        for code in (4, 17, 32, 613, 80001, 1, 2):
            self.assertTrue(graph.GraphError("x", code).retryable)

    def test_non_json_and_bare_bool(self):
        with self.assertRaises(graph.GraphError):
            graph.parse_response(502, b"<html>")
        self.assertEqual(graph.parse_response(200, b"true"), {"success": True})

    def test_get_uses_query_post_uses_body(self):
        seen = []
        def t(method, url, body):
            seen.append((method, url, body))
            return 200, b"{}"
        graph.request("GET", "/123", {"fields": "id"}, t)
        graph.request("POST", "123", {"about": "hi"}, t)
        self.assertIn("?fields=id", seen[0][1])
        self.assertIsNone(seen[0][2])
        self.assertNotIn("?", seen[1][1])
        self.assertEqual(seen[1][2], b"about=hi")


if __name__ == "__main__":
    unittest.main()
