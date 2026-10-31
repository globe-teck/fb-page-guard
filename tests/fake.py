"""A fake Graph API. Records every call; never touches the network."""
import json
import urllib.parse


class FakeGraph:
    def __init__(self, page_id="1234567890", fields=None):
        self.page_id = page_id
        self.fields = dict(fields or {"id": page_id, "name": "Example Page", "about": "Old about",
                                      "website": "https://example.com"})
        self.calls = []
        self.fail_next = []  # list of (status, error dict) to return before succeeding
        self.posts = []

    def __call__(self, method, url, body):
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.split("/", 2)[2]
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if body:
            params.update(urllib.parse.parse_qsl(body.decode()))
        self.calls.append((method, path, params))
        if self.fail_next:
            status, err = self.fail_next.pop(0)
            return status, json.dumps({"error": err}).encode()
        if method == "GET" and path == self.page_id:
            want = params.get("fields", "").split(",")
            return 200, json.dumps({k: self.fields.get(k) for k in want if k}).encode()
        if method == "GET" and path == f"{self.page_id}/published_posts":
            return 200, json.dumps({"data": self.posts}).encode()
        if method == "POST" and path == self.page_id:
            for k, v in params.items():
                if k != "access_token":
                    self.fields[k] = v
            return 200, b'{"success": true}'
        if method == "POST" and path == f"{self.page_id}/feed":
            pid = f"{self.page_id}_{len(self.posts) + 1}"
            self.posts.append({"id": pid, "message": params.get("message")})
            return 200, json.dumps({"id": pid}).encode()
        return 404, json.dumps({"error": {"message": f"unknown path {path}", "code": 803}}).encode()
