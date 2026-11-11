"""Minimal Graph / ARM client built on the stdlib. Tokens come from the Azure CLI."""
from __future__ import annotations

import base64
import json
import subprocess
import time
import urllib.error
import urllib.request

GRAPH = "https://graph.microsoft.com"
ARM = "https://management.azure.com"


class ApiError(Exception):
    def __init__(self, status: int, method: str, url: str, body: str):
        self.status, self.method, self.url, self.body = status, method, url, body
        super().__init__(f"{method} {url} -> HTTP {status}: {body[:400]}")


def get_token(resource: str) -> str:
    out = subprocess.run(
        ["az", "account", "get-access-token", "--resource", resource, "-o", "json"],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        raise RuntimeError(f"az account get-access-token failed for {resource}: {out.stderr.strip()}")
    return json.loads(out.stdout)["accessToken"]


def decode_jwt(token: str) -> dict:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


class Client:
    def __init__(self, base: str, token: str | None = None):
        self.base = base
        self.token = token or get_token(base)
        self.claims = decode_jwt(self.token)

    def request(self, method: str, url: str, body: dict | None = None, retries: int = 5) -> dict:
        if not url.startswith("http"):
            url = self.base + url
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(retries):
            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Content-Type", "application/json")
            req.add_header("ConsistencyLevel", "eventual")
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    raw = r.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode(errors="replace")
                if e.code in (429, 502, 503, 504) and attempt < retries - 1:
                    time.sleep(int(e.headers.get("Retry-After", 2 ** attempt)))
                    continue
                raise ApiError(e.code, method, url, text) from None
        raise RuntimeError("unreachable")

    def get(self, url: str) -> dict:
        return self.request("GET", url)

    def patch(self, url: str, body: dict) -> dict:
        return self.request("PATCH", url, body)

    def post(self, url: str, body: dict) -> dict:
        return self.request("POST", url, body)

    def get_all(self, url: str) -> list[dict]:
        """Follow @odata.nextLink (Graph) / nextLink (ARM)."""
        items: list[dict] = []
        while url:
            page = self.get(url)
            items.extend(page.get("value", []))
            url = page.get("@odata.nextLink") or page.get("nextLink")
        return items

    def resource_graph(self, query: str) -> list[dict]:
        """Azure Resource Graph across every subscription the caller can see."""
        rows: list[dict] = []
        body: dict = {"query": query, "options": {"resultFormat": "objectArray", "$top": 1000}}
        while True:
            res = self.post("/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01", body)
            rows.extend(res.get("data", []))
            skip = res.get("$skipToken")
            if not skip:
                return rows
            body["options"]["$skipToken"] = skip
