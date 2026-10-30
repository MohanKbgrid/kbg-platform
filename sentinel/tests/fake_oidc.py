# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A small OpenID Connect provider for tests: discovery, JWKS, authorize (signs in `user`), token (PKCE
checked, RS256-signed ID tokens; needs `cryptography`, a test-only dependency)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def b64(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def b64i(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class FakeOIDC:
    def __init__(self, client_id: str = "sentinel-console", secret: str | None = "s3cret") -> None:
        from cryptography.hazmat.primitives.asymmetric import rsa
        self.client_id, self.secret = client_id, secret
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "k1"
        self.forge = False                           # sign with a different key (a forged token)
        self.alg = "RS256"
        self.user: dict = {"sub": "u-hari", "email": "hari@acme.in", "email_verified": True}
        self.codes: dict[str, dict] = {}
        self.tamper: dict = {}                       # claim overrides for negative tests
        self.token_requests: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, code, obj):
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                u = urllib.parse.urlparse(self.path)
                if u.path == "/.well-known/openid-configuration":
                    return self._json(200, {"issuer": outer.issuer, "authorization_endpoint": outer.issuer + "/auth",
                                            "token_endpoint": outer.issuer + "/token",
                                            "jwks_uri": outer.issuer + "/jwks"})
                if u.path == "/jwks":
                    pub = outer.key.public_key().public_numbers()
                    return self._json(200, {"keys": [{"kty": "RSA", "kid": outer.kid, "alg": "RS256", "use": "sig",
                                                      "n": b64i(pub.n), "e": b64i(pub.e)}]})
                if u.path == "/auth":
                    q = dict(urllib.parse.parse_qsl(u.query))
                    code = secrets.token_urlsafe(8)
                    outer.codes[code] = q
                    loc = q["redirect_uri"] + "?" + urllib.parse.urlencode({"code": code, "state": q["state"]})
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                    return
                self._json(404, {})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                form = dict(urllib.parse.parse_qsl(self.rfile.read(n).decode()))
                outer.token_requests.append(form)
                q = outer.codes.pop(form.get("code"), None)
                if q is None or form.get("client_id") != outer.client_id or (
                        outer.secret and form.get("client_secret") != outer.secret):
                    return self._json(400, {"error": "invalid_grant"})
                chal = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=")
                if chal.decode() != q["code_challenge"]:
                    return self._json(400, {"error": "invalid_grant", "error_description": "pkce"})
                claims = {"iss": outer.issuer, "aud": outer.client_id, "exp": time.time() + 300, "iat": time.time(),
                          "nonce": q["nonce"], **outer.user, **outer.tamper}
                idt = outer.sign(claims)
                self._json(200, {"access_token": "at", "token_type": "Bearer", "id_token": idt})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.issuer = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def sign(self, claims: dict) -> str:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        head = b64({"alg": self.alg, "kid": self.kid, "typ": "JWT"}) + "." + b64(claims)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048) if self.forge else self.key
        sig = key.sign(head.encode(), padding.PKCS1v15(), hashes.SHA256())
        return head + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
