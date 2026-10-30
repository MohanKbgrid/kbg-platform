# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A stand-in for Ollama / OpenAI-compatible servers, so model tests need no model and no network.

Speaks: POST /api/chat, /api/embed, /v1/chat/completions, /v1/embeddings; GET /api/tags, /api/version.
`reply(body) -> str` decides the chat answer; `fail_with` makes every request fail (status code, or
"drop" to close the connection, or "slow" to sleep past the client's timeout).
"""
from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from collections.abc import Callable


class FakeModelServer:
    def __init__(self, reply: Callable[[dict[str, Any]], str] | None = None, models: list[str] | None = None) -> None:
        self.reply = reply or (lambda body: json.dumps({"ok": True}))
        self.models = models or ["qwen2.5:7b-instruct", "nomic-embed-text"]
        self.requests: list[dict[str, Any]] = []
        self.fail_with: int | str | None = None
        self.slow_s = 2.0
        self.in_flight = 0
        self.max_in_flight = 0
        self.hold_s = 0.0
        self._lock = threading.Lock()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:  # silence
                pass

            def _send(self, code: int, obj: Any) -> None:
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                if self.path == "/api/tags":
                    return self._send(200, {"models": [{"name": m} for m in outer.models]})
                if self.path == "/api/version":
                    return self._send(200, {"version": "0.0-fake"})
                self._send(404, {"error": "not found"})

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                with outer._lock:
                    outer.requests.append({"path": self.path, "headers": dict(self.headers), "body": body})
                    outer.in_flight += 1
                    outer.max_in_flight = max(outer.max_in_flight, outer.in_flight)
                try:
                    if outer.hold_s:
                        time.sleep(outer.hold_s)
                    f = outer.fail_with
                    if f == "drop":
                        self.close_connection = True
                        self.connection.shutdown(2)
                        return None
                    if f == "slow":
                        time.sleep(outer.slow_s)
                    elif isinstance(f, int):
                        return self._send(f, {"error": f"fake failure {f}"})
                    if body.get("model") not in outer.models:
                        return self._send(404, {"error": f"model '{body.get('model')}' not found"})
                    if self.path == "/api/chat":
                        text = outer.reply(body)
                        return self._send(200, {"model": body["model"], "message": {"role": "assistant",
                                                                                    "content": text},
                                                "done": True, "prompt_eval_count": 120, "eval_count": 30})
                    if self.path == "/v1/chat/completions":
                        text = outer.reply(body)
                        return self._send(200, {"choices": [{"message": {"role": "assistant", "content": text}}],
                                                "usage": {"prompt_tokens": 100, "completion_tokens": 20}})
                    if self.path == "/api/embed":
                        inp = body.get("input")
                        texts = inp if isinstance(inp, list) else [inp]
                        return self._send(200, {"embeddings": [[float(len(t)), 1.0, 0.0] for t in texts],
                                                "prompt_eval_count": sum(len(t) for t in texts)})
                    if self.path == "/v1/embeddings":
                        inp = body.get("input")
                        texts = inp if isinstance(inp, list) else [inp]
                        return self._send(200, {"data": [{"embedding": [float(len(t)), 1.0]} for t in texts],
                                                "usage": {"prompt_tokens": 5, "total_tokens": 5}})
                    return self._send(404, {"error": "not found"})
                finally:
                    with outer._lock:
                        outer.in_flight -= 1

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self._t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._t.start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()
