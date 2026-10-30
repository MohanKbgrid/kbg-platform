# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 KB Grid
"""A small MCP server for tests: stdio (run this file) or HTTP (FakeMCPHttp). Tools:

  get_stock(sku)      read-only (annotated)        -> structuredContent {sku, qty}
  find_order(id)      no annotations               -> text JSON
  cancel_order(id)    readOnlyHint false           -> must never be exposed
  broken()            returns isError
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOLS = [
    {"name": "get_stock", "description": "Stock for a SKU at every location",
     "inputSchema": {"type": "object", "properties": {"sku": {"type": "string"}}, "required": ["sku"]},
     "annotations": {"readOnlyHint": True}},
    {"name": "find_order", "description": "Order header by id",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}, "verbose": {"type": "boolean"}},
                     "required": ["id"]}},
    {"name": "cancel_order", "description": "Cancel an order",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}},
     "annotations": {"readOnlyHint": False, "destructiveHint": True}},
    {"name": "broken", "description": "Always fails", "inputSchema": {"type": "object", "properties": {}},
     "annotations": {"readOnlyHint": True}},
]


def handle(msg: dict) -> dict | None:
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if mid is None:
        return None                                                   # notification
    if method == "initialize":
        res = {"protocolVersion": params.get("protocolVersion"), "capabilities": {"tools": {}},
               "serverInfo": {"name": "fake-wms", "version": "1"}}
    elif method == "tools/list":
        if params.get("cursor") == "page2":
            res = {"tools": TOOLS[2:]}
        else:
            res = {"tools": TOOLS[:2], "nextCursor": "page2"}
    elif method == "tools/call":
        name, args = params.get("name"), params.get("arguments") or {}
        if name == "get_stock":
            res = {"content": [{"type": "text", "text": "ok"}],
                   "structuredContent": {"sku": args.get("sku"), "qty": {"WH_CHN": 4, "STORE_FLG": 1}}}
        elif name == "find_order":
            res = {"content": [{"type": "text", "text": json.dumps({"id": args.get("id"), "status": "paid"})}]}
        elif name == "cancel_order":
            res = {"content": [{"type": "text", "text": "cancelled!"}]}
        elif name == "broken":
            res = {"content": [{"type": "text", "text": "backend down"}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool {name}"}}
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": res}


class FakeMCPHttp:
    def __init__(self, sse: bool = False) -> None:
        self.calls: list[dict] = []
        self.headers: list[dict] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                msg = json.loads(self.rfile.read(n))
                outer.calls.append(msg)
                outer.headers.append(dict(self.headers))
                reply = handle(msg)
                if reply is None:
                    self.send_response(202)
                    self.end_headers()
                    return
                if sse:
                    data = (f"event: message\ndata: {json.dumps({'jsonrpc': '2.0', 'method': 'notifications/x'})}\n\n"
                            f"event: message\ndata: {json.dumps(reply)}\n\n").encode()
                    ctype = "text/event-stream"
                else:
                    data, ctype = json.dumps(reply).encode(), "application/json"
                self.send_response(200)
                self.send_header("Content-Type", ctype)
                self.send_header("Mcp-Session-Id", "sess-1")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}/mcp"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


if __name__ == "__main__":                                            # stdio transport
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        out = handle(msg)
        if out is not None:
            sys.stdout.write(json.dumps(out) + "\n")
            sys.stdout.flush()
