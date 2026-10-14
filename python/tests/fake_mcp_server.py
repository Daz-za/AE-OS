"""A tiny MCP stdio server for tests: answers initialize, tools/list and tools/call."""
import json
import sys

for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    m = msg.get("method")
    if m == "initialize":
        result = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                  "serverInfo": {"name": "fake-erp", "version": "0"}}
    elif m == "tools/list":
        result = {"tools": [{"name": "invoice.read"}, {"name": "invoice.pay"}]}
    elif m == "tools/call":
        p = msg["params"]
        result = {"content": [{"type": "text", "text": f"done {p['name']} {p['arguments']}"}],
                  "isError": p["name"] == "invoice.fail"}
    else:
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"],
                          "error": {"code": -32601, "message": "unknown"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": result}), flush=True)
