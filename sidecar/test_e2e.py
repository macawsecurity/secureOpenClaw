#!/usr/bin/env python3
"""
End-to-End Test for SecureOpenClaw MACAW Integration

This test validates the complete flow:
1. TypeScript → Bridge → Sidecar → MACAWClient → invoke_tool
2. MACAWClient → Callback → TypeScript (simulated)
3. Result → MACAWClient → Sidecar → Bridge → TypeScript

Prerequisites:
- MACAW installed (run install.sh first)
- MACAW_HOME set to macaw_lib directory
- Python dependencies installed (httpx, pydantic, fastapi, uvicorn)

Usage:
    cd secureopenclaw/openclaw/sidecar
    export MACAW_HOME=../macaw_lib
    python test_e2e.py
"""

import os
import sys
import json
import time
import hmac
import hashlib
import threading
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

import httpx

# Configuration
SIDECAR_PORT = 18798
CALLBACK_PORT = 18799
HMAC_SECRET = os.getenv("MACAW_HMAC_SECRET", "secure-openclaw-dev-secret")
SIDECAR_URL = f"http://127.0.0.1:{SIDECAR_PORT}"

# Test results
test_results = []


def compute_expected_hmac(data: Dict[str, Any]) -> str:
    """Compute expected HMAC for verification."""
    payload = json.dumps(data, sort_keys=True)
    return hmac.new(
        HMAC_SECRET.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()


class MockCallbackHandler(BaseHTTPRequestHandler):
    """
    Simulates the TypeScript callback server.
    When MACAW approves a tool invocation, it calls back here.
    """

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def do_POST(self):
        """Handle POST /execute/{tool_name}"""
        # Parse tool name from URL
        if not self.path.startswith("/execute/"):
            self.send_error(404, "Not found")
            return

        tool_name = self.path.split("/execute/")[1]

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")

        # Verify HMAC signature
        signature = self.headers.get("X-MACAW-Signature")
        if signature:
            try:
                params = json.loads(body)
                expected = compute_expected_hmac(params)
                if signature != expected:
                    print(f"  ⚠️  HMAC mismatch for {tool_name}")
                    print(f"      Expected: {expected[:16]}...")
                    print(f"      Got:      {signature[:16]}...")
            except:
                pass

        # Parse params
        try:
            params = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "Invalid JSON")
            return

        print(f"  📞 Callback received: {tool_name}")
        print(f"      Params: {json.dumps(params, indent=8)[:100]}...")

        # Simulate tool execution based on tool name
        if tool_name == "test_echo":
            result = {"echoed": params.get("message", ""), "tool": "test_echo"}
        elif tool_name == "test_math":
            a = params.get("a", 0)
            b = params.get("b", 0)
            op = params.get("op", "add")
            if op == "add":
                result = {"result": a + b, "operation": "add"}
            elif op == "multiply":
                result = {"result": a * b, "operation": "multiply"}
            else:
                result = {"error": f"Unknown operation: {op}"}
        elif tool_name == "test_file_read":
            # This might be denied by policy if path is sensitive
            result = {"content": "mock file content", "path": params.get("path", "")}
        else:
            result = {"status": "ok", "tool": tool_name, "params": params}

        # Send response
        response = {"ok": True, "result": result}
        response_body = json.dumps(response).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(response_body))
        self.end_headers()
        self.wfile.write(response_body)


def start_mock_callback_server() -> HTTPServer:
    """Start the mock callback server in a background thread."""
    server = HTTPServer(("127.0.0.1", CALLBACK_PORT), MockCallbackHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"✓ Mock callback server started on port {CALLBACK_PORT}")
    return server


def wait_for_sidecar(max_attempts: int = 30) -> bool:
    """Wait for sidecar to be healthy."""
    print("Waiting for sidecar to be healthy...")
    for i in range(max_attempts):
        try:
            response = httpx.get(f"{SIDECAR_URL}/health", timeout=2.0)
            if response.status_code == 200:
                data = response.json()
                print(f"✓ Sidecar healthy: {data}")
                return True
        except:
            pass
        time.sleep(0.5)
    return False


def register_tools(tools: list) -> bool:
    """Register tools with the sidecar."""
    try:
        response = httpx.post(
            f"{SIDECAR_URL}/register_tools",
            json={"tools": tools},
            timeout=10.0
        )
        if response.status_code == 200:
            data = response.json()
            print(f"✓ Registered {data.get('registered', 0)} tools")
            return True
        else:
            print(f"✗ Failed to register tools: {response.status_code}")
            return False
    except Exception as e:
        print(f"✗ Error registering tools: {e}")
        return False


def invoke_tool(tool: str, params: Dict[str, Any], principal: Optional[Dict] = None) -> Dict:
    """Invoke a tool through the sidecar."""
    request = {
        "tool": tool,
        "params": params,
        "principal": principal,
        "timeout": 30.0
    }
    try:
        response = httpx.post(
            f"{SIDECAR_URL}/invoke",
            json=request,
            timeout=35.0
        )
        return response.json()
    except Exception as e:
        return {"ok": False, "error": str(e)}


def test_echo():
    """Test basic echo tool."""
    print("\n📋 Test: Echo Tool")
    result = invoke_tool("test_echo", {"message": "Hello from SecureOpenClaw!"})
    if result.get("ok"):
        echoed = result.get("result", {}).get("echoed", "")
        if echoed == "Hello from SecureOpenClaw!":
            print("  ✓ Echo returned correct message")
            test_results.append(("echo", True, None))
            return True
    print(f"  ✗ Echo failed: {result}")
    test_results.append(("echo", False, result))
    return False


def test_math():
    """Test math operations."""
    print("\n📋 Test: Math Operations")
    success = True

    # Test addition
    result = invoke_tool("test_math", {"a": 5, "b": 3, "op": "add"})
    if result.get("ok") and result.get("result", {}).get("result") == 8:
        print("  ✓ Addition: 5 + 3 = 8")
    else:
        print(f"  ✗ Addition failed: {result}")
        success = False

    # Test multiplication
    result = invoke_tool("test_math", {"a": 4, "b": 7, "op": "multiply"})
    if result.get("ok") and result.get("result", {}).get("result") == 28:
        print("  ✓ Multiplication: 4 × 7 = 28")
    else:
        print(f"  ✗ Multiplication failed: {result}")
        success = False

    test_results.append(("math", success, None))
    return success


def test_with_principal():
    """Test invocation with principal context."""
    print("\n📋 Test: Invocation with Principal")
    principal = {
        "userId": "user-123",
        "userName": "Test User",
        "role": "admin",
        "channel": "cli",
        "sessionKey": "session-abc"
    }
    result = invoke_tool("test_echo", {"message": "Admin request"}, principal=principal)
    if result.get("ok"):
        print("  ✓ Invocation with principal succeeded")
        print(f"      Audit ID: {result.get('auditId', 'N/A')}")
        test_results.append(("principal", True, None))
        return True
    print(f"  ✗ Invocation with principal failed: {result}")
    test_results.append(("principal", False, result))
    return False


def test_unregistered_tool():
    """Test invoking an unregistered tool (should fail)."""
    print("\n📋 Test: Unregistered Tool (should fail)")
    result = invoke_tool("nonexistent_tool", {"foo": "bar"})
    if not result.get("ok") and result.get("error") == "tool_not_registered":
        print("  ✓ Correctly rejected unregistered tool")
        test_results.append(("unregistered", True, None))
        return True
    print(f"  ✗ Should have rejected unregistered tool: {result}")
    test_results.append(("unregistered", False, result))
    return False


def test_audit_event():
    """Test logging an audit event."""
    print("\n📋 Test: Audit Event Logging")
    event = {
        "event_type": "test_event",
        "source": "e2e_test",
        "action": "test_action",
        "target": "test_target",
        "outcome": "success",
        "signed": False,
        "category": "custom",
        "metadata": {"test_key": "test_value"}
    }
    try:
        response = httpx.post(
            f"{SIDECAR_URL}/audit",
            json=event,
            timeout=5.0
        )
        if response.status_code == 200 and response.json().get("ok"):
            print("  ✓ Audit event logged successfully")
            test_results.append(("audit", True, None))
            return True
    except Exception as e:
        print(f"  ✗ Audit event failed: {e}")
        test_results.append(("audit", False, str(e)))
        return False
    print(f"  ✗ Audit event failed: {response.text}")
    test_results.append(("audit", False, response.text))
    return False


def print_summary():
    """Print test summary."""
    print("\n" + "=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, success, _ in test_results if success)
    failed = sum(1 for _, success, _ in test_results if not success)

    for name, success, error in test_results:
        status = "✓ PASS" if success else "✗ FAIL"
        print(f"  {status}: {name}")
        if error:
            print(f"         Error: {error}")

    print("-" * 60)
    print(f"Total: {passed} passed, {failed} failed")

    if failed == 0:
        print("\n🎉 All tests passed! MACAW integration is working.")
        print("\nCheck console.macawsecurity.ai to see invocations in the activity graph.")
    else:
        print("\n⚠️  Some tests failed. Check MACAW configuration.")

    return failed == 0


def main():
    """Run end-to-end tests."""
    print("=" * 60)
    print("SecureOpenClaw MACAW Integration - End-to-End Test")
    print("=" * 60)

    # Check MACAW_HOME
    macaw_home = os.getenv("MACAW_HOME")
    if not macaw_home:
        print("\n✗ MACAW_HOME not set.")
        print("  Run: export MACAW_HOME=../macaw_lib")
        sys.exit(1)

    config_path = os.path.join(macaw_home, ".macaw", "config.json")
    if not os.path.exists(config_path):
        print(f"\n✗ MACAW config not found: {config_path}")
        print("  Run install.sh first to set up MACAW.")
        sys.exit(1)

    print(f"\n✓ MACAW_HOME: {macaw_home}")

    # Start mock callback server
    print("\n--- Starting Mock Callback Server ---")
    callback_server = start_mock_callback_server()

    # Start sidecar in background
    print("\n--- Starting Sidecar Server ---")
    print("(If sidecar is not running, start it with: python server.py)")

    # Check if sidecar is already running
    try:
        response = httpx.get(f"{SIDECAR_URL}/health", timeout=1.0)
        if response.status_code == 200:
            print(f"✓ Sidecar already running")
    except:
        print("Starting sidecar...")
        import subprocess
        sidecar_process = subprocess.Popen(
            [sys.executable, "server.py"],
            env={**os.environ, "MACAW_HOME": macaw_home},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        time.sleep(2)  # Give it time to start

    # Wait for sidecar
    if not wait_for_sidecar():
        print("\n✗ Sidecar failed to start. Check MACAW configuration.")
        sys.exit(1)

    # Register test tools
    print("\n--- Registering Test Tools ---")
    test_tools = ["test_echo", "test_math", "test_file_read"]
    if not register_tools(test_tools):
        print("✗ Failed to register tools")
        sys.exit(1)

    # Run tests
    print("\n--- Running Tests ---")

    try:
        test_echo()
        test_math()
        test_with_principal()
        test_unregistered_tool()
        test_audit_event()
    except Exception as e:
        print(f"\n✗ Test error: {e}")
        traceback.print_exc()

    # Summary
    success = print_summary()

    # Cleanup
    callback_server.shutdown()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
