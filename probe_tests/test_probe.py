import base64
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from probe.probe import Probe, RpcError, callback_parts, key_bytes, post_https, public_address, subscription_diagnostic, record_rpc_diagnostic

SECRET = "whsec_" + base64.b64encode(b"a" * 32).decode()
HOST = "callback.example.test"
URL = "https://" + HOST + "/events"


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 1700000000.0
        self.requests = []
        self.reply_codes = []
        self.receiver_secret = SECRET
        self.probe = self.make_probe()
        self.addCleanup(lambda: self.probe.close())

    def make_probe(self):
        return Probe(self.directory.name, post=self.receiver, allowed_hosts=[HOST], clock=lambda: self.now)

    def receiver(self, url, body, headers):
        self.assertEqual(url, URL)
        # Independent receiver verifies Standard Webhooks framing and exact bytes.
        message = headers["webhook-id"].encode() + b"." + headers["webhook-timestamp"].encode() + b"." + body
        expected = base64.b64encode(hmac.new(base64.b64decode(self.receiver_secret[6:]), message, hashlib.sha256).digest()).decode()
        self.assertIn("v1," + expected, headers["webhook-signature"].split(" "))
        self.requests.append((json.loads(body), headers.copy()))
        if json.loads(body).get("type") == "verification":
            return 200, json.dumps({"challenge": json.loads(body)["challenge"]}).encode()
        code = self.reply_codes.pop(0) if self.reply_codes else 200
        return code, b"{}"

    def params(self, secret=SECRET, ttl=86400000):
        return {"name": "test.ping", "arguments": {}, "delivery": {"mode": "webhook", "url": URL, "secret": secret}, "ttlMs": ttl}

    def rpc(self, method, params=None):
        return self.probe.rpc({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def test_real_discovery_and_complete_lifecycle(self):
        discover = self.rpc("server/discover")["result"]
        self.assertEqual(discover["supportedVersions"], ["2026-07-28"])
        self.assertIn("events", discover["capabilities"])
        self.assertEqual(self.rpc("events/list")["result"]["events"][0]["name"], "test.ping")
        sub = self.rpc("events/subscribe", self.params())["result"]
        ping = self.probe.emit()
        self.assertTrue(self.probe.deliver_once())
        event, headers = self.requests[-1]
        self.assertEqual(event["eventId"], ping["event_id"])
        self.assertEqual(headers["X-MCP-Subscription-Id"], sub["id"])
        args = {"event_id": event["eventId"], "nonce": event["data"]["nonce"]}
        result = self.rpc("tools/call", {"name": "acknowledge_test_ping", "arguments": args})["result"]["structuredContent"]
        self.assertTrue(result["acknowledged"])
        self.assertFalse(result["already_acknowledged"])
        self.assertTrue(self.probe.acknowledge(args)["already_acknowledged"])
        self.assertEqual(self.probe.status()["events"][0]["status"], "acknowledged")
        self.assertNotIn("secret", json.dumps(self.probe.status()))
        stop = self.params(); del stop["delivery"]["secret"]
        self.assertEqual(self.rpc("events/unsubscribe", stop)["result"], {})
        self.assertEqual(self.probe.status()["active_subscriptions"], 0)

    def test_restart_idempotent_refresh_and_rotation(self):
        first = self.probe.subscribe(self.params())
        ping = self.probe.emit()
        self.probe.close()
        self.probe = self.make_probe()
        self.assertEqual(self.probe.status()["events"][0]["id"], ping["event_id"])
        before = len(self.requests)
        self.assertEqual(self.probe.subscribe(self.params())["id"], first["id"])
        self.assertEqual(len(self.requests), before)  # bounded challenge cache
        self.receiver_secret = "whsec_" + base64.b64encode(b"b" * 32).decode()
        self.assertEqual(self.probe.subscribe(self.params(self.receiver_secret))["id"], first["id"])
        self.probe.deliver_once()
        self.assertEqual(len(self.requests[-1][1]["webhook-signature"].split(" ")), 2)

    def test_transient_retries_preserve_event_id_and_refresh_signing_time(self):
        self.probe.subscribe(self.params())
        ping = self.probe.emit()
        self.reply_codes = [503, 200]
        self.probe.deliver_once()
        first = self.requests[-1]
        self.now += 5
        self.probe.deliver_once()
        second = self.requests[-1]
        self.assertEqual(first[0]["eventId"], ping["event_id"])
        self.assertEqual(second[0]["eventId"], ping["event_id"])
        self.assertNotEqual(first[1]["webhook-timestamp"], second[1]["webhook-timestamp"])
        self.assertEqual(self.probe.status()["events"][0]["attempts"], 2)
        self.assertEqual(self.probe.status()["events"][0]["status"], "delivered")

    def test_terminal_errors_not_retried_and_expiration_stops_delivery(self):
        for code in (410, 413, 302):
            with self.subTest(code=code):
                self.probe.subscribe(self.params())
                self.probe.emit()
                self.reply_codes = [code]
                self.probe.deliver_once()
                self.now += 10
                count = len(self.requests)
                self.assertFalse(self.probe.deliver_once())
                self.assertEqual(len(self.requests), count)
                self.assertEqual(self.probe.status()["events"][0]["status"], "failed")
        self.probe.subscribe(self.params(ttl=1000))
        self.probe.emit()
        self.now += 2
        self.probe.deliver_once()
        self.assertEqual(self.probe.status()["events"][0]["status"], "cancelled")
        with self.assertRaises(RpcError): self.probe.emit()

    def test_ack_rejects_unknown_nonce_and_undelivered_event(self):
        self.probe.subscribe(self.params())
        ping = self.probe.emit()
        with self.assertRaises(RpcError): self.probe.acknowledge({"event_id": ping["event_id"], "nonce": "wrong"})
        row = self.probe.db.execute("SELECT nonce FROM pings WHERE id=?", (ping["event_id"],)).fetchone()
        with self.assertRaises(RpcError): self.probe.acknowledge({"event_id": ping["event_id"], "nonce": row["nonce"]})
        self.assertIn("error", self.rpc("tools/call", {"name": "send_weixin", "arguments": {}}))

    def test_schema_and_failed_verification_do_not_activate_subscription(self):
        self.assertIn("error", self.rpc("events/subscribe", {**self.params(), "name": "message.created"}))
        self.assertIn("error", self.rpc("events/subscribe", {**self.params(), "arguments": {"peer": "arbitrary"}}))
        self.probe.post = lambda *args: (200, b'{"challenge":"wrong"}')
        result = self.rpc("events/subscribe", self.params())
        self.assertEqual(result["error"]["code"], -32015)
        self.assertEqual(self.probe.status()["active_subscriptions"], 0)

    def test_stdio_process_is_a_real_json_rpc_endpoint(self):
        path = Path(__file__).resolve().parents[1] / "probe" / "probe.py"
        request = {"jsonrpc": "2.0", "id": 12, "method": "server/discover", "params": {}}
        run = subprocess.run([sys.executable, str(path), "--state-dir", self.directory.name + "/stdio"],
                             input=json.dumps(request) + "\n", text=True, capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stderr)
        result = json.loads(run.stdout)
        self.assertEqual(result["id"], 12)
        self.assertIn("events", result["result"]["capabilities"])
        log = Path(self.directory.name) / "stdio" / "rpc-diagnostics.jsonl"
        records = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([record["stage"] for record in records], ["received", "completed"])
        self.assertEqual(records[-1]["method"], "server/discover")
        self.assertTrue(records[-1]["success"])
        self.assertEqual(log.stat().st_mode & 0o777, 0o600)

    def test_second_daemon_cannot_start_duplicate_private_pollers(self):
        path = Path(__file__).resolve().parents[1] / "probe" / "probe.py"
        command = [sys.executable, str(path), "--state-dir", self.directory.name + "/single-daemon"]
        request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {}}) + "\n"
        first = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            first.stdin.write(request); first.stdin.flush()
            response = json.loads(first.stdout.readline())
            self.assertIn("result", response)
            duplicate = subprocess.run(command, input=request, text=True, capture_output=True, timeout=15)
            self.assertEqual(duplicate.returncode, 1)
            self.assertEqual(duplicate.stdout, "")
            self.assertIn("bridge already running", duplicate.stderr)
            status = subprocess.run(command + ["--status"], text=True, capture_output=True, timeout=15)
            self.assertEqual(status.returncode, 0)
            self.assertIn("active_subscriptions", json.loads(status.stdout))
        finally:
            first.stdin.close()
            try: first.wait(timeout=15)
            except subprocess.TimeoutExpired:
                first.kill(); first.wait(timeout=5)
            first.stdout.close(); first.stderr.close()


class NetworkPolicyTests(unittest.TestCase):
    def test_discovery_rejects_subscription_without_dns_socket_or_persistence(self):
        with tempfile.TemporaryDirectory() as directory:
            probe=Probe(directory,allowed_hosts=[])
            self.addCleanup(probe.close)
            request={'jsonrpc':'2.0','id':1,'method':'events/subscribe','params':{
                'name':'weixin.message','arguments':{},'delivery':{'mode':'webhook','url':URL,'secret':SECRET}}}
            record_rpc_diagnostic(directory,request)
            with patch('socket.getaddrinfo') as dns, patch('socket.create_connection') as connect:
                response=probe.rpc(request)
                self.assertEqual(response['error']['data']['reason'],'invalid_destination')
                dns.assert_not_called(); connect.assert_not_called()
            record_rpc_diagnostic(directory,request,response,completed=True)
            status=probe.status()
            self.assertEqual(status['active_subscriptions'],0)
            self.assertEqual(status['recent_rpc'][0]['callback_host'],HOST)
            self.assertNotIn(SECRET,json.dumps(status))
            self.assertNotIn('/events',json.dumps(status))

    def test_exact_public_callback_host_with_synthetic_path_preserves_exact_allowlist(self):
        host = "callbacks.example.com"
        url = "https://" + host + "/mcp-events/synthetic-callback"
        allowed = {"api.openai.com", "chatgpt.com", host}
        self.assertEqual(callback_parts(url, allowed).hostname, host)
        for bad in ("http://" + host + "/synthetic-callback",
                    "https://" + host + ".evil.test/synthetic-callback",
                    "https://other.example.com/synthetic-callback",
                    "https://" + host + ":444/synthetic-callback",
                    "https://user:pass@" + host + "/synthetic-callback"):
            with self.subTest(url=bad), self.assertRaises(RpcError):
                callback_parts(bad, allowed)
        answers = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("socket.getaddrinfo", return_value=answers), patch("socket.create_connection") as connect:
            with self.assertRaises(RpcError):
                post_https(url, b"{}", {}, allowed)
            connect.assert_not_called()

    def test_safe_status_exposes_persisted_rpc_diagnostic_only(self):
        with tempfile.TemporaryDirectory() as directory:
            request = {"method": "events/subscribe", "params": {
                "delivery": {"url": URL + "/private-capability-token", "secret": SECRET}}}
            record_rpc_diagnostic(directory, request)
            response = {"error": {"code": -32015, "message": "Callback endpoint rejected", "data": {"reason": "invalid_destination"}}}
            record_rpc_diagnostic(directory, request, response, completed=True)
            probe = Probe(directory)
            self.addCleanup(probe.close)
            result = probe.status()
            self.assertEqual(result["recent_rpc"][-1]["error_code"], -32015)
            self.assertEqual(result["recent_rpc"][-1]["error_kind"], "invalid_destination")
            for value in (SECRET, "private-capability-token"):
                self.assertNotIn(value, json.dumps(result))

    def test_subscription_diagnostics_exclude_secrets_and_url_paths(self):
        request = {"method": "events/subscribe", "params": {
            "delivery": {"url": URL + "/private-capability-token?secret=value", "secret": SECRET}}}
        received = subscription_diagnostic(request)
        self.assertEqual(json.loads(received)["callback_host"], HOST)
        for value in (SECRET, "private-capability-token", "secret=value"):
            self.assertNotIn(value, received)
        response = {"error": {"code": -32015, "message": SECRET, "data": {
            "reason": "invalid_destination", "secret": SECRET}}}
        completed = subscription_diagnostic(request, response)
        self.assertNotIn(SECRET, completed)
        self.assertEqual(json.loads(completed)["reason"], "invalid_destination")
        self.assertIsNone(subscription_diagnostic({"method": "tools/call", "params": request}))

    def test_https_host_allowlist_and_secret_validation(self):
        for url in ("http://" + HOST, "https://user:pass@" + HOST, "https://" + HOST + ":444/", "https://" + HOST + ".evil.test"):
            with self.assertRaises(RpcError): callback_parts(url, {HOST})
        with self.assertRaises(RpcError): key_bytes("whsec_bad")
        for ip in ("127.0.0.1", "169.254.169.254", "10.0.0.1", "100.64.0.1", "::1", "::ffff:8.8.8.8", "2001:db8::1"):
            self.assertFalse(public_address(ip), ip)

    def test_dns_mixed_private_answer_cannot_open_socket(self):
        answers = [(2, 1, 6, "", ("8.8.8.8", 443)), (2, 1, 6, "", ("127.0.0.1", 443))]
        with patch("socket.getaddrinfo", return_value=answers), patch("socket.create_connection") as connect:
            with self.assertRaises(RpcError): post_https(URL, b"{}", {}, {HOST})
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
