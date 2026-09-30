import base64
import json
import sqlite3
import tempfile
import unittest

from probe.probe import Probe, RpcError
from probe.weixin import MESSAGE_EVENT, WeixinError, api_base, public_ip, parse_api_json

SECRET = "whsec_" + base64.b64encode(b"b" * 32).decode()
OWNER, ACCOUNT = "owner-test@im.wechat", "bot-test"


class FakeIlink:
    def __init__(self):
        self.sent, self.results = [], []

    def send(self, account, peer, text, client_id, context):
        self.sent.append((peer, text, client_id, context))
        result = self.results.pop(0) if self.results else {"ret": 0}
        if isinstance(result, Exception):
            raise result
        return result


class WeixinTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.now = 1800000000.0
        self.client = FakeIlink()
        self.callback_events = []
        self.probe = self.open_probe()
        self.addCleanup(lambda: self.probe.close())
        self.probe.weixin.bind_confirmed({"status": "confirmed", "ilink_bot_id": ACCOUNT,
            "ilink_user_id": OWNER, "bot_token": "fixture-bot-token", "baseurl": "https://ilinkai.weixin.qq.com"})

    def callback(self, url, body, headers):
        event = json.loads(body)
        if event.get("type") == "verification":
            return 200, json.dumps({"challenge": event["challenge"]}).encode()
        self.callback_events.append(event)
        return 200, b"{}"

    def open_probe(self):
        return Probe(self.directory.name, post=self.callback, allowed_hosts=["callbacks.example.com"],
                     clock=lambda: self.now, weixin_client=self.client)

    def message(self, source="18446744073709551615", text="用户原文\n你好", context="fixture-context", **changes):
        result = {"message_id": source, "from_user_id": OWNER, "to_user_id": ACCOUNT,
                  "message_type": 1, "message_state": 2, "create_time_ms": self.now * 1000,
                  "context_token": context, "item_list": [{"type": 1, "text_item": {"text": text}}]}
        result.update(changes)
        return result

    def ingest(self, *messages, cursor="fixture-cursor"):
        return self.probe.weixin.ingest(self.probe.weixin.account(), {"ret": 0, "msgs": list(messages), "get_updates_buf": cursor})

    def inbound_id(self, source="18446744073709551615"):
        return self.probe.db.execute("SELECT id FROM weixin_inbox WHERE source_id=?", (source,)).fetchone()["id"]

    def subscribe(self, name):
        return self.probe.subscribe({"name": name, "arguments": {}, "delivery": {"mode": "webhook",
            "url": "https://callbacks.example.com/synthetic-callback", "secret": SECRET}})

    def test_owner_group_echo_filter_and_lossless_dedup(self):
        good = self.message()
        self.assertEqual(self.ingest(good, self.message("2", from_user_id="other"),
            self.message("3", group_id="group"), self.message("4", message_type=2),
            self.message("5", to_user_id="other-bot")), 1)
        self.assertEqual(self.ingest(good), 0)
        mid = self.inbound_id()
        result = self.probe.weixin.read_message(mid)
        self.assertEqual(result["text"], "用户原文\n你好")
        self.assertEqual(self.probe.weixin.account()["cursor"], "fixture-cursor")
        safe = json.dumps(result) + json.dumps(self.probe.weixin.status())
        for secret in ("fixture-context", "fixture-bot-token", OWNER):
            self.assertNotIn(secret, safe)

    def test_restart_persists_cursor_and_selects_latest_context_at_send(self):
        self.ingest(self.message(context="old-context"))
        mid = self.inbound_id()
        self.probe.weixin.queue_reply(mid, "回复原文")
        self.now += 1
        self.ingest(self.message("second", context="new-context"), cursor="new-cursor")
        self.ingest(self.message("older", context="obsolete-context", create_time_ms=(self.now - 10) * 1000))
        self.probe.close(); self.probe = self.open_probe()
        self.assertEqual(self.probe.weixin.account()["cursor"], "fixture-cursor")
        self.assertTrue(self.probe.weixin.send_once())
        self.assertEqual(self.client.sent[0][3], "new-context")
        status = self.probe.weixin.send_status(mid)
        self.assertEqual(status["outgoing_text"], "回复原文")
        self.assertTrue(status["accepted"])
        self.assertIsNone(status["delivered"])

    def test_two_event_subscriptions_and_idempotent_reply_roundtrip(self):
        test_sub = self.subscribe("test.ping")
        self.subscribe(MESSAGE_EVENT)
        self.assertEqual(self.probe.status()["active_subscriptions"], 2)
        self.ingest(self.message())
        mid = self.inbound_id()
        self.assertEqual(self.probe.queue_weixin_messages(), 1)
        self.assertEqual(self.probe.queue_weixin_messages(), 0)
        self.probe.deliver_once()
        self.assertEqual(self.callback_events[-1]["name"], MESSAGE_EVENT)
        self.assertEqual(self.callback_events[-1]["data"], {"message_id": mid})
        with self.assertRaises(RpcError):
            self.probe.acknowledge({"event_id": self.callback_events[-1]["eventId"], "nonce": ""})
        self.probe.weixin.queue_reply(mid, "只发回复")
        self.probe.weixin.send_once()
        self.probe.weixin.queue_reply(mid, "只发回复")
        self.assertFalse(self.probe.weixin.send_once())
        self.assertEqual(len(self.client.sent), 1)
        with self.assertRaises(WeixinError): self.probe.weixin.queue_reply(mid, "不同回复")
        self.assertEqual(self.probe.subscription_id({"name": "test.ping", "delivery": {
            "mode": "webhook", "url": "https://callbacks.example.com/synthetic-callback"}}), test_sub["id"])

    def test_stale_context_requires_fresh_owner_message_and_never_tokenless(self):
        self.ingest(self.message())
        mid = self.inbound_id()
        self.probe.weixin.queue_reply(mid, "回复")
        self.client.results = [{"ret": -2, "errmsg": "prepare failed"}, {"ret": 0}]
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(mid)["status"], "context_required")
        self.now += 86400 * 2
        self.assertFalse(self.probe.weixin.send_once())  # Simulated time, not a real idle validation.
        self.ingest(self.message("fresh", context="fresh-context"))
        self.probe.weixin.send_once()
        self.assertEqual(self.client.sent[-1][3], "fresh-context")
        self.assertEqual(self.client.sent[0][2], self.client.sent[-1][2])
        self.assertTrue(self.probe.weixin.send_status(mid)["accepted"])

    def test_uncertain_send_is_not_retried_and_status_reader_does_not_recover(self):
        self.ingest(self.message())
        mid = self.inbound_id(); self.probe.weixin.queue_reply(mid, "回复")
        self.client.results = [WeixinError("api_timeout")]
        self.probe.weixin.send_once(); self.now += 100
        self.assertEqual(self.probe.weixin.send_status(mid)["status"], "delivery_unknown")
        self.assertFalse(self.probe.weixin.send_once())
        self.probe.db.execute("UPDATE weixin_outbox SET status='sending' WHERE message_id=?", (mid,)); self.probe.db.commit()
        second = self.open_probe()
        self.assertEqual(second.weixin.send_status(mid)["status"], "sending")
        second.weixin.recover_inflight()
        self.assertEqual(second.weixin.send_status(mid)["status"], "delivery_unknown")
        second.close()
        self.assertEqual(len(self.client.sent), 1)

    def test_bot_auth_expiry_and_bounded_rate_retries_are_distinct(self):
        self.ingest(self.message())
        mid = self.inbound_id(); self.probe.weixin.queue_reply(mid, "回复")
        self.client.results = [{"ret": -2, "errmsg": "rate limit"}] * 3
        for _ in range(3): self.probe.weixin.send_once(); self.now += 30
        self.assertEqual(self.probe.weixin.send_status(mid)["status"], "rejected")
        self.assertEqual(len(self.client.sent), 3)
        self.ingest(self.message("second")); second = self.inbound_id("second")
        self.probe.weixin.queue_reply(second, "新回复")
        self.client.results = [{"ret": -14}]
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(second)["status"], "auth_required")
        self.assertFalse(self.probe.weixin.status()["connected"])

    def test_notifications_are_explicit_idempotent_owner_only_and_malformed_media_safe(self):
        self.ingest(self.message(item_list=[{"type": 1, "text_item": "bad"}, {"type": 3, "voice_item": "bad"}]))
        mid = self.inbound_id()
        result = self.probe.weixin.read_message(mid)
        self.assertEqual(result["kind"], "media")
        self.assertEqual(result['attachments'][0]['status'], 'transcript_unavailable')
        self.assertEqual(result['attachments'][0]['error_kind'], 'no_upstream_transcript')
        notice = self.probe.weixin.queue_notification("requested-task-run-1", "用户要求的提醒")
        again = self.probe.weixin.queue_notification("requested-task-run-1", "用户要求的提醒")
        self.assertEqual(notice["send_id"], again["send_id"])
        self.probe.weixin.send_once()
        self.assertEqual(self.client.sent[-1][0], OWNER)
        self.assertEqual(self.client.sent[-1][1], "用户要求的提醒")
        with self.assertRaises(WeixinError): self.probe.weixin.queue_notification("requested-task-run-1", "变更")
        with self.assertRaises(WeixinError): self.probe.weixin.bind_confirmed({"status": "confirmed", "ilink_bot_id": ACCOUNT,
            "ilink_user_id": "another-owner", "bot_token": "fixture-other"})

    def test_api_destination_validation(self):
        self.assertEqual(api_base("https://ilinkai.weixin.qq.com/"), "https://ilinkai.weixin.qq.com")
        for bad in ("http://ilinkai.weixin.qq.com", "https://ilinkai.weixin.qq.com.evil.test", "https://user:pass@ilinkai.weixin.qq.com", "https://ilinkai.weixin.qq.com:444", "https://127.0.0.1"):
            with self.assertRaises(WeixinError): api_base(bad)
        for bad in ("127.0.0.1", "10.0.0.1", "::1", "::ffff:8.8.8.8"):
            self.assertFalse(public_ip(bad))

    def test_send_success_optional_codes_explicit_errors_and_wrong_shapes(self):
        cases = [({}, "accepted"), ({"message_id": "18446744073709551615"}, "accepted"),
                 ({"ret": None, "errcode": None}, "accepted"), ({"errcode": 0}, "accepted"),
                 ({"ret": 0, "errcode": 7}, "rejected"), ({"errcode": 7}, "rejected"),
                 ({"ret": 9}, "rejected"), ({"ret": "0"}, "delivery_unknown"),
                 ({"ret": False}, "delivery_unknown"), ({"base_resp": {"ret": -1}}, "delivery_unknown"),
                 ([], "delivery_unknown")]
        for index, (response, expected) in enumerate(cases):
            with self.subTest(response=response):
                source = "response-" + str(index)
                self.ingest(self.message(source))
                mid = self.inbound_id(source)
                self.probe.weixin.queue_reply(mid, "回复")
                self.client.results = [response]
                self.probe.weixin.send_once()
                status = self.probe.weixin.send_status(mid)
                self.assertEqual(status["status"], expected)
                self.assertEqual(status["accepted"], expected == "accepted")
                self.assertIsNone(status["delivered"])
                self.assertFalse(self.probe.weixin.send_once())

    def test_empty_body_invalid_json_and_timeout_stay_uncertain_without_resend(self):
        for index, raw in enumerate((b"", b"not json", b"[]", b"null")):
            with self.assertRaises(WeixinError) as context: parse_api_json(raw)
            self.ingest(self.message("invalid-" + str(index)))
            mid = self.inbound_id("invalid-" + str(index))
            self.probe.weixin.queue_reply(mid, "回复")
            self.client.results = [context.exception]
            self.probe.weixin.send_once()
            status = self.probe.weixin.send_status(mid)
            self.assertEqual(status["status"], "delivery_unknown")
            self.assertFalse(status["api_result"]["response_received"])
            self.assertFalse(self.probe.weixin.send_once())
        self.assertEqual(parse_api_json(b"{}"), {})

    def test_owner_receipt_preserves_historical_uncertain_api_evidence(self):
        self.ingest(self.message())
        mid = self.inbound_id()
        self.probe.weixin.queue_reply(mid, "原回复")
        self.client.results = [WeixinError("api_timeout")]
        self.probe.weixin.send_once()
        self.probe.weixin.record_owner_receipt(mid)
        self.probe.close(); self.probe = self.open_probe()
        status = self.probe.weixin.send_status(mid)
        self.assertTrue(status["recipient_confirmed"])
        self.assertEqual(status["recipient_confirmation_source"], "owner_report")
        self.assertEqual(status["status"], "delivery_unknown")
        self.assertFalse(status["accepted"])
        self.assertEqual(status["error_kind"], "api_timeout")
        self.assertFalse(self.probe.weixin.send_once())
        self.assertEqual(len(self.client.sent), 1)


if __name__ == "__main__":
    unittest.main()
