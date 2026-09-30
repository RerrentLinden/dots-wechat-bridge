"""Owner-only Tencent iLink text transport; no model or ChatGPT history access.

Protocol reference: https://github.com/Tencent/openclaw-weixin/blob/main/docs/protocol.md
Credentials stay in the private server database. Exceptions contain fixed categories only.
"""
import base64
import hashlib
import http.client
import ipaddress
import json
import secrets
import socket
import ssl
import time
from urllib.parse import urlencode, urlsplit

BASE_URL = "https://ilinkai.weixin.qq.com"
CHANNEL_VERSION = "2.4.9"
MESSAGE_EVENT = "weixin.message"


class WeixinError(Exception):
    def __init__(self, kind, code=None):
        super().__init__(kind)
        self.kind, self.code = kind, code


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def api_base(value):
    try:
        p = urlsplit(value)
        host = p.hostname
        if (p.scheme != "https" or not host or not (host == "weixin.qq.com" or host.endswith(".weixin.qq.com"))
                or p.port not in (None, 443) or p.username or p.password or p.query or p.fragment
                or p.path not in ("", "/")):
            raise ValueError()
        return "https://" + host
    except (TypeError, ValueError):
        raise WeixinError("invalid_api_destination") from None


def public_ip(value):
    ip = ipaddress.ip_address(value)
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo)))


def parse_api_json(raw):
    try:
        result = json.loads(raw)
    except (ValueError, UnicodeError):
        raise WeixinError("invalid_api_json") from None
    if not isinstance(result, dict):
        raise WeixinError("invalid_api_response")
    return result


class IlinkClient:
    def __init__(self, clock=time.time):
        self.clock = clock

    def request(self, base, endpoint, payload=None, token=None, timeout=20):
        host = urlsplit(api_base(base)).hostname
        if not endpoint.startswith("/ilink/bot/") or "\r" in endpoint or "\n" in endpoint:
            raise WeixinError("invalid_api_endpoint")
        headers = {"iLink-App-Id": "bot", "iLink-App-ClientVersion": str((2 << 16) | (4 << 8) | 9)}
        body = None
        if payload is not None:
            headers.update({"Content-Type": "application/json", "AuthorizationType": "ilink_bot_token",
                            "X-WECHAT-UIN": base64.b64encode(str(secrets.randbits(32)).encode()).decode()})
            if token:
                headers["Authorization"] = "Bearer " + token
                payload = {**payload, "base_info": {"channel_version": CHANNEL_VERSION, "bot_agent": "DotsWechatBridge/0.2"}}
            body = encoded(payload).encode()
        try:
            addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)))
            if not addresses or not all(public_ip(x) for x in addresses):
                raise WeixinError("non_public_api_address")
            conn = http.client.HTTPSConnection(host, timeout=timeout, context=ssl.create_default_context())
            sock = socket.create_connection((addresses[0], 443), timeout=timeout)
            try:
                conn.sock = conn._context.wrap_socket(sock, server_hostname=host)
            except BaseException:
                sock.close()
                raise
            try:
                conn.request("POST" if payload is not None else "GET", endpoint, body, headers)
                response = conn.getresponse()
                raw = response.read(1048577)
                if len(raw) > 1048576:
                    raise WeixinError("api_response_too_large")
                if not 200 <= response.status < 300:
                    # No automatic redirects and no logging response bodies or URLs.
                    raise WeixinError("api_http_error", response.status)
                return parse_api_json(raw)
            finally:
                conn.close()
        except WeixinError:
            raise
        except (socket.timeout, TimeoutError):
            raise WeixinError("api_timeout") from None
        except Exception:
            raise WeixinError("api_network_error") from None

    def begin_login(self):
        result = self.request(BASE_URL, "/ilink/bot/get_bot_qrcode?bot_type=3", {"local_token_list": []})
        if not all(isinstance(result.get(k), str) and 0 < len(result[k]) < 8192 for k in ("qrcode", "qrcode_img_content")):
            raise WeixinError("invalid_login_response")
        return {"qrcode": result["qrcode"], "display": result["qrcode_img_content"], "base": BASE_URL,
                "started_at": self.clock()}

    def poll_login(self, login, verification_code=None):
        if self.clock() - login["started_at"] > 300:
            return {"status": "expired"}
        query = {"qrcode": login["qrcode"]}
        if verification_code:
            query["verify_code"] = verification_code
        return self.request(login["base"], "/ilink/bot/get_qrcode_status?" + urlencode(query), timeout=40)

    def poll(self, account):
        return self.request(account["base_url"], "/ilink/bot/getupdates", {"get_updates_buf": account["cursor"]},
                            account["token"], timeout=40)

    def send(self, account, peer, text, client_id, context_token):
        return self.send_items(account, peer, [{"type": 1, "text_item": {"text": text}}], client_id, context_token)

    def get_upload_url(self, account, payload):
        return self.request(account["base_url"], "/ilink/bot/getuploadurl", payload, account["token"])

    def send_items(self, account, peer, items, client_id, context_token):
        return self.request(account["base_url"], "/ilink/bot/sendmessage", {"msg": {
            "from_user_id": "", "to_user_id": peer, "client_id": client_id, "message_type": 2,
            "message_state": 2, "context_token": context_token,
            "item_list": items}}, account["token"])


class WeixinStore:
    def __init__(self, probe, client=None):
        self.probe, self.db, self.lock = probe, probe.db, probe.lock
        self.clock, self.client = probe.clock, client or IlinkClient()
        self.poll_after = 0
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS weixin_accounts (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, token TEXT NOT NULL, base_url TEXT NOT NULL,
                cursor TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'ready',
                last_poll REAL, last_error TEXT);
            CREATE TABLE IF NOT EXISTS weixin_peers (
                account TEXT NOT NULL, peer TEXT NOT NULL, token TEXT NOT NULL,
                source_ms REAL NOT NULL, received_at REAL NOT NULL, PRIMARY KEY(account,peer));
            CREATE TABLE IF NOT EXISTS weixin_inbox (
                id TEXT PRIMARY KEY, account TEXT NOT NULL, peer TEXT NOT NULL, source_id TEXT NOT NULL,
                text TEXT NOT NULL, created_at REAL NOT NULL, kind TEXT NOT NULL,
                unsupported TEXT NOT NULL, event_id TEXT);
            CREATE TABLE IF NOT EXISTS weixin_outbox (
                message_id TEXT PRIMARY KEY, account TEXT NOT NULL, peer TEXT NOT NULL,
                text TEXT NOT NULL, client_id TEXT NOT NULL UNIQUE, status TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL DEFAULT 0,
                context_at REAL, error_kind TEXT, server_code INTEGER, accepted_at REAL,
                created_at REAL NOT NULL, kind TEXT NOT NULL DEFAULT 'reply');
        """)
        columns = {r["name"] for r in self.db.execute("PRAGMA table_info(weixin_outbox)")}
        for name, sql_type in (("api_result", "TEXT"), ("recipient_confirmed_at", "REAL"),
                               ("upload_id", "TEXT"), ("source_message_id", "TEXT"), ("item_json", "TEXT")):
            if name not in columns:
                self.db.execute("ALTER TABLE weixin_outbox ADD COLUMN " + name + " " + sql_type)
        self.db.commit()
    def recover_inflight(self):
        # Only the single daemon calls this, never a read-only status process.
        with self.db:
            self.db.execute("UPDATE weixin_outbox SET status='delivery_unknown',error_kind='restart_during_send' WHERE status='sending'")

    def bind_confirmed(self, result):
        values = [result.get(k) for k in ("ilink_bot_id", "ilink_user_id", "bot_token")]
        if result.get("status") != "confirmed" or not all(isinstance(x, str) and 0 < len(x) <= 8192 for x in values):
            raise WeixinError("incomplete_owner_binding")
        account, owner, token = values
        base = api_base(result.get("baseurl") or BASE_URL)
        with self.lock, self.db:
            previous = self.db.execute("SELECT id,owner FROM weixin_accounts LIMIT 1").fetchone()
            if previous and (previous["id"] != account or previous["owner"] != owner):
                raise WeixinError("binding_identity_changed")
            self.db.execute("INSERT INTO weixin_accounts(id,owner,token,base_url) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET token=excluded.token,base_url=excluded.base_url,status='ready',last_error=NULL,last_poll=NULL",
                            (account, owner, token, base))
            self.db.execute("UPDATE weixin_outbox SET status='queued',next_at=0 WHERE account=? AND status='auth_required'", (account,))
        return {"connected": True, "owner_only": True}

    def account(self):
        with self.lock:
            row = self.db.execute("SELECT * FROM weixin_accounts LIMIT 1").fetchone()
        return dict(row) if row else None

    def ingest(self, account, response):
        codes = (response.get("ret", 0), response.get("errcode", 0))
        if any(x not in (0, None) for x in codes):
            raise WeixinError("auth_required" if -14 in codes else "poll_rejected", next(x for x in codes if x not in (0, None)))
        msgs = response.get("msgs", [])
        if not isinstance(msgs, list) or len(msgs) > 1000:
            raise WeixinError("invalid_update_batch")
        added = 0
        now = self.clock()
        with self.lock, self.db:
            for msg in msgs:
                if (not isinstance(msg, dict) or msg.get("from_user_id") != account["owner"]
                        or msg.get("group_id") or msg.get("room_id") or msg.get("message_type") != 1
                        or msg.get("message_state") == 1 or msg.get("delete_time_ms")
                        or msg.get("to_user_id") not in (None, "", account["id"])):
                    continue
                source = msg.get("message_id") or msg.get("client_id")
                if not isinstance(source, (str, int)) or isinstance(source, bool) or not source:
                    continue
                text, unsupported, has_media = [], [], False
                items = msg.get("item_list", [])
                if not isinstance(items, list):
                    continue
                for item in items:
                    if not isinstance(item, dict):
                        continue
                    text_item = item.get("text_item")
                    value = text_item.get("text") if item.get("type") == 1 and isinstance(text_item, dict) else None
                    if isinstance(value, str):
                        text.append(value)
                    elif item.get("type") in (2, 3, 4):
                        has_media = True
                        voice_item = item.get("voice_item")
                        transcript = voice_item.get("text") if item.get("type") == 3 and isinstance(voice_item, dict) else None
                        if isinstance(transcript, str) and transcript:
                            text.append(transcript)
                    elif item.get("type") == 5:
                        unsupported.append(5)
                content = "\n".join(text)
                if not content and not unsupported and not has_media:
                    continue
                if len(content.encode()) > 65536:
                    content, unsupported = "", ["text_too_large"]
                identity = "wx_" + hashlib.sha256(encoded([account["id"], account["owner"], str(source)]).encode()).hexdigest()[:32]
                created_ms = msg.get("create_time_ms")
                created_ms = created_ms if isinstance(created_ms, (float, int)) and 0 < created_ms <= (now + 300) * 1000 else now * 1000
                changed = self.db.execute("INSERT OR IGNORE INTO weixin_inbox VALUES(?,?,?,?,?,?,?,?,NULL)",
                    (identity, account["id"], account["owner"], str(source), content, created_ms / 1000,
                     "mixed" if content and has_media else "media" if has_media else "text" if content else "unsupported", encoded(unsupported))).rowcount
                if not changed:
                    continue
                added += 1
                self.probe.media.add(identity, account["id"], account["owner"], items)
                context = msg.get("context_token")
                if isinstance(context, str) and 0 < len(context) <= 16384:
                    old = self.db.execute("SELECT source_ms FROM weixin_peers WHERE account=? AND peer=?", (account["id"], account["owner"])).fetchone()
                    if not old or created_ms >= old["source_ms"]:
                        self.db.execute("INSERT OR REPLACE INTO weixin_peers VALUES(?,?,?,?,?)", (account["id"], account["owner"], context, created_ms, now))
                        self.db.execute("UPDATE weixin_outbox SET status='queued',next_at=0 WHERE account=? AND peer=? AND status='context_required' AND attempts<3",
                                        (account["id"], account["owner"]))
            cursor = response.get("get_updates_buf")
            self.db.execute("UPDATE weixin_accounts SET cursor=CASE WHEN ?!='' THEN ? ELSE cursor END,last_poll=?,last_error=NULL WHERE id=?",
                            (cursor if isinstance(cursor, str) else "", cursor if isinstance(cursor, str) else "", now, account["id"]))
        return added

    def read_message(self, message_id):
        account = self.account()
        if not account:
            raise WeixinError("not_bound")
        with self.lock:
            row = self.db.execute("SELECT * FROM weixin_inbox WHERE id=? AND account=? AND peer=?", (message_id, account["id"], account["owner"])).fetchone()
        if not row:
            raise WeixinError("unknown_owner_message")
        return {"message_id": row["id"], "text": row["text"], "created_at": self.probe.iso(row["created_at"]),
                "kind": row["kind"], "unsupported_types": json.loads(row["unsupported"]), "source": "owner_weixin_dm",
                "attachments": self.probe.media.list_for_message(row["id"])}

    def queue_reply(self, message_id, text):
        self.read_message(message_id)
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 8192:
            raise WeixinError("reply_text_must_be_1_to_8192_bytes")
        with self.lock, self.db:
            old = self.db.execute("SELECT text FROM weixin_outbox WHERE message_id=?", (message_id,)).fetchone()
            if old:
                if old["text"] != text:
                    raise WeixinError("reply_already_committed_with_different_text")
            else:
                self.check_queue_capacity()
                inbox = self.db.execute("SELECT account,peer FROM weixin_inbox WHERE id=?", (message_id,)).fetchone()
                self.db.execute("INSERT INTO weixin_outbox(message_id,account,peer,text,client_id,status,created_at) VALUES(?,?,?,?,?,'queued',?)",
                                (message_id, inbox["account"], inbox["peer"], text, "dots_" + message_id[3:], self.clock()))
        return self.send_status(message_id)

    def queue_notification(self, notification_id, text):
        account = self.account()
        if not account:
            raise WeixinError("not_bound")
        if not isinstance(notification_id, str) or not 0 < len(notification_id) <= 128:
            raise WeixinError("invalid_notification_identity")
        if not isinstance(text, str) or not text.strip() or len(text.encode()) > 8192:
            raise WeixinError("reply_text_must_be_1_to_8192_bytes")
        send_id = "notice_" + hashlib.sha256(encoded([account["id"], notification_id]).encode()).hexdigest()[:32]
        with self.lock, self.db:
            old = self.db.execute("SELECT text FROM weixin_outbox WHERE message_id=?", (send_id,)).fetchone()
            if old and old["text"] != text:
                raise WeixinError("reply_already_committed_with_different_text")
            if not old:
                self.check_queue_capacity()
                self.db.execute("INSERT INTO weixin_outbox(message_id,account,peer,text,client_id,status,created_at,kind) VALUES(?,?,?,?,?,'queued',?,'notification')",
                                (send_id, account["id"], account["owner"], text, "dots_" + send_id, self.clock()))
        return self.send_status(send_id)

    def check_queue_capacity(self):
        # Called inside the existing lock/transaction; terminal history does not count.
        count = self.db.execute("SELECT count(*) FROM weixin_outbox WHERE status IN ('queued','preparing','sending','context_required','auth_required')").fetchone()[0]
        if count >= 32:
            raise WeixinError("send_queue_busy")

    def send_status(self, message_id):
        account = self.account()
        if not account:
            raise WeixinError("not_bound")
        with self.lock:
            row = self.db.execute("SELECT message_id,text,status,attempts,error_kind,server_code,accepted_at,kind,api_result,recipient_confirmed_at,upload_id,source_message_id FROM weixin_outbox WHERE message_id=? AND account=? AND peer=?",
                                  (message_id, account["id"], account["owner"])).fetchone()
        if not row:
            self.read_message(message_id)
            return {"send_id": message_id, "status": "no_reply", "accepted": False, "delivered": None}
        result = dict(row)
        result["send_id"] = result.pop("message_id")
        result["outgoing_text"] = result.pop("text")
        result["api_result"] = json.loads(result["api_result"]) if result["api_result"] else None
        result["recipient_confirmed"] = row["recipient_confirmed_at"] is not None
        result["recipient_confirmation_source"] = "owner_report" if result["recipient_confirmed"] else None
        result.update({"accepted": row["status"] == "accepted", "delivered": None})
        if row["upload_id"]:
            result['transport_status'] = row['status']
            result['status'] = ('accepted' if row['status'] == 'accepted' else
                                'uncertain' if row['status'] == 'delivery_unknown' else
                                'error' if row['status'] in ('rejected','context_required','auth_required') else 'queued')
            result['delivery_receipt_available'] = False
            result['upload'] = self.probe.outbound.status(row['upload_id'])
        return result

    def record_owner_receipt(self, message_id):
        """Administrative evidence only, after an explicit owner's receipt report.

        Never exposed as an MCP tool. Does not alter historical API acceptance.
        """
        self.send_status(message_id)
        with self.lock, self.db:
            self.db.execute("UPDATE weixin_outbox SET recipient_confirmed_at=COALESCE(recipient_confirmed_at,?) WHERE message_id=?",
                            (self.clock(), message_id))

    def send_once(self):
        account = self.account()
        if not account or account["status"] != "ready":
            return False
        now = self.clock()
        with self.lock, self.db:
            row = self.db.execute("SELECT * FROM weixin_outbox WHERE status='queued' AND next_at<=? AND account=? ORDER BY created_at LIMIT 1", (now, account["id"])).fetchone()
            if not row:
                return False
            if row['peer'] != account['owner']:
                self.db.execute("UPDATE weixin_outbox SET status='rejected',error_kind='owner_identity_mismatch' WHERE message_id=?", (row['message_id'],))
                return True
            context = self.db.execute("SELECT token,received_at FROM weixin_peers WHERE account=? AND peer=?", (account["id"], row["peer"])).fetchone()
            if not context:
                self.db.execute("UPDATE weixin_outbox SET status='context_required',error_kind='fresh_inbound_required' WHERE message_id=?", (row["message_id"],))
                return True
            if row['upload_id'] and not row['item_json']:
                self.db.execute("UPDATE weixin_outbox SET status='preparing' WHERE message_id=?", (row['message_id'],))
        if row['upload_id'] and not row['item_json']:
            try:
                item = self.probe.outbound.prepare(row['upload_id'], account)
                with self.lock, self.db:
                    self.db.execute("UPDATE weixin_outbox SET item_json=?,status='queued',error_kind=NULL WHERE message_id=?", (encoded(item), row['message_id']))
            except Exception as exc:
                kind = exc.kind if isinstance(exc, WeixinError) else 'media_upload_error'
                with self.lock, self.db:
                    upload = self.db.execute('SELECT upload_attempts FROM weixin_uploads WHERE id=?', (row['upload_id'],)).fetchone()
                    retry = upload['upload_attempts'] < 3 and (kind in ('media_upload_timeout','media_upload_network_error','api_timeout','api_network_error') or
                        (kind in ('media_upload_http_error','api_http_error') and isinstance(exc,WeixinError) and type(exc.code) is int and exc.code >= 500))
                    state = 'auth_required' if kind == 'auth_required' else 'queued' if retry else 'rejected'
                    self.db.execute("UPDATE weixin_outbox SET status=?,error_kind=?,next_at=? WHERE message_id=?", (state,kind,self.clock()+5*upload['upload_attempts'],row['message_id']))
                    if state == 'auth_required':
                        self.db.execute("UPDATE weixin_accounts SET status='auth_required',last_error='bot_auth_expired' WHERE id=?", (account['id'],))
                return True
        # CDN preparation may take time. Re-read identity, expiry and the latest
        # peer context immediately before committing a message POST.
        account = self.account()
        with self.lock, self.db:
            row = self.db.execute('SELECT * FROM weixin_outbox WHERE message_id=?', (row['message_id'],)).fetchone()
            if not account or account['status'] != 'ready' or row['status'] != 'queued':
                return True
            if row['upload_id']:
                try:
                    self.probe.outbound.authorized(row['upload_id'])
                    self.read_message(row['source_message_id'])
                except WeixinError as exc:
                    self.db.execute("UPDATE weixin_outbox SET status='rejected',error_kind=?,item_json=NULL WHERE message_id=?", (exc.kind,row['message_id']))
                    return True
            context = self.db.execute("SELECT token,received_at FROM weixin_peers WHERE account=? AND peer=?", (account['id'],row['peer'])).fetchone()
            if not context:
                self.db.execute("UPDATE weixin_outbox SET status='context_required',error_kind='fresh_inbound_required' WHERE message_id=?", (row['message_id'],))
                return True
            self.db.execute("UPDATE weixin_outbox SET status='sending',attempts=attempts+1,context_at=? WHERE message_id=?", (context["received_at"], row["message_id"]))
        outcome, kind, code = "delivery_unknown", "uncertain_api_result", None
        diagnostic = {"response_received": False}
        try:
            if row['upload_id']:
                result = self.client.send_items(account, row['peer'], [json.loads(row['item_json'])], row['client_id'], context['token'])
            else:
                result = self.client.send(account, row["peer"], row["text"], row["client_id"], context["token"])
            if not isinstance(result, dict):
                raise WeixinError("invalid_api_response")
            codes = (result.get("ret"), result.get("errcode"))
            # The official API defines ret as optional; a successful HTTP JSON
            # object with omitted/null/zero codes is accepted, including {}.
            # Keep only controlled structural evidence, never response bodies.
            diagnostic = {"response_received": True, "valid_json_object": True, "empty_object": not result,
                          "ret_present": "ret" in result, "errcode_present": "errcode" in result,
                          "ret": codes[0] if type(codes[0]) is int else None,
                          "errcode": codes[1] if type(codes[1]) is int else None,
                          "has_server_message_id": isinstance(result.get("message_id"), (str, int)) and not isinstance(result.get("message_id"), bool),
                          "unexpected_base_resp": "base_resp" in result}
            if any(x is not None and type(x) is not int for x in codes):
                kind = "invalid_send_status_type"
            elif -14 in codes:
                outcome, kind, code = "auth_required", "bot_auth_expired", -14
            elif -2 in codes:
                code = -2
                error = str(result.get("errmsg") or result.get("msg") or "").lower()
                if error in ("prepare failed", "unknown error"):
                    outcome, kind = ("context_required", "fresh_inbound_required") if row["attempts"] + 1 < 3 else ("rejected", "retry_limit")
                elif row["attempts"] + 1 < 3:
                    outcome, kind = "queued", "rate_limited"
                else:
                    outcome, kind = "rejected", "retry_limit"
            elif any(x not in (0, None) for x in codes):
                outcome, kind = "rejected", "send_rejected"
                code = next((x for x in codes if type(x) is int and x != 0), None)
            elif "base_resp" in result:
                kind = "unexpected_send_response_shape"
            else:
                outcome, kind = "accepted", None
                diagnostic["acceptance_basis"] = "explicit_zero" if 0 in codes else "omitted_success_codes"
        except WeixinError as error:
            known = {"api_timeout", "api_network_error", "api_http_error", "invalid_api_json", "invalid_api_response",
                     "api_response_too_large", "invalid_api_destination", "non_public_api_address", "invalid_api_endpoint"}
            kind = error.kind if error.kind in known else "unexpected_send_error"
            diagnostic = {"response_received": False, "failure_kind": kind}
            if error.kind == "api_http_error" and type(error.code) is int:
                diagnostic["http_status"] = error.code
        except Exception:
            # Timeout/network errors after POST may have delivered; never blindly resend.
            kind = "unexpected_send_error"
            diagnostic = {"response_received": False, "failure_kind": kind}
        with self.lock, self.db:
            if outcome == "context_required":
                latest = self.db.execute("SELECT received_at FROM weixin_peers WHERE account=? AND peer=?", (account["id"], row["peer"])).fetchone()
                if latest and latest["received_at"] > context["received_at"] and row["attempts"] + 1 < 3:
                    outcome, kind = "queued", "fresh_context_available"
            self.db.execute("UPDATE weixin_outbox SET status=?,error_kind=?,server_code=?,accepted_at=?,next_at=?,api_result=? WHERE message_id=?",
                            (outcome, kind, code, self.clock() if outcome == "accepted" else None, now + 5 * (row["attempts"] + 1), encoded(diagnostic), row["message_id"]))
            if outcome == "auth_required":
                self.db.execute("UPDATE weixin_accounts SET status='auth_required',last_error='bot_auth_expired' WHERE id=?", (account["id"],))
            if row['upload_id'] and outcome in ('accepted','rejected','delivery_unknown'):
                self.db.execute('UPDATE weixin_outbox SET item_json=NULL WHERE message_id=?', (row['message_id'],))
        return True

    def poll_once(self):
        account = self.account()
        if not account or account["status"] != "ready" or self.clock() < self.poll_after:
            return False
        try:
            response = self.client.poll(account)
            self.ingest(account, response)
            self.poll_after = self.clock() + 0.5
        except WeixinError as error:
            self.poll_after = self.clock() + (1 if error.kind == "api_timeout" else 30)
            with self.lock, self.db:
                self.db.execute("UPDATE weixin_accounts SET status=CASE WHEN ?='auth_required' THEN 'auth_required' ELSE status END,last_error=? WHERE id=?", (error.kind, error.kind, account["id"]))
        return True

    def status(self):
        account = self.account()
        with self.lock:
            inbound = self.db.execute("SELECT count(*) FROM weixin_inbox").fetchone()[0]
            replies = {r["status"]: r["n"] for r in self.db.execute("SELECT status,count(*) n FROM weixin_outbox GROUP BY status")}
            latest = self.db.execute('SELECT id FROM weixin_inbox WHERE account=? AND peer=? ORDER BY created_at DESC,rowid DESC LIMIT 1', (account['id'],account['owner'])).fetchone() if account else None
        return {"bound": bool(account), "connected": bool(account and account["status"] == "ready" and account["last_poll"] is not None), "owner_only": bool(account),
                "account_status": account["status"] if account else "not_bound", "last_error": account["last_error"] if account else None,
                "inbound_count": inbound, "reply_counts": replies, "dot_origin_auto_forward": False,
                "latest_owner_message_id": latest['id'] if latest else None}
