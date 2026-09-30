"""Bounded owner-only MCP uploads and streaming Tencent CDN encryption.

Reference: Tencent/openclaw-weixin @ 24de5c9eb0dd5e595d7e2d090ed8a3f82870d42c.
No caller-controlled paths/URLs, credentials, whole-file buffers or delivery claims.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
import warnings
from urllib.parse import urlencode

try:
    from .weixin import WeixinError, encoded, public_ip
    from .media import MAX_FILE, MAX_CACHE, MAX_CHUNK, MAX_PIXELS, RETENTION, cdn_parts, safe_name
except ImportError:
    from weixin import WeixinError, encoded, public_ip
    from media import MAX_FILE, MAX_CACHE, MAX_CHUNK, MAX_PIXELS, RETENTION, cdn_parts, safe_name

MAX_PENDING = 32
MAX_UPLOADS = 8
MAX_RPC_BYTES = 128 * 1024


def upload_tools():
    string = {'type': 'string'}
    identity = {'type': 'string', 'pattern': '^[A-Za-z0-9_-]{1,128}$'}
    definitions = [
        ('begin_weixin_upload', 'Reserve a private owner upload, at most 20MiB. Read the actual cloud/local file bytes and compute its whole SHA256 first. upload_id must be stable for retries; returned upload_id is used for all next steps. Does not send to Weixin. No file paths or URLs are accepted.',
         {'upload_id': identity, 'filename': {'type': 'string', 'minLength': 1, 'maxLength': 512}, 'kind': {'type': 'string', 'enum': ['image','file']}, 'size': {'type': 'integer', 'minimum': 1, 'maximum': MAX_FILE}, 'sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}}),
        ('upload_weixin_chunk', 'Transfer actual file bytes through authenticated MCP in sequential chunks of 1..65536 bytes. Send offset, bounded base64 and SHA256 of decoded chunk. Identical retries are safe; conflicts/gaps are rejected. Never print base64 in chat. Does not send to Weixin.',
         {'upload_id': string, 'offset': {'type': 'integer', 'minimum': 0}, 'data_base64': {'type': 'string', 'minLength': 1, 'maxLength': 87384}, 'chunk_sha256': {'type': 'string', 'pattern': '^[a-f0-9]{64}$'}}),
        ('finalize_weixin_upload', 'Verify complete size and whole SHA256, validate bounded images and mark ready. An error result is not a usable upload. No Weixin message is sent.', {'upload_id': string}),
        ('get_weixin_upload_status', 'Read upload progress, expiry, hash, filename and committed send ID. Does not return bytes, keys or URLs.', {'upload_id': string}),
        ('send_weixin_media', 'Queue one finalized image/file to the bound owner, only for a user-requested send or response to this owner message. First read message_id from get_weixin_status/read_weixin_message. send_id must be stable for retries. One upload permits one send; returned send_id is used in get_weixin_send_status. Uses latest peer context at dispatch. queued/accepted are not delivery receipts; uncertain must never be blindly resent. Never auto-forward dot chats.',
         {'send_id': identity, 'upload_id': string, 'message_id': string}),
    ]
    return [{'name': name, 'description': description,
             'inputSchema': {'type': 'object', 'properties': properties, 'required': list(properties), 'additionalProperties': False},
             'annotations': {'readOnlyHint': name == 'get_weixin_upload_status', 'destructiveHint': False,
                             'idempotentHint': True, 'openWorldHint': name == 'send_weixin_media'}}
            for name, description, properties in definitions]


def digest_file(source):
    sha, md5, size = hashlib.sha256(), hashlib.md5(), 0
    source.seek(0)
    while block := source.read(MAX_CHUNK):
        size += len(block)
        if size > MAX_FILE:
            raise WeixinError('media_too_large')
        sha.update(block); md5.update(block)
    source.seek(0)
    return size, sha.hexdigest(), md5.hexdigest()


def encrypted_blocks(source, key):
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    pad = padding.PKCS7(128).padder()
    cipher = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    source.seek(0)
    while block := source.read(MAX_CHUNK):
        result = cipher.update(pad.update(block))
        if result:
            yield result
    yield cipher.update(pad.finalize()) + cipher.finalize()


def upload_cdn(url, source, key, size):
    """One bounded encrypted POST; TLS/public DNS pinned, no redirects or bodies logged."""
    p = cdn_parts(url)
    if p.hostname != 'novac2c.cdn.weixin.qq.com' or p.path != '/c2c/upload':
        raise WeixinError('invalid_upload_destination')
    conn = None
    deadline = time.monotonic() + 60
    try:
        addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)))
        if not addresses or not all(public_ip(a) for a in addresses):
            raise WeixinError('non_public_media_address')
        conn = http.client.HTTPSConnection(p.hostname, timeout=10, context=ssl.create_default_context())
        sock = socket.create_connection((addresses[0], 443), timeout=10)
        try:
            conn.sock = conn._context.wrap_socket(sock, server_hostname=p.hostname)
        except BaseException:
            sock.close(); raise
        conn.putrequest('POST', p.path + ('?' + p.query if p.query else ''))
        conn.putheader('Content-Type', 'application/octet-stream')
        conn.putheader('Content-Length', str((size // 16 + 1) * 16))
        conn.endheaders()
        sent = 0
        for block in encrypted_blocks(source, key):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise WeixinError('media_upload_timeout')
            conn.sock.settimeout(max(.1, min(10, remaining)))
            sent += len(block)
            if sent > (size // 16 + 1) * 16:
                raise WeixinError('upload_integrity_error')
            conn.send(block)
        if sent != (size // 16 + 1) * 16:
            raise WeixinError('upload_integrity_error')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise WeixinError('media_upload_timeout')
        conn.sock.settimeout(max(.1, min(10, remaining)))
        response = conn.getresponse()
        if response.status != 200:
            raise WeixinError('media_upload_http_error', response.status)
        query = response.getheader('x-encrypted-param')
        if not isinstance(query, str) or not 0 < len(query) <= 12000 or any(c in query for c in '\r\n\x00'):
            raise WeixinError('missing_cdn_download_param')
        # This protocol uses headers; close without buffering an arbitrary response body.
        return query
    except WeixinError:
        raise
    except (socket.timeout, TimeoutError):
        raise WeixinError('media_upload_timeout') from None
    except Exception:
        raise WeixinError('media_upload_network_error') from None
    finally:
        if conn:
            conn.close()


class OutboundStore:
    def __init__(self, probe, uploader=None):
        self.probe, self.db, self.lock, self.clock = probe, probe.db, probe.lock, probe.clock
        self.upload = uploader or upload_cdn
        self.directory = Path(probe.directory) / 'outgoing'
        self.directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.db.executescript('''CREATE TABLE IF NOT EXISTS weixin_uploads (
            id TEXT PRIMARY KEY, account TEXT NOT NULL, peer TEXT NOT NULL,
            filename TEXT NOT NULL, kind TEXT NOT NULL, size INTEGER NOT NULL,
            sha256 TEXT NOT NULL, received INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL, mime_type TEXT, md5 TEXT, send_id TEXT UNIQUE,
            upload_attempts INTEGER NOT NULL DEFAULT 0, error_kind TEXT,
            created_at REAL NOT NULL, expires_at REAL NOT NULL);
        ''')
        self.db.commit()

    def path(self, uid):
        if not isinstance(uid, str) or not re.fullmatch(r'up_[a-f0-9]{32}', uid):
            raise WeixinError('invalid_upload_id')
        return self.directory / uid

    def authorized(self, uid, allow_expired=False):
        self.path(uid)
        account = self.probe.weixin.account()
        if not account:
            raise WeixinError('not_bound')
        row = self.db.execute('SELECT * FROM weixin_uploads WHERE id=? AND account=? AND peer=?',
                              (uid, account['id'], account['owner'])).fetchone()
        if not row:
            raise WeixinError('unknown_owner_upload')
        if not allow_expired and (row['expires_at'] <= self.clock() or row['status'] == 'expired'):
            raise WeixinError('upload_expired')
        return row

    def metadata(self, row):
        return {'upload_id': row['id'], 'filename': row['filename'], 'kind': row['kind'],
                'size': row['size'], 'sha256': row['sha256'], 'next_offset': row['received'],
                'status': row['status'], 'mime_type': row['mime_type'], 'send_id': row['send_id'],
                'error_kind': row['error_kind'], 'max_chunk_bytes': MAX_CHUNK,
                'expires_at': self.probe.iso(row['expires_at'])}

    def status(self, uid):
        with self.lock:
            return self.metadata(self.authorized(uid, allow_expired=True))

    def begin(self, upload_id, filename, kind, size, sha256):
        if not isinstance(upload_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', upload_id):
            raise WeixinError('invalid_upload_identity')
        if kind not in ('image', 'file') or not isinstance(filename, str) or not 0 < len(filename.encode()) <= 512:
            raise WeixinError('invalid_upload_metadata')
        if type(size) is not int or not 1 <= size <= MAX_FILE:
            raise WeixinError('invalid_upload_size')
        if not isinstance(sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', sha256):
            raise WeixinError('invalid_upload_sha256')
        account = self.probe.weixin.account()
        if not account:
            raise WeixinError('not_bound')
        uid = 'up_' + hashlib.sha256(encoded([account['id'], upload_id]).encode()).hexdigest()[:32]
        filename = safe_name(filename)
        self.cleanup()
        with self.lock, self.db:
            old = self.db.execute('SELECT * FROM weixin_uploads WHERE id=?', (uid,)).fetchone()
            if old:
                if (old['filename'], old['kind'], old['size'], old['sha256']) != (filename, kind, size, sha256):
                    raise WeixinError('upload_identity_conflict')
                return self.metadata(old)
            active = self.db.execute("SELECT count(*) FROM weixin_uploads WHERE status IN ('uploading','ready')").fetchone()[0]
            if active >= MAX_UPLOADS:
                raise WeixinError('upload_queue_busy')
            if self.probe.media.cache_usage() + size > MAX_CACHE:
                raise WeixinError('media_cache_full')
            with os.fdopen(os.open(self.path(uid), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb'):
                pass
            now = self.clock()
            self.db.execute('''INSERT INTO weixin_uploads
                (id,account,peer,filename,kind,size,sha256,status,created_at,expires_at)
                VALUES(?,?,?,?,?,?,?,'uploading',?,?)''',
                (uid, account['id'], account['owner'], filename, kind, size, sha256, now, now + RETENTION))
            return self.metadata(self.authorized(uid))

    def chunk(self, upload_id, offset, data_base64, chunk_sha256):
        if type(offset) is not int or offset < 0 or not isinstance(data_base64, str) or not 0 < len(data_base64) <= 87384:
            raise WeixinError('invalid_upload_chunk')
        if not isinstance(chunk_sha256, str) or not re.fullmatch(r'[a-f0-9]{64}', chunk_sha256):
            raise WeixinError('invalid_chunk_sha256')
        try:
            block = base64.b64decode(data_base64, validate=True)
        except (ValueError, TypeError):
            raise WeixinError('invalid_upload_base64') from None
        if not 1 <= len(block) <= MAX_CHUNK or hashlib.sha256(block).hexdigest() != chunk_sha256:
            raise WeixinError('upload_chunk_integrity_error')
        with self.lock, self.db:
            row = self.authorized(upload_id)
            if row['status'] not in ('uploading', 'ready', 'committed'):
                raise WeixinError('upload_not_writable')
            if offset + len(block) > row['size'] or offset > row['received']:
                raise WeixinError('invalid_upload_range')
            try:
                with os.fdopen(os.open(self.path(upload_id), os.O_RDWR | os.O_NOFOLLOW), 'r+b') as output:
                    length = os.fstat(output.fileno()).st_size
                    if length < row['received'] or (row['status'] != 'uploading' and length != row['size']):
                        raise WeixinError('upload_integrity_error')
                    # Crash after fsync but before DB commit: discard only the uncommitted tail.
                    if length > row['received'] and row['status'] == 'uploading':
                        output.truncate(row['received'])
                    output.seek(offset)
                    duplicate = offset + len(block) <= row['received']
                    if duplicate:
                        if output.read(len(block)) != block:
                            raise WeixinError('upload_chunk_conflict')
                    else:
                        if offset != row['received'] or row['status'] != 'uploading':
                            raise WeixinError('invalid_upload_range')
                        output.write(block); output.flush(); os.fsync(output.fileno())
                        self.db.execute('UPDATE weixin_uploads SET received=? WHERE id=?', (offset + len(block), upload_id))
            except OSError:
                raise WeixinError('upload_cache_unavailable') from None
            return {**self.metadata(self.authorized(upload_id)), 'offset': offset,
                    'accepted_size': len(block), 'duplicate': duplicate}

    def finalize(self, upload_id):
        with self.lock, self.db:
            row = self.authorized(upload_id)
            if row['status'] in ('ready', 'committed'):
                return self.metadata(row)
            if row['status'] != 'uploading' or row['received'] != row['size']:
                raise WeixinError('upload_incomplete')
            try:
                with os.fdopen(os.open(self.path(upload_id), os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
                    size, sha, md5 = digest_file(source)
                    if (size, sha) != (row['size'], row['sha256']):
                        raise WeixinError('upload_integrity_error')
                    mime = 'application/octet-stream'
                    if row['kind'] == 'image':
                        from PIL import Image
                        try:
                            with warnings.catch_warnings():
                                warnings.simplefilter('error', Image.DecompressionBombWarning)
                                with Image.open(source) as image:
                                    if image.format not in ('JPEG', 'PNG', 'WEBP', 'GIF') or image.width * image.height > MAX_PIXELS:
                                        raise ValueError()
                                    mime = Image.MIME[image.format]
                                    image.verify()
                        except Exception:
                            raise WeixinError('invalid_or_oversize_image') from None
                    elif row['filename'].lower().endswith('.txt'):
                        mime = 'text/plain'
                self.db.execute("UPDATE weixin_uploads SET status='ready',mime_type=?,md5=?,error_kind=NULL WHERE id=?", (mime, md5, upload_id))
            except (WeixinError, OSError) as exc:
                kind = exc.kind if isinstance(exc, WeixinError) else 'upload_cache_unavailable'
                # Commit terminal failure so a conflicting upload cannot be silently reused.
                self.db.execute("UPDATE weixin_uploads SET status='error',error_kind=? WHERE id=?", (kind, upload_id))
                self.path(upload_id).unlink(missing_ok=True)
                return self.metadata(self.authorized(upload_id))
            return self.metadata(self.authorized(upload_id))

    def queue(self, send_id, upload_id, message_id):
        if not isinstance(send_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', send_id):
            raise WeixinError('invalid_send_identity')
        self.probe.weixin.read_message(message_id)
        account = self.probe.weixin.account()
        sid = 'media_' + hashlib.sha256(encoded([account['id'], send_id]).encode()).hexdigest()[:32]
        with self.lock, self.db:
            old = self.db.execute('SELECT upload_id,source_message_id FROM weixin_outbox WHERE message_id=?', (sid,)).fetchone()
            row = self.authorized(upload_id, allow_expired=bool(old))
            if old:
                if (old['upload_id'], old['source_message_id']) != (upload_id, message_id):
                    raise WeixinError('send_identity_conflict')
            else:
                if row['status'] != 'ready' or row['send_id']:
                    raise WeixinError('upload_not_ready_or_already_committed')
                self.probe.weixin.check_queue_capacity()
                self.db.execute('''INSERT INTO weixin_outbox
                    (message_id,account,peer,text,client_id,status,created_at,kind,upload_id,source_message_id)
                    VALUES(?,?,?,'',?,'queued',?,?,?,?)''',
                    (sid, account['id'], account['owner'], 'dots_' + sid, self.clock(), row['kind'], upload_id, message_id))
                self.db.execute("UPDATE weixin_uploads SET status='committed',send_id=? WHERE id=?", (sid, upload_id))
        return self.probe.weixin.send_status(sid)

    def prepare(self, upload_id, account):
        with self.lock, self.db:
            row = self.authorized(upload_id)
            if row['status'] != 'committed' or row['upload_attempts'] >= 3:
                raise WeixinError('media_upload_retry_limit')
            self.db.execute('UPDATE weixin_uploads SET upload_attempts=upload_attempts+1 WHERE id=?', (upload_id,))
        try:
            with os.fdopen(os.open(self.path(upload_id), os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
                size, sha, md5 = digest_file(source)
                if (size, sha, md5) != (row['size'], row['sha256'], row['md5']):
                    raise WeixinError('upload_integrity_error')
                key, filekey = secrets.token_bytes(16), secrets.token_hex(16)
                ticket = self.probe.weixin.client.get_upload_url(account, {
                    'filekey': filekey, 'media_type': 1 if row['kind'] == 'image' else 3,
                    'to_user_id': account['owner'], 'rawsize': size, 'rawfilemd5': md5,
                    'filesize': (size // 16 + 1) * 16, 'no_need_thumb': True, 'aeskey': key.hex()})
                if not isinstance(ticket, dict):
                    raise WeixinError('invalid_upload_response')
                codes = (ticket.get('ret'), ticket.get('errcode'))
                if -14 in codes:
                    raise WeixinError('auth_required', -14)
                if any(x is not None and (type(x) is not int or x != 0) for x in codes):
                    raise WeixinError('media_upload_rejected')
                full = ticket.get('upload_full_url')
                param = ticket.get('upload_param')
                if full is not None and not isinstance(full, str):
                    raise WeixinError('invalid_upload_response')
                url = full.strip() if full else None
                if not url:
                    if not isinstance(param, str) or not 0 < len(param) <= 12000:
                        raise WeixinError('missing_cdn_upload_param')
                    url = 'https://novac2c.cdn.weixin.qq.com/c2c/upload?' + urlencode({'encrypted_query_param': param, 'filekey': filekey})
                # Validate before any injected or actual transport is invoked.
                p = cdn_parts(url)
                if p.hostname != 'novac2c.cdn.weixin.qq.com' or p.path != '/c2c/upload':
                    raise WeixinError('invalid_upload_destination')
                query = self.upload(url, source, key, size)
                if not isinstance(query, str) or not 0 < len(query) <= 12000 or any(c in query for c in '\r\n\x00'):
                    raise WeixinError('missing_cdn_download_param')
        except OSError:
            raise WeixinError('upload_cache_unavailable') from None
        # Official send.ts encodes the ASCII hex key, rather than raw bytes, in base64.
        media = {'encrypt_query_param': query, 'aes_key': base64.b64encode(key.hex().encode()).decode(), 'encrypt_type': 1}
        if row['kind'] == 'image':
            return {'type': 2, 'image_item': {'media': media, 'mid_size': (size // 16 + 1) * 16}}
        return {'type': 4, 'file_item': {'media': media, 'file_name': row['filename'], 'len': str(size)}}

    def cleanup(self):
        now = self.clock()
        with self.lock, self.db:
            for row in self.db.execute("SELECT id,send_id FROM weixin_uploads WHERE expires_at<=? AND status!='expired'", (now,)).fetchall():
                # An active network send owns its file until it returns; cleanup retries later.
                active = self.db.execute("SELECT status FROM weixin_outbox WHERE message_id=?", (row['send_id'],)).fetchone()
                if active and active['status'] in ('sending', 'preparing'):
                    continue
                self.path(row['id']).unlink(missing_ok=True)
                self.db.execute("UPDATE weixin_uploads SET status='expired' WHERE id=?", (row['id'],))
                self.db.execute("UPDATE weixin_outbox SET status='rejected',error_kind='upload_expired',item_json=NULL WHERE upload_id=? AND status IN ('queued','context_required','auth_required')", (row['id'],))
            self.db.execute("UPDATE weixin_outbox SET item_json=NULL WHERE status IN ('accepted','rejected','delivery_unknown') AND upload_id IS NOT NULL")
        # A file created before an interrupted begin transaction has no reservation.
        for path in self.directory.glob('up_*'):
            with self.lock:
                known = self.db.execute('SELECT 1 FROM weixin_uploads WHERE id=?', (path.name,)).fetchone()
            if not known and now - path.stat().st_mtime > 3600:
                path.unlink(missing_ok=True)

    def recover_inflight(self):
        with self.lock, self.db:
            self.db.execute("UPDATE weixin_outbox SET status='queued',error_kind='restart_during_upload' WHERE status='preparing'")
        self.cleanup()
