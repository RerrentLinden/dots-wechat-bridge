"""Private owner-scoped Tencent CDN attachment transport, with no model runtime.

AES-128 ECB / PKCS7 follows Tencent's pic-decrypt.ts and aes-ecb.ts.
Opaque CDN references and keys remain inside the private SQLite database.
"""
import base64
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import socket
import ssl
import time
import unicodedata
import warnings
from urllib.parse import urlencode, urlsplit

try:
    from .weixin import WeixinError, encoded, public_ip
except ImportError:
    from weixin import WeixinError, encoded, public_ip

MAX_FILE = 20 * 1024 * 1024
MAX_CACHE = 128 * 1024 * 1024
MAX_CHUNK = 65536
RETENTION = 7 * 86400
MAX_PIXELS = 8_000_000
CDN_HOSTS = frozenset(('novac2c.cdn.weixin.qq.com', 'ilinkai.weixin.qq.com',
                      'wx.qlogo.cn', 'thirdwx.qlogo.cn', 'res.wx.qq.com',
                      'mmbiz.qpic.cn', 'mmbiz.qlogo.cn'))


def safe_name(value, fallback='attachment.bin'):
    if not isinstance(value, str):
        return fallback
    value = unicodedata.normalize('NFKC', value).replace('\\', '/').split('/')[-1]
    value = ''.join(c for c in value if not unicodedata.category(c).startswith('C'))
    value = value.strip(' .')[:120]
    return value or fallback


def cdn_parts(value):
    try:
        p = urlsplit(value)
        if (not isinstance(value, str) or len(value) > 16384 or any(c in value for c in '\r\n\x00')
                or p.scheme != 'https' or p.hostname not in CDN_HOSTS
                or p.port not in (None, 443) or p.username or p.password or p.fragment):
            raise ValueError()
        return p
    except (ValueError, TypeError):
        raise WeixinError('invalid_media_destination') from None


def download_cdn(value):
    """Pinned public DNS address, TLS original host, bounded GET; no redirects."""
    p = cdn_parts(value)
    conn = None
    deadline = time.monotonic() + 35
    try:
        addresses = list(dict.fromkeys(x[4][0] for x in socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)))
        if not addresses or not all(public_ip(a) for a in addresses):
            raise WeixinError('non_public_media_address')
        conn = http.client.HTTPSConnection(p.hostname, timeout=10, context=ssl.create_default_context())
        sock = socket.create_connection((addresses[0], 443), timeout=10)
        try:
            conn.sock = conn._context.wrap_socket(sock, server_hostname=p.hostname)
        except BaseException:
            sock.close()
            raise
        conn.request('GET', (p.path or '/') + ('?' + p.query if p.query else ''),
                     headers={'Accept': 'application/octet-stream', 'Accept-Encoding': 'identity'})
        response = conn.getresponse()
        if not 200 <= response.status < 300:
            raise WeixinError('media_http_error', response.status)
        length = response.getheader('Content-Length')
        if length and (not length.isdigit() or int(length) > MAX_FILE + 16):
            raise WeixinError('media_too_large')
        chunks, size = [], 0
        while True:
            if time.monotonic() >= deadline:
                raise WeixinError('media_timeout')
            if conn.sock:
                conn.sock.settimeout(max(.1, min(10, deadline - time.monotonic())))
            block = response.read(65536)
            if not block:
                break
            size += len(block)
            if size > MAX_FILE + 16:
                raise WeixinError('media_too_large')
            chunks.append(block)
        return b''.join(chunks)
    except WeixinError:
        raise
    except (socket.timeout, TimeoutError):
        raise WeixinError('media_timeout') from None
    except Exception:
        raise WeixinError('media_network_error') from None
    finally:
        if conn:
            conn.close()


def key_bytes(ref):
    try:
        if ref.get('hex_key'):
            if not re.fullmatch(r'[a-fA-F0-9]{32}', ref['hex_key']):
                raise ValueError()
            return bytes.fromhex(ref['hex_key'])
        key = base64.b64decode(ref['key'], validate=True)
        if len(key) == 32:
            key = bytes.fromhex(key.decode('ascii'))
        if len(key) != 16:
            raise ValueError()
        return key
    except (ValueError, KeyError, TypeError, UnicodeError):
        raise WeixinError('invalid_media_key') from None


def decrypt(raw, ref):
    if len(raw) > MAX_FILE + 16:
        raise WeixinError('media_too_large')
    if not ref.get('key') and not ref.get('hex_key'):
        if ref['kind'] == 'image':
            return raw
        raise WeixinError('missing_media_key')
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = key_bytes(ref)
    if not raw or len(raw) % 16:
        raise WeixinError('invalid_media_ciphertext')
    try:
        decoder = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        plain = decoder.update(raw) + decoder.finalize()
        unpad = padding.PKCS7(128).unpadder()
        result = unpad.update(plain) + unpad.finalize()
    except ValueError:
        raise WeixinError('invalid_media_padding') from None
    if len(result) > MAX_FILE:
        raise WeixinError('media_too_large')
    return result


def image_info(raw):
    from PIL import Image
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('error', Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(raw)) as image:
                if image.format not in ('JPEG', 'PNG', 'WEBP', 'GIF') or image.width * image.height > MAX_PIXELS:
                    raise ValueError()
                mime, dimensions = Image.MIME[image.format], [image.width, image.height]
                image.verify()
                return mime, dimensions
    except Exception:
        raise WeixinError('invalid_or_oversize_image') from None


def validate_plain(raw, ref):
    if not raw or len(raw) > MAX_FILE:
        raise WeixinError('invalid_media_size')
    if ref.get('expected_size') is not None and len(raw) != ref['expected_size']:
        raise WeixinError('media_size_mismatch')
    if ref.get('md5') and hashlib.md5(raw).hexdigest() != ref['md5'].lower():
        raise WeixinError('media_md5_mismatch')
    if ref['kind'] == 'image':
        return image_info(raw)[0]
    if ref['kind'] == 'voice':
        if raw.startswith((b'#!SILK_V3', b'\x02#!SILK_V3')):
            return 'audio/silk'
        if raw.startswith(b'RIFF') and raw[8:12] == b'WAVE':
            return 'audio/wav'
        if raw.startswith(b'OggS'):
            return 'audio/ogg'
        if raw.startswith(b'ID3') or raw[:2] in (b'\xff\xfb', b'\xff\xf3', b'\xff\xf2'):
            return 'audio/mpeg'
        if raw.startswith(b'#!AMR'):
            return 'audio/amr'
        raise WeixinError('unsupported_voice_encoding')
    if raw.startswith(b'%PDF-'):
        return 'application/pdf'
    if raw.startswith(b'PK\x03\x04'):
        return 'application/zip'
    try:
        raw.decode('utf-8')
        if b'\x00' not in raw:
            return 'text/plain'
    except UnicodeError:
        pass
    return 'application/octet-stream'


def extract_ref(item):
    kind = {2: 'image', 3: 'voice', 4: 'file'}[item['type']]
    data = item.get(kind + '_item')
    if not isinstance(data, dict) or not isinstance(data.get('media'), dict):
        raise WeixinError('missing_media_reference')
    media = data['media']
    url = media.get('full_url')
    if not url:
        query = media.get('encrypt_query_param')
        if not isinstance(query, str) or not query or len(query) > 12000:
            raise WeixinError('missing_media_reference')
        url = 'https://novac2c.cdn.weixin.qq.com/c2c/download?' + urlencode({'encrypted_query_param': query})
    cdn_parts(url)
    ref = {'kind': kind, 'url': url, 'key': media.get('aes_key')}
    if kind == 'image' and data.get('aeskey'):
        ref['hex_key'] = data['aeskey']
    if ref.get('key') or ref.get('hex_key'):
        key_bytes(ref)
    elif kind != 'image':
        raise WeixinError('missing_media_key')
    if kind == 'file' and data.get('len') is not None:
        try:
            length = int(data['len'])
            if isinstance(data['len'], bool) or length < 0 or str(length) != str(data['len']):
                raise ValueError()
            if length > MAX_FILE:
                raise WeixinError('media_too_large')
            ref['expected_size'] = length
        except (ValueError, TypeError):
            raise WeixinError('invalid_media_size') from None
    if kind == 'file' and data.get('md5'):
        if not isinstance(data['md5'], str) or not re.fullmatch(r'[a-fA-F0-9]{32}', data['md5']):
            raise WeixinError('invalid_media_md5')
        ref['md5'] = data['md5']
    return ref


class MediaStore:
    def __init__(self, probe, downloader=None):
        self.probe, self.db, self.lock, self.clock = probe, probe.db, probe.lock, probe.clock
        self.download = downloader or download_cdn
        self.directory = Path(probe.directory) / 'attachments'
        self.directory.mkdir(mode=0o700, exist_ok=True)
        os.chmod(self.directory, 0o700)
        self.next_cleanup = 0
        self.db.executescript('''CREATE TABLE IF NOT EXISTS weixin_attachments (
            id TEXT PRIMARY KEY, message_id TEXT NOT NULL, account TEXT NOT NULL, peer TEXT NOT NULL,
            kind TEXT NOT NULL, filename TEXT NOT NULL, ref_json TEXT,
            status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_at REAL NOT NULL DEFAULT 0,
            size INTEGER, mime_type TEXT, sha256 TEXT, error_kind TEXT,
            created_at REAL NOT NULL, expires_at REAL NOT NULL, provenance TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS attachment_message ON weixin_attachments(message_id);
        ''')
        self.db.commit()
        # Voice policy: only Tencent's upstream transcript, no eager raw audio.
        # Preserve prior cached user samples until ordinary retention expiry.
        with self.lock, self.db:
            for row in self.db.execute("SELECT id,provenance FROM weixin_attachments WHERE kind='voice' AND status IN ('queued','downloading')").fetchall():
                provenance = json.loads(row['provenance'])
                has_text = isinstance(provenance.get('upstream_transcript'), str) and bool(provenance['upstream_transcript'].strip())
                self.db.execute("UPDATE weixin_attachments SET status=?,error_kind=?,ref_json=NULL WHERE id=?",
                    ('transcript_only' if has_text else 'transcript_unavailable', None if has_text else 'no_upstream_transcript', row['id']))

    def add(self, message_id, account, peer, items):
        """Called inside owner-filtered inbox transaction; never commits by itself."""
        count = 0
        for index, item in enumerate(items):
            if not isinstance(item, dict) or item.get('type') not in (2, 3, 4):
                continue
            count += 1
            if count > 8:
                break
            kind = {2: 'image', 3: 'voice', 4: 'file'}[item['type']]
            data = item.get(kind + '_item')
            data = data if isinstance(data, dict) else {}
            name = safe_name(data.get('file_name'), kind + ('.silk' if kind == 'voice' else '.bin'))
            provenance = {}
            if kind == 'voice':
                for key in ('encode_type', 'sample_rate', 'bits_per_sample', 'playtime'):
                    if type(data.get(key)) is int and 0 <= data[key] <= 86400000:
                        provenance[key] = data[key]
                transcript = data.get('text')
                if isinstance(transcript, str) and len(transcript.encode()) <= 65536:
                    provenance['upstream_transcript'] = transcript
                    provenance['transcript_source'] = 'weixin_upstream'
            aid = 'att_' + hashlib.sha256(encoded([message_id, index]).encode()).hexdigest()[:32]
            status, error, ref = 'queued', None, None
            if kind == 'voice':
                transcript = provenance.get('upstream_transcript')
                has_text = isinstance(transcript, str) and bool(transcript.strip())
                status = 'transcript_only' if has_text else 'transcript_unavailable'
                error = None if has_text else 'no_upstream_transcript'
            else:
                try:
                    ref = extract_ref(item)
                except WeixinError as exc:
                    status, error = 'error', exc.kind
            if status == 'queued' and self.db.execute("SELECT count(*) FROM weixin_attachments WHERE status IN ('queued','downloading')").fetchone()[0] >= 32:
                status, error, ref = 'error', 'media_queue_busy', None
            now = self.clock()
            self.db.execute('''INSERT OR IGNORE INTO weixin_attachments
                (id,message_id,account,peer,kind,filename,ref_json,status,error_kind,created_at,expires_at,provenance)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?)''',
                (aid, message_id, account, peer, kind, name, encoded(ref) if ref else None,
                 status, error, now, now + RETENTION, encoded(provenance)))

    def recover_inflight(self):
        with self.lock, self.db:
            # CDN GET may safely retry; no message sends are performed here.
            self.db.execute("UPDATE weixin_attachments SET status='queued' WHERE status='downloading'")

    def cleanup(self):
        now = self.clock()
        if now < self.next_cleanup:
            return
        self.next_cleanup = now + 60
        with self.lock, self.db:
            rows = self.db.execute("SELECT id FROM weixin_attachments WHERE expires_at<=? AND status!='expired'", (now,)).fetchall()
            for row in rows:
                self.path(row['id']).unlink(missing_ok=True)
            self.db.execute("UPDATE weixin_attachments SET status='expired',ref_json=NULL WHERE expires_at<=?", (now,))
        # Remove only our own incomplete files left by interrupted writes.
        for path in self.directory.glob('att_*.part'):
            if now - path.stat().st_mtime > 3600:
                path.unlink(missing_ok=True)

    def path(self, aid):
        if not isinstance(aid, str) or not re.fullmatch(r'att_[a-f0-9]{32}', aid):
            raise WeixinError('invalid_attachment_id')
        return self.directory / aid

    def cache_usage(self):
        """Caller holds lock; outgoing reservations share the existing 128MiB budget."""
        total = self.db.execute("SELECT coalesce(sum(size),0) FROM weixin_attachments WHERE status='cached'").fetchone()[0]
        if self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='weixin_uploads'").fetchone():
            total += self.db.execute("SELECT coalesce(sum(size),0) FROM weixin_uploads WHERE status IN ('uploading','ready','committed')").fetchone()[0]
        return total

    def process_once(self):
        self.cleanup()
        now = self.clock()
        with self.lock, self.db:
            row = self.db.execute("SELECT * FROM weixin_attachments WHERE status='queued' AND next_at<=? ORDER BY created_at LIMIT 1", (now,)).fetchone()
            if not row:
                return False
            self.db.execute("UPDATE weixin_attachments SET status='downloading',attempts=attempts+1 WHERE id=?", (row['id'],))
        temp = self.path(row['id']).with_suffix('.part')
        try:
            ref = json.loads(row['ref_json'])
            raw = decrypt(self.download(ref['url']), ref)
            mime = validate_plain(raw, ref)
            with self.lock, self.db:
                if self.cache_usage() + len(raw) > MAX_CACHE:
                    raise WeixinError('media_cache_full')
                fd = os.open(temp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as output:
                    output.write(raw); output.flush(); os.fsync(output.fileno())
                os.replace(temp, self.path(row['id']))
                self.db.execute("UPDATE weixin_attachments SET status='cached',size=?,mime_type=?,sha256=?,error_kind=NULL,ref_json=NULL WHERE id=?",
                                (len(raw), mime, hashlib.sha256(raw).hexdigest(), row['id']))
        except Exception as exc:
            kind = exc.kind if isinstance(exc, WeixinError) else 'media_processing_error'
            retry = kind in ('media_timeout', 'media_network_error') and row['attempts'] + 1 < 3
            with self.lock, self.db:
                self.db.execute("UPDATE weixin_attachments SET status=?,next_at=?,error_kind=?,ref_json=CASE WHEN ? THEN ref_json ELSE NULL END WHERE id=?",
                                ('queued' if retry else 'error', now + 5 * (row['attempts'] + 1), kind, retry, row['id']))
        finally:
            temp.unlink(missing_ok=True)
        return True

    def metadata(self, row):
        return {'attachment_id': row['id'], 'message_id': row['message_id'], 'kind': row['kind'],
                'filename': row['filename'], 'status': row['status'], 'size': row['size'],
                'mime_type': row['mime_type'], 'sha256': row['sha256'], 'error_kind': row['error_kind'],
                'expires_at': self.probe.iso(row['expires_at']),
                **({'voice_policy': 'weixin_upstream_only', 'audio_downloaded': row['status'] == 'cached'} if row['kind'] == 'voice' else {}),
                **json.loads(row['provenance'])}

    def list_for_message(self, mid):
        with self.lock:
            rows = self.db.execute('SELECT * FROM weixin_attachments WHERE message_id=? ORDER BY rowid', (mid,)).fetchall()
        return [self.metadata(row) for row in rows]

    def authorized(self, mid, aid):
        account = self.probe.weixin.account()
        self.path(aid)
        if not account:
            raise WeixinError('not_bound')
        with self.lock:
            row = self.db.execute('''SELECT a.* FROM weixin_attachments a JOIN weixin_inbox i ON i.id=a.message_id
                WHERE a.id=? AND a.message_id=? AND a.account=? AND a.peer=? AND i.account=a.account AND i.peer=a.peer''',
                (aid, mid, account['id'], account['owner'])).fetchone()
        if not row:
            raise WeixinError('unknown_owner_attachment')
        if row['expires_at'] <= self.clock():
            raise WeixinError('attachment_expired')
        if row['status'] != 'cached':
            raise WeixinError('attachment_not_cached')
        return row

    def read_chunk(self, mid, aid, offset, length):
        if type(offset) is not int or type(length) is not int or offset < 0 or not 1 <= length <= MAX_CHUNK:
            raise WeixinError('invalid_attachment_range')
        row = self.authorized(mid, aid)
        if offset > row['size']:
            raise WeixinError('invalid_attachment_range')
        try:
            fd = os.open(self.path(aid), os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as source:
                if os.fstat(source.fileno()).st_size != row['size']:
                    raise WeixinError('attachment_integrity_error')
                source.seek(offset)
                raw = source.read(min(length, row['size'] - offset))
        except OSError:
            raise WeixinError('attachment_cache_unavailable') from None
        return {'message_id': mid, 'attachment_id': aid, 'offset': offset, 'size': len(raw),
                'total_size': row['size'], 'mime_type': row['mime_type'], 'sha256': row['sha256'],
                'data_base64': base64.b64encode(raw).decode(), 'eof': offset + len(raw) == row['size'],
                'filename': row['filename'], 'expires_at': self.probe.iso(row['expires_at'])}

    def read_image(self, mid, aid):
        row = self.authorized(mid, aid)
        if row['kind'] != 'image':
            raise WeixinError('attachment_is_not_image')
        with os.fdopen(os.open(self.path(aid), os.O_RDONLY | os.O_NOFOLLOW), 'rb') as source:
            raw = source.read(MAX_FILE + 1)
        if len(raw) != row['size'] or hashlib.sha256(raw).hexdigest() != row['sha256']:
            raise WeixinError('attachment_integrity_error')
        # Always strip EXIF/other private metadata and bound model-facing pixels.
        from PIL import Image, ImageOps
        with Image.open(io.BytesIO(raw)) as image:
            image = ImageOps.exif_transpose(image).convert('RGB')
            image.thumbnail((2048, 2048))
            output = io.BytesIO(); image.save(output, 'JPEG', quality=85)
        metadata = {**self.metadata(row), 'preview': True, 'preview_mime_type': 'image/jpeg'}
        return metadata, {'type': 'image', 'mimeType': 'image/jpeg', 'data': base64.b64encode(output.getvalue()).decode()}
