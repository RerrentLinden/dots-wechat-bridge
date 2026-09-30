import base64
import hashlib
import io
import json
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

from probe.probe import Probe
from probe.weixin import WeixinError
from probe.media import (MAX_FILE, MAX_CHUNK, RETENTION, cdn_parts, download_cdn,
                         decrypt, key_bytes, safe_name, validate_plain)

KEY = b'0123456789abcdef'
OWNER, ACCOUNT = 'fixture-owner', 'fixture-bot'
SECRET = 'whsec_' + base64.b64encode(b's' * 32).decode()


def cipher(raw):
    pad = padding.PKCS7(128).padder()
    padded = pad.update(raw) + pad.finalize()
    enc = Cipher(algorithms.AES(KEY), modes.ECB()).encryptor()
    return enc.update(padded) + enc.finalize()


class MediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1800000000.
        self.probe = self.open()
        self.addCleanup(lambda: self.probe.close())
        self.probe.weixin.bind_confirmed({'status': 'confirmed', 'ilink_bot_id': ACCOUNT,
            'ilink_user_id': OWNER, 'bot_token': 'fixture-token'})
        self.downloads = []
        self.payload = b'private file\n'
        self.probe.media.download = self.download

    def open(self):
        def callback(url, body, headers):
            event = json.loads(body)
            return 200, json.dumps({'challenge': event.get('challenge')}).encode()
        return Probe(self.temp.name, clock=lambda: self.now, post=callback,
                     allowed_hosts=['callbacks.example.com'])

    def download(self, url):
        self.downloads.append(url)
        return cipher(self.payload)

    def item(self, kind=4, **changes):
        name = {2: 'image_item', 3: 'voice_item', 4: 'file_item'}[kind]
        data = {'media': {'encrypt_query_param': 'fixture-opaque-query',
                         'aes_key': base64.b64encode(KEY).decode()}, 'file_name': '../../私有.txt'}
        data.update(changes)
        return {'type': kind, name: data}

    def ingest(self, items, source='1', **changes):
        msg = {'message_id': source, 'message_type': 1, 'from_user_id': OWNER,
               'to_user_id': ACCOUNT, 'item_list': items, 'context_token': 'fixture-context'}
        msg.update(changes)
        self.probe.weixin.ingest(self.probe.weixin.account(), {'msgs': [msg]})
        row = self.probe.db.execute('SELECT id FROM weixin_inbox WHERE source_id=?', (source,)).fetchone()
        return row['id'] if row else None

    def metadata(self, mid):
        return self.probe.weixin.read_message(mid)['attachments'][0]

    def test_binary_chunk_contract_owner_ids_hash_eof_and_no_secret(self):
        self.payload = bytes(range(256)) * 300
        mid = self.ingest([self.item()])
        self.probe.media.process_once()
        meta = self.metadata(mid)
        aid = meta['attachment_id']
        parts = []
        for offset in range(0, len(self.payload), MAX_CHUNK):
            chunk = self.probe.media.read_chunk(mid, aid, offset, MAX_CHUNK)
            self.assertEqual((chunk['message_id'], chunk['attachment_id'], chunk['offset']), (mid, aid, offset))
            self.assertEqual(chunk['size'], len(base64.b64decode(chunk['data_base64'])))
            parts.append(base64.b64decode(chunk['data_base64']))
        self.assertEqual(b''.join(parts), self.payload)
        self.assertEqual(chunk['sha256'], hashlib.sha256(self.payload).hexdigest())
        self.assertEqual(chunk['total_size'], len(self.payload))
        self.assertTrue(chunk['eof'])
        end = self.probe.media.read_chunk(mid, aid, len(self.payload), 10)
        self.assertEqual((end['size'], end['data_base64'], end['eof']), (0, '', True))
        safe = json.dumps(self.probe.weixin.read_message(mid))
        for secret in ('fixture-token', 'fixture-opaque-query', base64.b64encode(KEY).decode(), OWNER):
            self.assertNotIn(secret, safe)
        self.assertIsNone(self.probe.db.execute('SELECT ref_json FROM weixin_attachments').fetchone()[0])

    def test_cdn_rejects_userinfo_redirect_targets_private_dns_before_connection(self):
        for url in ('http://novac2c.cdn.weixin.qq.com/a', 'https://evil.example/a',
                    'https://novac2c.cdn.weixin.qq.com@localhost/a', 'https://novac2c.cdn.weixin.qq.com:8443/a',
                    'https://novac2c.cdn.weixin.qq.com/a#fragment', 'https://novac2c.cdn.weixin.qq.com/a\r\nX:yes'):
            with self.assertRaises(WeixinError): cdn_parts(url)
        with patch('probe.media.socket.getaddrinfo', return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]), patch('probe.media.socket.create_connection') as connect:
            with self.assertRaises(WeixinError): download_cdn('https://novac2c.cdn.weixin.qq.com/a')
            connect.assert_not_called()

    def test_ecb_key_raw_hex_base64_ascii_hex_and_bad_padding(self):
        for ref in ({'key': base64.b64encode(KEY).decode()}, {'key': base64.b64encode(KEY.hex().encode()).decode()}, {'hex_key': KEY.hex()}):
            self.assertEqual(key_bytes(ref), KEY)
            self.assertEqual(decrypt(cipher(b'hello'), {'kind': 'file', **ref}), b'hello')
        for key in ('x', base64.b64encode(b'x' * 15).decode(), base64.b64encode(b'g' * 32).decode()):
            with self.assertRaises(WeixinError): key_bytes({'key': key})
        with self.assertRaises(WeixinError): decrypt(b'x' * 16, {'kind': 'file', 'key': base64.b64encode(KEY).decode()})
        with self.assertRaises(WeixinError): decrypt(b'x' * 17, {'kind': 'file', 'key': base64.b64encode(KEY).decode()})

    def test_owner_filter_and_duplicate_download_job(self):
        self.assertIsNone(self.ingest([self.item()], from_user_id='other'))
        mid = self.ingest([self.item()])
        self.ingest([self.item()])
        self.assertEqual(len(self.probe.media.list_for_message(mid)), 1)
        self.probe.media.process_once()
        self.assertFalse(self.probe.media.process_once())
        self.assertEqual(len(self.downloads), 1)

    def test_attachment_cross_message_and_changed_owner_denied(self):
        mid = self.ingest([self.item()])
        second = self.ingest([{'type': 1, 'text_item': {'text': 'another'}}], source='2')
        self.probe.media.process_once()
        aid = self.metadata(mid)['attachment_id']
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(second, aid, 0, 1)
        with self.probe.db: self.probe.db.execute("UPDATE weixin_accounts SET owner='changed-owner'")
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, aid, 0, 1)

    def test_invalid_ranges_and_path_traversal_cannot_read(self):
        mid = self.ingest([self.item()]); self.probe.media.process_once(); aid = self.metadata(mid)['attachment_id']
        for offset, length in ((-1, 1), (True, 1), (0, False), (0, 0), (0, MAX_CHUNK + 1), (99999, 1)):
            with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, aid, offset, length)
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, '../../secrets/runtime.key', 0, 1)

    def test_cache_persists_restart_and_expires_without_secret_reference(self):
        mid = self.ingest([self.item()]); self.probe.media.process_once(); aid = self.metadata(mid)['attachment_id']
        self.probe.close(); self.probe = self.open()
        self.assertEqual(base64.b64decode(self.probe.media.read_chunk(mid, aid, 0, 20)['data_base64']), self.payload)
        self.now += RETENTION + 1
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, aid, 0, 20)
        self.probe.media.cleanup()
        self.assertEqual(self.metadata(mid)['status'], 'expired')
        self.assertFalse(self.probe.media.path(aid).exists())

    def test_safe_filename_size_md5_and_terminal_failures(self):
        self.assertEqual(safe_name('../../a\\b\x00.txt'), 'b.txt')
        mid = self.ingest([self.item(len=str(len(self.payload)), md5='0' * 32)])
        self.probe.media.process_once()
        self.assertEqual(self.metadata(mid)['error_kind'], 'media_md5_mismatch')
        second = self.ingest([self.item(len=str(MAX_FILE + 1))], source='2')
        self.assertEqual(self.metadata(second)['error_kind'], 'media_too_large')
        self.assertFalse(self.probe.media.process_once())

    def test_transient_get_retries_bounded_and_restart_get_recovery(self):
        mid = self.ingest([self.item()])
        def fail(url): raise WeixinError('media_timeout')
        self.probe.media.download = fail
        for attempt in range(3):
            self.probe.media.process_once(); self.now += 20
        self.assertEqual(self.metadata(mid)['status'], 'error')
        self.assertFalse(self.probe.media.process_once())
        with self.probe.db: self.probe.db.execute("UPDATE weixin_attachments SET status='downloading'")
        self.probe.media.recover_inflight()
        self.assertEqual(self.metadata(mid)['status'], 'queued')

    def test_event_waits_for_media_then_terminal_error_notifies(self):
        self.probe.subscribe({'name': 'weixin.message', 'arguments': {}, 'delivery': {'mode': 'webhook',
            'url': 'https://callbacks.example.com/fixture', 'secret': SECRET}})
        mid = self.ingest([self.item()])
        self.assertEqual(self.probe.queue_weixin_messages(), 0)
        self.probe.media.download = lambda url: b'invalid ciphertext'
        self.probe.media.process_once()
        self.assertEqual(self.probe.queue_weixin_messages(), 1)
        self.assertEqual(self.probe.queue_weixin_messages(), 0)

    def test_voice_upstream_transcript_only_never_downloads_raw_audio(self):
        self.payload = b'\x02#!SILK_V3' + b'fixture\x00'
        mid = self.ingest([self.item(3, text='上游转写', encode_type=6, sample_rate=24000, playtime=1234)])
        self.probe.media.process_once()
        data = self.probe.weixin.read_message(mid)
        meta = data['attachments'][0]
        self.assertIsNone(meta['mime_type'])
        self.assertEqual(meta['status'], 'transcript_only')
        self.assertFalse(meta['audio_downloaded'])
        self.assertEqual(self.downloads, [])
        self.assertEqual(meta['voice_policy'], 'weixin_upstream_only')
        self.assertEqual(meta['upstream_transcript'], '上游转写')
        self.assertEqual(meta['transcript_source'], 'weixin_upstream')
        self.assertEqual(meta['sample_rate'], 24000)
        self.assertEqual(data['text'], '上游转写')

    def test_real_image_mcp_content_block_preview_and_private_original(self):
        output = io.BytesIO(); Image.new('RGB', (3000, 1000), (42, 68, 90)).save(output, 'PNG')
        self.payload = output.getvalue()
        mid = self.ingest([self.item(2, aeskey=KEY.hex())]); self.probe.media.process_once()
        aid = self.metadata(mid)['attachment_id']
        response = self.probe.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'read_attachment_image', 'arguments': {'message_id': mid, 'attachment_id': aid}}})['result']
        block = response['content'][1]
        self.assertEqual((block['type'], block['mimeType']), ('image', 'image/jpeg'))
        with Image.open(io.BytesIO(base64.b64decode(block['data']))) as image:
            self.assertEqual(image.size, (2048, 683))
        self.assertTrue(response['structuredContent']['preview'])
        self.assertEqual(response['structuredContent']['sha256'], hashlib.sha256(self.payload).hexdigest())

    def test_chunk_rpc_text_excludes_binary_and_echoes_contract(self):
        mid = self.ingest([self.item()]); self.probe.media.process_once(); aid = self.metadata(mid)['attachment_id']
        result = self.probe.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call', 'params': {
            'name': 'read_attachment_chunk', 'arguments': {'message_id': mid, 'attachment_id': aid, 'offset': 0, 'length': 100}}})['result']
        self.assertNotIn('data_base64', result['content'][0]['text'])
        self.assertEqual(base64.b64decode(result['structuredContent']['data_base64']), self.payload)

    def test_cache_tamper_and_symlink_rejected(self):
        mid = self.ingest([self.item()]); self.probe.media.process_once(); aid = self.metadata(mid)['attachment_id']
        path = self.probe.media.path(aid); path.write_bytes(b'x')
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, aid, 0, 1)
        path.unlink(); path.symlink_to(self.probe.directory / 'probe.sqlite')
        with self.assertRaises(WeixinError): self.probe.media.read_chunk(mid, aid, 0, 1)

    def test_plain_image_requires_valid_image_and_voice_key_required(self):
        mid = self.ingest([self.item(3, media={'encrypt_query_param': 'fixture'})])
        self.assertEqual(self.metadata(mid)['error_kind'], 'no_upstream_transcript')
        self.assertEqual(self.metadata(mid)['status'], 'transcript_unavailable')
        self.assertFalse(self.probe.media.process_once())
        with self.assertRaises(WeixinError): validate_plain(b'not an image', {'kind': 'image'})
        self.assertEqual(decrypt(b'plain', {'kind': 'image'}), b'plain')

    def test_pending_queue_busy_is_explicit_without_unbounded_jobs(self):
        for i in range(34):
            mid = self.ingest([self.item()], source=str(i))
        self.assertEqual(self.metadata(mid)['error_kind'], 'media_queue_busy')
        self.assertEqual(self.probe.db.execute("SELECT count(*) FROM weixin_attachments WHERE status='queued'").fetchone()[0], 32)

    def test_cache_disk_cap_and_pixel_cap_fail_gracefully(self):
        mid = self.ingest([self.item()])
        with patch('probe.media.MAX_CACHE', 1): self.probe.media.process_once()
        self.assertEqual(self.metadata(mid)['error_kind'], 'media_cache_full')
        output = io.BytesIO(); Image.new('RGB', (3000, 3000)).save(output, 'PNG')
        with self.assertRaises(WeixinError): validate_plain(output.getvalue(), {'kind': 'image'})

    def test_voice_transcript_without_media_or_key_is_valid_and_not_unsupported(self):
        mid = self.ingest([{'type':3,'voice_item':{'text':'只用微信转写'}}])
        result = self.probe.weixin.read_message(mid)
        self.assertEqual(result['text'], '只用微信转写')
        self.assertEqual(result['unsupported_types'], [])
        self.assertEqual(result['attachments'][0]['status'], 'transcript_only')
        self.assertIsNone(result['attachments'][0]['error_kind'])
        self.assertFalse(self.probe.media.process_once())
        self.assertIsNone(self.probe.db.execute('SELECT ref_json FROM weixin_attachments').fetchone()[0])

    def test_voice_pending_from_old_version_is_retired_on_startup_without_get(self):
        mid = self.ingest([self.item(3, text='已转写')])
        with self.probe.db:
            self.probe.db.execute("UPDATE weixin_attachments SET status='queued',ref_json='{}'")
        self.probe.close(); self.probe = self.open()
        self.assertEqual(self.metadata(mid)['status'], 'transcript_only')
        self.assertFalse(self.probe.media.process_once())
        self.assertIsNone(self.probe.db.execute('SELECT ref_json FROM weixin_attachments').fetchone()[0])


if __name__ == '__main__': unittest.main()
