import base64
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PIL import Image
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from probe.probe import Probe
from probe.weixin import WeixinError, IlinkClient
from probe.media import MAX_FILE, MAX_CACHE, MAX_CHUNK, RETENTION
from probe.outbound import MAX_RPC_BYTES, encrypted_blocks, upload_cdn

OWNER, ACCOUNT = 'fixture-owner', 'fixture-bot'


class FakeClient:
    def __init__(self):
        self.tickets, self.sent, self.results = [], [], []
        self.ticket_result = {'upload_param': 'fixture-upload-param'}

    def get_upload_url(self, account, payload):
        self.tickets.append(payload)
        if isinstance(self.ticket_result, Exception):
            raise self.ticket_result
        return self.ticket_result

    def send_items(self, account, peer, items, client_id, context):
        self.sent.append((peer, items, client_id, context))
        result = self.results.pop(0) if self.results else {}
        if isinstance(result, Exception):
            raise result
        return result


class OutboundTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1800000000.
        self.client = FakeClient()
        self.probe = Probe(self.temp.name, clock=lambda: self.now, weixin_client=self.client)
        self.addCleanup(lambda: self.probe.close())
        self.probe.weixin.bind_confirmed({'status': 'confirmed', 'ilink_bot_id': ACCOUNT,
            'ilink_user_id': OWNER, 'bot_token': 'fixture-token'})
        self.mid = self.inbound('first')
        self.uploads = []
        self.probe.outbound.upload = self.fake_upload

    def inbound(self, source, context='fixture-context'):
        self.probe.weixin.ingest(self.probe.weixin.account(), {'msgs': [{
            'message_id': source, 'message_type': 1, 'from_user_id': OWNER,
            'to_user_id': ACCOUNT, 'context_token': context, 'item_list': [{'type':1,'text_item':{'text':'fixture'}}]}]})
        return self.probe.db.execute('SELECT id FROM weixin_inbox WHERE source_id=?',(source,)).fetchone()[0]

    def fake_upload(self, url, source, key, size):
        blocks = list(encrypted_blocks(source, key))
        self.assertLessEqual(max(map(len, blocks)), MAX_CHUNK)
        encrypted = b''.join(blocks)
        dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        padded = dec.update(encrypted) + dec.finalize()
        unpad = padding.PKCS7(128).unpadder()
        raw = unpad.update(padded) + unpad.finalize()
        self.assertEqual(len(raw), size)
        self.uploads.append((raw, key, url))
        return 'fixture-download-param'

    def begin(self, raw, identity='upload-one', kind='file', filename='fixture.txt', sha=None):
        return self.probe.outbound.begin(identity,filename,kind,len(raw),sha or hashlib.sha256(raw).hexdigest())['upload_id']

    def chunk(self, uid, raw, offset=0):
        return self.probe.outbound.chunk(uid,offset,base64.b64encode(raw).decode(),hashlib.sha256(raw).hexdigest())

    def ready(self, raw=b'Synthetic non-sensitive test.\n', **args):
        uid = self.begin(raw, **args)
        for offset in range(0,len(raw),MAX_CHUNK):
            self.chunk(uid,raw[offset:offset+MAX_CHUNK],offset)
        self.assertEqual(self.probe.outbound.finalize(uid)['status'],'ready')
        return uid

    def queue(self, uid, identity='send-one'):
        return self.probe.outbound.queue(identity,uid,self.mid)['send_id']

    def test_authenticated_mcp_full_chunk_and_no_binary_response(self):
        raw = bytes(range(256)) * 256
        uid = self.begin(raw)
        request = {'jsonrpc':'2.0','id':7,'method':'tools/call','params':{'name':'upload_weixin_chunk','arguments':{
            'upload_id':uid,'offset':0,'data_base64':base64.b64encode(raw).decode(),'chunk_sha256':hashlib.sha256(raw).hexdigest()}}}
        self.assertGreater(len(json.dumps(request).encode()),65536)
        self.assertLess(len(json.dumps(request).encode()),MAX_RPC_BYTES)
        result = self.probe.rpc(request)['result']
        self.assertEqual(result['structuredContent']['next_offset'],65536)
        self.assertNotIn('data_base64',result['content'][0]['text'])
        self.assertNotIn('fixture-token',json.dumps(result))

    def test_stdio_accepts_64k_base64_and_bounds_oversize_line(self):
        uid = self.begin(b'a' * MAX_CHUNK)
        request = {'jsonrpc':'2.0','id':8,'method':'tools/call','params':{'name':'upload_weixin_chunk','arguments':{
            'upload_id':uid,'offset':0,'data_base64':base64.b64encode(b'a'*MAX_CHUNK).decode(),'chunk_sha256':hashlib.sha256(b'a'*MAX_CHUNK).hexdigest()}}}
        inputs = (json.dumps(request)+'\n'+'x'*(MAX_RPC_BYTES+20)+'\n'+json.dumps({'jsonrpc':'2.0','id':9,'method':'ping'})+'\n').encode()
        # Daemon exits before its workers perform network I/O (0.5s initial wait).
        result = subprocess.run([sys.executable,'probe/probe.py','--state-dir',self.temp.name],input=inputs,capture_output=True,timeout=5)
        lines = [json.loads(line) for line in result.stdout.splitlines()]
        self.assertEqual(lines[0]['result']['structuredContent']['next_offset'],MAX_CHUNK)
        self.assertEqual(lines[1]['error']['message'],'Request too large')
        self.assertEqual(lines[2]['id'],9)

    def test_resume_identical_retry_conflict_gap_and_crash_tail(self):
        uid = self.begin(b'abcdef')
        self.chunk(uid,b'abc')
        self.assertTrue(self.chunk(uid,b'abc')['duplicate'])
        with self.assertRaisesRegex(WeixinError,'conflict'): self.chunk(uid,b'xxx')
        with self.assertRaisesRegex(WeixinError,'range'): self.chunk(uid,b'ef',4)
        with open(self.probe.outbound.path(uid),'ab') as file: file.write(b'crash-uncommitted')
        self.chunk(uid,b'def',3)
        self.assertEqual(self.probe.outbound.finalize(uid)['status'],'ready')
        self.assertTrue(self.chunk(uid,b'abc')['duplicate'])

    def test_validation_bounds_hash_and_base64(self):
        for size in (0,MAX_FILE+1,True):
            with self.assertRaises(WeixinError): self.probe.outbound.begin('x','x.txt','file',size,'a'*64)
        uid = self.begin(b'abcdef')
        for block,sha in [('@@@','a'*64),(base64.b64encode(b'a').decode(),'a'*64),('A'*87385,'a'*64)]:
            with self.assertRaises(WeixinError): self.probe.outbound.chunk(uid,0,block,sha)
        with self.assertRaises(WeixinError): self.chunk(uid,b'a'*(MAX_CHUNK+1))
        with self.assertRaisesRegex(WeixinError,'incomplete'): self.probe.outbound.finalize(uid)
        self.assertEqual(self.probe.outbound.status(uid)['next_offset'],0)

    def test_whole_integrity_error_is_terminal_and_frees_reservation(self):
        uid = self.begin(b'abc',sha='a'*64)
        self.chunk(uid,b'abc')
        result = self.probe.outbound.finalize(uid)
        self.assertEqual((result['status'],result['error_kind']),('error','upload_integrity_error'))
        self.assertFalse(self.probe.outbound.path(uid).exists())
        self.assertEqual(self.probe.media.cache_usage(),0)
        with self.assertRaises(WeixinError): self.queue(uid)

    def test_image_and_file_official_payloads_and_owner(self):
        img = io.BytesIO(); Image.new('RGB',(16,16),(34,120,200)).save(img,'PNG')
        for index,(kind,raw,name,item_type) in enumerate((('image',img.getvalue(),'fixture.png',2),('file',b'fixture\n','fixture.txt',4))):
            uid = self.ready(raw,identity='up-'+str(index),kind=kind,filename=name)
            sid = self.queue(uid,'send-'+str(index))
            self.probe.weixin.send_once()
            result = self.probe.weixin.send_status(sid)
            self.assertEqual(result['status'],'accepted'); self.assertIsNone(result['delivered'])
            peer,items,client,context = self.client.sent[-1]
            self.assertEqual((peer,items[0]['type']),(OWNER,item_type))
            item = items[0][kind+'_item']; media = item['media']
            self.assertEqual(base64.b64decode(media['aes_key']).decode(),self.uploads[-1][1].hex())
            self.assertEqual(media['encrypt_type'],1)
            self.assertEqual(self.uploads[-1][0],raw)
            ticket = self.client.tickets[-1]
            self.assertEqual((ticket['media_type'],ticket['rawsize'],ticket['rawfilemd5'],ticket['no_need_thumb']),
                             (1 if kind=='image' else 3,len(raw),hashlib.md5(raw).hexdigest(),True))
            if kind=='image': self.assertEqual(item['mid_size'],ticket['filesize'])
            else: self.assertEqual((item['file_name'],item['len']),(name,str(len(raw))))
            self.assertIsNone(self.probe.db.execute('SELECT item_json FROM weixin_outbox WHERE message_id=?',(sid,)).fetchone()[0])

    def test_invalid_and_oversize_pixel_images_never_send(self):
        for index,raw in enumerate((b'not a png', self.big_image())):
            uid = self.begin(raw,identity='bad-'+str(index),kind='image')
            self.chunk(uid,raw)
            self.assertEqual(self.probe.outbound.finalize(uid)['error_kind'],'invalid_or_oversize_image')
        self.assertEqual(self.client.sent,[])

    def big_image(self):
        data = io.BytesIO(); Image.new('1',(3000,3000)).save(data,'PNG'); return data.getvalue()

    def test_one_upload_one_send_stable_ids_and_conflicts(self):
        uid = self.ready(); sid = self.queue(uid)
        self.assertEqual(self.queue(uid),sid)
        with self.assertRaises(WeixinError): self.queue(uid,'different')
        other = self.ready(identity='other')
        with self.assertRaisesRegex(WeixinError,'conflict'): self.queue(other)
        self.probe.weixin.send_once()
        self.assertEqual(self.queue(uid),sid)
        self.assertFalse(self.probe.weixin.send_once()); self.assertEqual(len(self.client.sent),1)
        with self.assertRaisesRegex(WeixinError,'conflict'): self.begin(b'changed')

    def test_latest_context_after_upload_and_source_owner_checked(self):
        uid = self.ready(); sid = self.queue(uid)
        def upload(*args):
            self.now += 10
            self.inbound('new','latest-context')
            return self.fake_upload(*args)
        self.probe.outbound.upload = upload
        self.probe.weixin.send_once()
        self.assertEqual(self.client.sent[0][-1],'latest-context')
        with self.assertRaises(WeixinError): self.probe.outbound.queue('bad',uid,'wx_missing')
        with self.probe.db:
            self.probe.db.execute("UPDATE weixin_accounts SET owner='other'")
        with self.assertRaises(WeixinError): self.probe.outbound.status(uid)

    def test_missing_context_no_upload_then_fresh_message_resumes(self):
        uid=self.ready(); sid=self.queue(uid)
        with self.probe.db: self.probe.db.execute('DELETE FROM weixin_peers')
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(sid)['transport_status'],'context_required')
        self.assertEqual(self.client.tickets,[])
        self.inbound('fresh')
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(sid)['status'],'accepted')

    def test_uncertain_send_never_retried_and_crypto_reference_purged(self):
        uid=self.ready(); sid=self.queue(uid)
        self.client.results=[WeixinError('api_timeout')]
        self.probe.weixin.send_once()
        result=self.probe.weixin.send_status(sid)
        self.assertEqual((result['status'],result['transport_status'],result['accepted'],result['delivered']),('uncertain','delivery_unknown',False,None))
        self.assertFalse(self.probe.weixin.send_once()); self.queue(uid)
        self.assertEqual(len(self.client.sent),1)
        self.assertNotIn('fixture-download-param',json.dumps(result))

    def test_context_auth_and_rejected_states_retain_existing_behavior(self):
        for index,result in enumerate(({'ret':-2,'errmsg':'prepare failed'},{'ret':-14},{'ret':-5})):
            with self.probe.db: self.probe.db.execute("UPDATE weixin_accounts SET status='ready'")
            uid=self.ready(identity='up-'+str(index)); sid=self.queue(uid,'send-'+str(index))
            self.client.results=[result]
            self.probe.weixin.send_once()
            expected=('context_required','auth_required','rejected')[index]
            self.assertEqual(self.probe.weixin.send_status(sid)['transport_status'],expected)
        self.assertEqual(self.probe.weixin.send_status(sid)['status'],'error')

    def test_cdn_upload_retry_bounded_before_send_no_delivery_uncertainty(self):
        uid=self.ready(); sid=self.queue(uid)
        self.probe.outbound.upload=lambda *args: (_ for _ in ()).throw(WeixinError('media_upload_timeout'))
        for index in range(3):
            self.probe.weixin.send_once(); self.now+=30
        result=self.probe.weixin.send_status(sid)
        self.assertEqual((result['status'],result['attempts']),('error',0))
        self.assertEqual(len(self.client.tickets),3); self.assertEqual(self.client.sent,[])
        self.assertFalse(self.probe.weixin.send_once())

    def test_ticket_auth_error_and_untrusted_url_never_upload(self):
        uid=self.ready(); sid=self.queue(uid)
        self.client.ticket_result={'ret':-14}
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(sid)['transport_status'],'auth_required')
        self.assertEqual(self.uploads,[])
        with self.probe.db:
            self.probe.db.execute("UPDATE weixin_accounts SET status='ready'")
            self.probe.db.execute("UPDATE weixin_outbox SET status='queued' WHERE message_id=?",(sid,))
        self.client.ticket_result={'upload_full_url':'https://example.com/c2c/upload?secret=fixture'}
        self.now += 30
        self.probe.weixin.send_once()
        self.assertEqual(self.probe.weixin.send_status(sid)['status'],'error')
        self.assertEqual(self.uploads,[])

    def test_restart_preparing_safe_sending_uncertain_and_status_read_has_no_effect(self):
        uid=self.ready(); sid=self.queue(uid)
        with self.probe.db: self.probe.db.execute("UPDATE weixin_outbox SET status='preparing' WHERE message_id=?",(sid,))
        self.assertEqual(self.probe.weixin.send_status(sid)['transport_status'],'preparing')
        self.probe.outbound.recover_inflight()
        self.assertEqual(self.probe.weixin.send_status(sid)['transport_status'],'queued')
        with self.probe.db: self.probe.db.execute("UPDATE weixin_outbox SET status='sending',item_json='{}' WHERE message_id=?",(sid,))
        self.probe.weixin.recover_inflight(); self.probe.outbound.recover_inflight()
        self.assertEqual(self.probe.weixin.send_status(sid)['status'],'uncertain')
        self.assertIsNone(self.probe.db.execute('SELECT item_json FROM weixin_outbox WHERE message_id=?',(sid,)).fetchone()[0])

    def test_shared_cache_queue_expiry_and_retention(self):
        uid=self.begin(b'fixture')
        with patch('probe.outbound.MAX_CACHE',5):
            with self.assertRaisesRegex(WeixinError,'cache_full'): self.begin(b'x',identity='full')
        for index in range(7): self.begin(b'x',identity='pending-'+str(index))
        with self.assertRaisesRegex(WeixinError,'queue_busy'): self.begin(b'x',identity='ninth')
        self.now+=RETENTION+1; self.probe.outbound.cleanup()
        self.assertEqual(self.probe.outbound.status(uid)['status'],'expired')
        self.assertEqual(self.probe.media.cache_usage(),0)
        with self.assertRaisesRegex(WeixinError,'expired'): self.chunk(uid,b'fixture')

    def test_outgoing_reservation_prevents_incoming_overflow_and_expired_send(self):
        uid=self.ready(b'fixture'); sid=self.queue(uid)
        with patch('probe.media.MAX_CACHE',6):
            self.assertEqual(self.probe.media.cache_usage(),7)
        self.now+=RETENTION+1; self.probe.outbound.cleanup()
        self.assertEqual(self.probe.weixin.send_status(sid)['error_kind'],'upload_expired')
        self.assertFalse(self.probe.weixin.send_once())

    def test_send_queue_cap_preserves_existing_dedup(self):
        uid=self.ready()
        with self.probe.db:
            for index in range(32):
                self.probe.db.execute("INSERT INTO weixin_outbox(message_id,account,peer,text,client_id,status,created_at) VALUES(?,?,?,'',?,'queued',?)",
                                      ('fixture-'+str(index),ACCOUNT,OWNER,'client-'+str(index),self.now))
        with self.assertRaisesRegex(WeixinError,'queue_busy'): self.queue(uid)
        self.assertEqual(self.probe.outbound.status(uid)['status'],'ready')

    def test_symlink_and_disk_tamper_cannot_be_finalized_or_sent(self):
        uid=self.begin(b'abc'); self.chunk(uid,b'abc')
        self.probe.outbound.path(uid).write_bytes(b'xyz')
        self.assertEqual(self.probe.outbound.finalize(uid)['status'],'error')
        uid=self.begin(b'abc',identity='link')
        self.probe.outbound.path(uid).unlink(); self.probe.outbound.path(uid).symlink_to('/etc/passwd')
        with self.assertRaises(WeixinError): self.chunk(uid,b'abc')

    def test_cdn_public_dns_pinning_url_allowlist_before_socket(self):
        source=io.BytesIO(b'fixture')
        for url in ('http://novac2c.cdn.weixin.qq.com/c2c/upload',
                    'https://ilinkai.weixin.qq.com/c2c/upload',
                    'https://novac2c.cdn.weixin.qq.com/c2c/download'):
            with self.assertRaises(WeixinError): upload_cdn(url,source,b'0'*16,7)
        with patch('socket.getaddrinfo',return_value=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',443))]),patch('socket.create_connection') as connect:
            with self.assertRaisesRegex(WeixinError,'non_public'): upload_cdn('https://novac2c.cdn.weixin.qq.com/c2c/upload',source,b'0'*16,7)
            connect.assert_not_called()

    def test_streaming_aes_padding_16_boundary_without_full_read(self):
        class Bounded(io.BytesIO):
            def read(self,size=-1):
                if not 0 < size <= MAX_CHUNK: raise AssertionError('unbounded read')
                return super().read(size)
        for size in (1,16,65536,65537):
            raw=b'a'*size; encrypted=b''.join(encrypted_blocks(Bounded(raw),b'0'*16))
            self.assertEqual(len(encrypted),(size//16+1)*16)
            dec=Cipher(algorithms.AES(b'0'*16),modes.ECB()).decryptor()
            padded=dec.update(encrypted)+dec.finalize(); unpad=padding.PKCS7(128).unpadder()
            self.assertEqual(unpad.update(padded)+unpad.finalize(),raw)

    def test_ilink_request_protocol_routes_without_logging_keys(self):
        client=IlinkClient(); calls=[]
        client.request=lambda *args: calls.append(args) or {}
        account={'base_url':'https://ilinkai.weixin.qq.com','token':'fixture-token'}
        client.get_upload_url(account,{'filekey':'fixture'})
        client.send_items(account,OWNER,[{'type':2}], 'stable','latest')
        self.assertEqual(calls[0][1],'/ilink/bot/getuploadurl')
        self.assertEqual(calls[1][2]['msg']['item_list'],[{'type':2}])
        self.assertEqual(calls[1][2]['msg']['context_token'],'latest')


if __name__=='__main__': unittest.main()
