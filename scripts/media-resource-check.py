#!/usr/bin/env python3
"""Small offline synthetic resource check; no real inbox, network or messages."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import resource
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from PIL import Image
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from probe.probe import Probe

def main():
    os.umask(0o077)
    started = time.monotonic()
    cpu_start = time.process_time()
    with tempfile.TemporaryDirectory(prefix='dots-media-check-') as directory:
        probe = Probe(directory)
        try:
            probe.weixin.bind_confirmed({'status':'confirmed','ilink_bot_id':'fixture-bot','ilink_user_id':'fixture-owner','bot_token':'fixture'})
            key = b'fixture-key-1234'
            image = io.BytesIO(); Image.new('RGB', (2400, 1200), (12, 70, 125)).save(image, 'PNG')
            payloads = [('file', b'Small local synthetic resource sample.\n' * 56000), ('image', image.getvalue()), ('voice', b'\x02#!SILK_V3fixture')]
            samples = []
            for index, (kind, payload) in enumerate(payloads):
                pad = padding.PKCS7(128).padder(); padded = pad.update(payload) + pad.finalize()
                enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor(); encrypted = enc.update(padded) + enc.finalize()
                probe.media.download = lambda url: encrypted
                item = {'type': {'file':4,'image':2,'voice':3}[kind], kind+'_item': {'media': {'aes_key':base64.b64encode(key).decode(),'encrypt_query_param':'synthetic-local'}}}
                if kind == 'voice': item['voice_item']['text'] = '仅使用微信转写合成样本'
                probe.weixin.ingest(probe.weixin.account(), {'msgs':[{'message_type':1,'message_id':str(index),'from_user_id':'fixture-owner','to_user_id':'fixture-bot','item_list':[item]}]})
                probe.media.process_once()
                row = probe.db.execute('SELECT id FROM weixin_inbox WHERE source_id=?',(str(index),)).fetchone()
                metadata = probe.weixin.read_message(row['id'])['attachments'][0]
                if kind == 'voice':
                    assert metadata['status'] == 'transcript_only' and metadata['audio_downloaded'] is False
                    samples.append({'kind':kind,'bytes_cached':0,'status':'transcript_only'})
                    continue
                assert metadata['status'] == 'cached' and metadata['sha256'] == hashlib.sha256(payload).hexdigest()
                if kind == 'image':
                    probe.media.read_image(row['id'], metadata['attachment_id'])
                else:
                    for offset in range(0,len(payload),65536): probe.media.read_chunk(row['id'],metadata['attachment_id'],offset,65536)
                samples.append({'kind':kind,'bytes':len(payload),'status':'cached'})
            disk = sum(p.stat().st_size for p in Path(directory).rglob('*') if p.is_file())
            peak_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform == 'darwin': peak_kib //= 1024
            print(json.dumps({'samples':samples,'peak_rss_kib':peak_kib,'temporary_disk_bytes':disk,
                'elapsed_seconds':round(time.monotonic()-started,3),'cpu_seconds':round(time.process_time()-cpu_start,3),
                'network_requests':0,'model_processes':0}))
        finally: probe.close()

if __name__ == '__main__': main()
