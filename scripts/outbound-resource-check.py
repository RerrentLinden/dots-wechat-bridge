#!/usr/bin/env python3
"""Offline small synthetic upload/send check; bounded streaming, no actual messages."""
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

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from PIL import Image
from probe.probe import Probe
from probe.outbound import encrypted_blocks


class Fake:
    def __init__(self): self.sends=0; self.max_block=0
    def get_upload_url(self,account,payload): return {'upload_param':'synthetic'}
    def send_items(self,*args): self.sends+=1; return {'ret':0}
    def upload(self,url,source,key,size):
        total=0
        for block in encrypted_blocks(source,key):
            total+=len(block); self.max_block=max(self.max_block,len(block))
        assert total==(size//16+1)*16
        return 'synthetic-download'


def main():
    os.umask(0o077)
    start=time.monotonic(); cpu=time.process_time(); client=Fake()
    with tempfile.TemporaryDirectory(prefix='dots-outbound-check-') as directory:
        probe=Probe(directory,weixin_client=client)
        try:
            probe.weixin.bind_confirmed({'status':'confirmed','ilink_bot_id':'fixture-bot','ilink_user_id':'fixture-owner','bot_token':'fixture'})
            probe.weixin.ingest(probe.weixin.account(),{'msgs':[{'message_id':'fixture-source','message_type':1,'from_user_id':'fixture-owner','context_token':'fixture','item_list':[{'type':1,'text_item':{'text':'fixture'}}]}]})
            mid=probe.weixin.status()['latest_owner_message_id']; probe.outbound.upload=client.upload
            data=io.BytesIO(); Image.new('RGB',(2400,1200),(12,70,125)).save(data,'PNG')
            # 2MiB source exists only on disk; blocks remain <=64KiB throughout.
            paths=[]
            file=Path(directory)/'fixture.txt'
            with file.open('wb') as output:
                for _ in range(32): output.write(b'a'*65536)
            paths.append(('file',file))
            img=Path(directory)/'fixture.png'; img.write_bytes(data.getvalue()); paths.append(('image',img))
            samples=[]
            for index,(kind,path) in enumerate(paths):
                sha=hashlib.sha256()
                with path.open('rb') as source:
                    while block:=source.read(65536): sha.update(block)
                uid=probe.outbound.begin('fixture-'+str(index),path.name,kind,path.stat().st_size,sha.hexdigest())['upload_id']
                with path.open('rb') as source:
                    offset=0
                    while block:=source.read(65536):
                        probe.outbound.chunk(uid,offset,base64.b64encode(block).decode(),hashlib.sha256(block).hexdigest()); offset+=len(block)
                assert probe.outbound.finalize(uid)['status']=='ready'
                sid=probe.outbound.queue('send-'+str(index),uid,mid)['send_id']
                probe.weixin.send_once(); assert probe.weixin.send_status(sid)['status']=='accepted'
                samples.append({'kind':kind,'bytes':path.stat().st_size,'simulated_status':'accepted'})
            peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if sys.platform=='darwin': peak//=1024
            print(json.dumps({'samples':samples,'peak_rss_kib':peak,'max_stream_block_bytes':client.max_block,
                'temporary_disk_bytes':sum(p.stat().st_size for p in Path(directory).rglob('*') if p.is_file()),
                'cpu_seconds':round(time.process_time()-cpu,3),'elapsed_seconds':round(time.monotonic()-start,3),
                'network_requests':0,'real_weixin_sends':0,'model_processes':0}))
        finally: probe.close()

if __name__=='__main__': main()
