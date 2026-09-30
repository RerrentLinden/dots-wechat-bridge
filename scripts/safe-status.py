#!/usr/bin/env python3
"""Read safe counts and bounded loopback health, without keys or message bodies."""
import argparse
import http.client
import json
from pathlib import Path
import sqlite3
import time
from urllib.parse import urlsplit

parser=argparse.ArgumentParser(); parser.add_argument('--state-dir',required=True); args=parser.parse_args()
root=Path(args.state_dir)
with sqlite3.connect('file:'+str(root/'probe.sqlite')+'?mode=ro',uri=True) as db:
    account=db.execute('SELECT status,last_poll,last_error FROM weixin_accounts LIMIT 1').fetchone()
    result={'account_status':account[0] if account else 'not_bound','last_error':account[2] if account else None,
        'poll_age_seconds':round(time.time()-account[1],1) if account and account[1] else None,
        'send_counts':dict(db.execute('SELECT status,count(*) FROM weixin_outbox GROUP BY status').fetchall()),
        'active_subscriptions':dict(db.execute('SELECT name,count(*) FROM subscriptions WHERE expires>? GROUP BY name',(time.time(),)).fetchall())}
try:
    p=urlsplit((root/'service-health.url').read_text().strip())
    if p.scheme!='http' or p.hostname!='127.0.0.1' or not p.port: raise ValueError()
    result['health']={}
    for endpoint in ('/healthz','/readyz'):
        conn=http.client.HTTPConnection(p.hostname,p.port,timeout=2)
        try:
            conn.request('GET',endpoint); response=conn.getresponse(); result['health'][endpoint]=response.status
        finally: conn.close()
except Exception: result['health']='unavailable'
print(json.dumps(result))
