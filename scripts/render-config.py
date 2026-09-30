#!/usr/bin/env python3
"""Render private configuration; values are identifiers/references, never secret bytes."""
import argparse
import os
from pathlib import Path
import re
import shlex


def render(root, tunnel_id, callback_hosts, replace=False):
    root=Path(root).resolve()
    if not re.fullmatch(r'/[A-Za-z0-9_./-]+',str(root)):
        raise ValueError('Use an absolute installation path without spaces or shell metacharacters')
    if not re.fullmatch(r'tunnel_[a-f0-9]{32}',tunnel_id):
        raise ValueError('Use the actual tunnel ID returned by Platform')
    if not 1<=len(callback_hosts)<=3 or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?',h) or '.' not in h or '..' in h for h in callback_hosts):
        raise ValueError('Supply 1..3 exact callback hostnames observed from the authorized platform subscription')
    runtime=root/'runtime'; runtime.mkdir(mode=0o700,exist_ok=True)
    os.chmod(runtime,0o700)
    for name in ('state','secrets'):
        target=runtime/name; target.mkdir(mode=0o700,exist_ok=True); os.chmod(target,0o700)
    args=[str(root/'.venv/bin/python'),str(root/'probe/probe.py'),'--state-dir',str(runtime/'state')]
    for host in callback_hosts: args.extend(['--allow-callback-host',host])
    profile=(root/'config/tunnel-profile.yaml.example').read_text().replace('__TUNNEL_ID__',tunnel_id).replace('__ROOT__',str(root)).replace('__MCP_COMMAND__',shlex.join(args))
    service=(root/'config/dots-wechat-bridge.service.example').read_text().replace('__ROOT__',str(root))
    for name,text in (('profile.yaml',profile),('dots-wechat-bridge.service',service)):
        flags=os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW|(os.O_TRUNC if replace else os.O_EXCL)
        with os.fdopen(os.open(runtime/name,flags,0o600),'w') as output: output.write(text)
    return runtime


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--root',default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--tunnel-id',required=True)
    parser.add_argument('--callback-host',action='append',required=True)
    parser.add_argument('--replace',action='store_true',help='Update only rendered config; preserves key and database')
    args=parser.parse_args()
    try:
        runtime=render(args.root,args.tunnel_id,args.callback_host,args.replace)
        print('Rendered private profile and service in '+str(runtime))
    except (ValueError,OSError) as exc:
        parser.exit(1,type(exc).__name__+': config not generated; check inputs/file ownership\n')

if __name__=='__main__': main()
