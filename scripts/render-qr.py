#!/usr/bin/env python3
"""Render private, short-lived QR content locally; never print payload or publish it."""
import argparse
import os
from pathlib import Path
import qrcode
from qrcode.image.pil import PilImage


def render(directory):
    directory=Path(directory)
    source=directory/'weixin-qr-content.txt'
    with os.fdopen(os.open(source,os.O_RDONLY|os.O_NOFOLLOW),'r') as input:
        content=input.read(8193)
    if not content or len(content)>8192: raise ValueError('Invalid QR content')
    target=directory/'weixin-login-qr.png'
    qr=qrcode.make(content,image_factory=PilImage)
    with os.fdopen(os.open(target,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600),'wb') as output:
        qr.save(output)
    return target


def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--state-dir',required=True); args=parser.parse_args()
    try: print('Private QR image: '+str(render(args.state_dir)))
    except Exception: parser.exit(1,'QR render unavailable; check private input without exposing its contents.\n')

if __name__=='__main__': main()
