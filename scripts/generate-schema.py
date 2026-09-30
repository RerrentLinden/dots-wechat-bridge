#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from probe.probe import Probe
from probe.weixin import MESSAGE_EVENT

parser=argparse.ArgumentParser(); parser.add_argument('--check',action='store_true'); args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
text=json.dumps({'protocolVersion':'2026-07-28','tools':Probe.tools(),'events':[Probe.event(),Probe.event(MESSAGE_EVENT)]},ensure_ascii=False,indent=2)+'\n'
target=root/'docs/mcp-schema.json'
if args.check:
    if not target.exists() or target.read_text()!=text: raise SystemExit('MCP schema stale: run scripts/generate-schema.py')
else: target.write_text(text)
