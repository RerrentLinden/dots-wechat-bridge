import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]

def module(name):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/name)
    result=importlib.util.module_from_spec(spec); spec.loader.exec_module(result); return result


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); shutil.copytree(ROOT/'config',self.root/'config')
        self.config=module('render-config.py')

    def test_profile_only_references_private_key_service_resource_limits(self):
        runtime=self.config.render(self.root,'tunnel_'+'0'*32,['callbacks.example.com'])
        profile=(runtime/'profile.yaml').read_text(); service=(runtime/'dots-wechat-bridge.service').read_text()
        self.assertIn('api_key: file:',profile); self.assertNotIn('sk-',profile)
        self.assertIn('--allow-callback-host callbacks.example.com',profile)
        self.assertIn('127.0.0.1:0',profile)
        for value in ('CPUQuota=100%','MemoryMax=384M','User=dotsbridge','TasksMax=64'):
            self.assertIn(value,service)
        self.assertEqual((runtime/'profile.yaml').stat().st_mode&0o777,0o600)
        self.assertEqual((runtime/'state').stat().st_mode&0o777,0o700)

    def test_replace_config_preserves_secret_and_requires_explicit_replace(self):
        runtime=self.config.render(self.root,'tunnel_'+'0'*32,['callbacks.example.com'])
        key=runtime/'secrets/runtime.key'; key.write_text('synthetic-key-fixture')
        with self.assertRaises(FileExistsError): self.config.render(self.root,'tunnel_'+'0'*32,['callbacks.example.com'])
        self.config.render(self.root,'tunnel_'+'0'*32,['second.example.com'],True)
        self.assertEqual(key.read_text(),'synthetic-key-fixture')

    def test_invalid_ids_hosts_and_path_metacharacters_rejected(self):
        for tid,hosts in (('invalid',['callbacks.example.com']),('tunnel_'+'0'*32,['*']),('tunnel_'+'0'*32,[])):
            with self.assertRaises(ValueError): self.config.render(self.root,tid,hosts)
        with self.assertRaises(ValueError): self.config.render(str(self.root)+'/bad space','tunnel_'+'0'*32,['callbacks.example.com'])

    def test_private_synthetic_qr_render_no_network_or_payload_stdout(self):
        state=self.root/'state'; state.mkdir()
        (state/'weixin-qr-content.txt').write_text('https://example.com/synthetic-qr-test')
        target=module('render-qr.py').render(state)
        self.assertEqual(target.stat().st_mode&0o777,0o600)
        self.assertEqual(target.read_bytes()[:8],b'\x89PNG\r\n\x1a\n')

if __name__=='__main__': unittest.main()
