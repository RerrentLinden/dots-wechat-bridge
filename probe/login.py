#!/usr/bin/env python3
"""User-controlled iLink QR login. Bot credentials never leave the server.

--start only creates the QR; --poll stores a successful, same-owner confirmation.
The display file contains a short-lived QR payload, never a bot or Platform key.
"""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

try:
    from .probe import Probe
    from .weixin import WeixinError, api_base
except ImportError:
    from probe import Probe
    from weixin import WeixinError, api_base


def private_write(path, content):
    fd, pending = tempfile.mkstemp(prefix=".weixin-login-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(pending, 0o600)
        os.replace(pending, path)
    finally:
        if os.path.exists(pending):
            os.unlink(pending)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--state-dir", required=True)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--start", action="store_true")
    choice.add_argument("--poll", action="store_true")
    parser.add_argument("--verify-stdin", action="store_true", help="User supplies any required pairing code privately on stdin")
    args = parser.parse_args()
    os.umask(0o077)
    directory = Path(args.state_dir)
    probe = Probe(directory)
    login_file, display_file = directory / "weixin-login.json", directory / "weixin-qr-content.txt"
    try:
        if args.start:
            account = probe.weixin.account()
            if account and account["status"] == "ready":
                raise WeixinError("already_bound")
            login = probe.weixin.client.begin_login()
            private_write(login_file, json.dumps(login))
            private_write(display_file, login["display"])
            result = {"status": "wait", "qr_display_file": str(display_file), "expires_after_seconds": 300}
        else:
            login = json.loads(login_file.read_text())
            verification = sys.stdin.readline().strip() if args.verify_stdin else None
            result = probe.weixin.client.poll_login(login, verification)
            status = result.get("status")
            if status == "confirmed":
                probe.weixin.bind_confirmed(result)
                login_file.unlink(missing_ok=True)
                display_file.unlink(missing_ok=True)
                (directory / 'weixin-login-qr.png').unlink(missing_ok=True)
                result = {"status": "confirmed", "connected": True, "owner_only": True}
            elif status == "scaned_but_redirect":
                host = result.get("redirect_host", "")
                login["base"] = api_base(host if "://" in host else "https://" + host)
                private_write(login_file, json.dumps(login))
                result = {"status": "scaned_but_redirect"}
            elif status in ("wait", "scaned", "expired", "need_verifycode", "verify_code_blocked", "binded_redirect"):
                result = {"status": status}
            else:
                result = {"status": "unknown_login_response"}
        print(json.dumps(result))
    except WeixinError as error:
        print(json.dumps({"error": error.kind}))
        return 1
    except Exception:
        print(json.dumps({"error": "login_operation_failed"}))
        return 1
    finally:
        probe.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
