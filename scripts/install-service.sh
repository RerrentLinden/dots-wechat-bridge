#!/bin/sh
# Operator-approved Linux/systemd install. Uses only this repository's service.
set -eu
cd "$(dirname "$0")/.."
test "$(id -u)" = 0 || { echo 'Run this specific installer with sudo after review.' >&2; exit 1; }
test -x bin/tunnel-client
test -x .venv/bin/python
test -s runtime/profile.yaml
test -s runtime/secrets/runtime.key
test -s runtime/dots-wechat-bridge.service
if systemctl cat dots-wechat-bridge.service >/dev/null 2>&1; then
  echo 'Existing service detected. Follow docs/OPERATIONS.md; installer will not overwrite it.' >&2
  exit 1
fi
# Refuse before ownership/unit changes if a foreground worker still owns this state.
.venv/bin/python - <<'PY'
import fcntl
import os
import sys
fd = os.open('runtime/state/worker.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
try:
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    sys.exit('Bridge worker still running. Stop the foreground tunnel, wait for exit, then retry installation.')
finally:
    os.close(fd)
PY
if ! id dotsbridge >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir "$(pwd)" --shell /usr/sbin/nologin dotsbridge
fi
chown -R dotsbridge:dotsbridge runtime
chmod 700 runtime runtime/state runtime/secrets
chmod 600 runtime/profile.yaml runtime/secrets/runtime.key
install -m 644 runtime/dots-wechat-bridge.service /etc/systemd/system/dots-wechat-bridge.service
systemctl daemon-reload
systemctl enable --now dots-wechat-bridge.service
systemctl show dots-wechat-bridge.service --property=ActiveState,SubState,UnitFileState,MemoryCurrent,MemoryMax,CPUQuotaPerSecUSec
