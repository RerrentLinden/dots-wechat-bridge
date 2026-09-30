# Third-party notices and licensing status

The original Python bridge and repository documentation are licensed under the MIT License, Copyright 2026 RerrentLinden. See `LICENSE`.

Tencent/openclaw-weixin (MIT, Copyright 2026 Tencent) is the protocol reference for media upload/encryption/message fields. The bridge implements that protocol in Python; no Tencent TypeScript source is bundled. Its license text is retained for attribution in `licenses/Tencent-openclaw-weixin-MIT.txt`. Reference revision: `24de5c9eb0dd5e595d7e2d090ed8a3f82870d42c`.

OpenAI/tunnel-client is installed separately from its official distribution. Follow that distribution's LICENSE and included third-party notices. This repository does not relicense or redistribute it.

Python dependencies are installed separately from their publishers: cryptography (Apache-2.0 OR BSD-3-Clause), Pillow (MIT-CMU), cffi (MIT-0), pycparser (BSD-3-Clause), qrcode (BSD-3-Clause). The pinned distributions include their own notices. No dependency binaries are bundled here.

All account labels, tokens and cryptographic keys in offline tests are deliberately synthetic fixtures. This repository includes no deployment credentials or private message history. This independent project is not affiliated with or endorsed by OpenAI or Tencent.
