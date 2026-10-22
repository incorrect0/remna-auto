#!/usr/bin/env python3
"""Rebuild or verify the public release manifest; never include local config/secrets."""
import hashlib
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
FILES = ['tests/test_ux.py', 'bootstrap-deps.sh', 'controller.py', 'remote_worker.py', 'controller-install.sh', 'tests/test_controller.py', 'install.sh', 'run.sh', 'setup.py', 'config.example.json', 'README.md',
         'CHANGELOG.md', 'DEVELOPMENT.md', 'site/index.html', 'tests/test_setup.py',
         'tests/test_bootstrap.py', 'tools/checksums.py', 'tools/check_public_files.py',
         '.github/workflows/check.yml', '.gitignore', '.gitattributes']
text = ''.join(hashlib.sha256((ROOT / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in FILES)
manifest = ROOT / 'SHA256SUMS'
if '--check' in sys.argv:
    if not manifest.exists() or manifest.read_text() != text:
        raise SystemExit('SHA256SUMS устарел: выполните python tools/checksums.py')
    print('SHA256SUMS OK')
else:
    manifest.write_text(text, encoding='utf-8', newline='\n')
    print('SHA256SUMS updated')
