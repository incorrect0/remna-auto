#!/usr/bin/env python3
"""Pre-publication check for accidental credentials and real infrastructure addresses."""
import ipaddress
from pathlib import Path
import re
import subprocess
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
manifest = ROOT / 'SHA256SUMS'
allowed = {line.split('  ',1)[1] for line in manifest.read_text().splitlines()} | {'SHA256SUMS'}
if (ROOT/'.git').exists():
    tracked = subprocess.check_output(['git','ls-files'],cwd=ROOT,text=True).splitlines()
    extra = set(tracked) - allowed
    if extra:
        raise SystemExit('Не разрешены к публикации: '+', '.join(sorted(extra)))
hosts = {'api.ipify.org','ipv4.icanhazip.com','ipwho.is','ipapi.co','github.com','raw.githubusercontent.com','codeload.github.com','docs.rw',
         'download.docker.com','dl.cloudsmith.io','archive.ubuntu.com','security.ubuntu.com',
         'ports.ubuntu.com','deb.debian.org','security.debian.org','www.w3.org'}
docs_networks = [ipaddress.ip_network(n) for n in ('192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','127.0.0.0/8')]
patterns = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            r'gh[pousr]_[A-Za-z0-9]{25,}',r'github_pat_[A-Za-z0-9_]{40,}',
            r'\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            r'\b\d{8,}:[A-Za-z0-9_-]{30,}']
problems = []
for name in sorted(allowed):
    text=(ROOT/name).read_text(encoding='utf-8')
    if any(re.search(pattern,text) for pattern in patterns):
        problems.append(name+': возможный секрет (значение скрыто)')
    for match in re.finditer(r'https?://[^\s\x22\x27<>]+',text):
        raw=match.group().rstrip(').,;')
        if raw.endswith('://'):
            continue
        if any(c in raw.split('/')[2] for c in ('{','$')):
            continue  # Validated runtime variables are not personal values stored in source.
        url=urllib.parse.urlsplit(raw)
        host=url.hostname or ''
        dummy_auth=(name.startswith('tests/') and host.endswith('.test') and url.username=='user' and url.password=='pass')
        if ((url.username or url.password) and not dummy_auth) or not (host in hosts or host=='example.com' or host.endswith(('.example.com','.example','.test'))):
            problems.append(name+': непроверенный URL (значение скрыто)')
    for ip_text in re.findall(r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])',text):
        try:ip=ipaddress.ip_address(ip_text)
        except ValueError:continue
        if ip_text!='0.0.0.0' and not any(ip in net for net in docs_networks):
            problems.append(name+': адрес вне тестовых диапазонов (значение скрыто)')
if problems:
    raise SystemExit('\n'.join(sorted(set(problems))))
print(f'Public-file privacy check OK: {len(allowed)} allowlisted files')
