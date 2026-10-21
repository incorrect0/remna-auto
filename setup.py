#!/usr/bin/env python3
"""Independent Remnawave 3.x node installer; Python standard library only."""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

VERSION = '1.0.1'
HERE = Path(__file__).resolve().parent
ROOT = Path('/opt/remna-auto')
STACK = Path('/opt/remnanode')
SITE = Path('/var/www/site')
CADDY = Path('/etc/caddy/Caddyfile')
BACKUPS = Path('/var/backups/remna-auto')
NFT = ROOT / 'node-api.nft'
SERVICE = Path('/etc/systemd/system/remna-auto-firewall.service')
MARKER = '.remna-auto-managed'
SECRETS: list[str] = []
APT_SOURCE_FILE: Path | None = None


class SetupError(Exception):
    pass


def safe(value):
    value = str(value)
    for secret in SECRETS:
        if secret:
            value = value.replace(secret, '[REDACTED]')
    return value


def log(message):
    print(safe(message), flush=True)


def run(args, *, check=True, timeout=600, input=None):
    if args and str(args[0]) == 'apt-get':
        log('APT: ' + ' '.join(str(a) for a in args[1:]))
        args = [args[0], '-o', 'Acquire::Retries=2', '-o', 'Acquire::http::Timeout=20',
                '-o', 'Acquire::https::Timeout=20', '-o', 'DPkg::Lock::Timeout=120', *args[1:]]
        if APT_SOURCE_FILE:
            args[1:1] = ['-o', 'Dir::Etc::sourcelist=' + str(APT_SOURCE_FILE), '-o', 'Dir::Etc::sourceparts=-']
    result = subprocess.run([str(x) for x in args], input=input, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
                            env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    if check and result.returncode:
        # Never render argv: environment files and API headers must stay private.
        raise SetupError(f'Ошибка команды {Path(str(args[0])).name}:\n{safe(result.stdout[-3000:])}')
    return result


def atomic(path: Path, content: bytes | str, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(path.name + '.tmp-' + uuid.uuid4().hex[:8])
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'wb') as file:
            file.write(content.encode() if isinstance(content, str) else content)
            file.flush()
            os.fsync(file.fileno())
        # The bootstrap uses umask 077; explicit public config/site modes must still work.
        os.chmod(temp, mode)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def read_json(path, default=None):
    return json.loads(path.read_text()) if path.exists() else default


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SetupError('API вернул redirect. Укажите прямой HTTPS-адрес панели.')


class API:
    def __init__(self, url, token, proxy_key=''):
        self.url = validate_panel_url(url)
        if not token or any(c in token + proxy_key for c in '\r\n'):
            raise SetupError('Пустой или некорректный API-ключ.')
        self.token, self.proxy_key = token, proxy_key or token
        SECRETS.extend([token, proxy_key])
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))

    def request(self, method, path, body=None):
        if not path.startswith('/api/'):
            raise SetupError('Некорректный API endpoint.')
        headers = {'Authorization': 'Bearer ' + self.token, 'X-Api-Key': self.proxy_key,
                   'Accept': 'application/json', 'Content-Type': 'application/json'}
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, headers=headers, method=method)
        for attempt in range(3 if method == 'GET' else 1):
            try:
                with self.opener.open(req, timeout=25) as response:
                    raw = response.read(16 * 1024 * 1024)
                    return json.loads(raw).get('response') if raw else None
            except urllib.error.HTTPError as exc:
                if method == 'GET' and exc.code in (429, 502, 503, 504) and attempt < 2:
                    time.sleep(2 + attempt * 2)
                    continue
                hint = {401: 'неверный API-ключ', 403: 'нет прав API или доступ закрыт reverse proxy',
                        404: 'endpoint/запись не найдены', 409: 'запись уже существует'}.get(exc.code, 'ошибка панели')
                raise SetupError(f'API {method} {path}: HTTP {exc.code} — {hint}') from None
            except (urllib.error.URLError, TimeoutError, OSError):
                if method == 'GET' and attempt < 2:
                    time.sleep(2)
                    continue
                raise SetupError(f'API {method} {path}: сеть, TLS или тайм-аут; секреты не записаны в журнал.') from None
            except (ValueError, AttributeError):
                raise SetupError(f'API {path} вернул ответ, который не является JSON Remnawave.') from None


def validate_panel_url(value):
    value = value.strip().rstrip('/')
    u = urllib.parse.urlsplit(value)
    if u.scheme != 'https' or not u.hostname or u.username or u.password or u.query or u.fragment or u.path:
        raise SetupError('Адрес панели: https://panel.example.com, без /dashboard, /api, паролей и query.')
    return value


def validate_domain(value):
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise SetupError('Укажите домен латиницей без https://, порта, пути и wildcard.')
    return value


def validate_port(value):
    try:
        if isinstance(value, bool):
            raise ValueError()
        value = int(str(value))
    except ValueError:
        raise SetupError('Порт должен быть целым числом.') from None
    if not 1 <= value <= 65535:
        raise SetupError('Порт должен быть от 1 до 65535.')
    return value


def validate_config(cfg):
    cfg = dict(cfg)
    cfg['panel_url'] = validate_panel_url(cfg.get('panel_url', ''))
    cfg['domain'] = validate_domain(cfg.get('domain', ''))
    address = cfg.get('node_address', '').strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        address = validate_domain(address)
    cfg['node_address'] = address
    cfg['node_port'] = validate_port(cfg.get('node_port', 3001))
    if cfg['node_port'] in (22, 80, 443):
        raise SetupError('Порт управления ноды не должен совпадать с SSH/HTTP/HTTPS.')
    name = cfg.get('node_name', '')
    if not isinstance(name, str) or not 3 <= len(name) <= 30 or any(ord(c) < 32 for c in name):
        raise SetupError('Имя ноды: 3–30 символов без управляющих символов.')
    country = cfg.get('country_code', 'XX').upper()
    if not re.fullmatch('[A-Z]{2}', country):
        raise SetupError('Код страны: две латинские буквы, например DE или XX.')
    cfg['country_code'] = country
    ips = cfg.get('panel_ips', [])
    if isinstance(ips, str):
        ips = [x.strip() for x in ips.split(',') if x.strip()]
    try:
        if not isinstance(ips, list) or any(not isinstance(x, str) or '%' in x for x in ips):
            raise ValueError()
        cfg['panel_ips'] = sorted({str(ipaddress.ip_address(x)) for x in ips})
    except ValueError:
        raise SetupError('panel_ips: только отдельные IPv4/IPv6 сервера панели, без доменов и подсетей.') from None
    if not cfg['panel_ips']:
        raise SetupError('Нужен хотя бы один исходящий IP сервера панели для защиты порта управления.')
    image = cfg.get('node_image', 'remnawave/node:latest')
    if not re.fullmatch(r'(?:ghcr.io/)?remnawave/node(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})', image):
        raise SetupError('Допускается официальный образ remnawave/node или ghcr.io/remnawave/node.')
    cfg['node_image'] = image
    return cfg


def ask(label, default='', secret=False):
    suffix = f' [{default}]' if default and not secret else ''
    value = (getpass.getpass if secret else input)(label + suffix + ': ').strip()
    return value or default


def choose_profile(api, cfg, interactive):
    profiles = (api.request('GET', '/api/config-profiles') or {}).get('configProfiles', [])
    if not profiles:
        raise SetupError('В панели нет доступных профилей конфигурации.')
    if interactive and cfg.get('profile_uuid'):
        current_name = next((p['name'] for p in profiles if p['uuid'] == cfg['profile_uuid']), cfg['profile_uuid'])
        if ask(f'Изменить сохранённый профиль {current_name}? y/n', 'n').lower() == 'y':
            cfg.pop('profile_uuid', None)
            cfg.pop('inbound_uuids', None)
    if not cfg.get('profile_uuid'):
        if not interactive:
            raise SetupError('В config.json нужен profile_uuid; запустите интерактивно для выбора.')
        log('\nДоступные профили:')
        for i, p in enumerate(profiles, 1):
            log(f"  {i}. {p['name']}  ({p['uuid']})")
        try:
            number = int(ask('Номер профиля'))
            if not 1 <= number <= len(profiles):
                raise ValueError()
            cfg['profile_uuid'] = profiles[number - 1]['uuid']
        except ValueError:
            raise SetupError('Нет профиля с таким номером.') from None
    if cfg['profile_uuid'] not in {p['uuid'] for p in profiles}:
        raise SetupError('Выбранный профиль больше не существует или недоступен API-ключу.')
    profile = api.request('GET', '/api/config-profiles/' + cfg['profile_uuid'])
    # Resolve snippets using the panel's computed endpoint (3.x), not regex substitution.
    try:
        computed = api.request('GET', '/api/config-profiles/' + cfg['profile_uuid'] + '/computed-config')
    except SetupError as exc:
        if 'HTTP 404' not in str(exc):
            raise
        computed = profile
    inbounds = profile.get('inbounds', [])
    if not inbounds:
        raise SetupError('У профиля нет inbound’ов.')
    if interactive and not cfg.get('inbound_uuids'):
        log('\nInbound’ы выбранного профиля:')
        for i, inbound in enumerate(inbounds, 1):
            log(f"  {i}. {inbound['tag']} · {inbound.get('type')} · порт {inbound.get('port')}")
        value = ask('Номера через запятую или all', 'all')
        if value != 'all':
            try:
                numbers = {int(x.strip()) for x in value.split(',')}
                if not numbers or min(numbers) < 1 or max(numbers) > len(inbounds):
                    raise ValueError()
                cfg['inbound_uuids'] = [p['uuid'] for i, p in enumerate(inbounds, 1) if i in numbers]
            except ValueError:
                raise SetupError('Некорректный список inbound’ов.') from None
    selected = cfg.get('inbound_uuids') or [p['uuid'] for p in inbounds]
    if not isinstance(selected, list) or not selected or not set(selected).issubset({p['uuid'] for p in inbounds}):
        raise SetupError('Inbound’ы не принадлежат выбранному профилю.')
    cfg['inbound_uuids'] = selected
    cfg['profile_name'] = profile['name']
    cfg['inbound_tags'] = [p['tag'] for p in inbounds if p['uuid'] in selected]
    config = computed.get('config')
    if not isinstance(config, dict) or not isinstance(config.get('inbounds'), list):
        raise SetupError('Панель не вернула вычисленную конфигурацию с inbound’ами.')
    raw_by_tag = {b.get('tag'): b for b in config['inbounds'] if isinstance(b, dict)}
    ports = set()
    for inbound in inbounds:
        if inbound['uuid'] not in selected:
            continue
        raw = raw_by_tag.get(inbound['tag'])
        if raw is None:
            raise SetupError(f"Не найден inbound {inbound['tag']} в вычисленной конфигурации.")
        ports.update(validate_inbound(raw, cfg))
    cfg['vpn_ports'] = sorted(ports)
    return profile


def validate_inbound(raw, cfg):
    port = raw.get('port')
    if isinstance(port, str) and '-' in port:
        try:
            lo, hi = map(validate_port, port.split('-'))
        except (ValueError, SetupError):
            raise SetupError('Некорректный диапазон клиентских портов.') from None
        if lo > hi or hi - lo > 1000:
            raise SetupError('Слишком большой диапазон портов; выберите профиль с явными портами.')
        ports = set(range(lo, hi + 1))
    else:
        ports = {validate_port(port)}
    reserved = {22, 80, 443, cfg['node_port']}
    if ports & reserved:
        raise SetupError(f"Inbound {raw.get('tag')} занимает {sorted(ports & reserved)}. "
                         '443 занят Caddy, 3001/выбранный node_port — API ноды; выберите другой inbound/профиль.')
    stream = raw.get('streamSettings', {})
    if stream.get('security') == 'reality':
        reality = stream.get('realitySettings', {})
        target = reality.get('target', reality.get('dest'))
        if target not in ('127.0.0.1:443', 'localhost:443', '[::1]:443', cfg['domain'] + ':443'):
            raise SetupError(f"REALITY {raw.get('tag')}: для этого Selfsteal нужен target 127.0.0.1:443. "
                             'Общий профиль автоматически не изменяется.')
        if cfg['domain'] not in reality.get('serverNames', []):
            raise SetupError('Домен Caddy отсутствует в serverNames выбранного REALITY-профиля.')
        if reality.get('xver', 0) != 0:
            raise SetupError('Для обычного Caddy нужен REALITY xver: 0 (без PROXY protocol).')
    return ports


def caddyfile(domain):
    return f'{validate_domain(domain)}:443 {{\n    root * /var/www/site\n    try_files {{path}} /index.html\n    file_server\n}}\n'


def resolve(host):
    try:
        return {str(ipaddress.ip_address(x[4][0])) for x in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)}
    except socket.gaierror:
        raise SetupError(f'Не удалось разрешить DNS: {host}') from None


def local_ips():
    raw = json.loads(run(['ip', '-j', 'addr']).stdout)
    return {a['local'] for nic in raw for a in nic.get('addr_info', [])}


def check_dns(cfg):
    ips = resolve(cfg['domain'])
    local = local_ips()
    expected = resolve(cfg['node_address'])
    if not (ips & expected & local):
        raise SetupError('DNS домена не указывает на IP этой машины. Проверьте A/AAAA и отключите CDN-проксирование.')
    if not ips.issubset(local):
        raise SetupError('У домена есть A/AAAA на другой сервер. Исправьте DNS перед выпуском сертификата.')


def occupied(port, protocol):
    flags = '-Hlnutp' if protocol == 'udp' else '-Hlntp'
    output = run(['ss', flags, f'sport = :{port}']).stdout.strip()
    return output


def preflight(cfg, state):
    if os.geteuid() != 0:
        raise SetupError('Установка требует root.')
    os_info = Path('/etc/os-release').read_text()
    if not re.search(r'^ID=(?:"?)(ubuntu|debian)', os_info, re.M) or not shutil.which('systemctl'):
        raise SetupError('Поддерживаются Debian/Ubuntu с systemd.')
    if shutil.disk_usage('/').free < 2 * 1024**3:
        raise SetupError('Нужно не менее 2 ГБ свободного места.')
    for path in (STACK, SITE):
        if path.exists() and any(path.iterdir()) and not (path / MARKER).exists():
            raise SetupError(f'{path} уже занят чужой установкой. Автоматическая перезапись запрещена.')
    if CADDY.exists() and not state:
        raise SetupError('Caddy уже настроен. Для первой установки используйте чистый сервер.')
    if SERVICE.exists() and not state:
        raise SetupError('Обнаружено существующее правило firewall без состояния установщика.')
    if shutil.which('nft') and not state and run(['nft', 'list', 'table', 'inet', 'remna_auto'], check=False).returncode == 0:
        raise SetupError('Таблица firewall remna_auto уже существует без состояния установщика.')
    own_pids = set()
    if shutil.which('docker'):
        existing = run(['docker', 'inspect', 'remnanode'], check=False)
        if existing.returncode == 0:
            container = json.loads(existing.stdout)[0]
            owner = (container.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project')
            if not state or owner != 'remna-auto':
                raise SetupError('Контейнер remnanode уже существует и не принадлежит этой установке.')
            top = run(['docker', 'top', 'remnanode', '-eo', 'pid'], check=False)
            own_pids.update(re.findall(r'^\s*(\d+)\s*$', top.stdout, re.M))
    if state:
        caddy_pid = run(['systemctl', 'show', 'caddy', '--property=MainPID', '--value'], check=False).stdout.strip()
        if caddy_pid and caddy_pid != '0':
            own_pids.add(caddy_pid)
    ports = {80, 443, cfg['node_port'], *cfg['vpn_ports']}
    for port in sorted(ports):
        for proto in ('tcp', 'udp'):
            found = occupied(port, proto)
            pids = set(re.findall(r'pid=(\d+)', found))
            own = bool(pids and pids.issubset(own_pids))
            if found and not own:
                raise SetupError(f'Порт {port}/{proto} занят. Существующие службы не останавливаются.')
    check_dns(cfg)


def node_body(cfg, install_id):
    return {'name': cfg['node_name'], 'address': cfg['node_address'], 'port': cfg['node_port'],
            'countryCode': cfg['country_code'], 'note': 'remna-auto:' + install_id,
            'configProfile': {'activeConfigProfileUuid': cfg['profile_uuid'],
                              'activeInbounds': cfg['inbound_uuids']}}


def list_nodes(api):
    result = api.request('GET', '/api/nodes')
    if not isinstance(result, list):
        raise SetupError('Неожиданный формат /api/nodes: ожидался массив.')
    return result


def nft_config(cfg):
    lines = ['table inet remna_auto {', ' chain node_api {',
             '  type filter hook input priority -5; policy accept;', '  iifname "lo" accept']
    for ip in cfg['panel_ips']:
        family = 'ip6' if ':' in ip else 'ip'
        lines.append(f"  {family} saddr {ip} tcp dport {cfg['node_port']} accept")
    lines += [f"  tcp dport {cfg['node_port']} drop", ' }', '}', '']
    return '\n'.join(lines)


def install_dependencies():
    global APT_SOURCE_FILE
    log('Установка Docker Engine, Compose, Caddy и nftables…')
    os_release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            os_release[k] = v.strip('"')
    arch = run(['dpkg', '--print-architecture']).stdout.strip()
    distro, codename = os_release['ID'], os_release['VERSION_CODENAME']
    if distro not in ('debian', 'ubuntu') or not re.fullmatch('[a-z]+', codename):
        raise SetupError('Не поддерживается дистрибутив или его кодовое имя.')
    # Isolate this operation from unrelated provider repositories without editing them.
    if distro == 'ubuntu':
        mirror = 'https://archive.ubuntu.com/ubuntu' if arch in ('amd64', 'i386') else 'https://ports.ubuntu.com/ubuntu-ports'
        security = 'https://security.ubuntu.com/ubuntu' if arch in ('amd64', 'i386') else mirror
        keyring = '/usr/share/keyrings/ubuntu-archive-keyring.gpg'
        sources = [f'deb [signed-by={keyring}] {mirror} {suite} main universe' for suite in (codename, codename + '-updates')]
        sources.append(f'deb [signed-by={keyring}] {security} {codename}-security main universe')
    else:
        keyring = '/usr/share/keyrings/debian-archive-keyring.gpg'
        sources = [f'deb [signed-by={keyring}] https://deb.debian.org/debian {suite} main' for suite in (codename, codename + '-updates')]
        sources.append(f'deb [signed-by={keyring}] https://security.debian.org/debian-security {codename}-security main')
    APT_SOURCE_FILE = ROOT / 'install.sources.list'
    for source, key in (
        ('/etc/apt/sources.list.d/remna-auto-docker.list', '/etc/apt/keyrings/docker.asc'),
        ('/etc/apt/sources.list.d/caddy-stable.list', '/usr/share/keyrings/caddy-stable-archive-keyring.gpg'),
    ):
        if Path(source).exists() and Path(key).exists():
            os.chmod(key, 0o644)
    def refresh_sources():
        extra = []
        for filename in ('remna-auto-docker.list', 'caddy-stable.list'):
            path = Path('/etc/apt/sources.list.d') / filename
            if path.exists():
                extra.extend(path.read_text().splitlines())
        atomic(APT_SOURCE_FILE, '\n'.join(sources + extra) + '\n', 0o644)
    refresh_sources()
    log('Для установки используются отдельные официальные HTTPS-источники APT; репозитории провайдера не изменяются.')
    run(['apt-get', 'update'])
    run(['apt-get', 'install', '-y', 'ca-certificates', 'curl', 'gnupg', 'nftables', 'iproute2', 'logrotate'])
    if not shutil.which('docker'):
        key = run(['curl', '-fsSL', '--retry', '3', f'https://download.docker.com/linux/{distro}/gpg']).stdout
        Path('/etc/apt/keyrings').mkdir(parents=True, exist_ok=True)
        os.chmod('/etc/apt/keyrings', 0o755)
        atomic(Path('/etc/apt/keyrings/docker.asc'), key, 0o644)
        atomic(Path('/etc/apt/sources.list.d/remna-auto-docker.list'),
               f'deb [arch={arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/{distro} {codename} stable\n', 0o644)
        refresh_sources()
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y', 'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin'])
    if not shutil.which('caddy'):
        key = run(['curl', '-fsSL', '--retry', '3', 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key']).stdout
        armored = ROOT / 'caddy-key.asc'
        atomic(armored, key)
        run(['gpg', '--batch', '--yes', '--dearmor', '--output', '/usr/share/keyrings/caddy-stable-archive-keyring.gpg', armored])
        armored.unlink()
        os.chmod('/usr/share/keyrings/caddy-stable-archive-keyring.gpg', 0o644)
        caddy_sources = run(['curl', '-fsSL', '--retry', '3', 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt']).stdout
        atomic(Path('/etc/apt/sources.list.d/caddy-stable.list'), caddy_sources, 0o644)
        refresh_sources()
        run(['apt-get', 'update'])
        run(['apt-get', 'install', '-y', 'caddy'])
    run(['systemctl', 'enable', '--now', 'docker'])
    run(['docker', 'info'], timeout=30)
    run(['docker', 'compose', 'version'])


class Transaction:
    """Only installer-owned files, plus the Caddy config on a fresh host."""
    def __init__(self, state, cfg, install_id):
        self.path = BACKUPS / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S') + '-' + uuid.uuid4().hex[:6])
        self.path.mkdir(parents=True, mode=0o700)
        self.data = {'version': VERSION, 'config': cfg, 'install_id': install_id, 'files': {},
                     'previous_state': state, 'new_node_uuid': None, 'previous_node': None,
                     'caddy_was_active': run(['systemctl', 'is-active', 'caddy'], check=False).returncode == 0,
                     'caddy_was_enabled': run(['systemctl', 'is-enabled', 'caddy'], check=False).returncode == 0,
                     'firewall_was_active': run(['systemctl', 'is-active', 'remna-auto-firewall'], check=False).returncode == 0}
        self.save()

    def save(self):
        atomic(self.path / 'rollback.json', json.dumps(self.data, ensure_ascii=False, indent=2))

    def remember(self, path):
        key = str(path)
        if key in self.data['files']:
            return
        self.data['files'][key] = ({'bytes': base64.b64encode(path.read_bytes()).decode(),
                                   'mode': path.stat().st_mode & 0o777} if path.exists() else None)
        self.save()

    def write(self, path, content, mode=0o600):
        self.remember(path)
        atomic(path, content, mode)


def compose(*args, check=True):
    return run(['docker', 'compose', '--project-name', 'remna-auto', '-f', STACK / 'compose.json', *args], check=check)


def compose_payload(digest):
    return {'services': {'remnanode': {'image': digest, 'container_name': 'remnanode',
            'hostname': 'remnanode', 'network_mode': 'host', 'restart': 'unless-stopped',
            'cap_add': ['NET_ADMIN'], 'env_file': [str(STACK / '.env')],
            'volumes': [str(STACK / 'logs') + ':/var/log/remnanode'],
            'ulimits': {'nofile': {'soft': 1048576, 'hard': 1048576}},
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}}}


def prepare_local(cfg, secret, tx):
    if not SITE.parent.exists():
        SITE.parent.mkdir(parents=True, mode=0o755)
        os.chmod(SITE.parent, 0o755)
    for folder in (STACK, SITE, ROOT):
        folder.mkdir(parents=True, exist_ok=True)
        os.chmod(folder, 0o755 if folder == SITE else 0o700)
    # Existing certificates stay under Caddy's own /var/lib/caddy storage.
    staged = ROOT / 'Caddyfile.staged'
    atomic(staged, caddyfile(cfg['domain']), 0o644)
    run(['caddy', 'validate', '--config', staged, '--adapter', 'caddyfile'])
    tx.write(SITE / 'index.html', (HERE / 'site/index.html').read_bytes(), 0o644)
    tx.write(SITE / MARKER, 'Managed by remna-auto\n', 0o644)
    tx.write(STACK / MARKER, 'Managed by remna-auto\n')
    tx.write(CADDY, staged.read_bytes(), 0o644)
    staged.unlink()
    run(['systemctl', 'enable', 'caddy'])
    run(['systemctl', 'reload-or-restart', 'caddy'])

    # Dedicated nft table affects only this node's management port, never SSH or global rules.
    tx.write(NFT, nft_config(cfg))
    run(['nft', '--check', '-f', NFT])
    unit = ('[Unit]\nDescription=Remna Auto node API access control\nAfter=network-pre.target\n'
            'Before=docker.service\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\n'
            'ExecStartPre=-/usr/sbin/nft delete table inet remna_auto\n'
            f'ExecStart=/usr/sbin/nft -f {NFT}\n'
            'ExecStop=-/usr/sbin/nft delete table inet remna_auto\n\n[Install]\nWantedBy=multi-user.target\n')
    tx.write(SERVICE, unit, 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'remna-auto-firewall'])
    run(['systemctl', 'restart', 'remna-auto-firewall'])
    pinned = cfg.get('resolved_node_image', '')
    image_ref = (pinned if cfg.get('resolved_for_image') == cfg['node_image']
                 and re.fullmatch(r'(?:ghcr.io/)?remnawave/node@sha256:[a-f0-9]{64}', pinned)
                 else cfg['node_image'])
    run(['docker', 'pull', image_ref], timeout=1200)
    image = json.loads(run(['docker', 'image', 'inspect', image_ref]).stdout)[0]
    digest = next((s for s in image.get('RepoDigests', []) if 'remnawave/node@sha256:' in s), None)
    if not digest:
        raise SetupError('Docker не вернул digest официального образа ноды.')
    cfg['resolved_node_image'] = digest
    cfg['resolved_for_image'] = cfg['node_image']
    (STACK / 'logs').mkdir(exist_ok=True, mode=0o755)
    payload = compose_payload(digest)
    if not re.fullmatch(r'[A-Za-z0-9_+/=.:-]+', secret):
        raise SetupError('Неожиданный формат SECRET_KEY; небезопасно записывать в env-файл.')
    tx.write(STACK / '.env', f"NODE_PORT={cfg['node_port']}\nSECRET_KEY={secret}\n")
    tx.write(STACK / 'compose.json', json.dumps(payload, indent=2))
    tx.write(Path('/etc/logrotate.d/remna-auto'),
             str(STACK / 'logs') + '/*.log {\n daily\n maxsize 50M\n rotate 5\n compress\n missingok\n notifempty\n copytruncate\n}\n', 0o644)
    compose('config', '--quiet')
    compose('up', '-d', '--remove-orphans')
    for _ in range(45):
        try:
            with socket.create_connection(('127.0.0.1', cfg['node_port']), timeout=2):
                break
        except OSError:
            time.sleep(2)
    else:
        raise SetupError('Нода не открыла порт управления; проверьте docker logs remnanode.')


def verify_tls(domain, attempts=60):
    context = ssl.create_default_context()
    for _ in range(attempts):
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=5) as tcp:
                with context.wrap_socket(tcp, server_hostname=domain) as tls:
                    tls.sendall(f'GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode())
                    body = b''
                    while len(body) < 512 * 1024:
                        chunk = tls.recv(16384)
                        if not chunk:
                            break
                        body += chunk
                    if b'200 OK' in body[:100] and b'remna-auto-site' in body:
                        return
        except (OSError, ssl.SSLError):
            pass
        time.sleep(2)
    raise SetupError('Не получен валидный сертификат/ответ сайта. Проверьте DNS, входящие 80/443 и journalctl -u caddy.')


def restore_node_body(old):
    cp = old['configProfile']
    return {'uuid': old['uuid'], 'name': old['name'], 'address': old['address'],
            'port': old['port'], 'countryCode': old['countryCode'], 'note': old.get('note'),
            'configProfile': {'activeConfigProfileUuid': cp['activeConfigProfileUuid'],
                              'activeInbounds': [b['uuid'] if isinstance(b, dict) else b for b in cp['activeInbounds']]}}


def register_node(api, cfg, state, tx):
    body = node_body(cfg, tx.data['install_id'])
    if state:
        old = api.request('GET', '/api/nodes/' + state['node_uuid'])
        if old.get('note') != body['note']:
            raise SetupError('Запись ноды не принадлежит этому установщику; обновление запрещено.')
        tx.data['previous_node'] = restore_node_body(old)
        tx.save()
        api.request('PATCH', '/api/nodes', {'uuid': state['node_uuid'], **body})
        return state['node_uuid']
    # Persist the operation ID before POST, so even a lost response can be reconciled safely.
    tx.data['registration_attempted'] = True
    tx.save()
    try:
        node = api.request('POST', '/api/nodes', body)
    except SetupError:
        found = [n for n in list_nodes(api) if n.get('note') == body['note']]
        if len(found) != 1:
            raise
        node = found[0]
    if not node or not node.get('uuid'):
        raise SetupError('Создание ноды не вернуло UUID.')
    tx.data['new_node_uuid'] = node['uuid']
    tx.save()
    return node['uuid']


def wait_connected(api, node_uuid):
    for _ in range(60):
        node = api.request('GET', '/api/nodes/' + node_uuid)
        if node.get('isConnected') and not node.get('isDisabled'):
            return node
        time.sleep(2)
    raise SetupError('Панель не подключилась к ноде. Проверьте её исходящий IP и доступ к node_port.')


def rollback(data, api):
    errors = []
    try:
        if data.get('registration_attempted') and not data.get('new_node_uuid') and not data.get('previous_state'):
            found = [n for n in list_nodes(api) if n.get('note') == 'remna-auto:' + data['install_id']]
            if len(found) > 1:
                raise SetupError('Найдено несколько нод с operation ID. Требуется ручная проверка.')
            if found:
                data['new_node_uuid'] = found[0]['uuid']
        if data.get('new_node_uuid'):
            try:
                node = api.request('GET', '/api/nodes/' + data['new_node_uuid'])
            except SetupError as exc:
                if 'HTTP 404' not in str(exc):
                    raise
                node = None
            if node is not None:
                if node.get('note') != 'remna-auto:' + data['install_id']:
                    raise SetupError('Принадлежность ноды изменилась: автоматическое удаление отменено.')
                api.request('DELETE', '/api/nodes/' + data['new_node_uuid'])
        elif data.get('previous_node'):
            api.request('PATCH', '/api/nodes', data['previous_node'])
    except SetupError as exc:
        errors.append(safe(exc))
    if (STACK / 'compose.json').exists():
        compose('down', check=False)
    run(['systemctl', 'stop', 'remna-auto-firewall'], check=False)
    if not data['previous_state']:
        run(['systemctl', 'disable', 'remna-auto-firewall'], check=False)
    for filename, old in data['files'].items():
        path = Path(filename)
        if old is None:
            path.unlink(missing_ok=True)
        else:
            atomic(path, base64.b64decode(old['bytes']), old['mode'])
    run(['systemctl', 'daemon-reload'], check=False)
    if data['firewall_was_active']:
        run(['systemctl', 'restart', 'remna-auto-firewall'], check=False)
    if data['previous_state']:
        compose('up', '-d')
    if data['caddy_was_active'] and CADDY.exists():
        run(['systemctl', 'reload-or-restart', 'caddy'], check=False)
    else:
        run(['systemctl', 'stop', 'caddy'], check=False)
    if not data.get('caddy_was_enabled'):
        run(['systemctl', 'disable', 'caddy'], check=False)
    if errors:
        raise SetupError('Локальные файлы восстановлены, но откат API требует проверки: ' + '; '.join(errors))


def configure(args):
    state = read_json(ROOT / 'state.json', {})
    cfg = dict(state.get('config', {}))
    if args.config:
        cfg.update(read_json(Path(args.config), {}))
    interactive = not args.non_interactive
    if interactive:
        log('\nRemna Auto · RemnaNode + Caddy Selfsteal\nCaddy: 443 · API ноды: 3001 · клиентский порт VPN: из профиля\n')
        cfg['panel_url'] = ask('HTTPS-адрес панели', cfg.get('panel_url', ''))
        cfg['domain'] = ask('Домен Caddy / SNI', cfg.get('domain', ''))
        cfg['node_address'] = ask('IP/домен этой ноды для связи с панелью', cfg.get('node_address', cfg['domain']))
        cfg['node_name'] = ask('Название ноды в панели', cfg.get('node_name', 'Node-01'))
        cfg['node_port'] = ask('Порт управления RemnaNode', str(cfg.get('node_port', 3001)))
        cfg['country_code'] = ask('Код страны', cfg.get('country_code', 'XX'))
        cfg['panel_ips'] = ask('Исходящие IP СЕРВЕРА панели через запятую (не IP CDN)', ','.join(cfg.get('panel_ips', [])))
    cfg = validate_config(cfg)
    if args.refresh_image:
        cfg.pop('resolved_node_image', None)
        cfg.pop('resolved_for_image', None)
    token = load_token(args, interactive)
    proxy_key = os.environ.get('REMNA_PROXY_KEY', '')
    if interactive and ask('Панель требует отдельный X-Api-Key для reverse proxy? y/n', 'n').lower() == 'y':
        proxy_key = ask('Ключ reverse proxy (скрытый ввод)', secret=True)
    api = API(cfg['panel_url'], token, proxy_key)
    choose_profile(api, cfg, interactive)
    return cfg, api, state


def load_token(args, interactive):
    token = os.environ.get('REMNA_API_KEY', '')
    if args.api_key_file:
        path = Path(args.api_key_file)
        if os.name != 'nt' and path.stat().st_mode & 0o077:
            raise SetupError('Файл API-ключа должен иметь права 600.')
        token = path.read_text().strip()
    if not token and interactive:
        token = ask('API-ключ Remnawave (скрытый ввод)', secret=True)
    if not token:
        raise SetupError('Нужен REMNA_API_KEY или --api-key-file; ключ не передаётся аргументом командной строки.')
    return token


def install(cfg, api, state):
    preflight(cfg, state)
    install_id = state.get('install_id') or str(uuid.uuid4())
    nodes = list_nodes(api)
    for node in nodes:
        if node['uuid'] == state.get('node_uuid'):
            continue
        if node.get('name') == cfg['node_name'] or (node.get('address') == cfg['node_address'] and node.get('port') == cfg['node_port']):
            raise SetupError('В панели уже есть нода с таким именем или адресом/портом; чужая запись не перезаписывается.')
    keys = api.request('GET', '/api/keygen') or {}
    secret = keys.get('secretKey') or keys.get('pubKey')
    if not secret:
        raise SetupError('Панель не вернула SECRET_KEY.')
    SECRETS.append(secret)
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    tx = Transaction(state, cfg, install_id)
    log('Резервная копия и журнал отката: ' + str(tx.path))
    try:
        # Remember package-created defaults as absent on a fresh machine.
        tx.remember(CADDY)
        install_dependencies()
        prepare_local(cfg, secret, tx)
        log('Проверка доверенного TLS-сертификата и сайта с правильным SNI…')
        verify_tls(cfg['domain'])
        node_uuid = register_node(api, cfg, state, tx)
        log('Запись ноды создана/обновлена. Проверка соединения с панелью…')
        node = wait_connected(api, node_uuid)
        new_state = {'version': VERSION, 'install_id': install_id, 'node_uuid': node_uuid,
                     'config': cfg, 'backup': str(tx.path), 'installed_at': dt.datetime.now(dt.timezone.utc).isoformat()}
        tx.write(ROOT / 'state.json', json.dumps(new_state, ensure_ascii=False, indent=2))
        tx.data['completed'] = True
        tx.save()
        log(f"\nГотово. Сайт: https://{cfg['domain']} · Нода: {cfg['node_name']} · Connected: {node['isConnected']}")
        log('Профиль: ' + cfg['profile_name'] + ' · VPN-порты: ' + ', '.join(map(str, cfg['vpn_ports'])))
        log('API-ключ панели не сохранён. SECRET_KEY находится в /opt/remnanode/.env с правами 600.')
    except BaseException:
        log('Установка не завершена. Восстанавливаю предыдущие настройки…')
        try:
            rollback(tx.data, api)
        except BaseException as exc:
            log('Требуется проверка отката: ' + safe(exc))
        raise


def status():
    state = read_json(ROOT / 'state.json', {})
    if not state:
        log('Управляемая установка не найдена.')
        return
    cfg = state['config']
    log(f"Нода: {cfg['node_name']} · {state['node_uuid']}\nСайт: https://{cfg['domain']}\nПрофиль: {cfg['profile_name']}")
    for service in ('caddy', 'remna-auto-firewall'):
        log(service + ': ' + run(['systemctl', 'is-active', service], check=False).stdout.strip())
    log(compose('ps').stdout)
    token = os.environ.get('REMNA_API_KEY')
    if token:
        api = API(cfg['panel_url'], token, os.environ.get('REMNA_PROXY_KEY', ''))
        node = api.request('GET', '/api/nodes/' + state['node_uuid'])
        log('Panel isConnected: ' + str(node.get('isConnected')))


def main():
    parser = argparse.ArgumentParser(description='Автоматическая установка RemnaNode и Caddy Selfsteal')
    parser.add_argument('command', nargs='?', choices=['install', 'plan', 'status', 'rollback'], default='install')
    parser.add_argument('--config', help='JSON с несекретными параметрами')
    parser.add_argument('--api-key-file', help='Файл с API-ключом, права 600')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--backup', help='Каталог резервной копии для rollback')
    parser.add_argument('--refresh-image', action='store_true', help='Явно обновить образ вместо сохранённого digest')
    args = parser.parse_args()
    if args.command == 'status':
        status()
        return
    if args.command == 'plan':
        cfg, api, state = configure(args)
        log(json.dumps(cfg, ensure_ascii=False, indent=2))
        log('План готов. Изменений сервера и записей панели не выполнено.')
        return
    if os.name != 'posix' or os.geteuid() != 0:
        raise SetupError('Установка/откат запускаются от root на Debian/Ubuntu.')
    import fcntl
    with open('/run/lock/remna-auto.lock', 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SetupError('Другой процесс remna-auto уже работает.') from None
        if args.command == 'rollback':
            if not args.backup:
                raise SetupError('Укажите --backup /var/backups/remna-auto/…')
            path = Path(args.backup).resolve()
            if BACKUPS.resolve() not in path.parents:
                raise SetupError('Для отката разрешены только резервные копии /var/backups/remna-auto.')
            data = read_json(path / 'rollback.json')
            if not isinstance(data, dict):
                raise SetupError('Не найден журнал отката rollback.json.')
            token = load_token(args, not args.non_interactive)
            rollback(data, API(data['config']['panel_url'], token, os.environ.get('REMNA_PROXY_KEY', '')))
            log('Откат завершён. Установленные системные пакеты оставлены на сервере.')
        else:
            cfg, api, state = configure(args)
            install(cfg, api, state)


if __name__ == '__main__':
    try:
        main()
    except (SetupError, OSError, subprocess.TimeoutExpired, ValueError) as exc:
        log('ОШИБКА: ' + safe(exc))
        sys.exit(1)
    except KeyboardInterrupt:
        log('Остановлено пользователем.')
        sys.exit(130)
