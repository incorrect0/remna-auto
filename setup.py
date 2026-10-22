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
import unicodedata
import signal

VERSION = '1.3.0'
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


class PortConflictError(SetupError):
    pass


def safe(value):
    value = str(value)
    for secret in sorted(set(SECRETS), key=len, reverse=True):
        if secret:
            value = value.replace(secret, '[REDACTED]')
    # Remove terminal-control payloads from profile names, command output and errors.
    value = re.sub(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)', '', value)
    value = re.sub(r'\x1b\[(?![0-9;]*m)[0-?]*[ -/]*[@-~]', '', value)
    value = re.sub(r'\x1b(?!\[[0-9;]*m)', '', value)
    return ''.join(c for c in value if c in '\n\t\x1b' or unicodedata.category(c)[0] != 'C')


def terminal_width():
    return max(4, min(shutil.get_terminal_size((80, 24)).columns, 100))


def visible_width(text):
    text = re.sub(r'\x1b\[[0-9;]*m', '', text)
    return sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1 for c in text)


def wrapped(text, width):
    lines = []
    for line in str(text).expandtabs(4).split('\n'):
        current = ''; size = 0
        for token in re.findall(r'\x1b\[[0-9;]*m|[^\x1b]', line):
            amount = 0 if token.startswith('\x1b') else visible_width(token)
            if size + amount > width:
                split = current.rfind(' ')
                if split > 2:
                    lines.append(current[:split])
                    current = '  ' + current[split + 1:]
                else:
                    lines.append(current)
                    current = '  '
                size = visible_width(current)
            current += token; size += amount
        lines.append(current)
    return '\n'.join(lines)


def color(text, code):
    enabled = sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and 'NO_COLOR' not in os.environ
    return f'\033[{code}m{text}\033[0m' if enabled else str(text)


def section(title, detail=''):
    width = min(terminal_width(), 76)
    log('\n' + color('─' * max(1, width - 2), '38;5;60'))
    log(color('  ' + title, '1;38;5;87'))
    if detail:
        log('  ' + detail)


def banner():
    width = shutil.get_terminal_size((80, 24)).columns
    if width >= 64 and sys.stdout.isatty() and os.environ.get('TERM') != 'dumb':
        # Separate word/heart columns: no slicing through glyphs or half-block fonts.
        word = [
            r"   _ __ ___ _ __ ___  _ __   __ _ ",
            r"  | '__/ _ \ '_ ` _ \| '_ \ / _` |",
            r"  | | |  __/ | | | | | | | | (_| |",
            r"  |_|  \___|_| |_| |_|_| |_|\__,_|",
        ]
        heart = [' ▄██▄██▄ ', ' ███████ ', '  ▀███▀  ', '    ▀    ']
        log('')
        for text, icon in zip(word, heart):
            log(color(text.ljust(36), '1;38;5;87') + color(icon, '1;38;5;211'))
    else:
        log('\n' + color('  remna ', '1;38;5;87') + color('<3', '1;38;5;211'))
    log(color(f'  REMNA AUTO  /  v{VERSION}', '1;37'))
    log(color('  RemnaNode + Caddy', '38;5;245'))
    log(color('  HTTPS:443 | API:3001', '38;5;245'))


def completion(cfg, connected):
    section('[OK] Нода установлена', 'RemnaNode + Caddy установлены')
    if cfg.get('tls_ready') is False:
        log('  HTTPS: ожидает сертификата. Selfsteal через этот Caddy заработает после выпуска.')
    for label, value in [('Нода', cfg['node_name']), ('Сайт', 'https://' + cfg['domain']),
                         ('Профиль', cfg['profile_name']),
                         ('VPN-порты', ', '.join(map(str, cfg['vpn_ports']))),
                         ('Панель подключена', 'да' if connected else 'нет')]:
        log('  ' + color(label + ': ', '38;5;245') + str(value))
    log('\n  ' + color('Спасибо, что используете remna <3', '1;38;5;211'))


def log(message):
    message = safe(message)
    if not (sys.stdout.isatty() and os.environ.get('TERM') != 'dumb' and 'NO_COLOR' not in os.environ):
        message = re.sub(r'\x1b\[[0-9;]*m', '', message)
    if message.startswith('ОШИБКА:'):
        message = color(message, '1;31')
    elif message.startswith('Внимание:'):
        message = color(message, '33')
    message = '\n'.join('  ' + line if line and not re.sub(r'\x1b\[[0-9;]*m', '', line).startswith('  ') else line for line in message.split('\n'))
    print(wrapped(message, terminal_width()), flush=True)


def run(args, *, check=True, timeout=600, input=None):
    if args and str(args[0]) == 'apt-get':
        log('APT: ' + ' '.join(str(a) for a in args[1:]))
        args = [args[0], '-o', 'Acquire::Retries=2', '-o', 'Acquire::http::Timeout=20',
                '-o', 'Acquire::https::Timeout=20', '-o', 'DPkg::Lock::Timeout=120', *args[1:]]
        if APT_SOURCE_FILE:
            args[1:1] = ['-o', 'Dir::Etc::sourcelist=' + str(APT_SOURCE_FILE), '-o', 'Dir::Etc::sourceparts=-']
    command = [str(x) for x in args]
    started = time.monotonic()
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                               text=True, encoding='utf-8', errors='replace', stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=os.name == 'posix',
                               env={**os.environ, 'DEBIAN_FRONTEND': 'noninteractive'})
    first = True
    try:
        while True:
            remaining = timeout - (time.monotonic() - started)
            if remaining <= 0:
                raise subprocess.TimeoutExpired(command[0], timeout)
            try:
                output, _ = process.communicate(input=input if first else None, timeout=min(10, remaining))
                break
            except subprocess.TimeoutExpired:
                first = False
                if time.monotonic() - started >= timeout:
                    raise subprocess.TimeoutExpired(command[0], timeout) from None
                log(f'  Выполняется {Path(command[0]).name}: {int(time.monotonic() - started)} с…')
    except BaseException:
        if os.name == 'posix':
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            process.kill()
        process.communicate()
        raise
    result = subprocess.CompletedProcess(command, process.returncode, output)

    if check and result.returncode:
        # Never render argv: environment files and API headers must stay private.
        raise SetupError(f'Не удалось выполнить {Path(str(args[0])).name} (код {result.returncode}).\n'
                         f'{safe(result.stdout[-2000:])}\nПроверьте доступность сети, свободное место и состояние службы; повторный запуск не удаляет чужие файлы.')
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
    try:
        return json.loads(path.read_text(encoding='utf-8')) if path.exists() else default
    except (ValueError, OSError):
        raise SetupError('Не удалось прочитать JSON: ' + str(path) + '. Проверьте формат и права; файл не изменён.') from None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SetupError('API вернул redirect. Укажите прямой HTTPS-адрес панели.')


class API:
    def __init__(self, url, token, proxy_key=''):
        self.url = validate_panel_url(url)
        if not token or any(c in token + proxy_key for c in '\r\n'):
            raise SetupError('Пустой или некорректный API-ключ.')
        self.token, self.proxy_key = token, proxy_key or token
        SECRETS.extend([token, proxy_key, self.url])
        self.opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))

    def request(self, method, path, body=None):
        # A socket timeout does not bound DNS or a slow streaming response. Isolate
        # the request so a timed-out mutating request cannot continue in a thread.
        code = ("import runpy,json,sys\n"
                "m=runpy.run_path(sys.argv[1]); q=json.load(sys.stdin)\n"
                "try:\n"
                " a=m['API'](q['url'],q['token'],q['proxy']); "
                "r=a._request_direct(q['method'],q['path'],q['body']); "
                "print(json.dumps({'result':r}))\n"
                "except Exception as e:\n print(json.dumps({'error':m['safe'](str(e))})); sys.exit(1)\n")
        payload = json.dumps({'url': self.url, 'token': self.token, 'proxy': self.proxy_key,
                              'method': method, 'path': path, 'body': body})
        process = subprocess.Popen([sys.executable, '-c', code, str(HERE / 'setup.py')],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, encoding='utf-8', errors='replace')
        deadline = time.monotonic() + (90 if method == 'GET' else 30)
        first = True
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SetupError('Тайм-аут API панели. Проверьте DNS/сеть панели и повторите запуск.')
                try:
                    output, _ = process.communicate(input=payload if first else None, timeout=min(10, remaining))
                    break
                except subprocess.TimeoutExpired:
                    first = False
                    log('  Ожидание ответа панели…')
        except BaseException:
            process.kill()
            process.communicate()
            raise
        try:
            reply = json.loads(output)
            if not isinstance(reply, dict):
                raise ValueError()
        except (ValueError, TypeError):
            raise SetupError('API-процесс завершился без корректного ответа. Проверьте Python и доступность панели.') from None
        if 'error' in reply:
            raise SetupError(safe(reply['error']))
        if process.returncode or 'result' not in reply:
            raise SetupError('Ошибка процесса API панели; секреты не выводятся.')
        return reply['result']

    def _request_direct(self, method, path, body=None):
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
    if not isinstance(cfg, dict):
        raise SetupError('config.json должен содержать JSON-объект с параметрами.')
    cfg = dict(cfg)
    for key in ('panel_url', 'domain', 'node_address', 'node_name', 'country_code', 'node_image'):
        if key in cfg and not isinstance(cfg[key], str):
            raise SetupError('Поле ' + key + ' должно быть строкой.')
    if any(key in cfg for key in ('api_key', 'token', 'password', 'ssh_password', 'proxy_key')):
        raise SetupError('Не храните секреты в config.json. Используйте скрытый ввод, REMNA_API_KEY или --api-key-file.')
    cfg['panel_url'] = validate_panel_url(cfg.get('panel_url', ''))
    cfg['domain'] = validate_domain(cfg.get('domain', ''))
    address = cfg.get('node_address', '').strip()
    try:
        address = str(ipaddress.ip_address(address))
    except ValueError:
        address = validate_domain(address)
    cfg['node_address'] = address
    cfg['node_port'] = 3001
    name = cfg.get('node_name', '')
    if not isinstance(name, str) or not 3 <= len(name) <= 30 or any(ord(c) < 32 for c in name):
        raise SetupError('Имя ноды: 3–30 символов без управляющих символов.')
    country = cfg.get('country_code', 'XX').upper()
    if not re.fullmatch('[A-Z]{2}', country):
        raise SetupError('Код страны: две латинские буквы, например DE или XX.')
    cfg['country_code'] = country
    cfg.pop('panel_ips', None)
    image = cfg.get('node_image', 'remnawave/node:latest')
    if not re.fullmatch(r'(?:ghcr.io/)?remnawave/node(?::[A-Za-z0-9_.-]+|@sha256:[a-f0-9]{64})', image):
        raise SetupError('Допускается официальный образ remnawave/node или ghcr.io/remnawave/node.')
    cfg['node_image'] = image
    return cfg


def ask(label, default='', secret=False):
    suffix = f' [{default}]' if default and not secret else ''
    question = color('  > ', '38;5;87') + safe(label) + color(safe(suffix), '38;5;245') + ': '
    value = (getpass.getpass if secret else input)(wrapped(question, terminal_width())).strip()
    return value or default


def ask_validated(label, validator, default='', secret=False):
    while True:
        value = ask(label, default, secret)
        try:
            return validator(value)
        except (SetupError, ValueError) as exc:
            log('Внимание: ' + safe(exc))


def confirm(message):
    return ask(message + ' Введите yes для подтверждения', 'no').lower() == 'yes'


def select_profile(profiles, default=None):
    if not profiles:
        raise SetupError('В панели нет профилей. Создайте профиль в панели и повторите выбор.')
    for i, item in enumerate(profiles, 1):
        log(f"  {i}. {item['name']}")
    def number(value):
        try:
            index = int(value) - 1
        except ValueError:
            raise SetupError('Введите номер профиля из списка.') from None
        if not 0 <= index < len(profiles):
            raise SetupError('Такого номера нет в списке.')
        return profiles[index]['uuid']
    suggested = next((str(i) for i, p in enumerate(profiles, 1) if p['uuid'] == default), '')
    if len(profiles) == 1:
        log('  Единственный профиль выбран автоматически.')
        return profiles[0]['uuid']
    return ask_validated('Номер профиля', number, suggested)


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
        log('Доступные профили:')
        cfg['profile_uuid'] = select_profile(profiles)
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
    automatic = interactive or not cfg.get('inbound_uuids')
    selected = [p['uuid'] for p in inbounds] if automatic else cfg['inbound_uuids']
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
    accepted = []
    own_pids = owned_node_pids() if automatic else set()
    for inbound in inbounds:
        if inbound['uuid'] not in selected:
            continue
        raw = raw_by_tag.get(inbound['tag'])
        if raw is None:
            raise SetupError(f"Не найден inbound {inbound['tag']} в вычисленной конфигурации.")
        try:
            candidate = validate_inbound(raw, cfg)
            if candidate & ports:
                raise PortConflictError('порт пересекается с ранее выбранным inbound')
            if automatic and os.name == 'posix' and shutil.which('ss'):
                for port in candidate:
                    for proto in ('tcp', 'udp'):
                        found = occupied(port, proto)
                        pids = set(re.findall(r'pid=(\d+)', found))
                        if found and not (pids and pids.issubset(own_pids)):
                            raise PortConflictError(f'порт {port}/{proto} занят другой службой')
        except PortConflictError as exc:
            if not automatic:
                raise
            log(f"Пропущен {inbound['tag']}: {exc}")
            continue
        accepted.append(inbound['uuid'])
        ports.update(candidate)
    if not accepted:
        raise SetupError('Не осталось inbound’ов без конфликтов портов. Выберите другой профиль.')
    cfg['inbound_uuids'] = accepted
    cfg['inbound_tags'] = [p['tag'] for p in inbounds if p['uuid'] in accepted]
    log('Выбраны inbound’ы: ' + ', '.join(cfg['inbound_tags']))
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
        raise PortConflictError(f"Inbound {raw.get('tag')} занимает {sorted(ports & reserved)}. "
                         '443 занят Caddy, 3001 — API ноды; выберите другой inbound/профиль.')
    stream = raw.get('streamSettings', {})
    if stream.get('security') == 'reality':
        reality = stream.get('realitySettings', {})
        target = reality.get('target', reality.get('dest'))
        local_targets = ('127.0.0.1:443', 'localhost:443', '[::1]:443', cfg['domain'] + ':443')
        if target in local_targets:
            if cfg['domain'] not in reality.get('serverNames', []):
                raise SetupError('Для локального Selfsteal добавьте домен Caddy в serverNames выбранного профиля.')
            if reality.get('xver', 0) != 0:
                raise SetupError('Для обычного Caddy нужен REALITY xver: 0 (без PROXY protocol).')
        elif target:
            log(f"Внимание: REALITY {raw.get('tag')} использует внешний target; "
                'профиль сохранён без изменений, локальный Caddy не используется этим inbound как Selfsteal.')
        else:
            raise SetupError('В REALITY не задан target/dest. Исправьте выбранный профиль.')
    return ports


def caddyfile(domain):
    return f'{validate_domain(domain)}:443 {{\n    root * /var/www/site\n    try_files {{path}} /index.html\n    file_server\n}}\n'


def resolve(host):
    try:
        return {str(ipaddress.ip_address(host))}
    except ValueError:
        pass
    worker = ("import socket,json,sys; print(json.dumps(list({x[4][0] for x in "
              "socket.getaddrinfo(sys.argv[1],None,type=socket.SOCK_STREAM)})))")
    try:
        result = subprocess.run([sys.executable, '-c', worker, host], capture_output=True,
                                text=True, timeout=4, check=True)
        return {str(ipaddress.ip_address(ip)) for ip in json.loads(result.stdout)}
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SetupError(f'Не удалось разрешить DNS: {host}') from None


def local_ips():
    raw = json.loads(run(['ip', '-j', 'addr']).stdout)
    return {a['local'] for nic in raw for a in nic.get('addr_info', [])}


def owned_node_pids():
    if not read_json(ROOT / 'state.json', {}) or not shutil.which('docker'):
        return set()
    result = run(['docker', 'inspect', 'remnanode'], check=False)
    if result.returncode:
        return set()
    container = json.loads(result.stdout)[0]
    labels = container.get('Config', {}).get('Labels') or {}
    if labels.get('com.docker.compose.project') != 'remna-auto':
        return set()
    top = run(['docker', 'top', 'remnanode', '-eo', 'pid'], check=False)
    return set(re.findall(r'^\s*(\d+)\s*$', top.stdout, re.M))


def geo_lookup(ip, provider):
    """Executed in a short-lived process so DNS/slow responses cannot stall setup."""
    ip = str(ipaddress.IPv4Address(ip))
    url = (f'https://ipwho.is/{ip}?fields=ip,success,country_code,country'
           if provider == 'ipwho' else f'https://ipapi.co/{ip}/json/')
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={'Accept': 'application/json'})
    with opener.open(request, timeout=2) as response:
        body = response.read(32769)
    if len(body) > 32768:
        raise ValueError('GeoIP response too large')
    data = json.loads(body)
    code = data.get('country_code', '')
    name = data.get('country', '') if provider == 'ipwho' else data.get('country_name', '')
    if data.get('error') or data.get('ip') != ip or (provider == 'ipwho' and data.get('success') is not True):
        raise ValueError('Invalid GeoIP response')
    if not isinstance(code, str) or not isinstance(name, str):
        raise ValueError('Invalid country types')
    if not re.fullmatch('[A-Z]{2}', code) or not re.fullmatch(r"[A-Za-z][A-Za-z ()'.,-]{1,60}", name):
        raise ValueError('Invalid country')
    return code, name


def country_for_ipv4(address):
    try:
        ip = str(ipaddress.IPv4Address(address))
    except (ValueError, TypeError):
        return 'XX', 'auto-install'
    deadline = time.monotonic() + 6
    worker = ("import runpy,sys,json; m=runpy.run_path(sys.argv[1]); "
              "print(json.dumps(m['geo_lookup'](sys.argv[2],sys.argv[3])))")
    for provider in ('ipwho', 'ipapi'):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            result = subprocess.run([sys.executable, '-c', worker, str(HERE / 'setup.py'), ip, provider],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    text=True, timeout=min(3, remaining), check=True)
            code, name = json.loads(result.stdout)
            if not isinstance(code, str) or not isinstance(name, str):
                raise ValueError()
            if not re.fullmatch('[A-Z]{2}', code) or not re.fullmatch(r"[A-Za-z][A-Za-z ()'.,-]{1,60}", name):
                raise ValueError()
            return code, name
        except (OSError, ValueError, TypeError, subprocess.SubprocessError):
            continue
    log('Внимание: GeoIP недоступен; установка продолжается с XX / auto-install.')
    return 'XX', 'auto-install'


def automatic_name(base, nodes, own_uuid=None):
    base = base[:26].strip()
    used = {node.get('name', '').casefold() for node in nodes if own_uuid is None or node.get('uuid') != own_uuid}
    if base != 'auto-install' and base.casefold() not in used:
        return base
    number = 1
    while f'{base} {number}'.casefold() in used:
        number += 1
    return f'{base} {number}'[:30]


def external_ipv4():
    for url in ('https://api.ipify.org', 'https://ipv4.icanhazip.com'):
        try:
            result = subprocess.run(['curl', '-4', '--noproxy', '*', '-fsS',
                '--connect-timeout', '2', '--max-time', '3', '--max-filesize', '128', url],
                capture_output=True, text=True, timeout=4, check=True)
            ip = ipaddress.IPv4Address(result.stdout.strip())
            if ip.is_global:
                return str(ip)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    return None


def detect_ipv4(domain):
    """Domain DNS is optional; prefer a local public address, then route/echo APIs."""
    try:
        public = sorted(ip for ip in local_ips()
                        if ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global)
    except (SetupError, OSError, ValueError):
        public = []
    if len(public) == 1:
        return public[0]
    try:
        dns = sorted(ip for ip in resolve(validate_domain(domain))
                     if ipaddress.ip_address(ip).version == 4 and ipaddress.ip_address(ip).is_global)
    except SetupError:
        dns = []
    matching = sorted(set(public) & set(dns))
    if len(matching) == 1:
        return matching[0]
    try:
        route = json.loads(run(['ip', '-j', '-4', 'route', 'get', '192.0.2.1'], timeout=4).stdout)
        source = str(ipaddress.IPv4Address(route[0].get('prefsrc', '')))
        if source in public:
            return source
    except (SetupError, OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        pass
    address = external_ipv4()
    if address:
        return address
    if not public and len(dns) == 1:
        return dns[0]
    raise SetupError('Не удалось определить публичный IPv4. Укажите node_address в JSON; DNS домена не обязателен.')


def check_dns(cfg):
    try:
        ips = resolve(cfg['domain'])
        expected = resolve(cfg['node_address'])
        local = local_ips() | expected
        ready = bool(ips & expected) and ips.issubset(local)
    except (SetupError, OSError):
        ready = False
    cfg['dns_ready'] = ready
    if not ready:
        log('Внимание: DNS отсутствует, недоступен или указывает на другой сервер. '
            'Установка ноды продолжается по IPv4; Caddy получит сертификат после исправления DNS.')
    return ready


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


def install_dependencies():
    global APT_SOURCE_FILE
    log('Установка Docker Engine, Compose и Caddy…')
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
    run(['apt-get', 'install', '-y', 'ca-certificates', 'curl', 'gnupg', 'iproute2', 'logrotate', 'procps', 'kmod'])
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
                     'firewall_was_enabled': run(['systemctl', 'is-enabled', 'remna-auto-firewall'], check=False).returncode == 0,
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

    # Older versions installed an allowlist. Remove only our own tracked files/table.
    previous = tx.data.get('previous_state') or {}
    if previous and SERVICE.exists():
        tx.remember(SERVICE)
        tx.remember(NFT)
        run(['systemctl', 'disable', '--now', 'remna-auto-firewall'])
        run(['nft', 'delete', 'table', 'inet', 'remna_auto'], check=False)
        SERVICE.unlink(missing_ok=True)
        NFT.unlink(missing_ok=True)
        run(['systemctl', 'daemon-reload'])
    pinned = cfg.get('resolved_node_image', '')
    image_ref = (pinned if cfg.get('resolved_for_image') == cfg['node_image']
                 and re.fullmatch(r'(?:ghcr.io/)?remnawave/node@sha256:[a-f0-9]{64}', pinned)
                 else cfg['node_image'])
    available = run(['docker', 'image', 'inspect', image_ref], check=False)
    if '@sha256:' not in image_ref or available.returncode:
        run(['docker', 'pull', image_ref], timeout=1200)
    else:
        log('  Сохранённый образ уже загружен; повторное скачивание не требуется.')
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


def verify_tls(domain, attempts=60, timeout=45):
    context = ssl.create_default_context()
    deadline = time.monotonic() + timeout
    last_status = time.monotonic()
    for _ in range(attempts):
        if time.monotonic() >= deadline:
            break
        try:
            with socket.create_connection(('127.0.0.1', 443), timeout=5) as tcp:
                with context.wrap_socket(tcp, server_hostname=domain) as tls:
                    tls.sendall(f'GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n'.encode())
                    body = b''
                    while len(body) < 512 * 1024:
                        if time.monotonic() >= deadline:
                            raise OSError("HTTPS verification deadline")
                        chunk = tls.recv(16384)
                        if not chunk:
                            break
                        body += chunk
                    if b'200 OK' in body[:100] and b'remna-auto-site' in body:
                        return
        except (OSError, ssl.SSLError):
            pass
        if time.monotonic() - last_status >= 10:
            log('  Ожидание HTTPS-сертификата Caddy…')
            last_status = time.monotonic()
        time.sleep(min(2, max(0, deadline - time.monotonic())))
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
    raise SetupError('Панель не подключилась к ноде. Проверьте доступ панели к TCP 3001 и правила своего firewall.')


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
    for key, value in data.get('bbr_previous', {}).items():
        run(['sysctl', '-w', key + '=' + value], check=False)
    if data.get('firewall_was_enabled'):
        run(['systemctl', 'enable', 'remna-auto-firewall'], check=False)
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


def pending_transaction():
    pointer = read_json(ROOT / 'pending.json', {})
    if not pointer:
        return None
    path = Path(pointer.get('backup', '')).resolve()
    if BACKUPS.resolve() not in path.parents:
        raise SetupError('Некорректный путь журнала восстановления. Проверьте pending.json вручную.')
    data = read_json(path / 'rollback.json')
    if not isinstance(data, dict):
        raise SetupError('Журнал незавершённой установки не найден; файлы не изменены.')
    if data.get('completed'):
        return None
    return data


def recover_pending(api, interactive):
    data = pending_transaction()
    if data is None:
        return
    log('Внимание: предыдущая установка прервана. Есть сохранённый журнал отката.')
    if not interactive or not confirm('Восстановить прежние файлы и собственную запись ноды перед новым запуском?'):
        raise SetupError('Восстановление не подтверждено. Установка не продолжена; журнал сохранён в /var/backups/remna-auto.')
    rollback(data, api)
    (ROOT / 'pending.json').unlink(missing_ok=True)
    log('Предыдущее состояние восстановлено. Можно повторить установку.')


def configure(args):
    state = read_json(ROOT / 'state.json', {})
    pending = pending_transaction()
    cfg = dict((pending or state).get('config', {}))
    if args.config:
        cfg.update(read_json(Path(args.config), {}))
    interactive = not args.non_interactive
    if interactive:
        banner()
        section('01 / Настройка подключения', 'Домен можно добавить в DNS позже')
        cfg['panel_url'] = ask_validated('HTTPS-адрес панели (скрыто)', validate_panel_url, cfg.get('panel_url', ''), True)
        SECRETS.append(cfg['panel_url'])
        cfg['domain'] = ask_validated('Домен Caddy / SNI', validate_domain, cfg.get('domain', ''))
        cfg['node_address'] = detect_ipv4(cfg['domain'])
        log('IPv4 ноды определён автоматически: ' + cfg['node_address'])
    if not cfg.get('node_address'):
        cfg['node_address'] = detect_ipv4(cfg['domain'])
    country, base_name = country_for_ipv4(cfg['node_address'])
    cfg['country_code'] = country
    cfg['node_name'] = base_name[:26]
    cfg['auto_name_base'] = base_name
    cfg = validate_config(cfg)
    if args.refresh_image:
        cfg.pop('resolved_node_image', None)
        cfg.pop('resolved_for_image', None)
    if interactive:
        section('02 / Доступ к панели', 'API-ключ вводится скрыто и не сохраняется')
    token = load_token(args, interactive)
    proxy_key = os.environ.get('REMNA_PROXY_KEY', '')
    api = API(cfg['panel_url'], token, proxy_key)
    cfg['node_name'] = automatic_name(base_name, list_nodes(api), state.get('node_uuid'))
    log('Нода: ' + cfg['node_name'] + ' · страна: ' + cfg['country_code'])
    if interactive:
        section('03 / Профиль и inbound’ы', 'Выберите конфигурацию из вашей панели')
    if args.command != 'plan':
        recover_pending(api, interactive)
        state = read_json(ROOT / 'state.json', {})
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


def enable_bbr(tx):
    keys = ('net.core.default_qdisc', 'net.ipv4.tcp_congestion_control')
    old = {}
    try:
        for key in keys:
            old[key] = run(['sysctl', '-n', key]).stdout.strip()
        run(['modprobe', 'tcp_bbr'], check=False)
        run(['modprobe', 'sch_fq'], check=False)
        available = run(['sysctl', '-n', 'net.ipv4.tcp_available_congestion_control']).stdout.split()
        if 'bbr' not in available:
            log('Внимание: ядро не поддерживает BBR; установка продолжится без него.')
            return
        tx.data['bbr_previous'] = old
        tx.save()
        run(['sysctl', '-w', 'net.core.default_qdisc=fq'])
        run(['sysctl', '-w', 'net.ipv4.tcp_congestion_control=bbr'])
        if run(['sysctl', '-n', keys[1]]).stdout.strip() != 'bbr':
            raise SetupError('Проверка BBR не прошла')
        tx.write(Path('/etc/sysctl.d/99-remna-auto-bbr.conf'),
                 '# Managed by remna-auto\nnet.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n', 0o644)
        log('BBR включён автоматически · default_qdisc=fq')
    except (SetupError, OSError, subprocess.TimeoutExpired) as exc:
        for key, value in old.items():
            run(['sysctl', '-w', key + '=' + value], check=False)
        log('Внимание: BBR не включён; прежние параметры восстановлены. ' + safe(exc))


def install(cfg, api, state):
    section('04 / Проверка сервера', 'Порты, DNS и существующие службы')
    preflight(cfg, state)
    install_id = state.get('install_id') or str(uuid.uuid4())
    nodes = list_nodes(api)
    if cfg.get('auto_name_base'):
        cfg['node_name'] = automatic_name(cfg['auto_name_base'], nodes, state.get('node_uuid'))
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
    atomic(ROOT / 'pending.json', json.dumps({'backup': str(tx.path)}))
    log('Резервная копия и журнал отката: ' + str(tx.path))
    try:
        # Remember package-created defaults as absent on a fresh machine.
        tx.remember(CADDY)
        section('05 / Установка', 'Docker · RemnaNode · Caddy · сайт')
        install_dependencies()
        enable_bbr(tx)
        prepare_local(cfg, secret, tx)
        section('06 / Проверка соединения', 'HTTPS-сертификат, сайт и связь с панелью')
        cfg['tls_ready'] = False
        if cfg.get('dns_ready', True):
            try:
                verify_tls(cfg['domain'])
                cfg['tls_ready'] = True
            except SetupError:
                log('Внимание: HTTPS пока не готов. Caddy продолжит выпуск сертификата автоматически.')
        else:
            log('HTTPS отложен до появления DNS. RemnaNode устанавливается независимо.')
        node_uuid = register_node(api, cfg, state, tx)
        log('Запись ноды создана/обновлена. Проверка соединения с панелью…')
        node = wait_connected(api, node_uuid)
        new_state = {'version': VERSION, 'install_id': install_id, 'node_uuid': node_uuid,
                     'config': cfg, 'backup': str(tx.path), 'installed_at': dt.datetime.now(dt.timezone.utc).isoformat()}
        tx.write(ROOT / 'state.json', json.dumps(new_state, ensure_ascii=False, indent=2))
        tx.data['completed'] = True
        tx.save()
        (ROOT / 'pending.json').unlink(missing_ok=True)
        completion(cfg, node['isConnected'])
        log('API-ключ панели не сохранён. SECRET_KEY находится в /opt/remnanode/.env с правами 600.')
    except BaseException:
        log('Установка не завершена. Восстанавливаю предыдущие настройки…')
        try:
            rollback(tx.data, api)
            (ROOT / 'pending.json').unlink(missing_ok=True)
        except BaseException as exc:
            log('Требуется проверка отката: ' + safe(exc))
        raise


def status():
    state = read_json(ROOT / 'state.json', {})
    if not state:
        if (ROOT / 'pending.json').exists():
            log('Внимание: установка прервана. Повторите install для восстановления с подтверждением.')
        log('Управляемая установка не найдена.')
        return
    cfg = state['config']
    log(f"Нода: {cfg['node_name']} · {state['node_uuid']}\nСайт: https://{cfg['domain']}\nПрофиль: {cfg['profile_name']}")
    log('  HTTPS: ' + ('проверен при установке' if cfg.get('tls_ready') else 'ожидает DNS/сертификат; проверьте journalctl -u caddy'))
    for service in ('caddy',):
        log(service + ': ' + run(['systemctl', 'is-active', service], check=False).stdout.strip())
    log(compose('ps').stdout)
    token = os.environ.get('REMNA_API_KEY')
    if token:
        api = API(cfg['panel_url'], token, os.environ.get('REMNA_PROXY_KEY', ''))
        node = api.request('GET', '/api/nodes/' + state['node_uuid'])
        log('Panel isConnected: ' + str(node.get('isConnected')))


def main():
    parser = argparse.ArgumentParser(description='Автоматическая установка RemnaNode и Caddy Selfsteal')
    parser.add_argument('--version', action='version', version='remna-auto ' + VERSION)
    parser.add_argument('command', nargs='?', choices=['install', 'plan', 'status', 'rollback'], default='install')
    parser.add_argument('--config', help='JSON с несекретными параметрами')
    parser.add_argument('--api-key-file', help='Файл с API-ключом, права 600')
    parser.add_argument('--non-interactive', action='store_true')
    parser.add_argument('--backup', help='Каталог резервной копии для rollback')
    parser.add_argument('--refresh-image', action='store_true', help='Явно обновить образ вместо сохранённого digest')
    parser.add_argument('--yes', action='store_true', help='Подтвердить явно запрошенный неинтерактивный откат')
    parser.add_argument('--preview', action='store_true', help='Показать оформление без подключения и установки')
    args = parser.parse_args()
    if args.preview:
        banner()
        log('  Демонстрация оформления. Установка не выполняется.')
        section('01 / Настройка подключения', 'Домен можно добавить в DNS позже')
        log('  › HTTPS-адрес панели: https://panel.example.com')
        log('  › Домен Caddy / SNI: node.example.com')
        completion(dict(node_name='Node-01', domain='node.example.com',
                        profile_name='Selfsteal', vpn_ports=[444]), True)
        return
    if args.command == 'status':
        status()
        return
    if args.command == 'plan':
        cfg, api, state = configure(args)
        fields = {'domain', 'node_address', 'node_name', 'country_code', 'profile_name', 'profile_uuid', 'inbound_tags', 'vpn_ports', 'node_port', 'dns_ready', 'tls_ready'}
        public_cfg = {k: v for k, v in cfg.items() if k in fields}
        log(json.dumps(public_cfg, ensure_ascii=False, indent=2))
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
            if not args.non_interactive and not confirm('Откат заменит файлы и может удалить созданную этим запуском ноду.'):
                log('Откат отменён. Изменений нет.')
                return
            if args.non_interactive and not args.yes:
                raise SetupError('Для неинтерактивного отката необходимо --yes.')
            token = load_token(args, not args.non_interactive)
            rollback(data, API(data['config']['panel_url'], token, os.environ.get('REMNA_PROXY_KEY', '')))
            log('Откат завершён. Установленные системные пакеты оставлены на сервере.')
        else:
            cfg, api, state = configure(args)
            changed = state and (args.refresh_image or any(cfg.get(k) != state['config'].get(k) for k in ('domain', 'profile_uuid', 'inbound_uuids')))
            if changed and not args.yes:
                if args.non_interactive or not confirm('Изменятся параметры существующей ноды; возможен перерыв соединений.'):
                    raise SetupError('Обновление не подтверждено. Для автоматизации используйте --yes.')
            install(cfg, api, state)


if __name__ == '__main__':
    try:
        main()
    except (SetupError, OSError, subprocess.TimeoutExpired, ValueError, EOFError) as exc:
        log('ОШИБКА: ' + ('Превышено время ожидания команды. Проверьте сеть/службу и повторите запуск.' if isinstance(exc, subprocess.TimeoutExpired) else safe(exc)))
        sys.exit(1)
    except KeyboardInterrupt:
        log('Остановлено пользователем.')
        sys.exit(130)
