#!/usr/bin/env python3
"""Private SSH controller; only this machine holds panel credentials."""
import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import sys
import time
import uuid
import setup as s

HOME = Path('/etc/remna-auto-controller')
HERE = Path(__file__).resolve().parent


def private_dir():
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HOME, 0o700)


def settings():
    path = HOME / 'settings.json'
    mode = path.stat().st_mode
    if mode & 0o077 or path.stat().st_uid != 0:
        raise s.SetupError('Настройки должны принадлежать root с правами 600.')
    cfg = json.loads(path.read_text())
    s.SECRETS.extend([cfg['panel_url'], cfg['api_key'], cfg.get('proxy_key', '')])
    return cfg


def initialize():
    private_dir()
    url = s.validate_panel_url(input('HTTPS-адрес панели: ').strip())
    key = getpass.getpass('API-ключ (скрытый ввод): ').strip()
    s.API(url, key).request('GET', '/api/config-profiles')
    s.atomic(HOME / 'settings.json', json.dumps({'panel_url': url, 'api_key': key}))
    print('Настройки сохранены локально с правами 600.')


def fingerprint(key):
    return 'SHA256:' + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')


def connect(host, user, port, password=None, keyfile=None):
    import paramiko
    private_dir()
    known = HOME / 'known_hosts'
    if known.exists() and known.stat().st_mode & 0o077:
        raise s.SetupError('known_hosts должен иметь права 600.')

    class ConfirmKey(paramiko.MissingHostKeyPolicy):
        def missing_host_key(self, client, hostname, key):
            print('Новый SSH-сервер:', hostname, fingerprint(key))
            if input('Отпечаток проверен? Введите yes: ').strip() != 'yes':
                raise s.SetupError('Отпечаток SSH не подтверждён.')
            client.get_host_keys().add(hostname, key.get_name(), key)
            client.save_host_keys(str(known))
            os.chmod(known, 0o600)

    client = paramiko.SSHClient()
    if known.exists():
        client.load_host_keys(str(known))
    client.set_missing_host_key_policy(ConfirmKey())
    client.connect(host, port=port, username=user, password=password, key_filename=keyfile,
                   passphrase=password if keyfile else None, look_for_keys=False,
                   allow_agent=False, timeout=15, auth_timeout=20, banner_timeout=15)
    client.get_transport().set_keepalive(20)
    return client


def broker_request(api, method, path, body, host):
    # Restrict the tunnel to the installer API surface, never arbitrary URLs/headers.
    read = method == 'GET' and (path in ('/api/config-profiles', '/api/nodes', '/api/keygen') or
        re.fullmatch(r'/api/config-profiles/[a-f0-9-]{36}(?:/computed-config)?', path) or
        re.fullmatch(r'/api/nodes/[a-f0-9-]{36}', path))
    write = (method in ('POST', 'PATCH') and path == '/api/nodes') or (
        method == 'DELETE' and re.fullmatch(r'/api/nodes/[a-f0-9-]{36}', path))
    if not read and not write:
        raise s.SetupError('Запрос вне разрешённых API установщика.')
    if method == 'POST' and not str((body or {}).get('note', '')).startswith('remna-auto:'):
        raise s.SetupError('Создание чужой записи запрещено.')
    if method in ('POST', 'PATCH') and (body or {}).get('address') != host:
        raise s.SetupError('Запись вне целевого SSH-сервера запрещена.')
    if method in ('PATCH', 'DELETE'):
        ident = (body or {}).get('uuid') if method == 'PATCH' else path.rsplit('/', 1)[-1]
        old = api.request('GET', '/api/nodes/' + str(ident))
        if old.get('address') != host or not str(old.get('note', '')).startswith('remna-auto:'):
            raise s.SetupError('Изменение чужой ноды запрещено.')
    return api.request(method, path, body)


def deploy(args):
    cfg = settings()
    api = s.API(cfg['panel_url'], cfg['api_key'], cfg.get('proxy_key', ''))
    host = str(ipaddress.IPv4Address(input('IPv4 нового сервера: ').strip()))
    user = input('SSH-пользователь [root]: ').strip() or 'root'
    if not re.fullmatch('[a-zA-Z_][a-zA-Z0-9_-]{0,31}', user):
        raise s.SetupError('Некорректный SSH-пользователь.')
    port = s.validate_port(input('SSH-порт [22]: ').strip() or 22)
    keyfile = input('Путь к SSH-ключу (Enter — пароль): ').strip()
    password = getpass.getpass('Пароль/фраза ключа (скрыто): ') if not keyfile else getpass.getpass('Фраза ключа (Enter — без фразы): ')
    if password:
        s.SECRETS.append(password)
    domain = s.validate_domain(input('Домен Caddy: ').strip())
    profiles = api.request('GET', '/api/config-profiles')['configProfiles']
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {s.safe(profile['name'])}")
    index = int(input('Номер профиля: ')) - 1
    if not 0 <= index < len(profiles):
        raise s.SetupError('Некорректный номер профиля.')
    client = connect(host, user, port, password or None, keyfile or None)
    password = None
    remote = '/tmp/remna-controller-' + uuid.uuid4().hex
    prefix = '' if user == 'root' else 'sudo -n '
    try:
        # Root or passwordless sudo required; no saved sudo passwords.
        command = prefix + "sh -c 'test $(id -u) = 0 && (command -v python3 >/dev/null || (apt-get update && apt-get install -y python3 ca-certificates))'"
        _, out, _ = client.exec_command(command, timeout=300)
        # Drain output without displaying package errors containing private configuration.
        out.read()
        if out.channel.recv_exit_status():
            raise s.SetupError('Нужен root или sudo без пароля и Python 3.')
        ftp = client.open_sftp()
        ftp.mkdir(remote, mode=0o700)
        ftp.mkdir(remote + '/site', mode=0o700)
        for name in ('setup.py', 'remote_worker.py', 'site/index.html'):
            ftp.put(str(HERE / name), remote + '/' + name)
            ftp.chmod(remote + '/' + name, 0o600)
        ftp.close()
        stdin, stdout, stderr = client.exec_command(prefix + 'python3 -u ' + shlex.quote(remote + '/remote_worker.py'), timeout=2400)
        stdin.write(json.dumps({'domain': domain, 'address': host,
                               'profile_uuid': profiles[index]['uuid'], 'plan': args.plan}) + '\n')
        stdin.flush()
        done = False
        for line in stdout:
            message = json.loads(line)
            if 'api' in message:
                try:
                    method, path, body = message['api']
                    result = broker_request(api, method, path, body, host)
                    reply = {'result': result}
                except Exception as exc:
                    # Preserve HTTP code needed for fallback/rollback, never raw URLs or headers.
                    match = re.search(r'HTTP (\d{3})', str(exc))
                    reply = {'error': 'Ошибка API панели' + (' HTTP ' + match[1] if match else '')}
                stdin.write(json.dumps(reply) + '\n'); stdin.flush()
            elif 'log' in message:
                print(s.safe(message['log']), flush=True)
            elif 'error' in message:
                raise s.SetupError(s.safe(message['error']))
            elif message.get('done'):
                done = True
        if stdout.channel.recv_exit_status() or not done:
            raise s.SetupError('Удалённый процесс завершился без подтверждения. Проверьте состояние ноды.')
        print('Готово. API-ключ и настоящий адрес панели на ноду не передавались.')
    finally:
        # Only this invocation's exact random directory; no user paths in shell commands.
        try:
            _, out, _ = client.exec_command(prefix + 'rm -rf -- ' + shlex.quote(remote), timeout=15)
            out.channel.recv_exit_status()
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description='Remna Auto central SSH controller')
    parser.add_argument('command', choices=['init', 'deploy'])
    parser.add_argument('--plan', action='store_true', help='Проверка без установки ноды')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise s.SetupError('Центральный установщик запускается от root.')
    print('Не рекомендуется размещать центральный установщик на сервере с панелью: используйте отдельный сервер.')
    if args.command == 'init':
        initialize()
    else:
        deploy(args)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Остановлено. При разрыве SSH проверьте состояние удалённой установки.')
        sys.exit(130)
    except Exception as exc:
        print('ОШИБКА: ' + s.safe(str(exc)))
        sys.exit(1)
