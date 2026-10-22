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
import sys
import time
import uuid
import setup as s

HOME = Path('/etc/remna-auto-controller')
HERE = Path(__file__).resolve().parent
LAST_PROFILE = None


class NeedsPassphrase(s.SetupError):
    pass


def prompt(label, default=''):
    suffix = ' [' + default + ']' if default else ''
    value = input(s.wrapped(s.color('  > ', '38;5;87') + s.safe(label) + s.color(s.safe(suffix), '38;5;245') + ': ', s.terminal_width())).strip()
    return value or default


def validated(label, validator, default=''):
    while True:
        try:
            return validator(prompt(label, default))
        except (ValueError, s.SetupError) as exc:
            s.log('Внимание: ' + (str(exc) if isinstance(exc, s.SetupError) else 'Проверьте формат значения.'))


def ssh_user(value):
    if not re.fullmatch('[a-zA-Z_][a-zA-Z0-9_-]{0,31}', value):
        raise s.SetupError('Имя SSH-пользователя: латинские буквы, цифры, _ или -.')
    return value


def parse_ssh_target(value):
    identity, separator, address = value.strip().rpartition('@')
    user = ssh_user(identity) if separator else 'root'
    address = address if separator else value.strip()
    host, separator, port = address.partition(':')
    return str(ipaddress.IPv4Address(host)), user, s.validate_port(port if separator else 22)


def private_key_path(value):
    if not value:
        return ''
    path = Path(value).expanduser()
    if not path.is_file():
        raise s.SetupError('SSH-ключ не найден. Укажите путь к файлу или Enter для пароля.')
    if path.stat().st_mode & 0o077:
        raise s.SetupError('Ограничьте права SSH-ключа: chmod 600 <файл>.')
    return str(path)


def menu():
    s.section('Центральный установщик', 'Установка нод по SSH · настройки панели хранятся здесь')
    s.log('  1. Установить новую ноду')
    s.log('  2. Проверить план без установки')
    s.log('  3. Настроить подключение к панели')
    s.log('  0. Выход')
    while True:
        value = prompt('Выберите действие')
        if value in ('0', '1', '2', '3'):
            return value
        s.log('  Введите 1, 2, 3 или 0.')


def private_dir():
    HOME.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(HOME, 0o700)


def settings():
    path = HOME / 'settings.json'
    mode = path.stat().st_mode
    if mode & 0o077 or path.stat().st_uid != 0:
        raise s.SetupError('Настройки должны принадлежать root с правами 600.')
    if path.is_symlink():
        raise s.SetupError('Конфиг не должен быть символической ссылкой.')
    cfg = s.read_json(path)
    if not isinstance(cfg, dict) or not isinstance(cfg.get('api_key'), str) or not cfg['api_key']:
        raise s.SetupError('Конфиг панели повреждён. Запустите remna-controller init.')
    s.validate_panel_url(cfg.get('panel_url', ''))
    s.SECRETS.extend([cfg['panel_url'], cfg['api_key'], cfg.get('proxy_key', '')])
    return cfg


def initialize():
    private_dir()
    s.section('Настройки панели', 'Значения сохраняются только на управляющем сервере')
    previous = settings() if (HOME / 'settings.json').exists() else {}
    if previous:
        s.log('  Панель уже настроена. Enter — сохранить прежнее значение.')
    url = s.ask_validated('HTTPS-адрес панели (скрыто)', s.validate_panel_url, previous.get('panel_url', ''), True)
    s.SECRETS.append(url)
    key = getpass.getpass('  API-ключ (скрыто; Enter — сохранить): ').strip() or previous.get('api_key', '')
    s.log('  Проверка доступа к панели…')
    s.API(url, key, previous.get('proxy_key', '')).request('GET', '/api/config-profiles')
    s.atomic(HOME / 'settings.json', json.dumps({**previous, 'panel_url': url, 'api_key': key}))
    s.log('  Настройки проверены и сохранены с правами 600.')


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
            s.log('Новый SSH-сервер: ' + hostname + '\nОтпечаток: ' + fingerprint(key))
            if input('Отпечаток проверен? Введите yes: ').strip() != 'yes':
                raise s.SetupError('Отпечаток SSH не подтверждён.')
            client.get_host_keys().add(hostname, key.get_name(), key)
            client.save_host_keys(str(known))
            os.chmod(known, 0o600)

    client = paramiko.SSHClient()
    if known.exists():
        client.load_host_keys(str(known))
    client.set_missing_host_key_policy(ConfirmKey())
    try:
        client.connect(host, port=port, username=user, password=password, key_filename=keyfile,
                       passphrase=password if keyfile else None, look_for_keys=False,
                       allow_agent=False, timeout=15, auth_timeout=20, banner_timeout=15)
    except paramiko.BadHostKeyException:
        client.close()
        raise s.SetupError('SSH-ключ сервера изменился. Сверьте отпечаток у провайдера; проверка не отключена.') from None
    except paramiko.PasswordRequiredException:
        client.close()
        raise NeedsPassphrase('SSH-ключ защищён парольной фразой.') from None
    except s.SetupError:
        client.close()
        raise
    except paramiko.AuthenticationException:
        client.close()
        raise s.SetupError('SSH-доступ отклонён. Проверьте пользователя, пароль/ключ и разрешение входа по SSH.') from None
    except (paramiko.SSHException, OSError):
        client.close()
        raise s.SetupError('Нет SSH-соединения. Проверьте IP, порт и firewall; затем повторите действие.') from None
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


def worker_messages(channel, idle_timeout=180, total_timeout=3600):
    """Drain both SSH streams, preserve partial JSON, bound silence and total duration."""
    started = last_data = last_status = time.monotonic()
    buffer = b''
    while True:
        now = time.monotonic()
        if now - started > total_timeout or now - last_data > idle_timeout:
            raise s.SetupError('Удалённая установка не отвечает. Проверьте состояние ноды и журнал отката перед повтором.')
        if channel.recv_stderr_ready():
            channel.recv_stderr(65536)  # Raw stderr may contain credentials; never echo it.
        if channel.recv_ready():
            chunk = channel.recv(65536)
            if not chunk:
                break
            last_data = now
            buffer += chunk
            if len(buffer) > 16 * 1024 * 1024:
                raise s.SetupError('Удалённый ответ слишком велик; запуск остановлен.')
            while b'\n' in buffer:
                line, buffer = buffer.split(b'\n', 1)
                try:
                    value = json.loads(line)
                    if not isinstance(value, dict):
                        raise ValueError()
                    paused = time.monotonic()
                    yield value
                    resumed = time.monotonic()
                    started += resumed - paused
                    last_data = last_status = resumed
                except (ValueError, UnicodeError):
                    raise s.SetupError('Повреждён ответ удалённого установщика. Проверьте версии Python и файлов.') from None
        elif channel.exit_status_ready():
            if buffer.strip():
                raise s.SetupError('SSH-соединение оборвалось до завершения ответа.')
            break
        else:
            if now - last_status >= 10:
                s.log(f'  Удалённая установка выполняется: {int(now - started)} с…')
                last_status = now
            time.sleep(0.1)


def deploy(args):
    cfg = settings()
    api = s.API(cfg['panel_url'], cfg['api_key'], cfg.get('proxy_key', ''))
    s.section('01 / SSH-доступ', 'По умолчанию: root, порт 22. Пароль не сохраняется.')
    host, user, port = validated('SSH: [user@]IPv4[:port]', parse_ssh_target)
    keyfile = validated('SSH-ключ (Enter — пароль)', private_key_path)
    password = getpass.getpass('  SSH-пароль (скрыто): ') if not keyfile else ''
    if password:
        s.SECRETS.append(password)
    s.section('02 / Домен и профиль', 'Страна, имя, inbound’ы и BBR настраиваются автоматически')
    domain = validated('Домен Caddy', s.validate_domain)
    profiles = api.request('GET', '/api/config-profiles')['configProfiles']
    global LAST_PROFILE
    if not profiles:
        raise s.SetupError('Нет доступных профилей. Создайте профиль в панели и повторите установку.')
    for i, profile in enumerate(profiles, 1):
        s.log(f"  {i}. {profile['name']}")
    default = next((str(i) for i, p in enumerate(profiles, 1) if p['uuid'] == LAST_PROFILE), '')
    def profile_index(value):
        try:
            result = int(value) - 1
        except ValueError:
            raise s.SetupError('Введите номер профиля из списка.') from None
        if not 0 <= result < len(profiles):
            raise s.SetupError('Номер профиля вне списка.')
        return result
    index = 0 if len(profiles) == 1 else validated('Номер профиля', profile_index, default)
    LAST_PROFILE = profiles[index]['uuid']
    s.section('03 / Подключение к серверу', 'Проверка SSH и подготовка удалённого установщика')
    try:
        client = connect(host, user, port, password or None, keyfile or None)
    except NeedsPassphrase:
        password = getpass.getpass('  Фраза SSH-ключа (скрыто): ')
        s.SECRETS.append(password)
        client = connect(host, user, port, password or None, keyfile or None)
    password = None
    remote = '/tmp/remna-controller-' + uuid.uuid4().hex
    prefix = '' if user == 'root' else 'sudo -n '
    streams = []
    try:
        with client.open_sftp() as ftp:
            ftp.mkdir(remote, mode=0o700)
            ftp.mkdir(remote + '/site', mode=0o700)
            for name in ('setup.py', 'remote_worker.py', 'bootstrap-deps.sh', 'site/index.html'):
                ftp.put(str(HERE / name), remote + '/' + name)
                ftp.chmod(remote + '/' + name, 0o600)
        command = prefix + 'bash ' + shlex.quote(remote + '/bootstrap-deps.sh') + ' python3 curl ca-certificates'
        command += ' && ' + prefix + 'python3 -c ' + shlex.quote('import sys; assert sys.version_info >= (3,10)')
        check_in, out, check_err = client.exec_command(command, timeout=500)
        streams.extend([check_in, out, check_err])
        # Drain stderr too: APT warnings must not deadlock an SSH channel.
        out.channel.set_combine_stderr(True)
        started = last_status = time.monotonic()
        while not out.channel.exit_status_ready() or out.channel.recv_ready() or out.channel.recv_stderr_ready():
            if out.channel.recv_ready():
                out.channel.recv(65536)
            if out.channel.recv_stderr_ready():
                out.channel.recv_stderr(65536)
            if time.monotonic() - started > 490:
                raise s.SetupError('Превышено время подготовки зависимостей удалённого сервера.')
            if time.monotonic() - last_status >= 10:
                s.log('  Подготовка базовых зависимостей удалённого сервера…')
                last_status = time.monotonic()
            time.sleep(0.1)
        if out.channel.recv_exit_status():
            raise s.SetupError('Не удалось подготовить Python: проверьте root/sudo без пароля, APT и доступ к официальным репозиториям.')
        stdin, stdout, stderr = client.exec_command(prefix + 'python3 -u ' + shlex.quote(remote + '/remote_worker.py'), timeout=2400)
        streams.extend([stdin, stdout, stderr])
        stdin.write(json.dumps({'domain': domain, 'address': host,
                               'profile_uuid': profiles[index]['uuid'], 'plan': args.plan}) + '\n')
        stdin.flush()
        done = False
        pending_error = None
        for message in worker_messages(stdout.channel):
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
            elif 'confirm' in message:
                stdin.write(json.dumps({'confirmed': s.confirm(s.safe(message['confirm']))}) + '\n')
                stdin.flush()
            elif 'log' in message:
                s.log(message['log'])
            elif 'error' in message:
                pending_error = s.safe(message['error'])
            elif message.get('done'):
                done = True
        if pending_error:
            raise s.SetupError(pending_error)
        if stdout.channel.recv_exit_status() or not done:
            raise s.SetupError('Удалённый процесс завершился без подтверждения. Проверьте состояние ноды.')
        s.section('[OK] План проверен' if args.plan else '[OK] Удалённая установка завершена',
                  'API-ключ и настоящий адрес панели остались на управляющем сервере')
    finally:
        # Close ChannelFiles before the transport: avoids Paramiko finalizer tracebacks.
        for stream in streams:
            try:
                stream.close()
            except Exception:
                pass
        try:
            cleanup_in, cleanup_out, cleanup_err = client.exec_command(
                prefix + 'rm -rf -- ' + shlex.quote(remote), timeout=15)
            try:
                cleanup_out.channel.recv_exit_status()
            finally:
                for stream in (cleanup_in, cleanup_out, cleanup_err):
                    stream.close()
        except Exception:
            s.log('Внимание: временную папку удалённого запуска не удалось очистить.')
        finally:
            client.close()


def main():
    parser = argparse.ArgumentParser(description='Remna Auto central SSH controller')
    parser.add_argument('--version', action='version', version='remna-controller ' + s.VERSION)
    parser.add_argument('command', nargs='?', choices=['init', 'deploy'])
    parser.add_argument('--plan', action='store_true', help='Проверка без установки ноды')
    args = parser.parse_args()
    if getattr(os, 'geteuid', lambda: 1)() != 0:
        raise s.SetupError('Центральный установщик запускается от root.')
    s.banner()
    s.log(s.color('  Не рекомендуется размещать на сервере с панелью. Используйте отдельный сервер.', '33'))
    while True:
        if args.command is None:
            try:
                choice = menu()
            except EOFError:
                return
            if choice == '0':
                return
            args.command = 'init' if choice == '3' else 'deploy'
            args.plan = args.plan or choice == '2'
        try:
            if args.command == 'deploy' and not (HOME / 'settings.json').exists():
                initialize()
            if args.command == 'init':
                initialize()
            else:
                deploy(args)
        except Exception as exc:
            if not sys.stdin.isatty():
                raise
            s.log('ОШИБКА: ' + s.safe(str(exc)))
        if not sys.stdin.isatty():
            return
        args.command = None
        args.plan = False



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Остановлено. При разрыве SSH проверьте состояние удалённой установки.')
        sys.exit(130)
    except Exception as exc:
        s.log('ОШИБКА: ' + s.safe(str(exc)))
        sys.exit(1)
