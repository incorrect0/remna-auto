#!/usr/bin/env python3
"""SSH stdio worker. Panel credentials never enter this process."""
import json
import sys
import setup as s


def send(payload):
    print(json.dumps(payload, ensure_ascii=True), flush=True)


class Broker:
    def request(self, method, path, body=None):
        send({'api': [method, path, body]})
        line = sys.stdin.readline(8 * 1024 * 1024)
        if not line:
            raise s.SetupError('Связь с управляющим сервером потеряна.')
        reply = json.loads(line)
        if 'error' in reply:
            raise s.SetupError(reply['error'])
        return reply['result']


def confirm_via_controller(message):
    send({'confirm': message})
    line = sys.stdin.readline(65536)
    if not line:
        raise s.SetupError('Связь с контроллером потеряна до подтверждения.')
    return json.loads(line).get('confirmed') is True


def main():
    initial = json.loads(sys.stdin.readline(65536))
    # Never store the actual panel URL on a managed node.
    cfg = {'panel_url': 'https://panel.example.com', 'domain': initial['domain'],
           'node_address': initial['address'], 'profile_uuid': initial['profile_uuid'],
           'inbound_uuids': []}
    s.log = lambda message: send({'log': s.safe(message)})
    s.confirm = confirm_via_controller
    state = s.read_json(s.ROOT / 'state.json', {})
    if state:
        cfg = {**state['config'], **cfg}
    code, base = s.country_for_ipv4(cfg['node_address'])
    cfg.update(country_code=code, node_name=base[:26], auto_name_base=base)
    cfg = s.validate_config(cfg)
    api = Broker()
    cfg['node_name'] = s.automatic_name(base, s.list_nodes(api), state.get('node_uuid'))
    s.choose_profile(api, cfg, False)
    if initial.get('plan'):
        send({'log': 'План готов: ' + cfg['node_name'] + ' / ' + cfg['domain']})
    else:
        import fcntl
        with open('/run/lock/remna-auto.lock', 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            s.recover_pending(api, True)
            state = s.read_json(s.ROOT / 'state.json', {})
            if state and not s.confirm('Обновить существующую ноду? Возможен перерыв соединений.'):
                raise s.SetupError('Обновление отменено пользователем.')
            s.install(cfg, api, state)
    send({'done': True})


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        send({'error': s.safe(str(exc))})
        sys.exit(1)
