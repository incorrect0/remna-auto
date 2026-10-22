#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TARGET=/opt/remna-auto-controller
[[ $EUID -eq 0 ]] || { echo 'Запустите от root.' >&2; exit 1; }
if [[ -d "$TARGET" && ! -f "$TARGET/.managed" ]]; then
    echo 'Каталог контроллера занят чужими файлами.' >&2
    exit 1
fi
echo 'Не рекомендуется устанавливать контроллер на сервер с панелью. Используйте отдельный сервер.'
APT=(apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
if [[ -f /opt/remna-auto/install.sources.list ]]; then
    APT+=(-o Dir::Etc::sourcelist=/opt/remna-auto/install.sources.list -o Dir::Etc::sourceparts=-)
fi
"${APT[@]}" update
DEBIAN_FRONTEND=noninteractive "${APT[@]}" install -y python3 python3-paramiko ca-certificates
install -d -m 700 "$TARGET" "$TARGET/site" /etc/remna-auto-controller
for name in setup.py controller.py remote_worker.py; do
    install -m 600 "$BASE/$name" "$TARGET/$name"
done
install -m 600 "$BASE/site/index.html" "$TARGET/site/index.html"
touch "$TARGET/.managed"
cat > /usr/local/bin/remna-controller <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
umask 077
exec /usr/bin/python3 /opt/remna-auto-controller/controller.py "$@"
EOF
chmod 755 /usr/local/bin/remna-controller
echo 'Контроллер установлен. Настройка: remna-controller init'
echo 'Новая нода: remna-controller deploy'
