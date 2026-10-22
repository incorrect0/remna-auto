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
bash "$BASE/bootstrap-deps.sh" python3 python3-paramiko ca-certificates
python3 -c 'import sys; assert sys.version_info >= (3,10), "Нужен Python 3.10+"'
install -d -m 700 "$TARGET" "$TARGET/site" /etc/remna-auto-controller
touch "$TARGET/.managed"
for name in setup.py controller.py remote_worker.py bootstrap-deps.sh; do
    install -m 600 "$BASE/$name" "$TARGET/$name.new"
    mv -f -- "$TARGET/$name.new" "$TARGET/$name"
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
