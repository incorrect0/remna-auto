#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ $# -eq 0 ]]; then
    if [[ ! -t 0 ]]; then
        echo 'Укажите режим: install (эта машина) или controller (центральный установщик).' >&2
        exit 1
    fi
    CYAN='' PINK='' RESET=''
    if [[ -t 1 && ${TERM:-dumb} != dumb && ! ${NO_COLOR+x} ]]; then
        CYAN=$'\033[1;36m' PINK=$'\033[1;35m' RESET=$'\033[0m'
    fi
    while true; do
        printf '\n%s  remna %s<3%s\n\n' "$CYAN" "$PINK" "$RESET"
        printf '  1. Центральный установщик — установка нод по SSH\n'
        printf '  2. Установить ноду на текущий сервер\n'
        printf '  0. Выход\n\n'
        read -r -p '  Выберите режим [1/2/0]: ' MODE || exit 0
        case "$MODE" in
            1) if ! bash "$BASE/run.sh" controller; then echo '  Действие завершилось с ошибкой. Возврат в меню.'; fi ;;
            2) if ! bash "$BASE/run.sh" install; then echo '  Действие завершилось с ошибкой. Возврат в меню.'; fi ;;
            0) exit 0 ;;
            *) echo '  Введите 1, 2 или 0.' ;;
        esac
    done
fi
if [[ "${1:-}" == controller ]]; then
    bash "$BASE/controller-install.sh"
    if [[ -t 0 ]]; then
        exec /usr/local/bin/remna-controller
    fi
    exit 0
fi
if [[ "${1:-install}" != plan && "${1:-install}" != status && "${1:-}" != --help && "${1:-}" != -h && "${1:-}" != --version && "${1:-}" != --preview && ${EUID} -ne 0 ]]; then
    echo 'Запустите от root: sudo bash install.sh' >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    command -v apt-get >/dev/null || { echo 'Нужен Debian/Ubuntu и Python 3.10+' >&2; exit 1; }
    bash "$BASE/bootstrap-deps.sh" python3 ca-certificates
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Нужен Python 3.10+"'
exec python3 "$BASE/setup.py" "$@"
