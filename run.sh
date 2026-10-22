#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
BASE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
if [[ "${1:-}" == controller ]]; then
    exec bash "$BASE/controller-install.sh"
fi
if [[ "${1:-install}" != plan && "${1:-install}" != status && ${EUID} -ne 0 ]]; then
    echo 'Запустите от root: sudo bash install.sh' >&2
    exit 1
fi
if ! command -v python3 >/dev/null; then
    command -v apt-get >/dev/null || { echo 'Нужен Debian/Ubuntu и Python 3.10+' >&2; exit 1; }
    apt-get update
    apt-get install -y python3 ca-certificates
fi
exec python3 "$BASE/setup.py" "$@"
