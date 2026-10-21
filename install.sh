#!/usr/bin/env bash
# Public bootstrap. Downloads a consistent repository snapshot; never deletes installations.
set -Eeuo pipefail
umask 077
REPOSITORY='incorrect0/remna-auto'
REF="${REMNA_AUTO_REF:-main}"
COMMAND="${1:-install}"
if [[ "$COMMAND" != plan && "$COMMAND" != status && ${EUID} -ne 0 ]]; then
    echo 'Запустите команду от root.' >&2
    exit 1
fi
if [[ ! "$REF" =~ ^[a-zA-Z0-9._/-]+$ || "$REF" == *..* || "$REF" == /* ]]; then
    echo 'Некорректный REMNA_AUTO_REF.' >&2
    exit 1
fi

# A checked-out repository can also be run locally, without downloading it again.
LOCAL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)"
if [[ -f "$LOCAL_DIR/setup.py" && -f "$LOCAL_DIR/run.sh" && -f "$LOCAL_DIR/site/index.html" ]]; then
    exec bash "$LOCAL_DIR/run.sh" "$@"
fi
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
    if [[ ${EUID} -ne 0 ]] || ! command -v apt-get >/dev/null; then
        echo 'Для загрузчика нужны curl и Python 3.10+ (Debian/Ubuntu).' >&2
        exit 1
    fi
    apt-get -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 update
    apt-get -y install python3 curl ca-certificates
fi
TEMP_DIR="$(mktemp -d /tmp/remna-auto.XXXXXXXX)"
cleanup() {
    if [[ "$TEMP_DIR" == /tmp/remna-auto.* && -d "$TEMP_DIR" ]]; then
        rm -rf -- "$TEMP_DIR"
    fi
}
trap cleanup EXIT
echo "Remna Auto: загрузка $REPOSITORY ($REF)…"
curl --fail --silent --show-error --location --retry 3 --connect-timeout 10 --max-time 180 \
    "https://codeload.github.com/$REPOSITORY/tar.gz/$REF" --output "$TEMP_DIR/source.tar.gz"
python3 - "$TEMP_DIR/source.tar.gz" "$TEMP_DIR/package" <<'PY'
import hashlib, pathlib, re, sys, tarfile
archive, output = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
if archive.stat().st_size > 20 * 1024 * 1024:
    raise SystemExit('Архив неожиданно велик.')
with tarfile.open(archive, 'r:gz') as tar:
    members = tar.getmembers()
    roots = set()
    total = 0
    if len(members) > 2000:
        raise SystemExit('Слишком много файлов в архиве.')
    for member in members:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or not (member.isdir() or member.isfile()):
            raise SystemExit('Небезопасная структура архива.')
        roots.add(path.parts[0])
        total += member.size
    if len(roots) != 1 or total > 100 * 1024 * 1024:
        raise SystemExit('Некорректный размер или корневая папка архива.')
    output.mkdir(mode=0o700)
    for member in members:
        relative = pathlib.PurePosixPath(member.name).parts[1:]
        if not relative:
            continue
        target = output.joinpath(*relative)
        if member.isdir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            with tar.extractfile(member) as src, target.open('wb') as dest:
                dest.write(src.read())
manifest = output / 'SHA256SUMS'
if not manifest.is_file():
    raise SystemExit('Нет SHA256SUMS: установка отменена.')
verified = set()
for line in manifest.read_text().splitlines():
    match = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
    if not match:
        raise SystemExit('Повреждён SHA256SUMS.')
    digest, filename = match.groups()
    relative = pathlib.PurePosixPath(filename)
    if relative.is_absolute() or '..' in relative.parts:
        raise SystemExit('Небезопасный путь в SHA256SUMS.')
    file = output.joinpath(*relative.parts)
    if not file.is_file() or hashlib.sha256(file.read_bytes()).hexdigest() != digest:
        raise SystemExit('Не совпадает контрольная сумма: ' + filename)
    verified.add(filename)
for required in ('run.sh', 'setup.py', 'site/index.html'):
    if required not in verified:
        raise SystemExit('Не проверен обязательный файл: ' + required)
print('Архив распакован; контрольные суммы проверены.')
PY
bash "$TEMP_DIR/package/run.sh" "$@"
