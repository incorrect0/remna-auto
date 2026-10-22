#!/usr/bin/env bash
# Base dependencies only. Provider APT sources are not edited or queried.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Для зависимостей нужен root.' >&2; exit 1; }
[[ $# -gt 0 ]] || exit 0
MISSING=()
for PACKAGE in "$@"; do
    [[ "$PACKAGE" =~ ^[a-z0-9+.-]+$ ]] || exit 1
    if ! dpkg-query -W -f='${Status}' "$PACKAGE" 2>/dev/null | grep -qx 'install ok installed'; then
        MISSING+=("$PACKAGE")
    fi
done
[[ ${#MISSING[@]} -gt 0 ]] || { echo '  Базовые зависимости уже установлены.'; exit 0; }
# shellcheck source=/dev/null
. /etc/os-release
ARCH=$(dpkg --print-architecture)
[[ ${VERSION_CODENAME:-} =~ ^[a-z]+$ ]] || { echo 'Неизвестная версия системы.' >&2; exit 1; }
SOURCE=$(mktemp /tmp/remna-apt.XXXXXXXX.list)
trap 'rm -f -- "$SOURCE"' EXIT
if [[ $ID == ubuntu ]]; then
    MIRROR=https://archive.ubuntu.com/ubuntu
    SECURITY=https://security.ubuntu.com/ubuntu
    if [[ $ARCH != amd64 && $ARCH != i386 ]]; then
        MIRROR=https://ports.ubuntu.com/ubuntu-ports
        SECURITY=$MIRROR
    fi
    KEY=/usr/share/keyrings/ubuntu-archive-keyring.gpg
    printf 'deb [signed-by=%s] %s %s main universe\n' "$KEY" "$MIRROR" "$VERSION_CODENAME" > "$SOURCE"
    printf 'deb [signed-by=%s] %s %s-updates main universe\n' "$KEY" "$MIRROR" "$VERSION_CODENAME" >> "$SOURCE"
    printf 'deb [signed-by=%s] %s %s-security main universe\n' "$KEY" "$SECURITY" "$VERSION_CODENAME" >> "$SOURCE"
elif [[ $ID == debian ]]; then
    KEY=/usr/share/keyrings/debian-archive-keyring.gpg
    printf 'deb [signed-by=%s] https://deb.debian.org/debian %s main\n' "$KEY" "$VERSION_CODENAME" > "$SOURCE"
    printf 'deb [signed-by=%s] https://deb.debian.org/debian %s-updates main\n' "$KEY" "$VERSION_CODENAME" >> "$SOURCE"
    printf 'deb [signed-by=%s] https://security.debian.org/debian-security %s-security main\n' "$KEY" "$VERSION_CODENAME" >> "$SOURCE"
else
    echo 'Поддерживаются Debian/Ubuntu.' >&2; exit 1
fi
chmod 644 "$SOURCE"
APT=(apt-get -o "Dir::Etc::sourcelist=$SOURCE" -o Dir::Etc::sourceparts=-
    -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::https::Timeout=15 -o DPkg::Lock::Timeout=60)
echo '  Подготовка зависимостей через официальные HTTPS-репозитории…'
timeout 180 "${APT[@]}" update
DEBIAN_FRONTEND=noninteractive timeout 300 "${APT[@]}" install -y "${MISSING[@]}"
