# Публикация изменений

Этот репозиторий — основной источник исходников установщика. Изменения публикуются
коммитами по мере необходимости; одноразовая команда берёт опубликованную ветку main.
Изменение файлов GitHub само по себе не запускает обновление серверов.

Перед публикацией:

```bash
python -m unittest discover -s tests -v
shellcheck install.sh run.sh controller-install.sh bootstrap-deps.sh
ruff check --no-cache --select E9,F63,F7,F82 setup.py controller.py remote_worker.py tests
bash -n install.sh run.sh controller-install.sh bootstrap-deps.sh
python tools/checksums.py
python tools/checksums.py --check
python tools/check_public_files.py
git diff --check
```

Обновите VERSION в setup.py и CHANGELOG.md при выпуске новой версии. Добавление нового
публичного файла также требует внесения пути в tools/checksums.py. Не добавляйте config.json,
.env, API-ключи, SSH-доступы, state.json, серверные журналы и резервные копии. SHA256SUMS
проверяет соответствие файлов внутри снимка; это не независимая цифровая подпись.

GitHub Actions не устанавливает ноду и не обращается к боевой панели. Интеграционные
проверки публичного ACME и реальной ноды требуют отдельного тестового сервера и домена.
Контракты API: https://docs.rw/api/ .

Тесты tests/test_ux.py используют только временные файлы, имитацию API и локальные
процессы. На сервере с рабочими нодами запускайте их в отдельном контейнере без сети
и монтируйте только исходники, без Docker socket, /opt/remnanode и настроек панели.
