# Marzban, настоящий systemd и вложенный Docker

Это отдельный контейнерный Linux-стенд, не виртуальная машина. Внешний контейнер имеет собственную сеть и cgroup namespace; его Docker Engine запускает Marzban с `network_mode: host` внутри этой сети. Общий Docker socket не подключается. `--privileged` нужен для вложенного Docker, systemd, TUN и netfilter; ядро общее, поэтому это не граница безопасности виртуальной машины.

Используй только тестовую машину. Команды ниже предназначены для Linux с Docker CLI, из корня репозитория. Все имена должны быть свободны: при конфликте остановись, а не удаляй существующие контейнеры. Образ Marzban, его digest и версии Xray нужно сохранить в отчёте.

Подготовь Linux-бинарники Xray 26.3.27 и 26.11.9 и уже собранную Suricata 8.0.8 + nDPI 4.14. Движок должен включать `classification.config`, `reference.config`, `threshold.config` и плагин; одного бинарника Suricata недостаточно. Пути в его YAML должны существовать внутри стенда. В примере весь префикс движка монтируется read-only по исходному абсолютному пути:

Для проверки перезагрузки префикс движка и его YAML должны находиться в постоянном каталоге, например `/opt/xray-guard-test-engine`, а не `/tmp`: systemd очищает временные файлы при старте. Обычный установщик проекта собирает движок в `/opt/xray-connection-guard/engines/`.

```bash
ENGINE_PREFIX=/абсолютный/путь/к/движку
SURICATA_CONFIG=/абсолютный/путь/к/движку/etc/suricata/suricata.yaml
docker build -t xray-guard-systemd-test:local tests/docker
docker pull gozargah/marzban:latest
docker image inspect gozargah/marzban:latest --format '{{json .RepoDigests}}'
docker network create --label xray-guard.test=marzban xray-guard-marzban-test
docker run -d --name xray-guard-marzban-test --label xray-guard.test=marzban \
  --privileged --cgroupns private --network xray-guard-marzban-test \
  --tmpfs /run --tmpfs /run/lock --stop-timeout 20 \
  --env XRAY_GUARD_ISOLATED_HOST=marzban \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --mount "type=bind,source=$ENGINE_PREFIX,target=$ENGINE_PREFIX,readonly" \
  xray-guard-systemd-test:local
docker exec xray-guard-marzban-test systemctl is-system-running
docker exec xray-guard-marzban-test systemctl start docker
docker exec xray-guard-marzban-test docker version
docker exec xray-guard-marzban-test mkdir -p /fixtures/old /fixtures/new
docker cp /путь/к/xray-26.3.27 xray-guard-marzban-test:/fixtures/old/xray
docker cp /путь/к/xray-26.11.9 xray-guard-marzban-test:/fixtures/new/xray
docker exec xray-guard-marzban-test chmod 755 /fixtures/old/xray /fixtures/new/xray
docker save -o /tmp/marzban-test-image.tar gozargah/marzban:latest
docker cp /tmp/marzban-test-image.tar xray-guard-marzban-test:/tmp/marzban-image.tar
docker exec xray-guard-marzban-test docker load -i /tmp/marzban-image.tar
docker exec -e PYTHONPATH=/repo/src:/repo/tests/integration \
  xray-guard-marzban-test python3 -u -B /repo/tests/integration/test_marzban_host.py \
  --output /results/suite --binary "$ENGINE_PREFIX/bin/suricata" \
  --suricata-config "$SURICATA_CONFIG"
```

Нельзя давать внешнему контейнеру `--network host` или монтировать в него Docker socket основной машины. При его наличии внутри можно ошибочно запустить Marzban в сети основного Docker-хоста.

Тест создаёт настоящую панель, администратора и пользователей через API, применяет профиль, запускает неизменённые `manage.sh` и systemd-службы. Клиенты и выход находятся в отдельных network namespaces. Адреса `11.0.0.20/21/30` существуют только в клиентском namespace, достижимом через тестовый veth; внешние серверы с этими адресами не используются. Для зарезервированных IP пиров разрешение `freedom.finalRules` добавляется только в конфигурации стенда. Рабочий guard не подменяется: баны применяет настоящий systemd-процесс.

У Marzban 0.8.4 указан явный REALITY `publicKey`, поскольку его старый генератор ключей не разбирает новый формат вывода Xray. HTTPS панели использует тестовый сертификат и `UVICORN_SSL_CA_TYPE=private`. Внешние сервисы определения публичного IP направлены в loopback, чтобы запуск не зависел от интернета; ядро Xray, nftables, Suricata, Docker и systemd не подменяются.

Тест проверяет отсутствие IPv4 на 26.3.27, успешную работу на 26.11.9, TCP/UDP/DNS, атрибуцию и реальные IP-баны, смену UDP-пиров в одном сокете, перезапуски ядра и контейнера, режимы off/monitor, остановку Suricata/очереди, восстановление gateway и полный откат. Контрольные SSH и HTTPS проверяются параллельно. Отдельный отрицательный сценарий намеренно добавляет глобальный default route Xray и должен воспроизвести потерю SSH; затем профиль восстанавливается через локальный API. Поэтому запускать этот файл на рабочем хосте запрещено.

Остановка Suricata при сохранённых NFQUEUE-правилах должна блокировать выбранный трафик. При аварии процесса очереди правила также должны сохраниться; этот сценарий проверяется через настоящий `SIGKILL`. Штатный `systemctl stop` очереди намеренно удаляет её фильтр и не гарантирует fail-closed: возможность прохождения трафика в этом состоянии записывается как отрицательный сценарий, а не объявляется безопасной паузой. Полный откат всегда начинается с восстановления исходного профиля Xray.

После успешного основного теста проверяется холодный старт без повторного `enable`:

```bash
docker restart xray-guard-marzban-test
docker exec -e PYTHONPATH=/repo/src:/repo/tests/integration \
  xray-guard-marzban-test python3 -u -B /repo/tests/integration/test_marzban_reboot.py
```

Сохрани отчёты до удаления стенда; при ошибке сначала сохрани их, затем выполни очистку. Файлы содержат только тестовые конфиги и ключи, но не предназначены для публикации как рабочие настройки:

```bash
docker cp xray-guard-marzban-test:/results/. /tmp/marzban-docker-report
docker rm -f xray-guard-marzban-test
docker network rm xray-guard-marzban-test
```

Не используй `docker system prune`, `nft flush ruleset` или `ip rule flush` на основной машине. Образы после проверки остаются в кэше Docker; удаляются только явно созданные контейнер и сеть.
