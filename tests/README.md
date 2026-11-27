# Тесты

Команды выполняются из корня проекта на Linux. Нужны Python 3 и PyYAML.

## Модульные тесты

```bash
PYTHONPATH="$PWD/src" python3 -B -m unittest discover -s tests/unit -v
bash -n manage.sh
```

## Интеграционные тесты

Нужны права root, `unshare`, `ip`, `ss`, `nft` и `/dev/net/tun`. Проверки используют отдельные сетевые пространства имён; тест установщика также изолирует каталоги установки и `/run`, подменяет systemd и Suricata.

```bash
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_integration.py
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_integration.py --xudp
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_network.py
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_tun_network.py
sudo env PYTHONPATH="$PWD/src" unshare --mount --net python3 -B tests/integration/test_linux_installer.py
```

Тест установщика проверяет ранний отказ при старой/неопределённой версии запущенного Xray, сохранение файлов при отказе и повторную проверку при включении TUN. Для DIRECT/SO_MARK старое ядро допускается только с явным `install --inspection-mark`. Проверяются также ошибки остановки guard и чтения nftables при `off`: без ложного сообщения об успехе и без снятия банов при ошибке остановки службы.

Для `disable` проверяется снятие банов/NFQUEUE без изменения TUN-маршрутов, policy rule, сетевого состояния и `rp_filter`. Перезапуск/перезагрузка очереди должны сохранять режим «только маршрутизация»; `enable` должен возвращать анализ.

Для `uninstall` проверяется остановка всех служб, удаление установленных скриптов/unit-файлов, банов/NFQUEUE и собственных маршрутов с восстановлением `rp_filter`. Повторное удаление и установка должны работать; конфигурация, журналы, резервные копии, движок, чужие правила и Xray сохраняются. Ошибки systemd/nftables не должны приводить к ложному успеху или удалению программных файлов до очистки сети.

## Полная сборка Suricata и nDPI

Отдельная проверка скачивает зависимости, собирает движок в изолированных каталогах, проверяет распознавание BitTorrent на тестовом PCAP и повторную установку. Нужны интернет и несколько минут.

```bash
sudo env PYTHONPATH="$PWD/src" unshare --mount python3 -B tests/integration/test_linux_bootstrap.py
```

Для проверки уже установленного движка на тестовом PCAP:

```bash
sudo env PYTHONPATH="$PWD/src" python3 -B tests/integration/test_suricata_capture.py /путь/к/suricata /etc/xray-connection-guard/suricata.yaml
```

## Native Xray TUN → XHTTP/REALITY

Нужны Linux, root, `/dev/net/tun`, Xray с native TUN, `openssl`, PyYAML, `ip`, `nft`, `ss`, `nsenter` и `unshare`. Проверенный Xray на RU — **26.11.9**; **26.3.27 не проходит смену UDP-пиров через один сокет**. Стенд создаёт два сетевых namespace: RU и выходную ноду. Настоящие клиенты VLESS/REALITY обращаются через RU → freedom, привязанный к TUN → native TUN inbound → VLESS/XHTTP/REALITY → выходной Xray → локальные TCP/UDP-пиры по IPv4. Все адреса, UUID, ключи и сертификат тестовые; внешние ноды не используются.

Быстрая проверка транспорта, без Suricata:

```bash
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B \
  tests/integration/test_linux_tun.py --transport-only --xray /usr/local/bin/xray
```

Полная проверка с уже установленными Suricata 8+ и nDPI:

```bash
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B \
  tests/integration/test_linux_tun.py --xray /usr/local/bin/xray \
  --binary /путь/к/suricata --suricata-config /etc/xray-connection-guard/suricata.yaml \
  --output /tmp/xray-tun-live
```

Либо сборка движка в приватных overlay-каталогах с последующим запуском того же live-теста:

```bash
sudo env PYTHONPATH="$PWD/src" unshare --mount python3 -B \
  tests/integration/test_linux_bootstrap.py --tun --xray /usr/local/bin/xray \
  --tun-output /tmp/xray-tun-live
```

Каталог `--output` / `--tun-output` должен быть новым; там сохраняются диагностические конфиги, журналы и `result.json` успешного полного прогона. Без этого параметра временные файлы удаляются. Установки пакетов, сервисы и firewall хоста не меняются; для сборки нужен интернет.

Адрес IPv4 назначает сам Xray через `gateway`; маршруты и `rp_filter` создаёт тот же фоновый помощник, который запускается службой очереди. Проверяется восстановление после настоящего перезапуска Xray с пересозданием TUN без ручных сетевых команд. Основной маршрут должен остаться через физический интерфейс, повторная настройка не должна создавать дубликаты. Отдельный `test_linux_tun_network.py` проверяет конфликты таблицы/приоритета, сохранение чужих и заимствованных правил, очистку своих настроек и отсутствие изменений IPv6.

Проверяются TCP/UDP по IPv4, смена назначения в одной UDP-ассоциации, доменное назначение через DNS Xray, пять пиров на одном порту, реальный NFQUEUE/nDPI и IP-баны исходных TCP- и UDP/XUDP-клиентов на 600 секунд. Контрольный клиент должен продолжать работать. При остановке Suricata, отключении TUN или выходной ноды не должно быть обхода через DIRECT; после восстановления TUN и Suricata трафик должен снова проходить. Зарезервированные IP тестовых клиентов разрешаются к бану только внутри стенда; производственная защита служебных адресов не меняется.

Затем тот же live-стенд явно выключает инспекцию: TCP BitTorrent и UDP DHT должны проходить через TUN без новых EVE-событий; маршруты должны сохраняться, а перезапуски помощника/Xray — восстанавливать TUN без включения DPI. Повторное включение должно вернуть блокировку. Это отдельный намеренный режим, а не аварийный обход. [Отчёт проверки](results/routing-only.json) относится к локальным изолированным Xray; установщик/команды дополнительно проверяются с подменёнными systemd и Suricata.

Для проверки старых клиентов и выхода укажи `--external-xray /путь/к/другому/xray` в `test_linux_tun.py`: смешанный стенд с RU 26.11.9 и остальными Xray 26.3.27 также проходит. `--trace` сохраняет пакеты тестового TUN в `tun-packets.jsonl`. DHT может потребовать нескольких пакетов до классификации; тест проверяет блокировку после распознавания, а не невозможную гарантию блокировки всех неизвестных начальных пакетов.

Для выхода через **VLESS/RAW/REALITY с Vision** добавь к полной команде `test_linux_tun.py` параметры `--exit-network raw --exit-flow xtls-rprx-vision`. Меняется транспорт между RU и изолированной выходной нодой; `INSPECT_VIA_TUN` остаётся `freedom`. [Отчёт прогона](results/vless-raw-vision.json) фиксирует реальные блокировки TCP BitTorrent/DHT и два IP-бана на 600 секунд.

## Проверка доступности внешнего VLESS

Перед проверкой блокировок на реальном внешнем выходе проверь обычный HTTP/HTTPS через него. Сохрани VLESS URI в отдельном файле с правами `600` вне репозитория:

```bash
env PYTHONPATH="$PWD/src" python3 -B tests/integration/test_external_vless.py \
  --uri-file /защищённый/путь/node.link --xray /usr/local/bin/xray \
  --output /tmp/external-vless-probe
```

Каталог `--output` должен быть новым. Тест запускает отдельный Xray с SOCKS на localhost и проверяет ответы `api.ipify.org`, `www.cloudflare.com` и `example.com`. Для сравнения с `freedom` замени `--uri-file ...` на `--direct` и укажи другой каталог вывода. Сгенерированная конфигурация с ключом удаляется после завершения; в отчёт URI и параметры аутентификации не записываются.

Эта проверка не меняет firewall и маршруты хоста и не проверяет блокировки. Если HTTP/HTTPS не проходит ещё без guard, доступность внешнего туннеля нужно выяснить до проверки инспекции. Парсер сохраняет `flow` из ссылки и не подставляет Vision, когда параметр отсутствует.

## Блокировки через настоящий внешний VLESS

`test_external_inspection.py` использует предоставленный внешний VLESS/REALITY-outbound вместо локальной выходной ноды. Запускай только в одноразовом Docker-контейнере с собственной bridge-сетью: тест меняет адреса, маршруты и nftables **внутри контейнера**. Не используй `--network host`, Docker socket или сеть рабочего сервера. Внешняя нода и её конфигурация не меняются.

Нужны Linux-бинарник Xray 26.11.9 с native TUN и установленная Suricata 8+ с nDPI. YAML движка и все его зависимости должны оставаться доступны по тем же абсолютным путям внутри контейнера. Образ из `tests/docker` содержит необходимые системные библиотеки; systemd в этом тесте не запускается. Пример для Linux из корня проекта:

```bash
ENGINE_PREFIX=/абсолютный/путь/к/префиксу/движка
SURICATA_CONFIG="$ENGINE_PREFIX/etc/suricata/suricata.yaml"
XRAY_BINARY=/абсолютный/путь/к/xray
URI_FILE=/защищённый/путь/node.link
RESULTS_DIR=$(mktemp -d /tmp/xray-external-results.XXXXXX)
docker build -t xray-guard-systemd-test:local tests/docker
docker run --rm --name xray-guard-external-test --network bridge \
  --cap-add NET_ADMIN --device /dev/net/tun \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --mount "type=bind,source=$ENGINE_PREFIX,target=$ENGINE_PREFIX,readonly" \
  --mount "type=bind,source=$XRAY_BINARY,target=/fixtures/xray,readonly" \
  --mount "type=bind,source=$URI_FILE,target=/run/node.link,readonly" \
  --mount "type=bind,source=$RESULTS_DIR,target=/results" \
  --env XRAY_GUARD_EXTERNAL_TEST=1 --env PYTHONDONTWRITEBYTECODE=1 \
  --env PYTHONPATH=/repo/src --entrypoint python3 \
  xray-guard-systemd-test:local -u -B /repo/tests/integration/test_external_inspection.py \
  --uri-file /run/node.link --output /results/run --xray /fixtures/xray \
  --binary "$ENGINE_PREFIX/bin/suricata" --suricata-config "$SURICATA_CONFIG" \
  --expected-exit-ip ПУБЛИЧНЫЙ_IP_ВЫХОДА --trace
```

Имя контейнера должно быть свободным. `--expected-exit-ip` необязателен, но позволяет проверить именно ожидаемый выход. Конфигурации с URI создаются во временном каталоге контейнера и удаляются при завершении; URI, UUID и параметры аутентификации в отчёт не записываются. Файл `node.link` остаётся у владельца. `--trace` сохраняет тестовый plaintext-трафик TUN; публиковать этот захват не нужно.

Проверяются HTTPS и UDP DNS до/после включения DPI, блокировка настоящими nDPI/NFQUEUE, IP-баны обоих клиентов на 600 секунд и сохранение HTTPS/DNS третьего клиента. Guard вызывается через производственные `Correlator`/`Firewall` в тестовом процессе, а не через systemd; nftables и `ss -K` настоящие. Затем тест останавливает Suricata и временно запрещает TCP к адресу внешней ноды: в обоих случаях контрольный HTTPS должен перестать работать без перехода в DIRECT и восстановиться после снятия неисправности.

Трафик ограничен BitTorrent handshake к пяти публичным TCP-адресам и пятью DHT-запросами к каждому из шести публичных bootstrap-IP, без скачивания раздач. Все DHT-направления используют один UDP-сокет; порог бана остаётся пять сопоставленных потоков и пиров. Шестой адрес учитывает консервативный отказ сопоставлять первый поток, если его `flow.start` чуть раньше INFO-записи открытия сокета. Проверка поколения сокета не ослабляется. nDPI может пропустить начальные пакеты до окончания распознавания; тест не гарантирует блокировку первого пакета или всех разновидностей зашифрованного P2P.

[Успешный внешний прогон от 27.11.2026](results/external-vless.json) выполнен с RAW/REALITY **без `flow`**: выходной IP подтверждён до/после DPI и банов. Предыдущая ссылка с Vision не передавала HTTP/HTTPS; её результат в [историческом отчёте](results/vless-raw-vision.json) не подменяет проверку исправленного ключа.

## Marzban в Docker с настоящим systemd

Полный контейнерный стенд с настоящими Marzban, systemd и отдельным Docker Engine описан в [docker/README.md](docker/README.md). В отличие от теста установщика, службы здесь не подменяются; проверяются также SSH/HTTPS, рестарты контейнера и откат TUN-настроек. Этот стенд привилегированный и не должен запускаться на рабочей ноде.

[Отчёт прогона Marzban 0.8.4 от 26.11.2026](results/marzban-docker.json): сравнение Xray 26.3.27 и 26.11.9, 14 сценариев с учётом холодного старта, фактические баны и ограничения проверки. Отрицательные сценарии потери SSH при глобальном TUN default route и прохождения трафика после явного снятия очереди указаны отдельно, а не объявлены безопасными режимами.

## Сравнение масок протоколов nDPI

Эксперимент собирает Suricata и nDPI из тех же закреплённых исходников, что и установщик. Затем собирает второй плагин, в котором только рабочая маска `OnThreadInit` заменена на BitTorrent. Конфигурация проекта и установленный движок при этом не меняются.

Запускать на отдельной Linux-машине для тестов: сборка и PCAP требуют времени и нескольких ГБ диска. Пакеты устанавливаются в приватные overlay-каталоги через `unshare --mount`; сервисы и правила firewall хоста не меняются. Каталог `--output` должен быть новым:

```bash
sudo env PYTHONPATH="$PWD/src" unshare --mount python3 -B \
  tests/integration/build_ndpi_mask_comparison.py \
  --output /tmp/xray-ndpi-mask-comparison
```

В каталоге останутся `results.json`, `manifest.json`, журнал сборки, исходники обоих вариантов плагина, тестовые PCAP и журналы прогонов. В репозиторий захваты трафика не добавляются.

Проверяются TCP BitTorrent, DHT и uTP по IPv4/IPv6, HTTP, TLS, DNS, NTP, неизвестный UDP и HTTP-файл с байтами BitTorrent handshake. Дополнительно проигрывается выборка PCAP из тестов nDPI. Отчёт показывает новые и потерянные срабатывания; наличие отличий — результат эксперимента, а не ошибка запуска.

Для нагрузки используются новые веб-соединения, UDP-потоки и длинные веб-передачи. Каждый вариант сначала прогревается, затем запускается четыре раза с чередованием порядка на одном CPU. Сравнивается медиана процессорного времени Suricata, включая запуск и запись EVE, но без генерации PCAP и компиляции. Это локальный офлайн-замер: он не измеряет расходы NFQUEUE и не предсказывает процент снижения нагрузки на сервере.

### Результат для Suricata 8.0.8 + nDPI 4.14

Локальное сравнение в WSL на одном CPU дало следующие медианы CPU-времени. [Полный отчёт с отдельными прогонами](results/ndpi-mask-comparison.json).

| Нагрузка | Пакеты | Все протоколы, с | Только BitTorrent, с | Изменение |
| --- | ---: | ---: | ---: | ---: |
| 16 000 новых HTTP/TLS-потоков | 416 000 | 1,348 | 1,125 | −16,5% |
| 20 000 UDP-потоков: DNS/NTP/неизвестный | 200 000 | 0,619 | 0,441 | −28,7% |
| 1 000 длинных HTTP/TLS-передач | 522 000 | 0,729 | 0,703 | −3,6% |

Для длинных передач диапазоны отдельных прогонов перекрываются; устойчивый выигрыш такого размера не подтверждён. Дополнительный прогон с одним UDP-пакетом оценил запуск и завершение в 0,119 с и 0,107 с соответственно. Память и расходы NFQUEUE не измерялись.

В 18 синтетических сценариях обе маски распознали TCP BitTorrent, DHT и uTP по IPv4/IPv6. Полная маска не дала ложных срабатываний. Маска только BitTorrent дала два: обычный HTTP-ответ с бинарным файлом, содержащим BitTorrent handshake, классифицировался как BitTorrent по IPv4 и IPv6. С полной маской эти же потоки классифицировались как HTTP. Это специально построенный контрпример; он не оценивает частоту таких ошибок на реальном трафике.

В нагрузочных прогонах с обычным трафиком обнаружены дополнительные ложные срабатывания маски только BitTorrent: HTTP с исходным портом клиента `51413`, TLS с портом `53646` и NTP с портом `51413`. В EVE указана уверенность `Match by port`. Ошибки повторились во всех четырёх прогонах: два потока из 16 000 новых веб-потоков и один из 20 000 UDP-потоков. Полная маска не дала срабатываний в этих нагрузках. В тесте с HTTP-файлом уверенность была `DPI`, поэтому одним запретом догадок по порту все найденные ошибки не устраняются.

На 18 PCAP из тестов nDPI число срабатываний совпало: 24, 1 и 2 BitTorrent-потока в трёх соответствующих захватах, ноль срабатываний в остальных 15 захватах HTTP/TLS/QUIC/DNS/NTP.

Маска только BitTorrent **не включена в установщик**: эксперимент показал экономию CPU на части нагрузок и изменение классификации, способное вызвать ложную блокировку HTTP.
