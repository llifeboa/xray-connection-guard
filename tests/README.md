# Тесты

Команды выполняются из корня проекта на Linux. Нужны Python 3 и PyYAML.

## Модульные тесты

```bash
PYTHONPATH="$PWD/src" python3 -B -m unittest discover -s tests/unit -v
bash -n manage.sh
```

## Интеграционные тесты

Нужны права root, `unshare`, `ip`, `ss` и `nft`. Проверки используют отдельные сетевые пространства имён; тест установщика также изолирует каталоги установки и подменяет systemd и Suricata.

```bash
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_integration.py
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_integration.py --xudp
sudo env PYTHONPATH="$PWD/src" unshare --net python3 -B tests/integration/test_linux_network.py
sudo env PYTHONPATH="$PWD/src" unshare --mount --net python3 -B tests/integration/test_linux_installer.py
```

## Полная сборка Suricata и nDPI

Отдельная проверка скачивает зависимости, собирает движок в изолированных каталогах, проверяет распознавание BitTorrent на тестовом PCAP и повторную установку. Нужны интернет и несколько минут.

```bash
sudo env PYTHONPATH="$PWD/src" unshare --mount python3 -B tests/integration/test_linux_bootstrap.py
```

Для проверки уже установленного движка на тестовом PCAP:

```bash
sudo env PYTHONPATH="$PWD/src" python3 -B tests/integration/test_suricata_capture.py /путь/к/suricata /etc/xray-connection-guard/suricata.yaml
```
