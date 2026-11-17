# Тестовые векторы TUF (оракул python-tuf)

Каталог содержит TUF-репозитории, собранные **эталонной реализацией python-tuf** (`tuf==7.0.1`), а не
нашим кодом: Rust-верификатор `oncl-update` проверяется ими независимо от самого себя.

- `valid/` — корректный репозиторий в раскладке контракта (корень сайта `…/tuf/v1/`):
  `metadata/{1,2,3}.root.json`, `metadata/timestamp.json`, `metadata/2.snapshot.json`,
  `metadata/2.targets.json`, `targets/indexes/<sha256>.stable.json` и `….beta.json`
  (`consistent_snapshot: true`). Цели — `indexes/stable.json` и `indexes/beta.json`
  (маленькие синтетические индексы). Пакеты в репозиторий не входят.
- `<имя-атаки>/` — минимальные мутации `valid/` (полная копия с изменёнными файлами). В каждом лежит
  `expected.json`: шаг, на котором клиент обязан отказать (`must_fail_at`), класс ошибки словами
  (`error_class`), изменённые файлы (`changed_files_vs_valid`), предыдущее состояние клиента
  (`prior_state`) и вердикт python-tuf.
- `keys.json` — id, публичные ключи и сиды всех шести **синтетических тестовых ключей**. Они
  сгенерированы только для тестов, нигде не используются и не имеют отношения к реальным ключам
  проекта: `seed = sha256("oncl-tuf-oracle-v1/" + имя)`.

## Контракт, который воспроизводят векторы

Ed25519 (`keytype`/`scheme` = `ed25519`); `keyid` — hex sha256 канонического JSON (OLPC) объекта
ключа `{keytype, scheme, keyval:{public}}`; подпись — над каноническим JSON объекта `signed`.

| Корень | root | targets | snapshot | timestamp |
|---|---|---|---|---|
| v1 | `root-a` | `targets` | `snapshot` | `timestamp-1` |
| v2 | `root-a` | `targets` | `snapshot` | `timestamp-2` (ротация) |
| v3 | `root-b` (ротация, подписан `root-a` и `root-b`) | `targets` | `snapshot` | `timestamp-2` |

Порог каждой роли — 1. Доверенный якорь клиента — `valid/metadata/1.root.json`. Все файлы подписаны
в `2026-11-15T00:00:00Z`; **часы проверки фиксированы**: `2026-11-16T00:00:00Z` (`now` в
`expected.json`). Сроки: root 365 дней, targets и snapshot 30, timestamp 7. `version` timestamp —
Unix-время подписи (`1794700800`); snapshot и targets в `valid/` версии 2 (версии 1 лежат только в
репозиториях откатов). В реальном репозитории `timestamp.json` не коммитится; здесь он есть, чтобы
вектор был самодостаточным. В метаданных `snapshot`/`timestamp` указаны только `version` (без `length`
и `hashes`).

Отрицательные репозитории с `prior_state` (откаты) проверяются так: сначала клиент полностью
принимает `valid/` на тех же часах, затем получает репозиторий атаки с тем же локальным состоянием.
Пара файлов откатов:

- `rollback-timestamp`: `metadata/timestamp.json` с версией `1794697200` (< `1794700800`).
- `rollback-snapshot`: `metadata/timestamp.json` версии `1794704400`, указывающий на snapshot v1, и
  `metadata/1.snapshot.json` (+ `1.targets.json`) после принятого snapshot v2.
- `rollback-targets`: `metadata/timestamp.json` версии `1794708000`, `metadata/3.snapshot.json` с
  записью `targets.json` версии 1 и `metadata/1.targets.json` после принятого targets v2.

## Перегенерация

```sh
python3 -m venv /mnt/d/oncl-tuf-venv        # WSL Ubuntu
/mnt/d/oncl-tuf-venv/bin/pip install tuf==7.0.1 cryptography==50.0.2
/mnt/d/oncl-tuf-venv/bin/python xtask/assets/tuf-oracle/gen.py
```

Скрипт детерминирован (ключи из фиксированных сидов, подписи Ed25519 детерминированы): повторный
запуск не меняет ни байта. Он пересоздаёт все каталоги репозиториев, затем прогоняет
`tuf.ngclient.Updater` через локальный `http.server` по каждому репозиторию и печатает таблицу
вердиктов. Код выхода ненулевой, если вердикт python-tuf отличается от ожидаемого.

## Вердикты python-tuf (`tuf==7.0.1`)

| Репозиторий | python-tuf | Где отказал |
|---|---|---|
| `valid` | принят, оба индекса скачаны | — |
| `expired-timestamp` | отказ | timestamp: `ExpiredMetadataError` |
| `expired-snapshot` | отказ | snapshot: `ExpiredMetadataError` |
| `expired-targets` | отказ | targets: `ExpiredMetadataError` |
| `rollback-timestamp` | отказ | `BadVersionNumberError` |
| `rollback-snapshot` | отказ | `BadVersionNumberError` |
| `rollback-targets` | отказ | targets: `BadVersionNumberError` |
| `bad-signature-targets` | отказ | `UnsignedMetadataError` |
| `threshold-not-met` | отказ | root: `UnsignedMetadataError` (1 из 2) |
| `wrong-keyid-in-root` | **принят** (расхождение с контрактом, см. ниже) | — |
| `tampered-unknown-field` | отказ | `UnsignedMetadataError` |
| `target-hash-mismatch` | отказ | цель: `LengthOrHashMismatchError` |
| `target-length-mismatch` | отказ | цель: `DownloadLengthMismatchError` |
| `root-version-gap` | отказ | root: `BadVersionNumberError` |
| `new-root-signed-only-by-new-keys` | отказ | root: `UnsignedMetadataError` |

## Чем python-tuf отличается от контракта

Прохождение python-tuf **не означает** прохождения контракта проекта. Python-tuf шире нашего клиента:

- **`keyid` не проверяется.** `wrong-keyid-in-root` python-tuf принимает; наш клиент обязан отказать
  (пересчитывает sha256 канонической формы и сверяет с ключом словаря `keys`). Для этого вектора
  ожидание — отказ по контракту, а не по python-tuf.
- Принимает RSA, ECDSA и другие `keytype`/`scheme` (в т. ч. устаревшие), наш клиент — только `ed25519`.
- Выполняет делегирования (`delegations`, `paths`, `terminating`); наш клиент отказывает с явной
  ошибкой, если в targets есть `delegations`.
- Принимает хеши, кроме sha256, и `path_hash_prefixes`; наш клиент — только sha256, без префиксов.
- Не требует `consistent_snapshot: true` и принимает любые пороги у любых ролей.
- Не знает про индекс: `channel`, `seq` и срок `MAX_AGE` (который в режиме TUF у нас не применяется)
  вне его компетенции; пакеты и их sha256/размер он тоже не проверяет.
- Лимиты размеров и число ротаций root (`UpdaterConfig`) — свои, не наши.
- Часы подставляются из скрипта (`reference_time`); клиент по умолчанию берёт системные.
- Для откатов python-tuf может отказать на другом шаге, чем строго требует спецификация
  (`rollback-targets`: на шаге targets, а не snapshot); `must_fail_at` допускает оба.
