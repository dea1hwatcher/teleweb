# Релизы TeleWEB

Релиз собирается из трёх платформенных веток в **один** GitHub Release
с единым тегом и версией. Код веток различается платформенным слоем,
поэтому общие фиксы переносятся cherry-pick'ом до релиза.

| Ветка | Что собирает |
| :--- | :--- |
| `android` | `teleweb-<ver>-multiarch.zip` — модуль Magisk/KernelSU/APatch (сборка 4 linux-арх через `package_zip.py`) |
| `win` | `tgws-windows-{amd64,386,arm64}.exe`, `teleweb-windows-{amd64,386,arm64}.zip/.tar.gz` |
| `linux` | `teleweb-linux-{amd64,arm64}.zip/.tar.gz` |

Тег указывает на коммит в ветке `android`. Единый workflow `release`
собирает модуль Android, подтягивает ветки `win` и `linux`, собирает все
десктопные пакеты, верифицирует комплект из 14 ассетов и публикует их
в GitHub Release за один прогон, после чего обновляет `update.json` на `master`.

## 1. Подготовка

1. Убедиться, что нужные фиксы есть во всех трёх ветках (cherry-pick, не merge).
2. **Сверка `dev` ↔ `android` перед каждым релизом**: ветки не мержатся, а
   черри-пикаются, поэтому фикс мог осесть только в одной из них. Проверить
   потерянные блоки:
   ```bash
   git diff android dev -- src/main.go src/ws_pool.go
   ```
   Дифф должен быть пустым. Каждый минус-блок — кандидат на потерянный
   cherry-pick (пример: `routeCacheTTL` из v0.1.5 оставался только в `android`).
3. В `android` обновить:
   - `module.prop`: `version=vX.Y.Z`, `versionCode` = предыдущий + 1;
   - `update.json`: version/versionCode/zipUrl на новый тег;
   - `changelog.md`: раздел `### Изменения в vX.Y.Z:` первым.
4. Добавить тот же раздел `### Изменения в vX.Y.Z:` в `changelog.md` веток
   `win` и `linux`. Заметки релиза каждый прогон собирает из changelog своей
   ветки и **перезаписывает notes**; без раздела возьмётся весь файл.

5. Предрелизная проверка окружения демона: `git grep -nE '^[[:space:]]*export[[:space:]]+GOMEMLIMIT' android -- '*.sh'`
   **должен не дать ни одной строки** (exit code 1). Ищем только активный `export`:
   `git grep` не отличает комментарии от кода, поэтому шаблон `grep -n GOMEMLIMIT`
   ложно срабатывал на поясняющем комментарии в самом `service.sh` и такой gate
   никогда не был бы «зелёным». Рантайм уважает `GOMEMLIMIT` из
   окружения даже когда Go-код его не ставит, поэтому экспорт в `service.sh`
   молча возвращает GC-спираль — так устроен инцидент v0.1.7–v0.1.9, где
   «исправленный» Go-код соседствовал с `export GOMEMLIMIT=48MiB` в скрипте.
   `GOGC` — единственная разрешённая ручка тюнинга сборщика. Тот же шаблон
   зашит в workflow `release` (шаг `Reject a forced GOMEMLIMIT`), поэтому релиз
   без проверки собрать нельзя.

## 2. Публикация релиза

```bash
git checkout android
git add module.prop update.json changelog.md
git commit -s -m "chore: release vX.Y.Z"
git push origin android
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Workflow `release`:
1. Проверяет `module.prop == тег` и отсутствие форсированного `GOMEMLIMIT`.
2. Собирает Android multiarch модуль через `package_zip.py`.
3. Подтягивает ветки `win` и `linux` и собирает все desktop-пакеты через `build_desktop.ps1`.
4. Проверяет, что собрано ровно **14 ассетов**.
5. Создаёт/обновляет GitHub Release со всеми 14 ассетами и заметками из `changelog.md`.
6. Обновляет `update.json` на `master` и пушит коммит.

### Ручной запуск (workflow_dispatch)

При необходимости пересобрать или дособрать релиз для существующего тега можно
запустить workflow `release` вручную через GitHub Actions (`workflow_dispatch`),
передав параметр `tag: vX.Y.Z`. CI выкачает соответствующий тег, соберёт все
14 ассетов и обновит релиз (`gh release upload --clobber`).

## 3. Проверка релиза

- В релизе **14 ассетов**: 1 модуль + 9 Windows (3 exe, 6 архивов) + 4 Linux
  (2 zip, 2 tar.gz).
- Notes содержат все пункты версии.
- `update.json` на `master` указывает на новую версию, zipUrl отдаёт HTTP 200.
- `changelog.md` на `master` содержит раздел версии — его читает диалог
  обновления Magisk/KernelSU.

## Пересоздание уже выпущенного релиза

1. Удалить GitHub Release (ассеты удалятся вместе с ним).
2. Переставить тег на нужный коммит ветки `android`:
   ```bash
   git tag -fa vX.Y.Z -m "vX.Y.Z" <commit>
   git push --force origin vX.Y.Z
   ```
3. Повторить шаги 2–4. CI пересоздаст релиз; desktop-прогоны перезапишут
   notes и ассеты (`--clobber`).

## Замечания

- Desktop-прогон без раздела версии в changelog своей ветки затрёт notes
  релиза целиком (fallback «весь changelog»).
- `update.json` и `changelog.md` на `master` — витрина обновлений для
  устройств; обычно их обновляет CI, при ручной правке коммитить в `master`.
- Локальная проверка сборок до тега: `python package_zip.py` в `android`,
  `powershell -File build_desktop.ps1` в `win`/`linux`.
