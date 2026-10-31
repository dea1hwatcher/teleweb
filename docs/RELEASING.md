# Релизы TeleWEB

Релиз собирается из трёх платформенных веток в **один** GitHub Release
с единым тегом и версией. Код веток различается платформенным слоем,
поэтому общие фиксы переносятся cherry-pick'ом до релиза.

| Ветка | Что собирает |
| :--- | :--- |
| `android` | `teleweb-<ver>-multiarch.zip` — модуль Magisk/KernelSU/APatch (сборка 4 linux-арх через `package_zip.py`) |
| `win` | `tgws-windows-{amd64,386,arm64}.exe`, `teleweb-windows-{amd64,386,arm64}.zip/.tar.gz` |
| `linux` | `teleweb-linux-{amd64,arm64}.zip/.tar.gz` |

Тег может указывать только на один коммит, поэтому роли разделены:
Android-прогон создаёт релиз, desktop-прогоны прикрепляют к нему свои ассеты.

## 1. Подготовка

1. Убедиться, что нужные фиксы есть во всех трёх ветках (cherry-pick, не merge).
2. В `android` обновить:
   - `module.prop`: `version=vX.Y.Z`, `versionCode` = предыдущий + 1;
   - `update.json`: version/versionCode/zipUrl на новый тег;
   - `changelog.md`: раздел `### Изменения в vX.Y.Z:` первым.
3. Добавить тот же раздел `### Изменения в vX.Y.Z:` в `changelog.md` веток
   `win` и `linux`. Заметки релиза каждый прогон собирает из changelog своей
   ветки и **перезаписывает notes**; без раздела возьмётся весь файл.

## 2. Android-модуль (создаёт релиз)

```bash
git checkout android
git add module.prop update.json changelog.md
git commit -s -m "chore: release vX.Y.Z"
git push origin android
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z
```

Workflow `release` в ветке `android`: проверяет `module.prop == тег`,
собирает zip через `package_zip.py`, публикует GitHub Release и обновляет
`update.json` на `master`.

## 3. Desktop-пакеты (дополняют релиз)

После успешного Android-прогона запустить workflow `release` в ветках
`win` и `linux` с input `tag: vX.Y.Z`:

- GitHub → Actions → `release` → **Run workflow** → ветка `win` (затем `linux`),
  поле `tag` = `vX.Y.Z`;
- или через API (нужен токен с правом Actions):

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/dea1hwatcher/teleweb/actions/workflows/release.yml/dispatches \
  -d '{"ref":"win","inputs":{"tag":"vX.Y.Z"}}'
```

Повторить с `"ref":"linux"`. Каждый прогон собирает `build_desktop.ps1`
и прикрепляет `dist/*` к существующему релизу (`gh release upload --clobber`).

## 4. Проверка релиза

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
