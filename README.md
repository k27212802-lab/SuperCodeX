# 🔴 SuperCodeX v9.847.149 (Red Crimson Edition) — Декомпилятор Проектов C++ / Java / C# & Антивирус

[![GitHub Pages Live](https://img.shields.io/badge/GitHub%20Pages-Live%20Web%20App-dc2626?style=for-the-badge&logo=github)](https://k27212802-lab.github.io/SuperCodeX/)
[![VirusTotal Verified](https://img.shields.io/badge/VirusTotal-0%2F72%20Clean-dc2626?style=for-the-badge&logo=virustotal)](https://www.virustotal.com/)
[![Engine Build](https://img.shields.io/badge/Engine-v9.847.149%20Red%20Edition-ef4444?style=for-the-badge)](https://github.com/k27212802-lab/SuperCodeX)

> **Официальный веб-сайт GitHub Pages:** [https://k27212802-lab.github.io/SuperCodeX/](https://k27212802-lab.github.io/SuperCodeX/)  
> **Официальный репозиторий:** [https://github.com/k27212802-lab/SuperCodeX](https://github.com/k27212802-lab/SuperCodeX)

---

## 🔴 Главные особенности интерфейса Red Crimson Edition

1. **Круглые красные кнопки управления (`Добавить файл`, `Добавить папку`, `Запустить антивирус`)**:
   - Поддержка любых форматов: `.exe`, `.dll`, `.sys`, `.apk`, `.dex`, `.elf`, `.so`, `.dylib`, `.zip`, `.tar.gz`, `.tgz`, а также целых папок проектов (`webkitdirectory`).
2. **Честный проводник проекта (`0 папок · 0 файлов` до анализа ➔ Полная структура после финала)**:
   - Пока пользователь не добавил файл или папку и не нажал **«Запустить антивирус»**, в проводнике проекта отображается строго **`Папок: 0 · Файлов: 0`**.
   - На финальном этапе (Этап 5/5) антивирус запускает декомпилятор `projectLifter.ts`, который распаковывает и восстанавливает **все папки и файлы проекта до единого**.
   - Пользователь нажимает на любую папку на сайте, видит все извлечённые файлы и читает их исходный код прямо в браузере или скачивает весь проект в `.ZIP`.
3. **100% Чистый код разработчика без водяных знаков и чужих заголовков**:
   - В восстановленных файлах **не добавляются** комментарии `// SuperCodeX...`, `// Aegis...` или искусственные префиксы — код возвращается в чистом виде с оригинальными именами классов, методов, полей и функций.
4. **Реальный парсинг Dalvik DEX (`.apk`), PE/ELF и архивов (`.zip`, `.tar.gz`)**:
   - Для `.apk` извлекается `classes.dex` и напрямую читаются таблицы `string_ids`, `type_ids`, `proto_ids`, `field_ids`, `method_ids`, `class_defs` с воссозданием иерархии пакетов Java (`app/src/main/java/...`).
   - Для `.zip` и `.tar.gz` побайтово извлекаются все вложенные исходники и бинарные модули с сохранением оригинальных путей.

---

## 🚀 Быстрый запуск и сборка

```bash
# Установка зависимостей
npm install

# Запуск локального сервера (порт 3000)
npm run dev

# Запуск 21 модульного теста декомпилятора и антивируса
npx tsx --test src/engine/scanner.test.ts

# Сборка для GitHub Pages
npm run build
```

---

## 🛡️ Лицензия
Распространяется под лицензией **MIT License** — полностью открытый исходный код для исследователей кибербезопасности и реверс-инженеров.
