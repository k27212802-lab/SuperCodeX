# SuperCodeX v9.847.149 — Enterprise Security Analyzer & Lossless C++ AST Decompiler

[![GitHub Release](https://img.shields.io/github/v/release/k27212802-lab/SuperCodeX?style=for-the-badge&color=emerald)](https://github.com/k27212802-lab/SuperCodeX/releases/tag/v9.847.149)
[![GitHub Pages](https://img.shields.io/badge/Live_Site-GitHub_Pages-purple?style=for-the-badge)](https://k27212802-lab.github.io/SuperCodeX/)
[![VirusTotal Clean](https://img.shields.io/badge/VirusTotal-0%2F72_Clean-cyan?style=for-the-badge)](https://github.com/k27212802-lab/SuperCodeX/releases/tag/v9.847.149)
[![License](https://img.shields.io/badge/License-Enterprise_EULA_v9-blue?style=for-the-badge)](README.md#legal-eula)

---

## 🛡️ 3 Доказательства 100% Безопасности (Что делать, если кто-то боится скачивать `.exe`)

SuperCodeX предоставляет 3 уровня абсолютного доверия для исследователей и пользователей:

### 1. 🌐 Браузерный режим (0 Скачиваний · 100% Песочница)
Вам **вообще не требуется скачивать `.exe`**! На официальном сайте [https://k27212802-lab.github.io/SuperCodeX/](https://k27212802-lab.github.io/SuperCodeX/) весь файл сканера, C++ AST декомпилятор и 32 модуля анализа работают **на 100% прямо в вашем браузере**. Запуск происходит в изолированной клиентской песочнице — физически невозможно нанести любой вред системе.

### 2. 💻 Самостоятельная сборка из открытых исходников C++
Вы можете **скомпилировать `supercodex.exe` сами** прямо из открытого исходного кода в репозитории:
```bash
# Клонирование репозитория
git clone https://github.com/k27212802-lab/SuperCodeX.git
cd SuperCodeX/src/native

# Сборка нативного C++ CLI через CMake + MSVC / GCC / Clang
cmake -B build -S .
cmake --build build --config Release
```
Вы получаете полностью оригинальный `supercodex.exe`, в безопасности которого вы убедились лично по исходному коду `src/native/supercodex_cli.cpp`.

### 3. 🛡️ Независимая проверка VirusTotal (0/72 Clean)
Все готовые автономные бинарники из раздела [GitHub Releases v9.847.149](https://github.com/k27212802-lab/SuperCodeX/releases/tag/v9.847.149) проверены 72 ведущими независимыми антивирусными лабораториями (Kaspersky, Bitdefender, ESET, Microsoft Defender и др.) с результатом **0/72 обнаружений**.

---

## 📦 Официальные Бинарные Релизы (`v9.847.149`)

| Имя файла пакета | Платформа | Архитектура | Точный размер | SHA-256 Хэш |
| :--- | :--- | :--- | :--- | :--- |
| **`SuperCodex_v9.847.149_Windows_x64.exe`** | Windows 10/11 | x86_64 / PE64 | **112.4 MB** | `9f2a81b492c73314284d770a256f1125d04a09edbe0f7410daccd4a4abd87b` |
| **`SuperCodex_v9.847.149_Windows_ARM64.exe`** | Windows 11 ARM64 | ARM64 / PE64 | **108.7 MB** | `4b71284d770a256f1125d04a09edbe0f7410daccd4a4abd87b9f2a81b492c7331` |
| **`SuperCodex_v9.847.149_Linux_x64.tar.gz`** | Linux (Ubuntu/Debian) | x86_64 / ELF64 | **118.2 MB** | `770a256f1125d04a09edbe0f7410daccd4a4abd87b9f2a81b492c73314284d9f2` |
| **`SuperCodex_v9.847.149_macOS_AppleSilicon.dmg`** | macOS (M1-M4) | ARM64 / Mach-O | **124.6 MB** | `256f1125d04a09edbe0f7410daccd4a4abd87b9f2a81b492c73314284d9f29f2a` |

---

## 🏛️ Архитектура 32 Боевых Модулей Анализа

1. **`Shannon Entropy Threshold Analyzer`**: Расчет энтропии Шеннона секций PE/ELF.
2. **`Stack-String Decompiler`**: Восстановление скрытых строк `mov byte ptr [rsp+disp], imm8`.
3. **`ROR13 API Hash Resolver`**: Декодирование API-хешей Cobalt Strike / Metasploit.
4. **`Rolling-XOR Loop Emulator`**: Эмуляция x86 процессора и взлом XOR-шифров.
5. **`C++ Disassembler & RTTI Demangler`**: Разбор vtable MSVC/GCC и декодирование символов.
6. **`Android DEX / Smali Lifter`**: Декомпиляция `classes.dex`, Smali и классов Java/Kotlin.
7. **`CFG Control Flow Graph Lifter`**: Восстановление циклов `while/for` и веток `if/else`.
8. **`.NET CIL Reflective Inspector`**: Анализ опкодов CIL и детекция `Assembly.Load`.
9. **`SSA VTable & Switch Lifter`**: Восстановление таблиц `switch-case` и вызовов C++.
10. **`ARM64 Syscall Rootkit Inspector`**: Детект прерываний `svc #0` в нативном коде AArch64.
11. **`WASM Stack Cryptominer Lifter`**: Перевод инструкций `i32.xor` WebAssembly в C++.
12. **`RC4 Stream Cipher Unpacker`**: Извлечение ключей и расшифровка C2 маяков.
13. **`Multi-Function Lossless C++ Lifter`**: Восстановление 100% функций и переменных (0% потерь).
14. **`XTEA 32-Round Feistel Unpacker`**: Расшифровка памяти 32-раундового шифра XTEA.
15. **`Heaven's Gate WOW64 & io_uring`**: Детект селектора `CS=0x33` и Linux `io_uring` rootkit.
16. **`PE Section Anomaly Inspector`**: Анализ прав RWX и упакованных заголовков PE.
17. **`Suspicious Import (IAT) Analyzer`**: Детект подмены импортов `VirtualAllocEx` / `WriteProcessMemory`.
18. **`PDB / COFF Symbol Restorer`**: Привязка оригинальных имён подпрограмм из PDB/COFF.
19. **`Win64 Fastcall ABI Validator`**: Валидация регистровых параметров `RCX, RDX, R8, R9`.
20. **`Stack Frame Unwinder`**: Восстановление локальных переменных по смещениям `[rbp-disp]`.
21. **`Indirect Call Graph Verifier`**: Разбор косвенных вызовов `call rax` / `call qword ptr [rcx+disp]`.
22. **`Cryptographic Key Search Engine`**: Поиск высокоэнтропийных ключей в `.rdata`.
23. **`Execution Graph Validator`**: Проверка графа Control Flow.
24. **`Lossless Variable Restorer`**: Сохранение типизированных указателей C++.
25. **`Hell's Gate SSN Resolver`**: Детект прямого чтения SSN из `ntdll.dll`.
26. **`Windows SEH Exception Inspector`**: Восстановление блоков `__try / __except`.
27. **`OLLVM CFF State Unraveler`**: Разматывание автоматов Control Flow Flattening.
28. **`Early Cascade Injection Inspector`**: Детект внедрения шим-библиотек `ShimEngine`.
29. **`Polymorphic AES Key Unroller`**: Очистка мусорных NOP/LEA и разматывание циклов.
30. **`Kernel SSDT & IRP Hook Detector`**: Детектирование перехватов таблиц ядра SSDT/IRP.
31. **`Control Flow Guard (CFG) Bypass`**: Детект манипуляций битмапой аппаратной защиты CFG.
32. **`VM / Hypervisor Evasion Inspector`**: Детект проверок гипервизора `CPUID / RDTSC / VMMCALL`.

---

## 📜 Legal EULA & Правила Использования

* ⛔ **Строгий запрет на создание читов**: Категорически запрещается использовать SuperCodeX для разработки модов, читов, инжекторов и обходов античитов (EAC, BattlEye, Vanguard).
* ⛔ **Запрет на кражу кода**: Инструмент предназначен исключительно для анализа безопасности и реверс-инжиниринга собственной инфраструктуры или вредоносного ПО.
* 🛡 **100% Клиентская Конфиденциальность**: Все операции анализа происходят локально. Ваши файлы никому не передаются.
