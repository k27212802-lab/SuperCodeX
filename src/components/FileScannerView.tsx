import React, { useState } from 'react';
import { ScanReport } from '../engine/scanner';
import { BENCHMARK_SAMPLES, BenchmarkSample } from '../engine/benchmark';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Upload,
  FileCode,
  Binary,
  Hash,
  Terminal,
  Download,
  Layers,
  Cpu,
  KeyRound,
  Globe,
  RefreshCw,
  CheckCircle2,
  XCircle,
} from 'lucide-react';
import { queryVirusTotalFileReport } from '../engine/virustotal';

interface FileScannerViewProps {
  currentReport: ScanReport;
  isScanning: boolean;
  onScanBytes: (fileName: string, bytes: Uint8Array) => void;
}

export const FileScannerView: React.FC<FileScannerViewProps> = ({
  currentReport,
  isScanning,
  onScanBytes,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<
    'rules' | 'decompiler' | 'opcodes' | 'headers' | 'strings' | 'hex'
  >('decompiler');
  const [isCheckingVt, setIsCheckingVt] = useState(false);
  const [vtCheckResult, setVtCheckResult] = useState<any | null>(null);
  const [vtError, setVtError] = useState<string | null>(null);

  const handleCheckCurrentFileOnVirusTotal = async () => {
    setIsCheckingVt(true);
    setVtError(null);
    try {
      const res = await queryVirusTotalFileReport(currentReport.hashes.sha256);
      if (res.success && res.stats) {
        setVtCheckResult(res);
      } else {
        setVtError(res.error || 'Файл с данным хэшем ещё не был загружен в VirusTotal.');
      }
    } catch (e: any) {
      setVtError(e.message || String(e));
    } finally {
      setIsCheckingVt(false);
    }
  };

  const handleFileInput = async (file: File) => {
    const buffer = await file.arrayBuffer();
    onScanBytes(file.name, new Uint8Array(buffer));
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await handleFileInput(e.dataTransfer.files[0]);
    }
  };

  const handlePresetSample = (sample: BenchmarkSample) => {
    const bytes = sample.buildBytes();
    onScanBytes(sample.fileName, bytes);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `aegis-v5-report-${currentReport.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportDecompiledSource = () => {
    const isJava =
      currentReport.decompilation.targetLanguage ===
      'Java / Smali (Android APK & Dalvik DEX Decompiler)';
    const isCSharp =
      currentReport.decompilation.targetLanguage ===
      'C# / CIL (.NET Managed Assembly Decompiler)';
    const isWasm =
      currentReport.decompilation.targetLanguage ===
      'C / C++ (WebAssembly .WASM Stack-Machine to C AST Decompiler)';
    const ext = isJava ? 'java' : isCSharp ? 'cs' : isWasm ? 'c' : 'cpp';
    const blob = new Blob([currentReport.decompilation.reconstructedCode], {
      type: 'text/plain;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${currentReport.fileName}.decompiled.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const verdictBadgeColor =
    currentReport.verdict === 'MALICIOUS'
      ? 'text-red-400 bg-red-950/50 border-red-800/70'
      : currentReport.verdict === 'SUSPICIOUS'
      ? 'text-amber-300 bg-amber-950/50 border-amber-800/70'
      : 'text-emerald-300 bg-emerald-950/50 border-emerald-800/70';

  const quickPresets = [
    BENCHMARK_SAMPLES[25], // BM-26: Multi-Function C++ Call-Graph & Full Stack-Variable ALU Implant with PDB Symbols (.exe)
    BENCHMARK_SAMPLES[26], // BM-27: XTEA 32-Round Feistel Block Cipher (Delta 0x9E3779B9) Encrypted C2 Loader (.exe)
    BENCHMARK_SAMPLES[27], // BM-28: Heaven's Gate WOW64 (CS=0x33 Far Jump) Syscall Evasion Implant (.exe)
    BENCHMARK_SAMPLES[28], // BM-29: Linux io_uring (__NR_io_uring_setup=425) Syscall-less Ring-Buffer Rootkit (.elf)
    BENCHMARK_SAMPLES[21], // BM-22: C++ VTable [rax+0x18], Struct [rcx+0x10], Switch & Opaque Predicate APT (.exe)
    BENCHMARK_SAMPLES[31], // BM-32: Clean PE64 C++ Console Tool (Control)
  ];

  const qm = currentReport.decompilation.qualityMetrics;
  const cfg = currentReport.decompilation.cfgStats;

  return (
    <div className="space-y-6">
      {/* Upload & Quick Test Samples Zone */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-stretch">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragActive(true);
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={handleDrop}
          className={`lg:col-span-7 border rounded-lg p-6 transition-colors flex flex-col justify-between ${
            dragActive
              ? 'border-emerald-500 bg-emerald-950/20'
              : 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
          }`}
        >
          <div>
            <div className="flex items-center justify-between gap-4 mb-3">
              <h2 className="text-base font-semibold text-slate-100">
                Проверка любых файлов БЕЗ ЗАПУСКА + Декомпилятор C++ без потерь (Aegis v7)
              </h2>
              <span className="text-xs font-mono text-emerald-400 tabular-nums">
                24 модуля · 100% сохранение функций и переменных · XTEA / RC4 Unpacker
              </span>
            </div>
            <p className="text-sm text-slate-400 leading-relaxed mb-5">
              Перетащите любой исполняемый файл или скрипт (<code className="text-slate-300">.exe</code>,{' '}
              <code className="text-slate-300">.dll</code>, <code className="text-slate-300">.sys</code>,{' '}
              <code className="text-slate-300">ARM64 / x64 .elf</code>, <code className="text-slate-300">.wasm</code>,{' '}
              <code className="text-slate-300">.apk</code>, <code className="text-slate-300">classes.dex</code>,{' '}
              <code className="text-slate-300">.NET C#</code>, <code className="text-slate-300">OLE2</code>,{' '}
              <code className="text-slate-300">PDF</code>). <strong>Файл никогда не запускается в ОС</strong>: ядро{' '}
              <strong>Aegis v7 (24 боевых модуля)</strong> автоматически расшифровывает блочный шифр{' '}
              <strong>XTEA (32 раунда, delta=0x9E3779B9)</strong> и потоковый <strong>RC4 (KSA+PRGA)</strong>, ловит{' '}
              <strong>Heaven’s Gate WOW64 (CS=0x33)</strong> и руткиты <strong>Linux io_uring (№425)</strong>, а
              декомпилятор восстанавливает <strong>все функции и подпрограммы Call-Graph (`call sub_xxx`), 100% локальных переменных на стеке `[rbp-disp]` и арифметику ALU без удаления мертвых веток (0% потерь кода)</strong>.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-2">
            <label
              htmlFor="real-file-upload"
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium cursor-pointer transition-colors whitespace-nowrap shrink-0"
            >
              <Upload className="w-4 h-4" />
              <span>Выбрать любой файл с диска (проверка без запуска)</span>
              <input
                id="real-file-upload"
                type="file"
                className="sr-only"
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileInput(e.target.files[0]);
                  }
                }}
              />
            </label>

            <button
              type="button"
              onClick={handleExportJson}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-lg border border-slate-700 bg-slate-800/80 hover:bg-slate-800 text-slate-200 text-sm font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer"
            >
              <Download className="w-4 h-4" />
              <span>Скачать JSON-отчет</span>
            </button>
          </div>
        </div>

        {/* Instant Synthetic Byte Payloads for Verification */}
        <div className="lg:col-span-5 border border-slate-800 bg-slate-900/60 rounded-lg p-6 flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-semibold text-slate-200 mb-1">
              Новые тест-образцы v7: Multi-Function C++ + PDB, XTEA-32, Heaven’s Gate и io_uring
            </h3>
            <p className="text-xs text-slate-400 mb-3">
              Нажмите на любой образец, чтобы без запуска восстановить все функции и переменные C++ и проверить 24 модуля:
            </p>
            <div className="space-y-1.5">
              {quickPresets.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => handlePresetSample(sample)}
                  className="w-full text-left px-3 py-2 rounded border border-slate-800 bg-slate-950/70 hover:border-slate-700 hover:bg-slate-900 transition-colors flex items-center justify-between gap-3 cursor-pointer"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-slate-200 truncate">
                      {sample.name}
                    </div>
                    <div className="text-[11px] text-slate-400 font-mono truncate">
                      {sample.fileName} · {sample.category}
                    </div>
                  </div>
                  <span
                    className={`text-[11px] font-mono shrink-0 ${
                      sample.expectedMalicious ? 'text-red-400' : 'text-emerald-400'
                    }`}
                  >
                    {sample.expectedMalicious ? 'APT Угроза' : 'Чистый'}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Verdict Summary Header */}
      <div className={`border rounded-lg p-6 ${verdictBadgeColor}`}>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="flex items-start gap-4">
            <div className="p-3 rounded-lg bg-slate-950/60 border border-current/20 shrink-0">
              {currentReport.verdict === 'MALICIOUS' ? (
                <ShieldAlert className="w-7 h-7 text-red-400" />
              ) : currentReport.verdict === 'SUSPICIOUS' ? (
                <AlertTriangle className="w-7 h-7 text-amber-300" />
              ) : (
                <ShieldCheck className="w-7 h-7 text-emerald-400" />
              )}
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-300 mb-1">
                <span>Файл: {currentReport.fileName}</span>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">{currentReport.fileSize.toLocaleString('ru-RU')} байт</span>
                <span aria-hidden="true">·</span>
                <span className="tabular-nums">Статический разбор без запуска: {currentReport.scanDurationMs} мс</span>
              </div>
              <h2 className="text-xl font-bold tracking-tight text-white mb-1">
                Вердикт:{' '}
                {currentReport.verdict === 'MALICIOUS'
                  ? 'ВРЕДОНОСНЫЙ ОБЪЕКТ (MALICIOUS)'
                  : currentReport.verdict === 'SUSPICIOUS'
                  ? 'ПОДОЗРИТЕЛЬНЫЙ ОБЪЕКТ (SUSPICIOUS)'
                  : 'ЧИСТЫЙ ФАЙЛ (CLEAN)'}
              </h2>
              <p className="text-sm text-slate-200/90 max-w-3xl">
                {currentReport.verdictSummary}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-6 shrink-0 border-t md:border-t-0 pt-4 md:pt-0 border-current/20">
            <div className="text-right">
              <div className="text-xs text-slate-300">Индекс угрозы (Risk Score)</div>
              <div className="text-3xl font-bold font-mono tabular-nums text-white">
                {currentReport.riskScore}
                <span className="text-base font-normal text-slate-400">/100</span>
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-slate-300">Энтропия Шеннона</div>
              <div className="text-2xl font-bold font-mono tabular-nums text-white">
                {currentReport.entropy.globalShannon.toFixed(3)}
                <span className="text-xs font-normal text-slate-400"> / 8.0</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Telemetry & Cryptographic Fingerprint Bar */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="border border-slate-800 bg-slate-900/60 rounded-lg p-4">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Hash className="w-3.5 h-3.5 text-emerald-400" />
            <span>Криптографический отпечаток SHA-256</span>
          </div>
          <div className="font-mono text-xs text-slate-200 break-all select-all tabular-nums">
            {currentReport.hashes.sha256}
          </div>
          <div className="mt-2 text-xs text-slate-400 font-mono tabular-nums flex items-center justify-between">
            <span>FNV1a-32: <span className="text-slate-300">{currentReport.hashes.fnv1a32}</span></span>
          </div>
          <div className="mt-3 pt-2 border-t border-slate-800 flex flex-col gap-2">
            <button
              type="button"
              onClick={handleCheckCurrentFileOnVirusTotal}
              disabled={isCheckingVt}
              className="inline-flex items-center justify-center gap-1.5 px-2.5 py-1.5 rounded bg-sky-950/80 hover:bg-sky-900 border border-sky-700/80 text-sky-200 text-xs font-medium transition-colors cursor-pointer disabled:opacity-50"
            >
              <Globe className={`w-3.5 h-3.5 ${isCheckingVt ? 'animate-spin text-sky-400' : 'text-sky-400'}`} />
              <span>{isCheckingVt ? 'Запрос к VirusTotal v3...' : 'Проверить в VirusTotal (Kaspersky)'}</span>
            </button>
            {vtCheckResult && (
              <div className="p-2 rounded bg-slate-950 border border-sky-800/80 text-[11px] font-mono space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">VT Детекты:</span>
                  <span className="text-sky-300 font-bold">{vtCheckResult.stats.malicious} / {vtCheckResult.totalEngines}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-slate-400">Kaspersky:</span>
                  <span className={vtCheckResult.kaspersky?.category === 'malicious' ? 'text-rose-400 font-bold' : 'text-slate-300'}>
                    {vtCheckResult.kaspersky?.category || 'undetected'} ({vtCheckResult.kaspersky?.result || 'сигнатуры нет'})
                  </span>
                </div>
              </div>
            )}
            {vtError && (
              <div className="text-[11px] text-amber-300/90 font-mono">
                {vtError}
              </div>
            )}
          </div>
        </div>

        <div className="border border-slate-800 bg-slate-900/60 rounded-lg p-4">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Binary className="w-3.5 h-3.5 text-emerald-400" />
            <span>Бинарный формат и сигнатура заголовка (Без запуска)</span>
          </div>
          <div className="text-sm font-semibold text-slate-100">
            {currentReport.headerAnalysis.format}
          </div>
          <div className="mt-1 text-xs font-mono text-slate-400 tabular-nums">
            Magic: <span className="text-slate-200">{currentReport.headerAnalysis.magicHex || 'N/A'}</span> · Расширение:{' '}
            <span className="text-slate-200">{currentReport.headerAnalysis.declaredExtension}</span>
          </div>
        </div>

        <div className="border border-slate-800 bg-slate-900/60 rounded-lg p-4">
          <div className="flex items-center gap-2 text-xs text-slate-400 mb-1">
            <Layers className="w-3.5 h-3.5 text-emerald-400" />
            <span>Статистика распределения байтов</span>
          </div>
          <div className="text-sm font-semibold text-slate-100">
            {currentReport.entropy.assessment}
          </div>
          <div className="mt-1 text-xs font-mono text-slate-400 tabular-nums">
            ASCII: <span className="text-slate-200">{currentReport.entropy.byteDistribution.printableAsciiRatio}%</span> ·
            Null (0x00): <span className="text-slate-200">{currentReport.entropy.byteDistribution.nullByteRatio}%</span> ·
            High-Bit: <span className="text-slate-200">{currentReport.entropy.byteDistribution.highBitRatio}%</span>
          </div>
        </div>
      </div>

      {/* Detailed Inspection Sub-Navigation */}
      <div className="border border-slate-800 bg-slate-900/60 rounded-lg overflow-hidden">
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-3 border-b border-slate-800 bg-slate-950/50">
          <div className="flex flex-wrap items-center gap-1 p-1 bg-slate-900 rounded-lg border border-slate-800">
            <button
              type="button"
              onClick={() => setActiveDetailTab('decompiler')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'decompiler'
                  ? 'bg-emerald-600 text-white'
                  : 'text-emerald-400 hover:text-white'
              }`}
            >
              Lossless AST Декомпилятор C++ ({currentReport.decompilation.disassemblyListing.length} инстр. · {qm.overallAegisQualityPercent}% точность)
            </button>
            <button
              type="button"
              onClick={() => setActiveDetailTab('rules')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'rules'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Срабатывания YARA и Эвристик ({currentReport.triggeredRules.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveDetailTab('opcodes')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'opcodes'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Опкоды, Heaven’s Gate, io_uring и ROR13 ({currentReport.opcodeFindings.length + currentReport.resolvedApiHashes.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveDetailTab('headers')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'headers'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              PE/TLS/Rich Заголовки и Энтропия
            </button>
            <button
              type="button"
              onClick={() => setActiveDetailTab('strings')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'strings'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              XTEA-32, RC4, Стековые строки и XOR ({currentReport.deobfuscatedLayers.length})
            </button>
            <button
              type="button"
              onClick={() => setActiveDetailTab('hex')}
              className={`px-3 py-1.5 text-xs font-medium rounded-md transition-colors whitespace-nowrap shrink-0 cursor-pointer ${
                activeDetailTab === 'hex'
                  ? 'bg-slate-800 text-white'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Hex-дамп (Первые 256 байт)
            </button>
          </div>
          {isScanning && (
            <span className="text-xs font-mono text-emerald-400">Выполняется анализ байтов...</span>
          )}
        </div>

        <div className="p-6">
          {activeDetailTab === 'decompiler' && (
            <div className="space-y-6">
              {/* Decompilation Quality, Accuracy & Correctness Metrics Card (Aegis v7 vs Reference Baselines) */}
              <div className="p-4 rounded-lg bg-slate-950/90 border border-slate-800 space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
                      <span className="text-emerald-400 font-semibold">
                        РЕЖИМ AST-ДЕКОМПИЛЯЦИИ БЕЗ ПОТЕРЬ (LOSSLESS v7): {currentReport.decompilation.targetLanguage}
                      </span>
                      <span className="text-slate-500">·</span>
                      <span className="text-amber-300">
                        Компилятор / Символы: {currentReport.decompilation.compilerOrRuntimeDetected}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed max-w-4xl">
                      {currentReport.decompilation.honestTechnicalNote}
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={handleExportDecompiledSource}
                    className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Скачать восстановленный код (.cpp / .cs / .java)</span>
                  </button>
                </div>

                {/* Quantitative Accuracy & Comparison Bars for the Current File */}
                <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3 pt-1">
                  <div className="p-2.5 rounded border border-slate-800 bg-slate-900/60">
                    <div className="text-[11px] text-slate-400">Точность опкодов</div>
                    <div className="text-base font-bold font-mono text-white tabular-nums mt-0.5">
                      {qm.instructionDecodeAccuracy.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800 bg-slate-900/60">
                    <div className="text-[11px] text-slate-400">Точность CFG AST</div>
                    <div className="text-base font-bold font-mono text-white tabular-nums mt-0.5">
                      {qm.controlFlowAstAccuracy.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800 bg-slate-900/60">
                    <div className="text-[11px] text-slate-400">Переменные и ABI</div>
                    <div className="text-base font-bold font-mono text-white tabular-nums mt-0.5">
                      {qm.typeAndAbiAccuracy.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800 bg-slate-900/60">
                    <div className="text-[11px] text-slate-400">Символы PDB / RTTI</div>
                    <div className="text-base font-bold font-mono text-white tabular-nums mt-0.5">
                      {qm.symbolAndApiRecovery.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-emerald-700/70 bg-emerald-950/30">
                    <div className="text-[11px] text-emerald-300 font-medium">Качество Aegis v7 (Live)</div>
                    <div
                      data-testid="file-aegis-decompiler-quality"
                      className="text-lg font-bold font-mono text-emerald-400 tabular-nums mt-0.5"
                    >
                      {qm.overallAegisQualityPercent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-amber-700/60 bg-amber-950/20">
                    <div className="text-[11px] text-amber-300 font-medium">Ghidra 11.2 (Референс)</div>
                    <div
                      data-testid="file-ghidra-decompiler-quality"
                      className="text-lg font-bold font-mono text-amber-300 tabular-nums mt-0.5"
                    >
                      {qm.ghidraReferenceQualityPercent.toFixed(1)}%
                    </div>
                  </div>
                  <div className="p-2.5 rounded border border-slate-800 bg-slate-900/60">
                    <div className="text-[11px] text-slate-400">IDA Hex-Rays (Референс)</div>
                    <div className="text-lg font-bold font-mono text-slate-200 tabular-nums mt-0.5">
                      {qm.idaHexRaysReferencePercent.toFixed(1)}%
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 text-xs font-mono text-slate-300 pt-1">
                  <div>
                    AST и Lossless-метрики:{' '}
                    <span className="text-emerald-400 font-semibold">
                      Функций: {cfg.recoveredFunctionsCount || 1}
                    </span>{' '}
                    ·{' '}
                    <span className="text-emerald-400 font-semibold">
                      Стековых переменных: {cfg.localVariablesCount}
                    </span>{' '}
                    ·{' '}
                    <span className="text-emerald-400">
                      ALU-операций: {cfg.aluOperationsCount || 0}
                    </span>{' '}
                    · <span className="text-emerald-400">if/else: {cfg.ifElseBranchesCount}</span> ·{' '}
                    <span className="text-emerald-400">циклы: {cfg.loopsCount}</span> ·{' '}
                    <span className="text-emerald-400">switch: {cfg.switchBlocksCount || 0}</span> ·{' '}
                    <span className="text-emerald-400">VTable: {cfg.vtableCallsCount || 0}</span> ·{' '}
                    <span className="text-emerald-300 font-semibold">
                      Сохранено инструкций: {cfg.instructionPreservationPercent ?? 100}% (0% удалено)
                    </span>
                  </div>
                  <div className="text-slate-400 font-sans">
                    {qm.recoveredConstructsSummary}
                  </div>
                </div>
              </div>

              {/* Side-by-Side: Disassembled Machine Instructions (ASM / Smali / CIL) + Reconstructed C++ / C# / Java Code */}
              <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                {/* Left Column: Machine Code Disassembly + Demangled C++ Symbols or APK DEX / .NET CIL Metadata */}
                <div className="lg:col-span-5 space-y-4">
                  <div className="border border-slate-800 rounded-lg bg-slate-950 overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-slate-800 bg-slate-900/70 flex items-center justify-between">
                      <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                        <Cpu className="w-3.5 h-3.5 text-emerald-400" />
                        <span>
                          Извлеченный машинный код / байткод ({currentReport.decompilation.disassemblyListing.length} инстр.)
                        </span>
                      </span>
                      <span className="text-[11px] font-mono text-slate-400">
                        {currentReport.decompilation.apkDexInfo.isApkOrDex
                          ? 'Dalvik Smali'
                          : currentReport.decompilation.dotNetInfo.isDotNetAssembly
                          ? 'MSFT CIL (MSIL)'
                          : 'x86_64 ASM'}
                      </span>
                    </div>

                    {currentReport.decompilation.disassemblyListing.length === 0 ? (
                      <div className="p-4 text-xs font-mono text-slate-400">
                        Файл является текстовым скриптом или контейнером данных без машинных опкодов x86_64 / DEX / CIL.
                      </div>
                    ) : (
                      <div className="max-h-96 overflow-y-auto divide-y divide-slate-900 font-mono text-xs">
                        {currentReport.decompilation.disassemblyListing.map((ins, idx) => (
                          <div key={idx} className="p-2.5 hover:bg-slate-900/50 space-y-1">
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-emerald-400 tabular-nums">{ins.addressHex}</span>
                              <span className="text-amber-300/90 tabular-nums">{ins.bytesHex}</span>
                            </div>
                            <div className="text-white font-semibold">
                              {ins.mnemonic} <span className="text-slate-300 font-normal">{ins.operands}</span>
                            </div>
                            <div className="text-[11px] text-slate-400 font-sans">{ins.comment}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Demangled C++ RTTI / Mangled Symbols if present */}
                  {currentReport.decompilation.demangledCppSymbols.length > 0 && (
                    <div className="border border-slate-800 rounded-lg bg-slate-950 overflow-hidden">
                      <div className="px-4 py-2.5 border-b border-slate-800 bg-slate-900/70">
                        <span className="text-xs font-semibold text-slate-200">
                          Деманглированные классы и методы C++ (MSVC RTTI / Itanium ABI)
                        </span>
                      </div>
                      <div className="divide-y divide-slate-900 font-mono text-xs">
                        {currentReport.decompilation.demangledCppSymbols.map((sym, idx) => (
                          <div key={idx} className="p-3 space-y-1">
                            <div className="text-[11px] text-slate-400 break-all">
                              Raw: <span className="text-amber-300">{sym.rawSymbol}</span>{' '}
                              {sym.offsetHex ? `(@${sym.offsetHex})` : ''}
                            </div>
                            <div className="text-emerald-300 font-semibold break-all">
                              &rarr; {sym.demangledSignature}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* .NET / C# CLI Metadata if present */}
                  {currentReport.decompilation.dotNetInfo.isDotNetAssembly && (
                    <div className="border border-slate-800 rounded-lg bg-slate-950 p-4 space-y-2.5 font-mono text-xs">
                      <div className="text-slate-200 font-sans font-semibold">
                        Метаданные сборки .NET CLR ({currentReport.decompilation.dotNetInfo.clrVersion})
                      </div>
                      {currentReport.decompilation.dotNetInfo.discoveredTypes.length > 0 && (
                        <div>
                          <div className="text-slate-400 mb-0.5">Классы и пространства имен:</div>
                          <div className="text-emerald-300 break-all">
                            {currentReport.decompilation.dotNetInfo.discoveredTypes.join(', ')}
                          </div>
                        </div>
                      )}
                      {currentReport.decompilation.dotNetInfo.discoveredMethods.length > 0 && (
                        <div>
                          <div className="text-slate-400 mb-0.5">Вызовы методов BCL / Reflection:</div>
                          <div className="text-amber-300 break-all">
                            {currentReport.decompilation.dotNetInfo.discoveredMethods.join(', ')}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Android APK / DEX Structure if present */}
                  {currentReport.decompilation.apkDexInfo.isApkOrDex && (
                    <div className="border border-slate-800 rounded-lg bg-slate-950 p-4 space-y-3 font-mono text-xs">
                      <div className="text-slate-200 font-sans font-semibold">
                        Структура пакета Android (.apk ZIP + {currentReport.decompilation.apkDexInfo.dexVersion || 'classes.dex'})
                      </div>
                      {currentReport.decompilation.apkDexInfo.zipEntries.length > 0 && (
                        <div>
                          <div className="text-slate-400 mb-1">Файлы внутри ZIP-контейнера APK:</div>
                          <div className="text-emerald-300">
                            {currentReport.decompilation.apkDexInfo.zipEntries.join(' · ')}
                          </div>
                        </div>
                      )}
                      {currentReport.decompilation.apkDexInfo.discoveredClasses.length > 0 && (
                        <div>
                          <div className="text-slate-400 mb-1">Декомпилированные классы из таблицы type_ids DEX:</div>
                          <div className="text-amber-300 break-all">
                            {currentReport.decompilation.apkDexInfo.discoveredClasses.join(', ')}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>

                {/* Right Column: Reconstructed C/C++, C#, or Java Source Code */}
                <div className="lg:col-span-7 border border-slate-800 rounded-lg bg-slate-950 overflow-hidden">
                  <div className="px-4 py-2.5 border-b border-slate-800 bg-slate-900/70 flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                      <FileCode className="w-3.5 h-3.5 text-emerald-400" />
                      <span>
                        Восстановленный код ({currentReport.decompilation.targetLanguage})
                      </span>
                    </span>
                    <span className="text-[11px] font-mono text-emerald-400">
                      Точность: {qm.overallAegisQualityPercent}% (Ghidra: {qm.ghidraReferenceQualityPercent}%)
                    </span>
                  </div>
                  <pre
                    data-testid="decompiled-source-code"
                    className="p-4 text-xs font-mono text-slate-200 overflow-x-auto leading-relaxed whitespace-pre"
                  >
                    {currentReport.decompilation.reconstructedCode}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {activeDetailTab === 'rules' && (
            <div>
              {currentReport.triggeredRules.length === 0 ? (
                <div className="py-8 text-center">
                  <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto mb-2" />
                  <div className="text-sm font-medium text-slate-200">
                    Ни одно сигнатурное YARA-правило, стековая строка, ROR13-хеш или опкод шеллкода не сработали
                  </div>
                  <p className="text-xs text-slate-400 mt-1 max-w-lg mx-auto">
                    В файле отсутствуют известные сигнатуры вредоносного кода, опасные цепочки импорта Win32 API,
                    XOR-зашифрованные блоки и машинные инструкции прямого обращения к PEB/Syscall.
                  </p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="border-b border-slate-800 text-xs text-slate-400">
                        <th className="py-2.5 pr-4 font-medium">ID Правила</th>
                        <th className="py-2.5 px-4 font-medium">Название и описание</th>
                        <th className="py-2.5 px-4 font-medium">MITRE ATT&amp;CK</th>
                        <th className="py-2.5 px-4 font-medium">Найденные артефакты в байтах</th>
                        <th className="py-2.5 pl-4 text-right font-medium">Вес</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/80 text-sm">
                      {currentReport.triggeredRules.map((tr) => (
                        <tr key={tr.ruleId} className="hover:bg-slate-800/30">
                          <td className="py-3 pr-4 font-mono text-xs text-emerald-400 whitespace-nowrap align-top">
                            {tr.ruleId}
                          </td>
                          <td className="py-3 px-4 align-top">
                            <div className="font-semibold text-slate-100">{tr.ruleName}</div>
                            <div className="text-xs text-slate-400 mt-0.5">{tr.description}</div>
                          </td>
                          <td className="py-3 px-4 font-mono text-xs text-slate-300 whitespace-nowrap align-top">
                            {tr.mitreTechnique || '—'}
                          </td>
                          <td className="py-3 px-4 font-mono text-xs text-amber-300 align-top">
                            {tr.matchedArtifacts.join(' · ')}
                          </td>
                          <td className="py-3 pl-4 text-right font-mono text-xs font-bold text-red-400 tabular-nums align-top whitespace-nowrap">
                            +{tr.scoreAdded}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {activeDetailTab === 'opcodes' && (
            <div className="space-y-6">
              {/* Machine Opcode Disassembler */}
              <div>
                <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-3">
                  <Cpu className="w-4 h-4 text-emerald-400" />
                  <span>Дизассемблер машинных инструкций x86/x64 (PEB Walk, Direct Syscall, NOP Sled, GetPC)</span>
                </h4>
                {currentReport.opcodeFindings.length === 0 ? (
                  <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono">
                    Подозрительных машинных опкодов шеллкода (`mov rax, gs:[0x60]`, `syscall 0F 05`, `call $+5; pop reg`) не обнаружено.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 pr-4">Смещение</th>
                          <th className="py-2 px-4">Сигнатура опкодов (Hex)</th>
                          <th className="py-2 px-4">Дизассемблированная мнемоника</th>
                          <th className="py-2 px-4">Описание техники</th>
                          <th className="py-2 pl-4 text-right">Вес</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {currentReport.opcodeFindings.map((op, i) => (
                          <tr key={i} className="hover:bg-slate-800/30">
                            <td className="py-3 pr-4 text-emerald-400 tabular-nums align-top">
                              {op.offsetHex}
                            </td>
                            <td className="py-3 px-4 text-amber-300 align-top whitespace-nowrap">
                              {op.opcodeHex}
                            </td>
                            <td className="py-3 px-4 text-white font-semibold align-top">
                              {op.mnemonic}
                            </td>
                            <td className="py-3 px-4 text-slate-300 font-sans align-top">
                              <div className="font-semibold text-slate-100">{op.patternName}</div>
                              <div className="text-slate-400 mt-0.5">{op.description}</div>
                            </td>
                            <td className="py-3 pl-4 text-right text-red-400 font-bold tabular-nums align-top">
                              +{op.scoreWeight}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>

              {/* Dynamic API Hash Resolver (ROR13 Cobalt Strike / Metasploit) */}
              <div>
                <h4 className="text-sm font-semibold text-slate-200 flex items-center gap-2 mb-3">
                  <KeyRound className="w-4 h-4 text-amber-400" />
                  <span>Резолвер динамических API-хешей ROR13 (Cobalt Strike / Metasploit block_api)</span>
                </h4>
                {currentReport.resolvedApiHashes.length === 0 ? (
                  <div className="p-4 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400 font-mono">
                    Скрытых 32-битных ROR13-хешей системных функций Win32 API не обнаружено.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 pr-4">Смещение в бинарнике</th>
                          <th className="py-2 px-4">32-битный хеш</th>
                          <th className="py-2 px-4">Алгоритм хеширования</th>
                          <th className="py-2 pl-4">Вскрытая функция Win32 API</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {currentReport.resolvedApiHashes.map((h, i) => (
                          <tr key={i} className="hover:bg-slate-800/30">
                            <td className="py-2.5 pr-4 text-emerald-400 tabular-nums">{h.offsetHex}</td>
                            <td className="py-2.5 px-4 text-amber-300 font-bold tabular-nums">{h.hashHex}</td>
                            <td className="py-2.5 px-4 text-slate-300">{h.algorithm}</td>
                            <td className="py-2.5 pl-4 text-red-400 font-semibold">{h.resolvedModuleAndApi}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {activeDetailTab === 'headers' && (
            <div className="space-y-6">
              {/* Block Entropy Bar Visualization */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-slate-200">
                    Карта распределения энтропии Шеннона по блокам файла (0.0 — 8.0 бит/байт)
                  </h4>
                  <span className="text-xs font-mono text-slate-400">
                    Порог криптопакера: &ge; 7.25 бит/байт
                  </span>
                </div>
                <div className="grid grid-cols-16 sm:grid-cols-32 gap-1 h-20 items-end p-3 bg-slate-950 rounded-lg border border-slate-800">
                  {currentReport.entropy.blockEntropies.map((be, idx) => {
                    const heightPct = Math.max(8, Math.round((be / 8.0) * 100));
                    const barColor =
                      be >= 7.2
                        ? 'bg-red-500'
                        : be >= 6.2
                        ? 'bg-amber-400'
                        : 'bg-emerald-500';
                    return (
                      <div
                        key={idx}
                        title={`Блок #${idx + 1}: H = ${be.toFixed(2)} бит/байт`}
                        className="w-full h-full flex items-end"
                      >
                        <div
                          className={`w-full rounded-t ${barColor} transition-transform`}
                          style={{ height: `${heightPct}%` }}
                        />
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* PE Section Table & TLS / Rich Header status */}
              {currentReport.headerAnalysis.peDetails ? (
                <div className="space-y-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h4 className="text-sm font-semibold text-slate-200">
                      Таблица секций и структур Windows PE ({currentReport.headerAnalysis.peDetails.machine})
                    </h4>
                    <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-400 tabular-nums">
                      <span>
                        RWX-секция:{' '}
                        <strong
                          className={
                            currentReport.headerAnalysis.peDetails.hasRWXSection
                              ? 'text-red-400'
                              : 'text-emerald-400'
                          }
                        >
                          {currentReport.headerAnalysis.peDetails.hasRWXSection ? 'ДА' : 'НЕТ'}
                        </strong>
                      </span>
                      <span>·</span>
                      <span>
                        TLS Callback (DataDir[9]):{' '}
                        <strong
                          className={
                            currentReport.headerAnalysis.peDetails.hasTlsDirectoryCallback
                              ? 'text-red-400'
                              : 'text-emerald-400'
                          }
                        >
                          {currentReport.headerAnalysis.peDetails.hasTlsDirectoryCallback
                            ? 'ОБНАРУЖЕН ПЕРЕХВАТ ДО ТОЧКИ ВХОДА'
                            : 'НЕТ'}
                        </strong>
                      </span>
                      <span>·</span>
                      <span>
                        Rich Header:{' '}
                        <strong
                          className={
                            currentReport.headerAnalysis.peDetails.richHeaderForged
                              ? 'text-amber-300'
                              : 'text-emerald-400'
                          }
                        >
                          {currentReport.headerAnalysis.peDetails.richHeaderForged
                            ? 'ПОДДЕЛАН (0xDEADBEEF)'
                            : 'НОРМА'}
                        </strong>
                      </span>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800 text-slate-400">
                          <th className="py-2 pr-4">Имя секции</th>
                          <th className="py-2 px-4 text-right">VirtualSize</th>
                          <th className="py-2 px-4 text-right">RawSize</th>
                          <th className="py-2 px-4 text-right">Энтропия (H)</th>
                          <th className="py-2 pl-4 text-right">Права доступа</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/70">
                        {currentReport.headerAnalysis.peDetails.sections.map((sec, i) => (
                          <tr key={i} className="hover:bg-slate-800/30">
                            <td className="py-2.5 pr-4 font-bold text-slate-200">{sec.name}</td>
                            <td className="py-2.5 px-4 text-right text-slate-300 tabular-nums">
                              {sec.virtualSize.toLocaleString('ru-RU')} байт
                            </td>
                            <td className="py-2.5 px-4 text-right text-slate-300 tabular-nums">
                              {sec.rawSize.toLocaleString('ru-RU')} байт
                            </td>
                            <td className="py-2.5 px-4 text-right tabular-nums">
                              <span className={sec.entropy >= 7.2 ? 'text-red-400 font-bold' : 'text-slate-200'}>
                                {sec.entropy.toFixed(3)}
                              </span>
                            </td>
                            <td className="py-2.5 pl-4 text-right">
                              <span
                                className={
                                  sec.isRWX ? 'text-red-400 font-bold' : 'text-emerald-400'
                                }
                              >
                                {sec.flagsDescription} {sec.isRWX ? '(RWX ОПАСНО)' : ''}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-400 font-mono">
                  Формат контейнера: {currentReport.headerAnalysis.format} (Архитектура:{' '}
                  {currentReport.headerAnalysis.architecture || 'N/A'}).
                </div>
              )}
            </div>
          )}

          {activeDetailTab === 'strings' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-2">
                    <FileCode className="w-4 h-4 text-amber-400" />
                    <span>Обнаруженные опасные вызовы API ({currentReport.extractedStrings.suspiciousApis.length})</span>
                  </h4>
                  {currentReport.extractedStrings.suspiciousApis.length === 0 ? (
                    <div className="text-xs text-slate-500 font-mono">
                      В открытом виде опасных вызовов Win32 API не найдено.
                    </div>
                  ) : (
                    <div className="font-mono text-xs text-amber-300 bg-slate-950 p-3 rounded border border-slate-800">
                      {currentReport.extractedStrings.suspiciousApis.join(' · ')}
                    </div>
                  )}
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    <span>Системные интерпретаторы и сетевые IOC (включая вскрытые из Rolling-XOR/Base64)</span>
                  </h4>
                  <div className="font-mono text-xs text-slate-300 bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
                    <div>
                      Команды:{' '}
                      {currentReport.extractedStrings.commandPatterns.length > 0
                        ? currentReport.extractedStrings.commandPatterns.join(' · ')
                        : 'нет'}
                    </div>
                    <div>
                      URL:{' '}
                      {currentReport.extractedStrings.urls.length > 0
                        ? currentReport.extractedStrings.urls.join(' · ')
                        : 'нет'}
                    </div>
                    <div>
                      IPv4:{' '}
                      {currentReport.extractedStrings.ipv4Addresses.length > 0
                        ? currentReport.extractedStrings.ipv4Addresses.join(' · ')
                        : 'нет'}
                    </div>
                  </div>
                </div>
              </div>

              {/* Deobfuscated, Stack-Reconstructed & Rolling-XOR Cracked Payloads */}
              <div>
                <h4 className="text-xs font-semibold text-slate-300 mb-2">
                  Вскрытые слои: Декомпилятор стековых строк / CPU-Эмулятор Rolling-XOR / Single-Byte XOR / Base64
                </h4>
                {currentReport.deobfuscatedLayers.length === 0 ? (
                  <div className="text-xs text-slate-500 font-mono">
                    Скрытых стековых строк, Rolling-XOR, Base64 или CharCode пейлоадов не обнаружено.
                  </div>
                ) : (
                  <div className="space-y-3">
                    {currentReport.deobfuscatedLayers.map((layer, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded bg-slate-950 border border-slate-800 font-mono text-xs space-y-1.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 text-slate-400">
                          <span className="text-emerald-400 font-semibold">
                            Метод: {layer.method}{' '}
                            {layer.xorKeyHex ? `(${layer.xorKeyHex})` : ''}
                          </span>
                          <span>
                            Найдены индикаторы:{' '}
                            <strong className="text-red-400">
                              {layer.suspiciousFindings.join(', ') || 'нет'}
                            </strong>
                          </span>
                        </div>
                        <div className="text-slate-500 truncate">Источник в коде: {layer.originalSnippet}</div>
                        <div className="text-amber-200 bg-slate-900/90 p-2 rounded break-all">
                          Восстановлено в памяти: {layer.decodedSnippet}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {activeDetailTab === 'hex' && (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse font-mono text-xs">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 pr-4">Смещение (Offset)</th>
                    <th className="py-2 px-4">Шестнадцатеричные байты (Hex)</th>
                    <th className="py-2 pl-4">ASCII-представление</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {currentReport.hexPreview.map((row) => (
                    <tr key={row.offsetHex} className="hover:bg-slate-800/30">
                      <td className="py-1.5 pr-4 text-emerald-400 tabular-nums">0x{row.offsetHex}</td>
                      <td className="py-1.5 px-4 text-slate-200 tabular-nums whitespace-nowrap">
                        {row.bytesHex}
                      </td>
                      <td className="py-1.5 pl-4 text-amber-300 whitespace-pre">{row.ascii}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
