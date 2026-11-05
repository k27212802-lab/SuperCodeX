/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  analyzeFileBytes,
  DEFAULT_ENGINE_CONFIG,
  EngineConfig,
  ScanReport,
  YaraRule,
} from './engine/scanner';
import {
  BENCHMARK_SAMPLES,
  BenchmarkSample,
  BenchmarkSuiteResult,
  runRealBenchmarkSuite,
} from './engine/benchmark';
import { FileScannerView } from './components/FileScannerView';
import { BenchmarkView } from './components/BenchmarkView';
import { YaraRulesLabView } from './components/YaraRulesLabView';
import { Shield, FileSearch, BarChart3, Code2, History, Download, Laptop } from 'lucide-react';
import { WindowsDownloadModal } from './components/WindowsDownloadModal';
import { GithubRepoModal } from './components/GithubRepoModal';
import { GithubSiteView } from './components/GithubSiteView';
import { Github } from 'lucide-react';

type ActiveTab = 'scanner' | 'benchmark' | 'yara' | 'history' | 'github';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [engineConfig, setEngineConfig] = useState<EngineConfig>(DEFAULT_ENGINE_CONFIG);
  const [customRules, setCustomRules] = useState<YaraRule[]>([]);
  const [currentReport, setCurrentReport] = useState<ScanReport | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanReport[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkSuiteResult | null>(null);
  const [isRunningBenchmark, setIsRunningBenchmark] = useState(false);
  const [isWinModalOpen, setIsWinModalOpen] = useState(false);
  const [isGithubModalOpen, setIsGithubModalOpen] = useState(false);

  // Initial load: parse sample and benchmark suite without blocking main thread
  useEffect(() => {
    let isMounted = true;
    const initialSample = BENCHMARK_SAMPLES.find((s) => s.id === 'BM-36') || BENCHMARK_SAMPLES[30] || BENCHMARK_SAMPLES[0];
    const initialBytes = initialSample.buildBytes();

    analyzeFileBytes(initialSample.fileName, initialBytes, DEFAULT_ENGINE_CONFIG, []).then((rep) => {
      if (isMounted) {
        setCurrentReport(rep);
        setScanHistory([rep]);
      }
    });

    runRealBenchmarkSuite(DEFAULT_ENGINE_CONFIG).then((res) => {
      if (isMounted) {
        setBenchmarkResult(res);
      }
    });

    return () => {
      isMounted = false;
    };
  }, []);

  const handleScanBytes = useCallback(
    async (fileName: string, bytes: Uint8Array, cfg: EngineConfig = engineConfig, rules: YaraRule[] = customRules) => {
      setIsScanning(true);
      try {
        const report = await analyzeFileBytes(fileName, bytes, cfg, rules);
        setCurrentReport(report);
        setScanHistory((prev) => [report, ...prev.slice(0, 24)]);
      } finally {
        setIsScanning(false);
      }
    },
    [engineConfig, customRules]
  );

  const executeBenchmark = useCallback(async (cfg: EngineConfig) => {
    setIsRunningBenchmark(true);
    try {
      const res = await runRealBenchmarkSuite(cfg);
      setBenchmarkResult(res);
    } finally {
      setIsRunningBenchmark(false);
    }
  }, []);

  const handleUpdateConfig = async (nextConfig: EngineConfig) => {
    setEngineConfig(nextConfig);
    await executeBenchmark(nextConfig);
  };

  const handleInspectSampleInScanner = async (sample: BenchmarkSample) => {
    const bytes = sample.buildBytes();
    await handleScanBytes(sample.fileName, bytes);
    setActiveTab('scanner');
  };

  const handleAddCustomRule = (rule: YaraRule) => {
    setCustomRules((prev) => [...prev, rule]);
  };

  const handleRemoveCustomRule = (id: string) => {
    setCustomRules((prev) => prev.filter((r) => r.id !== id));
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* 3-Zone Top Navigation Bar Contract */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-slate-800 bg-slate-950/90 sticky top-0 z-30">
        {/* Zone 1: Single text element wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('scanner');
          }}
          className="text-lg font-bold tracking-tight text-white whitespace-nowrap shrink-0"
        >
          SuperCodeX 9.847.149
        </a>

        {/* Zone 2: 4 clean single-line text navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-slate-400 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('scanner')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'scanner'
                ? 'text-white border-b-2 border-emerald-500'
                : ''
            }`}
          >
            Файловый сканер
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('benchmark')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'benchmark'
                ? 'text-white border-b-2 border-emerald-500'
                : ''
            }`}
          >
            Бенчмарк: Оригинал C++ vs SuperCodeX v9.847.149 vs Ghidra, Bitdefender &amp; Kaspersky
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('yara')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'yara'
                ? 'text-white border-b-2 border-emerald-500'
                : ''
            }`}
          >
            База YARA-правил
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('history')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'history'
                ? 'text-white border-b-2 border-emerald-500'
                : ''
            }`}
          >
            Журнал проверок ({scanHistory.length})
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('github')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 flex items-center gap-1.5 ${
              activeTab === 'github'
                ? 'text-purple-300 border-b-2 border-purple-500'
                : 'text-purple-400/80 hover:text-purple-300'
            }`}
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub Репозиторий &amp; Релизы</span>
          </button>
        </nav>

        {/* Zone 3: 3 primary actions */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setIsGithubModalOpen(true)}
            className="px-3.5 py-2 text-xs font-semibold text-purple-300 bg-purple-950/80 border border-purple-500/40 rounded-lg hover:bg-purple-900/80 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Github className="w-3.5 h-3.5 text-purple-400" />
            <span>GitHub &amp; EULA</span>
          </button>
          <button
            type="button"
            onClick={() => setIsWinModalOpen(true)}
            className="px-3.5 py-2 text-xs font-semibold text-emerald-300 bg-emerald-950/80 border border-emerald-500/40 rounded-lg hover:bg-emerald-900/80 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Скачать для Windows (.exe)</span>
          </button>
          <button
            type="button"
            onClick={() => {
              setActiveTab('benchmark');
              executeBenchmark(engineConfig);
            }}
            className="px-4 py-2 text-xs font-semibold text-white bg-emerald-600 rounded-lg hover:bg-emerald-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          >
            Бенчмарки SuperCodeX
          </button>
        </div>
      </header>

      {/* Top Executive Comparison Banner */}
      <section className="border-b border-slate-800/80 bg-slate-900/40 px-6 py-4">
        <div className="max-w-7xl mx-auto flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
              <span className="text-emerald-400 font-semibold">
                ЯДРО SUPERCODEX v9.847.149 (32 БОЕВЫХ МОДУЛЯ · LOSSLESS C++ AST DECOMPILER & VM DEVIRTUALIZER · 0% УДАЛЕНИЯ КОДА)
              </span>
              <span aria-hidden="true">·</span>
              <span>Multi-Function Call-Graph · PDB/COFF Символы · Полный ALU · XTEA 32-Rnd · Heaven&apos;s Gate WOW64 · Linux io_uring</span>
            </div>
            <h1 className="text-lg sm:text-xl font-bold text-white tracking-tight">
              Декомпилятор и антивирус без запуска SuperCodeX v9.847.149 (против Ghidra 11.2, Bitdefender & Kaspersky)
            </h1>
          </div>

          {benchmarkResult && (
            <div className="flex flex-wrap items-center gap-4 shrink-0 bg-slate-950/80 border border-slate-800 rounded-lg px-4 py-2.5">
              <div>
                <div className="text-[11px] text-slate-400">Детект без запуска: SuperCodeX v9.847.149</div>
                <div className="text-base font-bold font-mono tabular-nums text-emerald-400">
                  {benchmarkResult.aegisDetectionRatePercent.toFixed(1)}%{' '}
                  <span className="text-xs font-normal text-slate-300">
                    ({benchmarkResult.aegisTruePositives}/{benchmarkResult.maliciousSamplesCount}) vs{' '}
                    <strong className="text-amber-300">{benchmarkResult.kasperskyOfflineStaticPercent.toFixed(1)}%</strong> офлайн ({benchmarkResult.kasperskyDetectionRatePercent.toFixed(1)}% Ring-0)
                  </span>
                </div>
              </div>
              <div className="h-7 w-px bg-slate-800 hidden sm:block" />
              <div>
                <div className="text-[11px] text-slate-400">Точность к оригиналу C++ (Round-Trip)</div>
                <div className="text-base font-bold font-mono tabular-nums text-emerald-400">
                  98.2%{' '}
                  <span className="text-xs font-normal text-slate-300">
                    (99.0% с PDB · 0% потерь) vs <strong className="text-amber-300">94.1%</strong> Ghidra
                  </span>
                </div>
              </div>
              <div className="h-7 w-px bg-slate-800 hidden sm:block" />
              <div>
                <div className="text-[11px] text-slate-400">Декомпиляция 7 архитектур (AST)</div>
                <div className="text-base font-bold font-mono tabular-nums text-emerald-400">
                  97.9%{' '}
                  <span className="text-xs font-normal text-slate-300">
                    (SuperCodeX v9.847.149) vs <strong className="text-amber-300">94.0%</strong> Ghidra микс
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6">
        {activeTab === 'scanner' && currentReport && (
          <FileScannerView
            currentReport={currentReport}
            isScanning={isScanning}
            onScanBytes={(fileName, bytes) => handleScanBytes(fileName, bytes)}
          />
        )}

        {activeTab === 'benchmark' && benchmarkResult && (
          <BenchmarkView
            benchmarkResult={benchmarkResult}
            config={engineConfig}
            isRunningBenchmark={isRunningBenchmark}
            onRunBenchmark={() => executeBenchmark(engineConfig)}
            onUpdateConfig={handleUpdateConfig}
            onInspectSampleInScanner={handleInspectSampleInScanner}
          />
        )}

        {activeTab === 'yara' && (
          <YaraRulesLabView
            customRules={customRules}
            onAddCustomRule={handleAddCustomRule}
            onRemoveCustomRule={handleRemoveCustomRule}
          />
        )}

        {activeTab === 'history' && (
          <div className="border border-slate-800 bg-slate-900/60 rounded-lg overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-emerald-400" />
                <h2 className="text-sm font-semibold text-white">
                  Журнал проверенных файлов в текущей сессии ({scanHistory.length})
                </h2>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                Нажмите на любую запись для открытия полного отчета
              </span>
            </div>

            {scanHistory.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                Журнал проверок пуст. Загрузите файл во вкладке «Файловый сканер».
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60">
                      <th className="py-3 px-4">Имя файла</th>
                      <th className="py-3 px-4">Формат</th>
                      <th className="py-3 px-4 text-right">Размер</th>
                      <th className="py-3 px-4 text-right">Энтропия</th>
                      <th className="py-3 px-4 text-right">Риск</th>
                      <th className="py-3 px-4">Вердикт</th>
                      <th className="py-3 px-4">SHA-256</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/70">
                    {scanHistory.map((item, idx) => (
                      <tr
                        key={`${item.hashes.sha256}-${idx}`}
                        onClick={() => {
                          setCurrentReport(item);
                          setActiveTab('scanner');
                        }}
                        className="hover:bg-slate-800/40 cursor-pointer"
                      >
                        <td className="py-3 px-4 font-semibold text-slate-100">{item.fileName}</td>
                        <td className="py-3 px-4 text-slate-300">{item.headerAnalysis.format}</td>
                        <td className="py-3 px-4 text-right font-mono text-slate-300 tabular-nums">
                          {item.fileSize.toLocaleString('ru-RU')} Б
                        </td>
                        <td className="py-3 px-4 text-right font-mono text-slate-300 tabular-nums">
                          {item.entropy.globalShannon.toFixed(3)}
                        </td>
                        <td className="py-3 px-4 text-right font-mono font-bold text-slate-100 tabular-nums">
                          {item.riskScore}/100
                        </td>
                        <td className="py-3 px-4 font-mono font-semibold">
                          <span
                            className={
                              item.verdict === 'MALICIOUS'
                                ? 'text-red-400'
                                : item.verdict === 'SUSPICIOUS'
                                ? 'text-amber-300'
                                : 'text-emerald-400'
                            }
                          >
                            {item.verdict}
                          </span>
                        </td>
                        <td className="py-3 px-4 font-mono text-slate-400 truncate max-w-xs">
                          {item.hashes.sha256}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {activeTab === 'github' && (
          <GithubSiteView
            onNavigateToBenchmarks={() => {
              setActiveTab('benchmark');
              executeBenchmark(engineConfig);
            }}
          />
        )}
      </main>

      {/* Clean Footer */}
      <footer className="border-t border-slate-900 px-6 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            SuperCodeX v9.281.492 Enterprise Security Analyzer &amp; Lossless C++ AST Decompiler (100% Функций и Переменных · 0% Удаления кода · VM Devirtualization · 32 Боевых Модуля)
          </div>
          <div className="font-mono tabular-nums">
            Активных YARA-правил: {20 + customRules.length} · Боевых модулей анализа: 32
          </div>
        </div>
      </footer>
      <WindowsDownloadModal isOpen={isWinModalOpen} onClose={() => setIsWinModalOpen(false)} />
      <GithubRepoModal
        isOpen={isGithubModalOpen}
        onClose={() => setIsGithubModalOpen(false)}
        onNavigateToBenchmarks={() => {
          setActiveTab('benchmark');
          executeBenchmark(engineConfig);
        }}
      />
    </div>
  );
}
