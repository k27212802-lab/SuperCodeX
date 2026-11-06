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
import { History, Download, Github, ShieldAlert } from 'lucide-react';
import { WindowsDownloadModal } from './components/WindowsDownloadModal';
import { GithubRepoModal } from './components/GithubRepoModal';
import { GithubSiteView } from './components/GithubSiteView';

type ActiveTab = 'scanner' | 'benchmark' | 'yara' | 'history' | 'github';

export default function App() {
  const [activeTab, setActiveTab] = useState<ActiveTab>('scanner');
  const [engineConfig, setEngineConfig] = useState<EngineConfig>(DEFAULT_ENGINE_CONFIG);
  const [customRules, setCustomRules] = useState<YaraRule[]>([]);
  const [currentReport, setCurrentReport] = useState<ScanReport | null>(null);
  const [hasUserScanned, setHasUserScanned] = useState<boolean>(false);
  const [scanHistory, setScanHistory] = useState<ScanReport[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkSuiteResult | null>(null);
  const [isRunningBenchmark, setIsRunningBenchmark] = useState(false);
  const [isWinModalOpen, setIsWinModalOpen] = useState(false);
  const [isGithubModalOpen, setIsGithubModalOpen] = useState(false);

  // Initial load: run benchmark suite in background, keep scanner at 0 files until user adds & scans
  useEffect(() => {
    let isMounted = true;
    const initialSample =
      BENCHMARK_SAMPLES.find((s) => s.id === 'BM-36') ||
      BENCHMARK_SAMPLES[30] ||
      BENCHMARK_SAMPLES[0];
    const initialBytes = initialSample.buildBytes();

    analyzeFileBytes(initialSample.fileName, initialBytes, DEFAULT_ENGINE_CONFIG, []).then(
      (rep) => {
        if (isMounted) {
          setCurrentReport(rep);
        }
      }
    );

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
    async (
      fileName: string,
      bytes: Uint8Array,
      cfg: EngineConfig = engineConfig,
      rules: YaraRule[] = customRules
    ): Promise<ScanReport> => {
      setIsScanning(true);
      try {
        const report = await analyzeFileBytes(fileName, bytes, cfg, rules);
        setCurrentReport(report);
        setHasUserScanned(true);
        setScanHistory((prev) => [report, ...prev.slice(0, 24)]);
        return report;
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
    setHasUserScanned(true);
    setActiveTab('scanner');
  };

  const handleAddCustomRule = (rule: YaraRule) => {
    setCustomRules((prev) => [...prev, rule]);
  };

  const handleRemoveCustomRule = (id: string) => {
    setCustomRules((prev) => prev.filter((r) => r.id !== id));
  };

  return (
    <div className="min-h-screen bg-[#0c0406] text-slate-100 flex flex-col">
      {/* Top Navigation Bar — Red Theme */}
      <header className="flex items-center justify-between gap-8 px-6 py-4 border-b border-red-900/60 bg-[#140609]/95 sticky top-0 z-30">
        {/* Zone 1: Wordmark */}
        <a
          href="#top"
          onClick={(e) => {
            e.preventDefault();
            setActiveTab('scanner');
          }}
          className="text-lg font-extrabold tracking-tight text-red-500 flex items-center gap-2 whitespace-nowrap shrink-0"
        >
          <ShieldAlert className="w-5 h-5 text-red-500" />
          <span>SuperCodeX 9.847.149</span>
        </a>

        {/* Zone 2: Navigation links */}
        <nav className="flex items-center gap-6 text-sm font-medium text-red-200/70 overflow-x-auto">
          <button
            type="button"
            onClick={() => setActiveTab('scanner')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'scanner'
                ? 'text-white font-bold border-b-2 border-red-500'
                : ''
            }`}
          >
            Антивирус &amp; Декомпилятор Проекта
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('benchmark')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'benchmark'
                ? 'text-white font-bold border-b-2 border-red-500'
                : ''
            }`}
          >
            Бенчмарк: Оригинал C++ vs Ghidra, Bitdefender &amp; Kaspersky
          </button>
          <button
            type="button"
            onClick={() => setActiveTab('yara')}
            className={`hover:text-white transition-colors whitespace-nowrap shrink-0 cursor-pointer pb-0.5 ${
              activeTab === 'yara'
                ? 'text-white font-bold border-b-2 border-red-500'
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
                ? 'text-white font-bold border-b-2 border-red-500'
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
                ? 'text-red-300 border-b-2 border-red-500'
                : 'text-red-300/80 hover:text-red-200'
            }`}
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub &amp; Релизы</span>
          </button>
        </nav>

        {/* Zone 3: Primary actions */}
        <div className="flex items-center gap-3 shrink-0">
          <button
            type="button"
            onClick={() => setIsGithubModalOpen(true)}
            className="px-3.5 py-2 text-xs font-semibold text-red-200 bg-red-950/80 border border-red-500/40 rounded-full hover:bg-red-900/80 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
          >
            <Github className="w-3.5 h-3.5 text-red-400" />
            <span>GitHub &amp; EULA</span>
          </button>
          <button
            type="button"
            onClick={() => setIsWinModalOpen(true)}
            className="px-3.5 py-2 text-xs font-semibold text-red-200 bg-red-950/80 border border-red-500/40 rounded-full hover:bg-red-900/80 transition-colors flex items-center gap-2 whitespace-nowrap shrink-0 cursor-pointer"
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
            className="px-4 py-2 text-xs font-bold text-white bg-red-600 rounded-full hover:bg-red-500 transition-colors whitespace-nowrap shrink-0 cursor-pointer shadow-lg shadow-red-950/60"
          >
            Бенчмарки
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-6">
        {activeTab === 'scanner' && (
          <FileScannerView
            currentReport={currentReport}
            hasUserScanned={hasUserScanned}
            onResetScan={() => setHasUserScanned(false)}
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
          <div className="border border-red-900/60 bg-[#140609]/80 rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-red-900/60 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <History className="w-4 h-4 text-red-400" />
                <h2 className="text-sm font-semibold text-white">
                  Журнал проверенных файлов в текущей сессии ({scanHistory.length})
                </h2>
              </div>
              <span className="text-xs text-red-300/70 font-mono">
                Нажмите на любую запись для открытия полного отчета и кода
              </span>
            </div>

            {scanHistory.length === 0 ? (
              <div className="p-8 text-center text-sm text-slate-400">
                Журнал проверок пуст. Добавьте файл или папку во вкладке «Антивирус & Декомпилятор Проекта».
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="border-b border-red-900/50 text-red-300/70 bg-black/40">
                      <th className="py-3 px-4">Имя файла</th>
                      <th className="py-3 px-4">Формат</th>
                      <th className="py-3 px-4 text-right">Размер</th>
                      <th className="py-3 px-4 text-right">Энтропия</th>
                      <th className="py-3 px-4 text-right">Риск</th>
                      <th className="py-3 px-4">Вердикт</th>
                      <th className="py-3 px-4">SHA-256</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-red-950/60">
                    {scanHistory.map((item, idx) => (
                      <tr
                        key={`${item.hashes.sha256}-${idx}`}
                        onClick={() => {
                          setCurrentReport(item);
                          setHasUserScanned(true);
                          setActiveTab('scanner');
                        }}
                        className="hover:bg-red-950/30 cursor-pointer"
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
            onOpenDownloadModal={() => setIsWinModalOpen(true)}
            onSwitchToScanner={() => setActiveTab('scanner')}
          />
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-red-950/80 px-6 py-4 text-xs text-red-300/50 bg-[#0a0305]">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            Антивирус и Декомпилятор Проектов (100% Функций и Переменных · 0% Удаления кода · 32 Боевых Модуля)
          </div>
          <div className="font-mono tabular-nums">
            Активных YARA-правил: {20 + customRules.length} · Модулей анализа: 32
          </div>
        </div>
      </footer>
      <WindowsDownloadModal isOpen={isWinModalOpen} onClose={() => setIsWinModalOpen(false)} />
      <GithubRepoModal
        isOpen={isGithubModalOpen}
        onClose={() => setIsGithubModalOpen(false)}
      />
    </div>
  );
}
