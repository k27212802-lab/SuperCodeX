import React, { useState, useMemo } from 'react';
import { ScanReport } from '../engine/scanner';
import { BENCHMARK_SAMPLES, BenchmarkSample } from '../engine/benchmark';
import { unpackArchiveFiles } from '../engine/archive';
import {
  downloadProjectAsZip,
  ReconstructedProject,
  ReconstructedProjectFile,
} from '../engine/projectLifter';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Binary,
  Hash,
  Download,
  Layers,
  Cpu,
  Globe,
  Sparkles,
  Bot,
  Folder,
  Play,
  FolderPlus,
  FilePlus,
  Loader2,
  Trash2,
  FileText,
  MessageSquare,
  Send,
  Archive,
  FolderTree,
  FolderOpen,
  Copy,
  Search,
  Check,
  FileCode2,
  RotateCcw,
} from 'lucide-react';
import { queryVirusTotalFileReport } from '../engine/virustotal';

interface QueuedItem {
  id: string;
  name: string;
  relativePath?: string;
  size: number;
  file?: File;
  sample?: BenchmarkSample;
  directBytes?: Uint8Array;
}

interface ChatMessage {
  role: 'user' | 'assistant';
  content: string;
}

interface FileScannerViewProps {
  currentReport: ScanReport | null;
  hasUserScanned: boolean;
  onResetScan: () => void;
  isScanning: boolean;
  onScanBytes: (fileName: string, bytes: Uint8Array) => Promise<ScanReport | void>;
}

export const FileScannerView: React.FC<FileScannerViewProps> = ({
  currentReport,
  hasUserScanned,
  onResetScan,
  onScanBytes,
}) => {
  const [queuedItems, setQueuedItems] = useState<QueuedItem[]>([]);
  const [batchReports, setBatchReports] = useState<ScanReport[]>([]);
  const [selectedBatchIndex, setSelectedBatchIndex] = useState<number>(0);
  const [isRunningAntivirus, setIsRunningAntivirus] = useState<boolean>(false);

  const [dragActive, setDragActive] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<
    'project' | 'decompiler' | 'ai' | 'chat' | 'rules' | 'opcodes' | 'headers' | 'strings'
  >('project');

  const [selectedFilePath, setSelectedFilePath] = useState<string | null>(null);
  const [projectSearchTerm, setProjectSearchTerm] = useState<string>('');
  const [isCopied, setIsCopied] = useState<boolean>(false);
  const [expandedFolders, setExpandedFolders] = useState<Record<string, boolean>>({});

  const toggleFolder = (folderPath: string) => {
    setExpandedFolders((prev) => ({
      ...prev,
      [folderPath]: !(prev[folderPath] ?? true),
    }));
  };

  const handleCopyCode = (text: string) => {
    navigator.clipboard.writeText(text);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  const [isCheckingVt, setIsCheckingVt] = useState(false);
  const [vtCheckResult, setVtCheckResult] = useState<any | null>(null);
  const [vtError, setVtError] = useState<string | null>(null);

  // AI Audit State
  const [isAuditingWithAi, setIsAuditingWithAi] = useState(false);
  const [aiAuditResult, setAiAuditResult] = useState<string | null>(null);
  const [aiAuditError, setAiAuditError] = useState<string | null>(null);
  const [aiModelUsed, setAiModelUsed] = useState<string | null>(null);

  // Interactive AI Chat State
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatInput, setChatInput] = useState('');
  const [isSendingChat, setIsSendingChat] = useState(false);

  // Antivirus pipeline steps
  const [analysisStep, setAnalysisStep] = useState<number>(0);
  const [analysisStatusText, setAnalysisStatusText] = useState<string>('');

  const activeReport = hasUserScanned
    ? batchReports[selectedBatchIndex] || currentReport
    : null;

  const [cppSyntaxStatusByPath, setCppSyntaxStatusByPath] = useState<Record<string, 'OK' | 'FAIL'>>({});
  const [cppSyntaxSummary, setCppSyntaxSummary] = useState<{ total: number; passed: number; failed: number } | null>(null);

  // Build unified project across single binary or multi-file archive/folder scan
  const unifiedProject: ReconstructedProject | null = useMemo(() => {
    if (!hasUserScanned || !activeReport) return null;

    if (batchReports.length <= 1) {
      return activeReport.decompilation.reconstructedProject || null;
    }

    // Merge all files from batchReports into one complete multi-folder project
    const mergedFiles: ReconstructedProjectFile[] = [];
    const seenPaths = new Set<string>();

    for (const rep of batchReports) {
      const cleanEntryPath = rep.fileName.includes(' :: ')
        ? rep.fileName.split(' :: ')[1]
        : rep.fileName;

      // Requirement 4: Skip .qm, .xml, .txt and any data files where no code was generated
      if (
        rep.decompilation.targetLanguage.includes('Data / Resource File') ||
        !rep.decompilation.reconstructedCode
      ) {
        continue;
      }

      if (rep.headerAnalysis.format === 'Script / Text') {
        const lower = cleanEntryPath.toLowerCase();
        if (lower.endsWith('.qm') || lower.endsWith('.xml') || lower.endsWith('.txt')) {
          continue;
        }
        const lang: ReconstructedProjectFile['language'] =
          lower.endsWith('.h') || lower.endsWith('.hpp')
            ? 'h'
            : lower.endsWith('.java') || lower.endsWith('.kt')
            ? 'java'
            : lower.endsWith('.cs')
            ? 'cs'
            : lower.endsWith('.gradle') || lower.endsWith('.mk') || lower.includes('makefile')
            ? 'makefile'
            : lower.includes('cmake')
            ? 'cmake'
            : 'cpp';

        const pathKey = cleanEntryPath.replace(/^\/+/, '');
        if (!seenPaths.has(pathKey)) {
          seenPaths.add(pathKey);
          mergedFiles.push({
            path: pathKey,
            language: lang,
            content: rep.decompilation.reconstructedCode,
            sizeBytes: rep.fileSize,
            description: pathKey,
          });
        }
      } else if (rep.decompilation.reconstructedProject && rep.decompilation.reconstructedProject.files.length > 0) {
        const prefix =
          batchReports.length > 1
            ? cleanEntryPath.replace(/\.[^/.]+$/, '').replace(/[^a-zA-Z0-9_/-]/g, '_') + '/'
            : '';
        for (const pf of rep.decompilation.reconstructedProject.files) {
          const fullPath = `${prefix}${pf.path}`.replace(/^\/+/, '');
          if (!seenPaths.has(fullPath)) {
            seenPaths.add(fullPath);
            mergedFiles.push({
              ...pf,
              path: fullPath,
            });
          }
        }
      }
    }

    if (mergedFiles.length === 0 && activeReport.decompilation.reconstructedProject) {
      return activeReport.decompilation.reconstructedProject;
    }

    const totalLines = mergedFiles.reduce((acc, f) => acc + f.content.split('\n').length, 0);
    const baseProject = activeReport.decompilation.reconstructedProject;

    return {
      projectName: baseProject?.projectName || 'extracted_project',
      targetFramework: baseProject?.targetFramework || 'C++ / Multi-Module Project',
      totalFiles: mergedFiles.length,
      totalLines,
      files: mergedFiles,
      directoryTree: baseProject?.directoryTree || {
        name: 'root',
        path: '',
        files: mergedFiles,
        subdirectories: [],
      },
    };
  }, [hasUserScanned, activeReport, batchReports]);

  React.useEffect(() => {
    if (!unifiedProject || unifiedProject.files.length === 0) {
      setCppSyntaxStatusByPath({});
      setCppSyntaxSummary(null);
      return;
    }
    const hasCpp = unifiedProject.files.some((f) => f.language === 'cpp' && f.path.endsWith('.cpp'));
    if (!hasCpp) {
      setCppSyntaxStatusByPath({});
      setCppSyntaxSummary(null);
      return;
    }
    let cancelled = false;
    fetch('/api/verify-cpp-syntax', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ project: unifiedProject }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (cancelled || !data?.success || !data?.report) return;
        const map: Record<string, 'OK' | 'FAIL'> = {};
        for (const item of data.report.results || []) {
          map[item.path] = item.status;
        }
        setCppSyntaxStatusByPath(map);
        setCppSyntaxSummary({
          total: data.report.totalCppFiles,
          passed: data.report.passedCount,
          failed: data.report.failedCount,
        });
      })
      .catch(() => {
        // Ignore network errors in offline mode
      });
    return () => {
      cancelled = true;
    };
  }, [unifiedProject]);

  const handleRunAiAudit = async (reportToAudit: ScanReport | null = activeReport) => {
    if (!reportToAudit) return;
    setIsAuditingWithAi(true);
    setAiAuditError(null);
    try {
      const response = await fetch('/api/ai-audit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          code: reportToAudit.decompilation.reconstructedCode,
          fileName: reportToAudit.fileName,
          format: reportToAudit.headerAnalysis.format,
        }),
      });
      const data = await response.json();
      if (data.success && data.analysis) {
        setAiAuditResult(data.analysis);
        setAiModelUsed(data.modelUsed || 'gemini-3.8-flash');
      } else {
        setAiAuditError(data.error || 'Ошибка ИИ-аудита исходного кода.');
      }
    } catch (e: any) {
      setAiAuditError(e.message || String(e));
    } finally {
      setIsAuditingWithAi(false);
    }
  };

  const handleSendChatMessage = async () => {
    if (!chatInput.trim() || isSendingChat || !activeReport) return;

    const userMsg: ChatMessage = { role: 'user', content: chatInput.trim() };
    const updatedMessages = [...chatMessages, userMsg];
    setChatMessages(updatedMessages);
    setChatInput('');
    setIsSendingChat(true);

    try {
      const response = await fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          messages: updatedMessages,
          codeContext: activeReport.decompilation.reconstructedCode,
          fileName: activeReport.fileName,
        }),
      });
      const data = await response.json();
      if (data.success && data.reply) {
        setChatMessages([
          ...updatedMessages,
          { role: 'assistant', content: data.reply },
        ]);
        if (data.modelUsed) setAiModelUsed(data.modelUsed);
      } else {
        setChatMessages([
          ...updatedMessages,
          {
            role: 'assistant',
            content: `Ошибка ответа ИИ: ${data.error || 'Модель перегружена'}`,
          },
        ]);
      }
    } catch (err: any) {
      setChatMessages([
        ...updatedMessages,
        {
          role: 'assistant',
          content: `Сетевая ошибка обращения к серверу ИИ: ${err.message || String(err)}`,
        },
      ]);
    } finally {
      setIsSendingChat(false);
    }
  };

  // Recursive folder traversal for drag-and-drop directories
  const traverseFileTree = async (item: any, path = ''): Promise<{ file: File; relPath: string }[]> => {
    const results: { file: File; relPath: string }[] = [];
    if (item.isFile) {
      const file = await new Promise<File>((resolve) => item.file(resolve));
      results.push({ file, relPath: path ? `${path}/${file.name}` : file.name });
    } else if (item.isDirectory) {
      const dirReader = item.createReader();
      const entries = await new Promise<any[]>((resolve) => {
        dirReader.readEntries((res: any[]) => resolve(res));
      });
      for (const entry of entries) {
        const subFiles = await traverseFileTree(entry, path ? `${path}/${item.name}` : item.name);
        results.push(...subFiles);
      }
    }
    return results;
  };

  const addFilesToQueue = async (files: File[]) => {
    const itemsToAdd: QueuedItem[] = [];

    for (let i = 0; i < files.length; i++) {
      const f = files[i];
      const lowerName = f.name.toLowerCase();
      const relPath = (f as any).webkitRelativePath || f.name;

      // Note: .apk is kept as a single APK unit so classes.dex + manifest + resources are decompiled into a full Java project
      if (
        (lowerName.endsWith('.zip') ||
          lowerName.endsWith('.tar.gz') ||
          lowerName.endsWith('.tgz') ||
          lowerName.endsWith('.gz') ||
          lowerName.endsWith('.tar')) &&
        !lowerName.endsWith('.apk')
      ) {
        const buffer = await f.arrayBuffer();
        const extracted = await unpackArchiveFiles(f.name, new Uint8Array(buffer));
        if (extracted.length > 0) {
          for (const extFile of extracted) {
            itemsToAdd.push({
              id: `${f.name}-${extFile.name}-${extFile.bytes.length}-${Date.now()}-${i}`,
              name: `${f.name} :: ${extFile.name}`,
              relativePath: extFile.name,
              size: extFile.bytes.length,
              directBytes: extFile.bytes,
            });
          }
          continue;
        }
      }

      itemsToAdd.push({
        id: `${f.name}-${f.size}-${Date.now()}-${i}`,
        name: relPath || f.name,
        relativePath: relPath || f.name,
        size: f.size,
        file: f,
      });
    }

    setQueuedItems((prev) => [...prev, ...itemsToAdd]);
  };

  const addPresetToQueue = (sample: BenchmarkSample) => {
    const newItem: QueuedItem = {
      id: `${sample.id}-${Date.now()}`,
      name: sample.fileName,
      size: sample.buildBytes().length,
      sample: sample,
    };
    setQueuedItems((prev) => [...prev, newItem]);
  };

  const removeQueuedItem = (id: string) => {
    setQueuedItems((prev) => prev.filter((item) => item.id !== id));
  };

  const clearQueue = () => {
    setQueuedItems([]);
    setBatchReports([]);
    setSelectedFilePath(null);
    onResetScan();
  };

  const handleDrop = async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const items = e.dataTransfer.items;
    const extractedFiles: File[] = [];

    if (items && items.length > 0) {
      for (let i = 0; i < items.length; i++) {
        const item = items[i];
        if (item.kind === 'file') {
          const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
          if (entry) {
            const subFiles = await traverseFileTree(entry);
            for (const sf of subFiles) {
              Object.defineProperty(sf.file, 'webkitRelativePath', {
                value: sf.relPath,
                configurable: true,
              });
              extractedFiles.push(sf.file);
            }
          } else {
            const file = item.getAsFile();
            if (file) extractedFiles.push(file);
          }
        }
      }
    } else if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      for (let i = 0; i < e.dataTransfer.files.length; i++) {
        extractedFiles.push(e.dataTransfer.files[i]);
      }
    }

    if (extractedFiles.length > 0) {
      await addFilesToQueue(extractedFiles);
    }
  };

  const runFullAnalysisPipeline = async () => {
    if (queuedItems.length === 0) return;

    setIsRunningAntivirus(true);
    setSelectedFilePath(null);
    setAnalysisStep(1);
    setAnalysisStatusText('Этап 1/5: Чтение бинарных заголовков PE / DEX / ELF и расчёт SHA-256...');

    const reports: ScanReport[] = [];

    for (let idx = 0; idx < queuedItems.length; idx++) {
      const item = queuedItems[idx];

      setAnalysisStep(2);
      setAnalysisStatusText(
        `Этап 2/5 [${idx + 1}/${queuedItems.length}]: Антивирусное сканирование (32 модуля и YARA) — ${item.name}...`
      );
      await new Promise((r) => setTimeout(r, 90));

      setAnalysisStep(3);
      setAnalysisStatusText(
        `Этап 3/5 [${idx + 1}/${queuedItems.length}]: Вскрытие шифров XTEA-32, RC4, XOR и ROR13 API хэшей...`
      );
      await new Promise((r) => setTimeout(r, 90));

      let bytes: Uint8Array;
      if (item.directBytes) {
        bytes = item.directBytes;
      } else if (item.file) {
        const buffer = await item.file.arrayBuffer();
        bytes = new Uint8Array(buffer);
      } else if (item.sample) {
        bytes = item.sample.buildBytes();
      } else {
        continue;
      }

      setAnalysisStep(4);
      setAnalysisStatusText(
        `Этап 4/5 [${idx + 1}/${queuedItems.length}]: Анализ безопасности и расчёт индекса угрозы...`
      );

      const report = await onScanBytes(item.name, bytes);
      if (report) {
        reports.push(report);
      }

      setAnalysisStep(5);
      setAnalysisStatusText(
        `Этап 5/5 (ФИНАЛ): Декомпилятор достаёт весь исходный код, все папки и все файлы из ${item.name}...`
      );
      await new Promise((r) => setTimeout(r, 120));
    }

    setIsRunningAntivirus(false);

    if (reports.length > 0) {
      setBatchReports(reports);
      setSelectedBatchIndex(0);
      setActiveDetailTab('project');
      if (reports[0].decompilation.reconstructedCode) {
        handleRunAiAudit(reports[0]);
      }
    }
  };

  const handleExportJson = () => {
    if (!activeReport) return;
    const blob = new Blob([JSON.stringify(activeReport, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${activeReport.fileName}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportDecompiledSource = () => {
    if (!activeReport) return;
    const isJava =
      activeReport.decompilation.targetLanguage ===
      'Java / Smali (Android APK & Dalvik DEX Decompiler)';
    const isCSharp =
      activeReport.decompilation.targetLanguage ===
      'C# / CIL (.NET Managed Assembly Decompiler)';
    const ext = isJava ? 'java' : isCSharp ? 'cs' : 'cpp';
    const blob = new Blob([activeReport.decompilation.reconstructedCode], {
      type: 'text/plain;charset=utf-8',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeReport.fileName}.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleCheckCurrentFileOnVirusTotal = async () => {
    if (!activeReport) return;
    setIsCheckingVt(true);
    setVtError(null);
    setVtCheckResult(null);
    try {
      const res = await queryVirusTotalFileReport(activeReport.hashes.sha256);
      if (res.success && res.stats) {
        setVtCheckResult(res);
      } else {
        setVtError(res.error || 'Хэш не найден в базе VirusTotal.');
      }
    } catch (e: any) {
      setVtError(e.message || String(e));
    } finally {
      setIsCheckingVt(false);
    }
  };

  const quickPresets = [
    BENCHMARK_SAMPLES.find((s) => s.id === 'BM-26'), // C++ Multi-Function PE64 (.exe)
    BENCHMARK_SAMPLES.find((s) => s.id === 'BM-19'), // Android APK (.apk)
    BENCHMARK_SAMPLES.find((s) => s.id === 'BM-18'), // C++ RTTI Process Hollower (.exe)
    BENCHMARK_SAMPLES.find((s) => s.id === 'BM-21'), // .NET C# Stager (.exe)
  ].filter(Boolean) as BenchmarkSample[];

  // Compute folder groups for the Project Tree
  const projectFoldersAndFiles = useMemo(() => {
    if (!unifiedProject || unifiedProject.files.length === 0) {
      return {
        folders: {} as Record<string, ReconstructedProjectFile[]>,
        rootFiles: [] as ReconstructedProjectFile[],
        folderCount: 0,
        fileCount: 0,
        filteredFiles: [] as ReconstructedProjectFile[],
      };
    }

    const filteredFiles = unifiedProject.files.filter((f) =>
      projectSearchTerm
        ? f.path.toLowerCase().includes(projectSearchTerm.toLowerCase()) ||
          f.content.toLowerCase().includes(projectSearchTerm.toLowerCase())
        : true
    );

    const folders: Record<string, ReconstructedProjectFile[]> = {};
    const rootFiles: ReconstructedProjectFile[] = [];

    for (const f of filteredFiles) {
      const slashIdx = f.path.indexOf('/');
      if (slashIdx === -1) {
        rootFiles.push(f);
      } else {
        const folder = f.path.substring(0, f.path.lastIndexOf('/'));
        if (!folders[folder]) folders[folder] = [];
        folders[folder].push(f);
      }
    }

    return {
      folders,
      rootFiles,
      folderCount: Object.keys(folders).length,
      fileCount: unifiedProject.files.length,
      filteredFiles,
    };
  }, [unifiedProject, projectSearchTerm]);

  return (
    <div className="space-y-6">
      {/* ===================================================================== */}
      {/* RED COMMAND CENTER: CIRCULAR RED BUTTONS FOR FILE, FOLDER & ANTIVIRUS */}
      {/* ===================================================================== */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragActive(true);
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={handleDrop}
        className={`rounded-2xl border-2 p-6 transition-all shadow-2xl ${
          dragActive
            ? 'border-red-400 bg-red-950/60 scale-[0.99]'
            : 'border-red-800/80 bg-gradient-to-b from-[#1f070b] to-[#120407]'
        }`}
      >
        <div className="flex flex-col lg:flex-row items-center justify-between gap-8">
          {/* Left: 3 Circular Red Buttons */}
          <div className="flex flex-wrap items-center justify-center gap-6">
            {/* Circular Red Button 1: Добавить файл */}
            <label
              htmlFor="red-add-file-input"
              className="w-36 h-36 rounded-full bg-red-600 hover:bg-red-500 active:scale-95 border-4 border-red-400/70 shadow-[0_0_30px_rgba(220,38,38,0.5)] text-white cursor-pointer transition-all flex flex-col items-center justify-center p-3 text-center select-none"
            >
              <FilePlus className="w-8 h-8 mb-1.5 text-white" />
              <span className="text-xs font-extrabold uppercase tracking-wide leading-tight">
                Добавить файл
              </span>
              <span className="text-[10px] text-red-100/90 mt-1 font-mono">
                .exe .apk .zip .tar.gz
              </span>
              <input
                id="red-add-file-input"
                type="file"
                multiple
                className="sr-only"
                onChange={async (e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    await addFilesToQueue(Array.from(e.target.files));
                    e.target.value = '';
                  }
                }}
              />
            </label>

            {/* Circular Red Button 2: Добавить папку */}
            <label
              htmlFor="red-add-folder-input"
              className="w-36 h-36 rounded-full bg-red-700 hover:bg-red-600 active:scale-95 border-4 border-red-400/70 shadow-[0_0_30px_rgba(185,28,28,0.5)] text-white cursor-pointer transition-all flex flex-col items-center justify-center p-3 text-center select-none"
            >
              <FolderPlus className="w-8 h-8 mb-1.5 text-white" />
              <span className="text-xs font-extrabold uppercase tracking-wide leading-tight">
                Добавить папку
              </span>
              <span className="text-[10px] text-red-100/90 mt-1 font-mono">
                Все файлы внутри
              </span>
              <input
                id="red-add-folder-input"
                type="file"
                // @ts-ignore
                webkitdirectory="true"
                // @ts-ignore
                directory="true"
                multiple
                className="sr-only"
                onChange={async (e) => {
                  if (e.target.files && e.target.files.length > 0) {
                    await addFilesToQueue(Array.from(e.target.files));
                    e.target.value = '';
                  }
                }}
              />
            </label>

            {/* Circular Red Button 3: Запустить антивирус */}
            <button
              type="button"
              disabled={queuedItems.length === 0 || isRunningAntivirus}
              onClick={runFullAnalysisPipeline}
              className="w-40 h-40 rounded-full bg-gradient-to-br from-red-500 via-red-600 to-red-900 hover:from-red-400 hover:to-red-700 disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 border-4 border-red-300 shadow-[0_0_45px_rgba(239,68,68,0.75)] text-white cursor-pointer transition-all flex flex-col items-center justify-center p-4 text-center select-none"
            >
              {isRunningAntivirus ? (
                <Loader2 className="w-10 h-10 mb-1.5 text-white animate-spin" />
              ) : (
                <Play className="w-10 h-10 mb-1.5 text-white fill-current" />
              )}
              <span className="text-xs font-black uppercase tracking-wider leading-tight">
                {isRunningAntivirus ? 'Идёт проверка...' : 'Запустить антивирус'}
              </span>
              <span className="text-[10px] text-red-100 mt-1 font-mono">
                {queuedItems.length > 0
                  ? `В очереди: ${queuedItems.length} шт.`
                  : 'Сначала добавьте файл'}
              </span>
            </button>
          </div>

          {/* Right: Queue & Quick Test Files */}
          <div className="flex-1 w-full lg:max-w-xl bg-black/50 border border-red-900/60 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-red-950 pb-2">
              <div className="flex items-center gap-2 text-xs font-bold text-red-200">
                <Layers className="w-4 h-4 text-red-500" />
                <span>Выбранные файлы и папки для проверки ({queuedItems.length})</span>
              </div>
              { (queuedItems.length > 0 || hasUserScanned) && (
                <button
                  type="button"
                  onClick={clearQueue}
                  className="px-2.5 py-1 rounded-full bg-red-950/90 hover:bg-red-900 text-red-200 text-[11px] font-mono flex items-center gap-1 cursor-pointer border border-red-700/50"
                >
                  <RotateCcw className="w-3 h-3" />
                  <span>Сбросить в 0</span>
                </button>
              )}
            </div>

            {queuedItems.length === 0 ? (
              <div className="py-3 text-xs text-red-200/60 font-mono">
                Очередь пуста (0 файлов). Нажмите круглую красную кнопку «Добавить файл» (.exe, .apk, .zip, .tar.gz) или «Добавить папку», либо выберите тестовый файл ниже:
              </div>
            ) : (
              <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                {queuedItems.map((item) => (
                  <div
                    key={item.id}
                    className="px-3 py-1.5 rounded-lg border border-red-900/50 bg-red-950/30 flex items-center justify-between gap-2 text-xs"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <FileCode className="w-4 h-4 text-red-400 shrink-0" />
                      <span className="font-semibold text-white truncate">{item.name}</span>
                      <span className="text-[10px] text-red-300/70 font-mono shrink-0">
                        ({(item.size / 1024).toFixed(1)} КБ)
                      </span>
                    </div>
                    <button
                      type="button"
                      onClick={() => removeQueuedItem(item.id)}
                      className="text-red-400 hover:text-red-200 p-1 cursor-pointer"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Quick 1-Click Test Samples */}
            <div className="pt-2 border-t border-red-950/80">
              <div className="text-[11px] text-red-300/80 mb-2 font-medium">
                Быстрое добавление тестового файла (.exe / .apk) для проверки:
              </div>
              <div className="flex flex-wrap gap-1.5">
                {quickPresets.map((sample) => (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => addPresetToQueue(sample)}
                    className="px-3 py-1 rounded-full bg-red-950/80 hover:bg-red-800 border border-red-600/50 text-[11px] font-mono text-red-100 cursor-pointer transition-colors"
                  >
                    + {sample.fileName}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Progress Bar when Antivirus is running */}
        {isRunningAntivirus && (
          <div className="mt-6 pt-5 border-t border-red-900/60 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono text-red-200">
              <span className="font-bold flex items-center gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-red-400" />
                {analysisStatusText}
              </span>
              <span className="text-red-400 font-bold">Шаг {analysisStep} из 5</span>
            </div>
            <div className="grid grid-cols-5 gap-2">
              {[
                '1. Заголовки и Хэши',
                '2. Антивирус (32 модуля)',
                '3. Вскрытие XTEA/RC4',
                '4. Оценка риска',
                '5. ФИНАЛ: Достаём весь код и папки',
              ].map((label, idx) => (
                <div
                  key={label}
                  className={`p-2 rounded-lg border text-[11px] font-mono text-center ${
                    analysisStep > idx + 1
                      ? 'border-red-500 bg-red-900/50 text-white'
                      : analysisStep === idx + 1
                      ? 'border-red-400 bg-red-600 text-white font-bold animate-pulse'
                      : 'border-red-950 bg-black/40 text-red-300/40'
                  }`}
                >
                  {label}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ===================================================================== */}
      {/* ANTIVIRUS VERDICT BANNER (Shown after scan completes)                 */}
      {/* ===================================================================== */}
      {hasUserScanned && activeReport && (
        <div className="rounded-2xl border-2 border-red-700/80 bg-gradient-to-r from-red-950/90 via-[#1a0509] to-red-950/90 p-5 shadow-xl">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-start gap-4">
              <div className="p-3 rounded-full bg-red-600/20 border-2 border-red-500 shrink-0">
                {activeReport.verdict === 'MALICIOUS' ? (
                  <ShieldAlert className="w-8 h-8 text-red-400" />
                ) : activeReport.verdict === 'SUSPICIOUS' ? (
                  <AlertTriangle className="w-8 h-8 text-amber-300" />
                ) : (
                  <ShieldCheck className="w-8 h-8 text-emerald-400" />
                )}
              </div>
              <div>
                <div className="text-xs font-mono text-red-200/80 mb-0.5">
                  Проверен файл: <strong className="text-white">{activeReport.fileName}</strong> ·{' '}
                  {activeReport.fileSize.toLocaleString('ru-RU')} байт · Формат:{' '}
                  {activeReport.headerAnalysis.format}
                </div>
                <h2 className="text-lg font-extrabold text-white">
                  Вердикт антивируса:{' '}
                  <span
                    className={
                      activeReport.verdict === 'MALICIOUS'
                        ? 'text-red-400'
                        : activeReport.verdict === 'SUSPICIOUS'
                        ? 'text-amber-300'
                        : 'text-emerald-400'
                    }
                  >
                    {activeReport.verdict === 'MALICIOUS'
                      ? 'ОБНАРУЖЕНА УГРОЗА (MALICIOUS)'
                      : activeReport.verdict === 'SUSPICIOUS'
                      ? 'ПОДОЗРИТЕЛЬНЫЙ ФАЙЛ (SUSPICIOUS)'
                      : 'БЕЗОПАСНЫЙ ФАЙЛ (CLEAN)'}
                  </span>
                </h2>
                <p className="text-xs text-red-100/80 mt-1 max-w-3xl">
                  {activeReport.verdictSummary}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-6 shrink-0 border-t md:border-t-0 pt-3 md:pt-0 border-red-800/60">
              <div className="text-right">
                <div className="text-[11px] text-red-200/80">Индекс угрозы</div>
                <div className="text-3xl font-black font-mono text-white">
                  {activeReport.riskScore}
                  <span className="text-xs font-normal text-red-300">/100</span>
                </div>
              </div>
              <div className="text-right">
                <div className="text-[11px] text-red-200/80">Извлечено файлов</div>
                <div className="text-3xl font-black font-mono text-red-400">
                  {projectFoldersAndFiles.fileCount}
                </div>
              </div>
            </div>
          </div>

          {batchReports.length > 1 && (
            <div className="mt-4 pt-3 border-t border-red-900/60 flex items-center gap-2 overflow-x-auto">
              <span className="text-xs font-bold text-red-200 shrink-0">
                Проверенные объекты ({batchReports.length}):
              </span>
              {batchReports.map((rep, idx) => (
                <button
                  key={`${rep.fileName}-${idx}`}
                  type="button"
                  onClick={() => setSelectedBatchIndex(idx)}
                  className={`px-3 py-1 rounded-full text-xs font-mono shrink-0 cursor-pointer border transition-colors ${
                    selectedBatchIndex === idx
                      ? 'bg-red-600 text-white border-red-400 font-bold'
                      : 'bg-black/50 text-red-200 border-red-900 hover:bg-red-950'
                  }`}
                >
                  {rep.fileName} [{rep.riskScore}/100]
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ===================================================================== */}
      {/* EXTRACTED PROJECT FOLDERS & SOURCE CODE EXPLORER (0 before scan!)     */}
      {/* ===================================================================== */}
      <div className="rounded-2xl border-2 border-red-800/80 bg-[#140508] overflow-hidden shadow-2xl">
        {/* Top Header of Project Explorer */}
        <div className="px-6 py-4 border-b border-red-900/70 bg-[#1c060a] flex flex-wrap items-center justify-between gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-sm font-extrabold text-white">
              <FolderTree className="w-5 h-5 text-red-500" />
              <span>ПАПКИ И ИСХОДНЫЙ КОД ПРОЕКТА:</span>
            </div>

            {/* Live Badge: 0 files before scan, >0 after antivirus finale */}
            <div
              className={`px-3.5 py-1 rounded-full text-xs font-mono font-bold border ${
                projectFoldersAndFiles.fileCount > 0
                  ? 'bg-red-600 text-white border-red-400 shadow-md shadow-red-950'
                  : 'bg-black/60 text-red-300/70 border-red-900/60'
              }`}
            >
              Папок: {projectFoldersAndFiles.folderCount} · Файлов: {projectFoldersAndFiles.fileCount}
            </div>

            {cppSyntaxSummary && (
              <div
                className={`px-3 py-1 rounded-full text-xs font-mono font-bold border ${
                  cppSyntaxSummary.failed === 0
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-500/60'
                    : 'bg-amber-950/80 text-amber-300 border-amber-500/60'
                }`}
              >
                g++ -fsyntax-only: {cppSyntaxSummary.passed}/{cppSyntaxSummary.total} OK
              </div>
            )}

            {hasUserScanned && activeReport && (
              <div className="flex flex-wrap items-center gap-1.5 ml-2">
                <button
                  type="button"
                  onClick={() => setActiveDetailTab('project')}
                  className={`px-3 py-1 rounded-full text-xs font-bold cursor-pointer transition-colors ${
                    activeDetailTab === 'project'
                      ? 'bg-red-600 text-white'
                      : 'bg-red-950/60 text-red-200 hover:bg-red-900'
                  }`}
                >
                  Папки и файлы ({projectFoldersAndFiles.fileCount})
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDetailTab('decompiler')}
                  className={`px-3 py-1 rounded-full text-xs font-bold cursor-pointer transition-colors ${
                    activeDetailTab === 'decompiler'
                      ? 'bg-red-600 text-white'
                      : 'bg-red-950/60 text-red-200 hover:bg-red-900'
                  }`}
                >
                  Ассемблер и код
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDetailTab('ai')}
                  className={`px-3 py-1 rounded-full text-xs font-bold cursor-pointer transition-colors flex items-center gap-1 ${
                    activeDetailTab === 'ai'
                      ? 'bg-red-600 text-white'
                      : 'bg-red-950/60 text-red-200 hover:bg-red-900'
                  }`}
                >
                  <Bot className="w-3.5 h-3.5" />
                  <span>ИИ-Аудит</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDetailTab('chat')}
                  className={`px-3 py-1 rounded-full text-xs font-bold cursor-pointer transition-colors flex items-center gap-1 ${
                    activeDetailTab === 'chat'
                      ? 'bg-red-600 text-white'
                      : 'bg-red-950/60 text-red-200 hover:bg-red-900'
                  }`}
                >
                  <MessageSquare className="w-3.5 h-3.5" />
                  <span>Чат ({chatMessages.length})</span>
                </button>
                <button
                  type="button"
                  onClick={() => setActiveDetailTab('rules')}
                  className={`px-3 py-1 rounded-full text-xs font-bold cursor-pointer transition-colors ${
                    activeDetailTab === 'rules'
                      ? 'bg-red-600 text-white'
                      : 'bg-red-950/60 text-red-200 hover:bg-red-900'
                  }`}
                >
                  YARA ({activeReport.triggeredRules.length})
                </button>
              </div>
            )}
          </div>

          {/* Right: Download C++ Project (.ZIP) Button */}
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={!unifiedProject || unifiedProject.files.length === 0}
              onClick={() => unifiedProject && downloadProjectAsZip(unifiedProject)}
              className="px-5 py-2.5 rounded-full bg-red-600 hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-xs font-extrabold transition-all flex items-center gap-2 cursor-pointer shadow-lg shadow-red-950 border border-red-400/50"
            >
              <Archive className="w-4 h-4" />
              <span>Скачать C++ проект (.ZIP)</span>
            </button>

            {hasUserScanned && activeReport && (
              <>
                <button
                  type="button"
                  onClick={handleExportDecompiledSource}
                  className="px-3.5 py-2 rounded-full border border-red-700 bg-red-950/70 text-red-100 text-xs font-semibold hover:bg-red-900 transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Один файл</span>
                </button>
                <button
                  type="button"
                  onClick={handleExportJson}
                  className="px-3.5 py-2 rounded-full border border-red-700 bg-red-950/70 text-red-100 text-xs font-semibold hover:bg-red-900 transition-colors flex items-center gap-1.5 cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Отчёт JSON</span>
                </button>
              </>
            )}
          </div>
        </div>

        {/* Main Body of Project Explorer */}
        <div className="p-6">
          {/* WHEN NOTHING ADDED / SCANNED YET -> SHOW 0 FILES */}
          {(!hasUserScanned || !unifiedProject || unifiedProject.files.length === 0) ? (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch border border-red-900/60 rounded-xl bg-[#0d0305] overflow-hidden min-h-[420px]">
              {/* Left Sidebar showing 0 folders / 0 files */}
              <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-red-900/60 bg-[#140508] p-4 flex flex-col justify-between">
                <div className="space-y-4">
                  <div className="text-xs font-mono font-bold text-red-300 flex items-center justify-between border-b border-red-950 pb-2">
                    <span>ПАПКИ И ФАЙЛЫ</span>
                    <span className="text-red-400">0 папок · 0 файлов</span>
                  </div>
                  <div className="py-16 text-center space-y-2">
                    <Folder className="w-10 h-10 text-red-900 mx-auto" />
                    <div className="text-sm font-bold text-red-200/70">0 файлов</div>
                    <p className="text-xs text-red-300/50 max-w-xs mx-auto leading-relaxed">
                      Пока вы ничего не добавили и не запустили антивирус, список папок пуст (0).
                    </p>
                  </div>
                </div>
                <div className="pt-3 border-t border-red-950 text-[11px] font-mono text-red-400/60">
                  Ожидание запуска антивируса...
                </div>
              </div>

              {/* Right Empty Code Viewer */}
              <div className="lg:col-span-8 flex flex-col items-center justify-center p-8 text-center bg-[#0a0204]">
                <FileCode2 className="w-12 h-12 text-red-800/60 mb-3" />
                <h3 className="text-base font-bold text-white mb-1">
                  Исходный код и папки появятся здесь в финале работы антивируса
                </h3>
                <p className="text-xs text-red-200/70 max-w-lg leading-relaxed">
                  1. Нажмите круглую красную кнопку <strong className="text-red-400">«Добавить файл»</strong> (.exe, .apk, .zip, .tar.gz) или <strong className="text-red-400">«Добавить папку»</strong> выше.<br />
                  2. Нажмите круглую красную кнопку <strong className="text-red-400">«Запустить антивирус»</strong>.<br />
                  3. В финале проверки антивирус через декомпилятор достанет все папки и все файлы с исходным кодом — вы сможете нажимать на папки и просматривать код каждого файла.
                </p>
              </div>
            </div>
          ) : (
            <>
              {/* TAB 0: EXTRACTED FOLDERS & CLEAN CODE VIEWER */}
              {activeDetailTab === 'project' && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch border border-red-900/70 rounded-xl bg-[#0d0305] overflow-hidden shadow-2xl min-h-[560px]">
                  {/* Left Sidebar: Clickable Folders & Files */}
                  <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-red-900/70 bg-[#160509] p-3 space-y-3 flex flex-col justify-between">
                    <div className="space-y-3">
                      {/* Search Input */}
                      <div className="relative">
                        <Search className="w-3.5 h-3.5 text-red-400 absolute left-3 top-2.5" />
                        <input
                          type="text"
                          value={projectSearchTerm}
                          onChange={(e) => setProjectSearchTerm(e.target.value)}
                          placeholder="Поиск файла или функции..."
                          className="w-full pl-8 pr-3 py-1.5 rounded-full bg-black/70 border border-red-800/80 text-xs text-white placeholder-red-300/40 focus:outline-none focus:border-red-500 font-mono"
                        />
                      </div>

                      <div className="text-[11px] font-mono text-red-200 font-bold px-1 flex items-center justify-between">
                        <span>ИЗВЛЕЧЁННЫЕ ПАПКИ ({projectFoldersAndFiles.folderCount})</span>
                        <span className="text-red-400">{projectFoldersAndFiles.filteredFiles.length} файлов</span>
                      </div>

                      {/* Folder & File Tree */}
                      <div className="space-y-1 max-h-[470px] overflow-y-auto pr-1 text-xs font-mono">
                        {Object.entries(projectFoldersAndFiles.folders).map(([folderName, folderFiles]) => {
                          const isExpanded = expandedFolders[folderName] ?? true;
                          const activeFile =
                            unifiedProject.files.find((f) => f.path === selectedFilePath) ||
                            projectFoldersAndFiles.filteredFiles[0] ||
                            unifiedProject.files[0];

                          return (
                            <div key={folderName} className="space-y-0.5">
                              <button
                                type="button"
                                onClick={() => toggleFolder(folderName)}
                                className="w-full px-2.5 py-1.5 rounded-lg hover:bg-red-900/40 text-red-100 font-bold flex items-center gap-2 text-left cursor-pointer transition-colors"
                              >
                                {isExpanded ? (
                                  <FolderOpen className="w-4 h-4 text-red-400 shrink-0" />
                                ) : (
                                  <Folder className="w-4 h-4 text-red-500 shrink-0" />
                                )}
                                <span className="truncate">{folderName}/</span>
                                <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded-full bg-red-950 text-red-300 tabular-nums">
                                  {folderFiles.length}
                                </span>
                              </button>

                              {isExpanded && (
                                <div className="pl-4 space-y-0.5 border-l border-red-900/60 ml-2.5">
                                  {folderFiles.map((f) => {
                                    const isSelected = activeFile?.path === f.path;
                                    const shortName = f.path.substring(f.path.lastIndexOf('/') + 1);
                                    return (
                                      <button
                                        key={f.path}
                                        type="button"
                                        onClick={() => setSelectedFilePath(f.path)}
                                        className={`w-full px-2.5 py-1.5 rounded-lg text-left flex items-center justify-between gap-2 cursor-pointer transition-colors ${
                                          isSelected
                                            ? 'bg-red-600 text-white font-bold shadow-md'
                                            : 'text-red-200/80 hover:text-white hover:bg-red-950/60'
                                        }`}
                                      >
                                        <span className="flex items-center gap-1.5 truncate">
                                          <FileCode2
                                            className={`w-3.5 h-3.5 shrink-0 ${
                                              isSelected ? 'text-white' : 'text-red-400'
                                            }`}
                                          />
                                          <span className="truncate">{shortName}</span>
                                        </span>
                                        <span
                                          className={`text-[10px] tabular-nums shrink-0 ${
                                            isSelected ? 'text-red-100' : 'text-red-400/70'
                                          }`}
                                        >
                                          {(f.sizeBytes / 1024).toFixed(1)} КБ
                                        </span>
                                      </button>
                                    );
                                  })}
                                </div>
                              )}
                            </div>
                          );
                        })}

                        {/* Root Files */}
                        {projectFoldersAndFiles.rootFiles.map((f) => {
                          const activeFile =
                            unifiedProject.files.find((fl) => fl.path === selectedFilePath) ||
                            projectFoldersAndFiles.filteredFiles[0] ||
                            unifiedProject.files[0];
                          const isSelected = activeFile?.path === f.path;

                          return (
                            <button
                              key={f.path}
                              type="button"
                              onClick={() => setSelectedFilePath(f.path)}
                              className={`w-full px-2.5 py-1.5 rounded-lg text-left flex items-center justify-between gap-2 cursor-pointer transition-colors ${
                                isSelected
                                  ? 'bg-red-600 text-white font-bold shadow-md'
                                  : 'text-red-200/80 hover:text-white hover:bg-red-950/60'
                              }`}
                            >
                              <span className="flex items-center gap-1.5 truncate">
                                <FileText
                                  className={`w-3.5 h-3.5 shrink-0 ${
                                    isSelected ? 'text-white' : 'text-red-400'
                                  }`}
                                />
                                <span className="truncate">{f.path}</span>
                              </span>
                              <span
                                className={`text-[10px] tabular-nums shrink-0 ${
                                  isSelected ? 'text-red-100' : 'text-red-400/70'
                                }`}
                              >
                                {(f.sizeBytes / 1024).toFixed(1)} КБ
                              </span>
                            </button>
                          );
                        })}
                      </div>
                    </div>

                    <div className="pt-2 border-t border-red-900/60 text-[10px] font-mono text-red-300/70 flex items-center justify-between">
                      <span>Нажмите на любой файл для чтения кода</span>
                      <span className="text-red-400 font-bold">100% Код</span>
                    </div>
                  </div>

                  {/* Right Area: Clean Source Code Viewer */}
                  {(() => {
                    const activeFile: ReconstructedProjectFile =
                      unifiedProject.files.find((f) => f.path === selectedFilePath) ||
                      projectFoldersAndFiles.filteredFiles[0] ||
                      unifiedProject.files[0];
                    const activeFileLines = activeFile.content.split('\n');

                    return (
                      <div className="lg:col-span-8 flex flex-col justify-between bg-[#0a0204]">
                        {/* File Header */}
                        <div className="px-4 py-2.5 border-b border-red-900/60 bg-[#190509] flex flex-wrap items-center justify-between gap-3">
                          <div className="flex items-center gap-2 text-xs font-mono">
                            <span className="text-red-400 font-bold">{activeFile.path}</span>
                          </div>

                          <div className="flex items-center gap-2">
                            <span className="px-2.5 py-0.5 rounded-full bg-red-950 text-red-200 font-mono text-[10px] border border-red-800/60">
                              {activeFileLines.length} строк · {(activeFile.sizeBytes / 1024).toFixed(1)} КБ
                            </span>
                            <button
                              type="button"
                              onClick={() => handleCopyCode(activeFile.content)}
                              className="px-3 py-1 rounded-full bg-red-600 hover:bg-red-500 text-white text-xs font-bold transition-colors flex items-center gap-1 cursor-pointer"
                            >
                              {isCopied ? (
                                <>
                                  <Check className="w-3 h-3 text-white" />
                                  <span className="text-[11px]">Скопировано</span>
                                </>
                              ) : (
                                <>
                                  <Copy className="w-3 h-3" />
                                  <span className="text-[11px]">Копировать код</span>
                                </>
                              )}
                            </button>
                          </div>
                        </div>

                        {/* Code View with Line Numbers */}
                        <div className="flex-1 overflow-x-auto max-h-[520px] overflow-y-auto font-mono text-xs text-slate-100 flex">
                          <div className="py-4 pr-3 pl-4 border-r border-red-950/80 text-red-400/50 select-none text-right font-mono text-[11px] bg-[#100306] shrink-0">
                            {activeFileLines.map((_, idx) => (
                              <div key={idx} className="leading-relaxed">
                                {idx + 1}
                              </div>
                            ))}
                          </div>

                          <pre className="py-4 px-4 leading-relaxed font-mono whitespace-pre flex-1 text-slate-100">
                            {activeFile.content}
                          </pre>
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}

              {/* TAB 1: Assembler & Single Listing */}
              {activeDetailTab === 'decompiler' && activeReport && (
                <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
                  <div className="lg:col-span-5 border border-red-900/70 rounded-xl bg-[#0a0204] overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-red-900/70 bg-[#190509] text-xs font-bold text-white flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-red-400" />
                      <span>
                        Дизассемблер ({activeReport.decompilation.disassemblyListing.length} инструкций)
                      </span>
                    </div>
                    <div className="max-h-[480px] overflow-y-auto divide-y divide-red-950/60 font-mono text-xs">
                      {activeReport.decompilation.disassemblyListing.map((ins, i) => (
                        <div key={i} className="p-2.5 hover:bg-red-950/30">
                          <div className="flex justify-between text-[11px] text-red-400">
                            <span>{ins.addressHex}</span>
                            <span className="text-amber-300/80">{ins.bytesHex}</span>
                          </div>
                          <div className="text-white font-semibold">
                            {ins.mnemonic}{' '}
                            <span className="text-red-200/80 font-normal">{ins.operands}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="lg:col-span-7 border border-red-900/70 rounded-xl bg-[#0a0204] overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-red-900/70 bg-[#190509] text-xs font-bold text-white flex items-center gap-2">
                      <FileCode className="w-4 h-4 text-red-400" />
                      <span>Полный исходный код</span>
                    </div>
                    <pre className="p-4 text-xs font-mono text-slate-100 overflow-x-auto leading-relaxed whitespace-pre max-h-[480px]">
                      {activeReport.decompilation.reconstructedCode}
                    </pre>
                  </div>
                </div>
              )}

              {/* TAB 2: AI Audit */}
              {activeDetailTab === 'ai' && activeReport && (
                <div className="p-5 rounded-xl border border-red-800/70 bg-[#0d0305] space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <Bot className="w-5 h-5 text-red-400" />
                      <h3 className="text-sm font-bold text-white flex items-center gap-2">
                        <span>ИИ-Аудит безопасности исходного кода</span>
                        {aiModelUsed && (
                          <span className="px-2.5 py-0.5 rounded-full bg-red-950 border border-red-600/50 text-red-200 font-mono text-[10px]">
                            {aiModelUsed}
                          </span>
                        )}
                      </h3>
                    </div>
                    <button
                      type="button"
                      onClick={() => handleRunAiAudit()}
                      disabled={isAuditingWithAi}
                      className="px-4 py-2 rounded-full bg-red-600 hover:bg-red-500 text-white font-bold text-xs transition-colors flex items-center gap-2 cursor-pointer disabled:opacity-50"
                    >
                      <Sparkles className="w-4 h-4" />
                      <span>{isAuditingWithAi ? 'Анализ...' : 'Запустить ИИ-Аудит'}</span>
                    </button>
                  </div>

                  {aiAuditError && (
                    <div className="p-3 rounded-lg bg-red-950/90 border border-red-500 text-xs text-red-200">
                      {aiAuditError}
                    </div>
                  )}

                  {aiAuditResult ? (
                    <div className="p-4 rounded-xl bg-black/60 border border-red-900/60 text-xs font-sans text-slate-100 leading-relaxed whitespace-pre-wrap">
                      {aiAuditResult}
                    </div>
                  ) : (
                    <div className="p-8 text-center text-xs text-red-300/60 font-mono">
                      Нажмите «Запустить ИИ-Аудит» для проверки всех функций нейросетью.
                    </div>
                  )}
                </div>
              )}

              {/* TAB 3: AI Chat */}
              {activeDetailTab === 'chat' && activeReport && (
                <div className="p-5 rounded-xl border border-red-800/70 bg-[#0d0305] space-y-4">
                  <div className="space-y-3 max-h-[380px] overflow-y-auto p-3 rounded-lg bg-black/60 border border-red-900/60">
                    {chatMessages.length === 0 ? (
                      <div className="py-8 text-center text-xs font-mono text-red-300/60">
                        Задайте любой вопрос о функциях и коде файла {activeReport.fileName}.
                      </div>
                    ) : (
                      chatMessages.map((msg, i) => (
                        <div
                          key={i}
                          className={`p-3 rounded-lg text-xs leading-relaxed ${
                            msg.role === 'user'
                              ? 'bg-red-950/80 border border-red-500/50 text-white ml-8'
                              : 'bg-[#190509] border border-red-800/70 text-slate-100 mr-8 whitespace-pre-wrap'
                          }`}
                        >
                          <div className="font-bold mb-1 text-[11px] text-red-300">
                            {msg.role === 'user' ? 'Вы' : 'ИИ-Вирусолог'}
                          </div>
                          {msg.content}
                        </div>
                      ))
                    )}
                    {isSendingChat && (
                      <div className="p-3 rounded-lg bg-red-950/40 text-xs text-red-300 animate-pulse flex items-center gap-2">
                        <Loader2 className="w-4 h-4 animate-spin text-red-400" />
                        <span>ИИ анализирует код...</span>
                      </div>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      value={chatInput}
                      onChange={(e) => setChatInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') handleSendChatMessage();
                      }}
                      placeholder="Спросите о функциях или коде..."
                      className="flex-1 px-4 py-2.5 rounded-full bg-black border border-red-800 text-xs text-white placeholder-red-300/40 focus:outline-none focus:border-red-500"
                    />
                    <button
                      type="button"
                      onClick={handleSendChatMessage}
                      disabled={isSendingChat || !chatInput.trim()}
                      className="px-5 py-2.5 rounded-full bg-red-600 hover:bg-red-500 disabled:opacity-50 text-white font-bold text-xs transition-colors flex items-center gap-2 cursor-pointer"
                    >
                      <Send className="w-4 h-4" />
                      <span>Отправить</span>
                    </button>
                  </div>
                </div>
              )}

              {/* TAB 4: YARA Rules */}
              {activeDetailTab === 'rules' && activeReport && (
                <div className="p-4 rounded-xl border border-red-900/60 bg-[#0a0204]">
                  {activeReport.triggeredRules.length === 0 ? (
                    <div className="py-8 text-center text-xs text-red-300/60 font-mono">
                      Вредоносных сигнатур YARA не обнаружено.
                    </div>
                  ) : (
                    <table className="w-full text-left border-collapse text-xs">
                      <thead>
                        <tr className="border-b border-red-900/60 text-red-300">
                          <th className="py-2 pr-4">ID Правила</th>
                          <th className="py-2 px-4">Название</th>
                          <th className="py-2 px-4">MITRE ATT&amp;CK</th>
                          <th className="py-2 pl-4 text-right">Вес риска</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-red-950/60">
                        {activeReport.triggeredRules.map((tr) => (
                          <tr key={tr.ruleId} className="hover:bg-red-950/30">
                            <td className="py-2.5 pr-4 font-mono text-red-400">{tr.ruleId}</td>
                            <td className="py-2.5 px-4 font-semibold text-white">{tr.ruleName}</td>
                            <td className="py-2.5 px-4 font-mono text-red-200/70">{tr.mitreTechnique || '—'}</td>
                            <td className="py-2.5 pl-4 text-right font-mono font-bold text-red-400">+{tr.scoreAdded}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
};
