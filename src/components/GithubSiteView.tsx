import React, { useState, useEffect } from 'react';
import JSZip from 'jszip';
import {
  Globe,
  GitBranch,
  Download,
  Terminal,
  Copy,
  Check,
  Code2,
  ShieldCheck,
  ExternalLink,
  Cpu,
  BookOpen,
  FileCode,
  Award,
  FolderOpen,
  Play,
  UploadCloud,
  RefreshCw,
  AlertCircle,
  CheckCircle2,
  KeyRound,
  Folder,
} from 'lucide-react';

interface GithubSiteViewProps {
  onOpenDownloadModal: () => void;
  onSwitchToScanner?: () => void;
}

export const GithubSiteView: React.FC<GithubSiteViewProps> = ({
  onOpenDownloadModal,
  onSwitchToScanner,
}) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [activeDocTab, setActiveDocTab] = useState<'sync' | 'readme' | 'files' | 'workflow'>('sync');

  // Real repository files fetched from /api/github-bundle
  const [repoFiles, setRepoFiles] = useState<Record<string, string>>({});
  const [selectedRepoFile, setSelectedRepoFile] = useState<string>('src/components/FileScannerView.tsx');
  const [isLoadingBundle, setIsLoadingBundle] = useState<boolean>(false);
  const [isExportingZip, setIsExportingZip] = useState<boolean>(false);

  // Direct GitHub Push state
  const [githubToken, setGithubToken] = useState<string>('');
  const [targetRepo, setTargetRepo] = useState<string>('k27212802-lab/SuperCodeX');
  const [targetBranch, setTargetBranch] = useState<string>('main');
  const [commitMessage, setCommitMessage] = useState<string>(
    'Red Crimson UI + Pure Project Decompiler (0-to-N folders/files without headers)'
  );
  const [isPushing, setIsPushing] = useState<boolean>(false);
  const [pushResult, setPushResult] = useState<{
    success: boolean;
    message: string;
    commitUrl?: string;
    commitSha?: string;
  } | null>(null);

  const officialGithubRepoUrl = 'https://github.com/k27212802-lab/SuperCodeX';
  const officialGithubPagesUrl = 'https://k27212802-lab.github.io/SuperCodeX/';

  useEffect(() => {
    const fetchBundle = async () => {
      setIsLoadingBundle(true);
      try {
        const res = await fetch('/api/github-bundle');
        const data = await res.json();
        if (data.success && data.files) {
          setRepoFiles(data.files);
        }
      } catch {
        // Fallback if offline
      } finally {
        setIsLoadingBundle(false);
      }
    };
    fetchBundle();
  }, []);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  // Download full real .ZIP of the repository for GitHub
  const handleDownloadFullRepoZip = async () => {
    setIsExportingZip(true);
    try {
      let filesToZip = repoFiles;
      if (Object.keys(filesToZip).length === 0) {
        const res = await fetch('/api/github-bundle');
        const data = await res.json();
        if (data.success && data.files) {
          filesToZip = data.files;
          setRepoFiles(data.files);
        }
      }

      const zip = new JSZip();
      for (const [filePath, content] of Object.entries(filesToZip)) {
        zip.file(filePath, content);
      }

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'SuperCodeX-Red-Edition-GitHub-Repo.zip';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setIsExportingZip(false);
    }
  };

  // Push directly to GitHub repository via /api/github-push
  const handlePushToGithub = async () => {
    if (!githubToken.trim()) {
      setPushResult({
        success: false,
        message:
          'Введите ваш GitHub Personal Access Token (ghp_... или github_pat_...), чтобы отправить коммит напрямую в репозиторий k27212802-lab/SuperCodeX.',
      });
      return;
    }

    setIsPushing(true);
    setPushResult(null);
    try {
      const res = await fetch('/api/github-push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: githubToken.trim(),
          repo: targetRepo.trim(),
          branch: targetBranch.trim(),
          commitMessage: commitMessage.trim(),
        }),
      });
      const data = await res.json();
      if (data.success) {
        setPushResult({
          success: true,
          message: `Успешно обновлено ${data.filesUpdated} файлов в ${targetRepo} (ветка ${targetBranch})! GitHub Actions автоматически обновит GitHub Pages.`,
          commitUrl: data.commitUrl,
          commitSha: data.commitSha,
        });
      } else {
        setPushResult({
          success: false,
          message: data.error || 'Ошибка отправки в GitHub API',
        });
      }
    } catch (e: any) {
      setPushResult({
        success: false,
        message: e.message || 'Сетевая ошибка при обращении к /api/github-push',
      });
    } finally {
      setIsPushing(false);
    }
  };

  const gitPushCommands = `# Быстрое обновление репозитория GitHub из скачанного архива:
unzip SuperCodeX-Red-Edition-GitHub-Repo.zip -d SuperCodeX-Red
cd SuperCodeX-Red
git init
git branch -M main
git remote add origin https://github.com/k27212802-lab/SuperCodeX.git
git add .
git commit -m "Update entire interface to Red Crimson Edition + Pure Project Decompiler"
git push -u origin main --force`;

  const githubWorkflowYaml =
    repoFiles['.github/workflows/deploy.yml'] ||
    `name: Deploy SuperCodeX to GitHub Pages

on:
  push:
    branches: [ main ]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Node.js 22
        uses: actions/setup-node@v4
        with:
          node-version: '22'

      - name: Install Dependencies & Build
        run: |
          npm install
          npm run build

      - name: Upload Pages Artifact
        uses: actions/upload-pages-artifact@v3
        with:
          path: ./dist

      - name: Deploy to GitHub Pages
        uses: actions/deploy-pages@v4`;

  const fileList = Object.keys(repoFiles);

  return (
    <div className="space-y-6">
      {/* Top Hero Banner — Red Crimson GitHub Portal */}
      <div className="rounded-3xl border-2 border-red-800/80 bg-gradient-to-b from-[#1f070c] to-[#110306] p-6 sm:p-8 shadow-2xl shadow-red-950/60 relative overflow-hidden">
        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-3 max-w-3xl">
            <div className="flex flex-wrap items-center gap-2">
              <span className="px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-red-600/20 text-red-300 border border-red-500/40 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-red-400" />
                <span>GITHUB REPOSITORY & PAGES — RED EDITION v9.847.149</span>
              </span>
              <span className="px-3 py-1 rounded-full text-[11px] font-mono font-bold bg-red-950/90 text-red-200 border border-red-700/60 flex items-center gap-1.5">
                <ShieldCheck className="w-3.5 h-3.5 text-red-400" />
                <span>ЧИСТЫЙ КОД БЕЗ ЗАГОЛОВКОВ · 0 ➔ N ПАПОК И ФАЙЛОВ</span>
              </span>
            </div>

            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight leading-tight">
              Официальный GitHub Портал SuperCodeX Red Edition
            </h1>

            <p className="text-sm text-red-200/80 leading-relaxed">
              Весь интерфейс GitHub-портала и репозитория обновлён под новую красную архитектуру:{' '}
              <span className="text-white font-semibold">3 круглые красные кнопки</span> («Добавить файл», «Добавить папку», «Запустить антивирус»), честный счётчик{' '}
              <span className="text-red-300 font-mono font-bold">Папок: 0 · Файлов: 0</span> до запуска проверки, и полное извлечение всех папок и чистых исходников (`.exe`, `.apk`, `.zip`, `.tar.gz`) на финальном шаге антивируса без единого чужого комментария.
            </p>

            {/* Official Links */}
            <div className="pt-2 grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3 rounded-2xl bg-[#160509] border border-red-800/70 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[10px] font-mono uppercase text-red-400 font-bold">
                    GitHub Pages (Веб-версия):
                  </div>
                  <a
                    href={officialGithubPagesUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-white hover:text-red-300 underline truncate block"
                  >
                    {officialGithubPagesUrl}
                  </a>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleCopy(officialGithubPagesUrl, 'pages-url')}
                    className="p-2 rounded-full bg-red-950/80 hover:bg-red-800 text-red-200 transition-colors cursor-pointer"
                    title="Скопировать ссылку"
                  >
                    {copiedId === 'pages-url' ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                  <a
                    href={officialGithubPagesUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-full bg-red-600 hover:bg-red-500 text-white transition-colors"
                    title="Открыть GitHub Pages"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>

              <div className="p-3 rounded-2xl bg-[#160509] border border-red-800/70 flex items-center justify-between gap-2">
                <div className="min-w-0">
                  <div className="text-[10px] font-mono uppercase text-red-400 font-bold">
                    GitHub Репозиторий (Исходный код):
                  </div>
                  <a
                    href={officialGithubRepoUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono text-white hover:text-red-300 underline truncate block"
                  >
                    {officialGithubRepoUrl}
                  </a>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    type="button"
                    onClick={() => handleCopy(officialGithubRepoUrl, 'repo-url')}
                    className="p-2 rounded-full bg-red-950/80 hover:bg-red-800 text-red-200 transition-colors cursor-pointer"
                    title="Скопировать ссылку"
                  >
                    {copiedId === 'repo-url' ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                  <a
                    href={officialGithubRepoUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="p-2 rounded-full bg-red-600 hover:bg-red-500 text-white transition-colors"
                    title="Открыть репозиторий GitHub"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                </div>
              </div>
            </div>
          </div>

          {/* Circular Red Action Buttons matching the main scanner UI */}
          <div className="flex flex-wrap items-center justify-center gap-4 shrink-0">
            <button
              type="button"
              onClick={handleDownloadFullRepoZip}
              disabled={isExportingZip}
              className="w-36 h-36 rounded-full bg-gradient-to-b from-red-500 via-red-600 to-red-800 hover:from-red-400 hover:via-red-500 hover:to-red-700 text-white border-4 border-red-300/60 shadow-2xl shadow-red-600/40 flex flex-col items-center justify-center gap-1.5 transition-all hover:scale-105 active:scale-95 cursor-pointer p-3 text-center"
            >
              <Download className="w-8 h-8 text-white drop-shadow" />
              <span className="text-xs font-extrabold uppercase tracking-wider leading-tight">
                {isExportingZip ? 'Упаковка...' : 'Скачать ZIP для GitHub'}
              </span>
              <span className="text-[9px] text-red-100 font-mono">
                {fileList.length || 21} файлов репо
              </span>
            </button>

            <button
              type="button"
              onClick={onOpenDownloadModal}
              className="w-36 h-36 rounded-full bg-gradient-to-b from-red-700 to-red-950 hover:from-red-600 hover:to-red-900 text-white border-2 border-red-500/60 shadow-xl shadow-red-950/60 flex flex-col items-center justify-center gap-1.5 transition-all hover:scale-105 active:scale-95 cursor-pointer p-3 text-center"
            >
              <Cpu className="w-8 h-8 text-red-200" />
              <span className="text-xs font-extrabold uppercase tracking-wider leading-tight">
                Скачать на ПК (.EXE / Linux)
              </span>
              <span className="text-[9px] text-red-300 font-mono">112.4 MB PE64</span>
            </button>

            {onSwitchToScanner && (
              <button
                type="button"
                onClick={onSwitchToScanner}
                className="w-36 h-36 rounded-full bg-gradient-to-b from-red-800 to-[#1a0509] hover:from-red-700 hover:to-red-950 text-white border-2 border-red-500/50 shadow-xl shadow-red-950/60 flex flex-col items-center justify-center gap-1.5 transition-all hover:scale-105 active:scale-95 cursor-pointer p-3 text-center"
              >
                <Play className="w-8 h-8 text-red-300 fill-red-300" />
                <span className="text-xs font-extrabold uppercase tracking-wider leading-tight">
                  Открыть Антивирус
                </span>
                <span className="text-[9px] text-red-300 font-mono">Сканер и Проводник</span>
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Red Interface Architecture Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-2xl border border-red-800/70 bg-[#140508] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-red-300">1. Круглые красные кнопки</span>
            <Play className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono">3 Круга Управления</div>
          <p className="text-[11px] text-red-200/70 leading-relaxed">
            «Добавить файл», «Добавить папку» и «Запустить антивирус» в едином красном стиле.
          </p>
        </div>

        <div className="p-4 rounded-2xl border border-red-800/70 bg-[#140508] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-red-300">2. Проводник: 0 ➔ Все файлы</span>
            <FolderOpen className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono">0 папок до старта</div>
          <p className="text-[11px] text-red-200/70 leading-relaxed">
            До анализа строго 0 файлов. В финале антивируса декомпилятор достаёт все папки и файлы проекта.
          </p>
        </div>

        <div className="p-4 rounded-2xl border border-red-800/70 bg-[#140508] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-red-300">3. Без водяных знаков</span>
            <Code2 className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono">100% Чистый Код</div>
          <p className="text-[11px] text-red-200/70 leading-relaxed">
            Никаких заголовков <code className="text-red-300">// SuperCodeX</code> — только оригинальный код и имена разработчика.
          </p>
        </div>

        <div className="p-4 rounded-2xl border border-red-800/70 bg-[#140508] space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-red-300">4. Все форматы и архивы</span>
            <Award className="w-4 h-4 text-red-400" />
          </div>
          <div className="text-lg font-extrabold text-white font-mono">.EXE · .APK · .ZIP · .TAR.GZ</div>
          <p className="text-[11px] text-red-200/70 leading-relaxed">
            Прямой парсинг таблиц классов Dalvik DEX из <code className="text-red-300">.apk</code>, секций PE/ELF и архивов.
          </p>
        </div>
      </div>

      {/* Main GitHub Tabs */}
      <div className="rounded-3xl border-2 border-red-900/80 bg-[#120407] overflow-hidden shadow-xl">
        <div className="border-b border-red-900/70 bg-[#1a060a] px-4 py-3 flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setActiveDocTab('sync')}
              className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeDocTab === 'sync'
                  ? 'bg-red-600 text-white shadow-lg shadow-red-600/30 border border-red-400'
                  : 'bg-red-950/50 text-red-200/80 hover:text-white border border-red-800/50'
              }`}
            >
              <UploadCloud className="w-3.5 h-3.5" />
              <span>Синхронизация и Push в GitHub</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDocTab('files')}
              className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeDocTab === 'files'
                  ? 'bg-red-600 text-white shadow-lg shadow-red-600/30 border border-red-400'
                  : 'bg-red-950/50 text-red-200/80 hover:text-white border border-red-800/50'
              }`}
            >
              <Folder className="w-3.5 h-3.5" />
              <span>Файлы репозитория ({fileList.length || 21})</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDocTab('readme')}
              className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeDocTab === 'readme'
                  ? 'bg-red-600 text-white shadow-lg shadow-red-600/30 border border-red-400'
                  : 'bg-red-950/50 text-red-200/80 hover:text-white border border-red-800/50'
              }`}
            >
              <BookOpen className="w-3.5 h-3.5" />
              <span>README.md (Red Edition)</span>
            </button>

            <button
              type="button"
              onClick={() => setActiveDocTab('workflow')}
              className={`px-4 py-2 rounded-full text-xs font-bold transition-all flex items-center gap-1.5 cursor-pointer ${
                activeDocTab === 'workflow'
                  ? 'bg-red-600 text-white shadow-lg shadow-red-600/30 border border-red-400'
                  : 'bg-red-950/50 text-red-200/80 hover:text-white border border-red-800/50'
              }`}
            >
              <GitBranch className="w-3.5 h-3.5" />
              <span>GitHub Actions (.github/workflows/deploy.yml)</span>
            </button>
          </div>

          <div className="text-[11px] font-mono text-red-300/80">
            Репозиторий: <span className="text-white font-bold">k27212802-lab/SuperCodeX</span>
          </div>
        </div>

        {/* TAB 1: Direct GitHub Sync & ZIP Export */}
        {activeDocTab === 'sync' && (
          <div className="p-6 space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Left Column: Direct GitHub API Push */}
              <div className="p-5 rounded-2xl border border-red-800/80 bg-[#18060a] space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <UploadCloud className="w-4 h-4 text-red-400" />
                    <span>Способ 1: Прямой Push обновлённого интерфейса в GitHub API</span>
                  </h3>
                  <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-red-600/20 text-red-300 border border-red-500/40">
                    Git Data REST API
                  </span>
                </div>

                <p className="text-xs text-red-200/80 leading-relaxed">
                  Отправляет все <span className="text-white font-bold">{fileList.length || 21} файлов</span> обновлённого красного интерфейса напрямую в ваш репозиторий{' '}
                  <code className="text-red-300">k27212802-lab/SuperCodeX</code> одним коммитом. После пуша GitHub Actions автоматически пересоберёт сайт GitHub Pages.
                </p>

                <div className="space-y-3">
                  <div>
                    <label className="block text-[11px] font-semibold text-red-300 mb-1">
                      GitHub Personal Access Token (с правами repo и workflow):
                    </label>
                    <div className="relative">
                      <KeyRound className="w-4 h-4 text-red-400 absolute left-3 top-2.5" />
                      <input
                        type="password"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                        className="w-full pl-9 pr-3 py-2 rounded-xl bg-[#0d0305] border border-red-800/80 text-xs text-white font-mono focus:outline-none focus:border-red-500"
                      />
                    </div>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-[11px] font-semibold text-red-300 mb-1">
                        Целевой репозиторий (owner/repo):
                      </label>
                      <input
                        type="text"
                        value={targetRepo}
                        onChange={(e) => setTargetRepo(e.target.value)}
                        className="w-full px-3 py-2 rounded-xl bg-[#0d0305] border border-red-800/80 text-xs text-white font-mono focus:outline-none focus:border-red-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[11px] font-semibold text-red-300 mb-1">
                        Ветка (branch):
                      </label>
                      <input
                        type="text"
                        value={targetBranch}
                        onChange={(e) => setTargetBranch(e.target.value)}
                        className="w-full px-3 py-2 rounded-xl bg-[#0d0305] border border-red-800/80 text-xs text-white font-mono focus:outline-none focus:border-red-500"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-[11px] font-semibold text-red-300 mb-1">
                      Сообщение коммита:
                    </label>
                    <input
                      type="text"
                      value={commitMessage}
                      onChange={(e) => setCommitMessage(e.target.value)}
                      className="w-full px-3 py-2 rounded-xl bg-[#0d0305] border border-red-800/80 text-xs text-white font-mono focus:outline-none focus:border-red-500"
                    />
                  </div>

                  <button
                    type="button"
                    onClick={handlePushToGithub}
                    disabled={isPushing}
                    className="w-full py-3 px-5 rounded-full bg-gradient-to-r from-red-600 via-red-500 to-red-700 hover:from-red-500 hover:to-red-600 text-white font-extrabold text-xs uppercase tracking-wider shadow-lg shadow-red-600/30 border border-red-400/60 flex items-center justify-center gap-2 transition-all cursor-pointer disabled:opacity-50"
                  >
                    {isPushing ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Отправка коммита в GitHub ({targetRepo})...</span>
                      </>
                    ) : (
                      <>
                        <UploadCloud className="w-4 h-4" />
                        <span>Отправить весь обновлённый интерфейс в GitHub (Push)</span>
                      </>
                    )}
                  </button>

                  {pushResult && (
                    <div
                      className={`p-3.5 rounded-xl border text-xs flex items-start gap-2.5 ${
                        pushResult.success
                          ? 'bg-emerald-950/50 border-emerald-500/50 text-emerald-200'
                          : 'bg-red-950/70 border-red-500/60 text-red-200'
                      }`}
                    >
                      {pushResult.success ? (
                        <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                      )}
                      <div className="space-y-1 min-w-0">
                        <div className="font-semibold">{pushResult.message}</div>
                        {pushResult.commitUrl && (
                          <a
                            href={pushResult.commitUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1 text-emerald-300 underline font-mono text-[11px]"
                          >
                            <span>Открыть коммит {pushResult.commitSha?.slice(0, 8)} на GitHub</span>
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column: ZIP Download + Terminal Push Commands */}
              <div className="p-5 rounded-2xl border border-red-800/80 bg-[#18060a] space-y-4 flex flex-col justify-between">
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Download className="w-4 h-4 text-red-400" />
                      <span>Способ 2: Скачать готовый ZIP-архив для GitHub</span>
                    </h3>
                    <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono bg-red-600/20 text-red-300 border border-red-500/40">
                      Полный Архив .ZIP
                    </span>
                  </div>

                  <p className="text-xs text-red-200/80 leading-relaxed">
                    Скачивает реальный архив <code className="text-red-300">SuperCodeX-Red-Edition-GitHub-Repo.zip</code> со всеми обновлёнными файлами (`src/App.tsx`, `src/components/FileScannerView.tsx`, `src/engine/projectLifter.ts`, `.github/workflows/deploy.yml`, `README.md`), готовый для загрузки через веб-интерфейс GitHub или консоль.
                  </p>

                  <button
                    type="button"
                    onClick={handleDownloadFullRepoZip}
                    disabled={isExportingZip}
                    className="w-full py-3 px-5 rounded-full bg-red-900/70 hover:bg-red-800 text-white font-extrabold text-xs uppercase tracking-wider border border-red-500/60 flex items-center justify-center gap-2 transition-all cursor-pointer"
                  >
                    <Download className="w-4 h-4" />
                    <span>
                      {isExportingZip
                        ? 'Создание ZIP-архива...'
                        : `Скачать SuperCodeX-Red-Edition-GitHub-Repo.zip (${fileList.length || 21} файлов)`}
                    </span>
                  </button>

                  <div className="pt-2 space-y-1.5">
                    <div className="flex items-center justify-between text-[11px] text-red-300 font-semibold">
                      <span className="flex items-center gap-1.5">
                        <Terminal className="w-3.5 h-3.5 text-red-400" />
                        <span>Команды для отправки через Git CLI:</span>
                      </span>
                      <button
                        type="button"
                        onClick={() => handleCopy(gitPushCommands, 'git-cli')}
                        className="px-2.5 py-1 rounded-full bg-red-950 hover:bg-red-800 text-red-200 border border-red-700/60 text-[10px] flex items-center gap-1 cursor-pointer"
                      >
                        {copiedId === 'git-cli' ? (
                          <>
                            <Check className="w-3 h-3 text-emerald-400" />
                            <span>Скопировано</span>
                          </>
                        ) : (
                          <>
                            <Copy className="w-3 h-3" />
                            <span>Копировать</span>
                          </>
                        )}
                      </button>
                    </div>
                    <pre className="p-3 rounded-xl bg-[#0b0204] border border-red-900/70 font-mono text-[11px] text-red-200 overflow-x-auto leading-relaxed">
                      {gitPushCommands}
                    </pre>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: Interactive Repository File Browser */}
        {activeDocTab === 'files' && (
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-xs text-red-200">
                Нажмите на любой файл репозитория, чтобы посмотреть актуальный исходный код Red Edition:
              </div>
              {isLoadingBundle && (
                <span className="text-xs text-red-400 font-mono">Загрузка файлов...</span>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
              <div className="lg:col-span-4 rounded-2xl border border-red-900/80 bg-[#0d0305] p-3 max-h-[520px] overflow-y-auto space-y-1">
                {fileList.map((filePath) => {
                  const isSelected = filePath === selectedRepoFile;
                  return (
                    <button
                      key={filePath}
                      type="button"
                      onClick={() => setSelectedRepoFile(filePath)}
                      className={`w-full text-left px-3 py-2 rounded-xl font-mono text-xs flex items-center justify-between gap-2 transition-colors cursor-pointer ${
                        isSelected
                          ? 'bg-red-600 text-white font-bold'
                          : 'text-red-200/80 hover:bg-red-950/60 hover:text-white'
                      }`}
                    >
                      <span className="truncate flex items-center gap-2">
                        <FileCode className="w-3.5 h-3.5 shrink-0" />
                        <span className="truncate">{filePath}</span>
                      </span>
                      <span className="text-[10px] opacity-75 shrink-0">
                        {((repoFiles[filePath]?.length || 0) / 1024).toFixed(1)} KB
                      </span>
                    </button>
                  );
                })}
              </div>

              <div className="lg:col-span-8 rounded-2xl border border-red-900/80 bg-[#0d0305] overflow-hidden flex flex-col max-h-[520px]">
                <div className="px-4 py-2.5 bg-[#190509] border-b border-red-900/70 flex items-center justify-between">
                  <span className="font-mono text-xs font-bold text-red-200">
                    {selectedRepoFile}
                  </span>
                  <button
                    type="button"
                    onClick={() =>
                      handleCopy(repoFiles[selectedRepoFile] || '', 'selected-repo-file')
                    }
                    className="px-3 py-1 rounded-full bg-red-900/60 hover:bg-red-700 text-white text-[11px] flex items-center gap-1.5 cursor-pointer"
                  >
                    {copiedId === 'selected-repo-file' ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Скопировано</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Копировать код файла</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="p-4 font-mono text-[11.5px] text-red-100 overflow-auto leading-relaxed flex-1">
                  {repoFiles[selectedRepoFile] || 'Выберите файл слева для просмотра...'}
                </pre>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: README.md */}
        {activeDocTab === 'readme' && (
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-xs font-mono text-red-300">
                Файл: <span className="text-white font-bold">README.md</span> (Red Crimson Edition)
              </div>
              <button
                type="button"
                onClick={() => handleCopy(repoFiles['README.md'] || '', 'readme-copy')}
                className="px-3 py-1.5 rounded-full bg-red-900/60 hover:bg-red-700 text-white text-xs flex items-center gap-1.5 cursor-pointer"
              >
                {copiedId === 'readme-copy' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Скопировано</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Скопировать README.md</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-5 rounded-2xl bg-[#0b0204] border border-red-900/80 font-mono text-xs text-red-100 overflow-x-auto leading-relaxed whitespace-pre-wrap">
              {repoFiles['README.md'] || 'Загрузка README.md...'}
            </pre>
          </div>
        )}

        {/* TAB 4: GitHub Actions Workflow */}
        {activeDocTab === 'workflow' && (
          <div className="p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div className="text-xs font-mono text-red-300">
                Файл: <span className="text-white font-bold">.github/workflows/deploy.yml</span>
              </div>
              <button
                type="button"
                onClick={() => handleCopy(githubWorkflowYaml, 'workflow-copy')}
                className="px-3 py-1.5 rounded-full bg-red-900/60 hover:bg-red-700 text-white text-xs flex items-center gap-1.5 cursor-pointer"
              >
                {copiedId === 'workflow-copy' ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Скопировано</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Скопировать deploy.yml</span>
                  </>
                )}
              </button>
            </div>
            <pre className="p-5 rounded-2xl bg-[#0b0204] border border-red-900/80 font-mono text-xs text-red-200 overflow-x-auto leading-relaxed">
              {githubWorkflowYaml}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
};
