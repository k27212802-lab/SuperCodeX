import React, { useState } from 'react';
import JSZip from 'jszip';
import {
  GitBranch,
  Terminal,
  Copy,
  Check,
  X,
  FolderGit2,
  Globe,
  ExternalLink,
  Download,
  UploadCloud,
  KeyRound,
  RefreshCw,
} from 'lucide-react';

interface GithubRepoModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const GithubRepoModal: React.FC<GithubRepoModalProps> = ({ isOpen, onClose }) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [githubToken, setGithubToken] = useState<string>('');
  const [isPushing, setIsPushing] = useState<boolean>(false);
  const [isDownloadingZip, setIsDownloadingZip] = useState<boolean>(false);
  const [pushStatus, setPushStatus] = useState<{ ok: boolean; msg: string; url?: string } | null>(
    null
  );

  if (!isOpen) return null;

  const officialRepoUrl = 'https://github.com/k27212802-lab/SuperCodeX';
  const officialPagesUrl = 'https://k27212802-lab.github.io/SuperCodeX/';

  const gitPushCmd = `git init
git add .
git commit -m "Update entire SuperCodeX interface to Red Crimson Edition"
git branch -M main
git remote add origin https://github.com/k27212802-lab/SuperCodeX.git
git push -u origin main --force`;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard?.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleDownloadRepoZip = async () => {
    setIsDownloadingZip(true);
    try {
      const res = await fetch('/api/github-bundle');
      const data = await res.json();
      if (data.success && data.files) {
        const zip = new JSZip();
        for (const [filePath, content] of Object.entries(data.files as Record<string, string>)) {
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
      }
    } finally {
      setIsDownloadingZip(false);
    }
  };

  const handlePushDirect = async () => {
    if (!githubToken.trim()) {
      setPushStatus({
        ok: false,
        msg: 'Введите ваш GitHub Personal Access Token (ghp_...) для прямой отправки коммита.',
      });
      return;
    }
    setIsPushing(true);
    setPushStatus(null);
    try {
      const res = await fetch('/api/github-push', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: githubToken.trim(),
          repo: 'k27212802-lab/SuperCodeX',
          branch: 'main',
          commitMessage: 'Update entire SuperCodeX interface to Red Crimson Edition',
        }),
      });
      const data = await res.json();
      if (data.success) {
        setPushStatus({
          ok: true,
          msg: `Успешно обновлено ${data.filesUpdated} файлов в k27212802-lab/SuperCodeX!`,
          url: data.commitUrl,
        });
      } else {
        setPushStatus({ ok: false, msg: data.error || 'Ошибка GitHub API' });
      }
    } catch (e: any) {
      setPushStatus({ ok: false, msg: e.message || 'Ошибка сети' });
    } finally {
      setIsPushing(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/85 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-[#140508] border-2 border-red-800/80 rounded-3xl max-w-2xl w-full p-6 space-y-5 shadow-2xl shadow-red-950/70 relative my-8">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-2 rounded-full text-red-300 hover:text-white hover:bg-red-900/60 transition-colors cursor-pointer"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-full bg-red-600/20 border-2 border-red-500/50 flex items-center justify-center shrink-0">
            <FolderGit2 className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-extrabold text-white tracking-tight">
                GitHub Репозиторий & Обновление (Red Edition)
              </h2>
              <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-red-600/30 text-red-200 border border-red-500/40">
                v9.847.149
              </span>
            </div>
            <p className="text-xs text-red-200/75 mt-0.5">
              Прямая синхронизация красного интерфейса с k27212802-lab/SuperCodeX и выгрузка полного ZIP
            </p>
          </div>
        </div>

        {/* Links */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
          <div className="p-3.5 rounded-2xl border border-red-800/70 bg-[#1c070c] space-y-1.5">
            <div className="font-bold text-red-300 flex items-center gap-1.5">
              <Globe className="w-3.5 h-3.5 text-red-400" />
              <span>GitHub Pages (Веб-приложение)</span>
            </div>
            <a
              href={officialPagesUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[11px] text-white hover:text-red-300 underline flex items-center gap-1 break-all"
            >
              <span>{officialPagesUrl}</span>
              <ExternalLink className="w-3 h-3 shrink-0" />
            </a>
          </div>

          <div className="p-3.5 rounded-2xl border border-red-800/70 bg-[#1c070c] space-y-1.5">
            <div className="font-bold text-red-300 flex items-center gap-1.5">
              <GitBranch className="w-3.5 h-3.5 text-red-400" />
              <span>Официальный Репозиторий</span>
            </div>
            <a
              href={officialRepoUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="font-mono text-[11px] text-white hover:text-red-300 underline flex items-center gap-1 break-all"
            >
              <span>{officialRepoUrl}</span>
              <ExternalLink className="w-3 h-3 shrink-0" />
            </a>
          </div>
        </div>

        {/* Direct GitHub Push Box */}
        <div className="p-4 rounded-2xl border border-red-800/80 bg-[#1a060a] space-y-3">
          <div className="text-xs font-bold text-white flex items-center gap-2">
            <UploadCloud className="w-4 h-4 text-red-400" />
            <span>Обновить репозиторий k27212802-lab/SuperCodeX в 1 клик (GitHub API):</span>
          </div>
          <div className="flex flex-col sm:flex-row gap-2">
            <div className="relative flex-1">
              <KeyRound className="w-4 h-4 text-red-400 absolute left-3 top-2.5" />
              <input
                type="password"
                value={githubToken}
                onChange={(e) => setGithubToken(e.target.value)}
                placeholder="Вставьте GitHub Token (ghp_...)"
                className="w-full pl-9 pr-3 py-2 rounded-full bg-[#0d0305] border border-red-800 text-xs text-white font-mono focus:outline-none focus:border-red-500"
              />
            </div>
            <button
              type="button"
              onClick={handlePushDirect}
              disabled={isPushing}
              className="px-5 py-2 rounded-full bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center justify-center gap-1.5 cursor-pointer shrink-0 shadow-lg shadow-red-600/30 disabled:opacity-50"
            >
              {isPushing ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Отправка...</span>
                </>
              ) : (
                <>
                  <UploadCloud className="w-3.5 h-3.5" />
                  <span>Push в GitHub</span>
                </>
              )}
            </button>
          </div>
          {pushStatus && (
            <div
              className={`text-xs p-2.5 rounded-xl border ${
                pushStatus.ok
                  ? 'bg-emerald-950/60 border-emerald-500/50 text-emerald-200'
                  : 'bg-red-950/70 border-red-500/60 text-red-200'
              }`}
            >
              <div>{pushStatus.msg}</div>
              {pushStatus.url && (
                <a
                  href={pushStatus.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="underline text-emerald-300 font-mono text-[11px]"
                >
                  Посмотреть коммит на GitHub
                </a>
              )}
            </div>
          )}
        </div>

        {/* Download ZIP + Git CLI */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-red-200 flex items-center gap-1.5">
              <Terminal className="w-4 h-4 text-red-400" />
              <span>Скачать архив всех исходников или запушить через Git CLI:</span>
            </span>
            <button
              type="button"
              onClick={handleDownloadRepoZip}
              disabled={isDownloadingZip}
              className="px-4 py-1.5 rounded-full bg-red-700 hover:bg-red-600 text-white text-xs font-bold flex items-center gap-1.5 cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>{isDownloadingZip ? 'Упаковка...' : 'Скачать ZIP репозитория'}</span>
            </button>
          </div>
          <div className="p-3 rounded-2xl bg-[#0b0204] border border-red-900/80 font-mono text-[11px] text-red-200 relative">
            <pre className="overflow-x-auto leading-relaxed">{gitPushCmd}</pre>
            <button
              type="button"
              onClick={() => handleCopy(gitPushCmd, 'push-cmd')}
              className="absolute top-2.5 right-2.5 p-1.5 rounded-full bg-red-950 hover:bg-red-800 text-red-200 cursor-pointer"
            >
              {copiedId === 'push-cmd' ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-red-900/60 flex items-center justify-between text-xs text-red-300/70">
          <div>Репозиторий: github.com/k27212802-lab/SuperCodeX</div>
          <button
            type="button"
            onClick={onClose}
            className="px-5 py-1.5 rounded-full bg-red-950 hover:bg-red-900 text-red-100 border border-red-800 text-xs font-bold transition-colors cursor-pointer"
          >
            Закрыть
          </button>
        </div>
      </div>
    </div>
  );
};
