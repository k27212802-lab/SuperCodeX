import React, { useState } from 'react';
import {
  Github,
  ShieldCheck,
  ShieldAlert,
  Lock,
  Scale,
  X,
  Copy,
  Check,
  ExternalLink,
  BarChart3,
  Cpu,
  FileCode2,
  Zap,
} from 'lucide-react';

interface GithubRepoModalProps {
  isOpen: boolean;
  onClose: () => void;
  onNavigateToBenchmarks: () => void;
}

export const GithubRepoModal: React.FC<GithubRepoModalProps> = ({
  isOpen,
  onClose,
  onNavigateToBenchmarks,
}) => {
  const [copiedClone, setCopiedClone] = useState(false);

  if (!isOpen) return null;

  const repoCloneUrl = 'git clone https://github.com/supercodex-security/supercodex-v9.281.492-engine.git';

  const handleCopyClone = () => {
    navigator.clipboard?.writeText(repoCloneUrl);
    setCopiedClone(true);
    setTimeout(() => setCopiedClone(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/85 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-6 space-y-6 shadow-2xl relative my-8">
        <button
          type="button"
          onClick={onClose}
          className="absolute top-4 right-4 p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
        >
          <X className="w-5 h-5" />
        </button>

        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-xl bg-purple-500/10 border border-purple-500/30 flex items-center justify-center shrink-0">
            <Github className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-lg font-bold text-white tracking-tight">
                Официальный Репозиторий GitHub &amp; EULA Лицензия
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/20 text-purple-300 border border-purple-500/30">
                v9.281.492 PUBLIC REPO
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              SuperCodeX Security Framework · Превосходство над Ghidra 11.2 &amp; IDA Pro 8.4
            </p>
          </div>
        </div>

        {/* Git Clone Snippet & Benchmark Button */}
        <div className="p-4 rounded-xl border border-slate-800 bg-slate-950/80 space-y-3">
          <div className="flex items-center justify-between gap-3 text-xs font-semibold text-slate-300">
            <div className="flex items-center gap-2">
              <Github className="w-4 h-4 text-purple-400" />
              <span>Клонирование репозитория релизов SuperCodeX:</span>
            </div>
            <button
              type="button"
              onClick={() => {
                onClose();
                onNavigateToBenchmarks();
              }}
              className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition-colors flex items-center gap-1.5 cursor-pointer shadow-md"
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Бенчмарки SuperCodeX</span>
            </button>
          </div>
          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 font-mono text-xs text-purple-300 flex items-center justify-between gap-3">
            <code className="truncate">{repoCloneUrl}</code>
            <button
              type="button"
              onClick={handleCopyClone}
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-colors shrink-0 cursor-pointer"
            >
              {copiedClone ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <Copy className="w-4 h-4" />
              )}
            </button>
          </div>
        </div>

        {/* Prohibited Uses (Strict Anti-Abuse Warning) */}
        <div className="p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 space-y-2">
          <div className="text-xs font-bold text-rose-300 flex items-center gap-2">
            <ShieldAlert className="w-4 h-4" />
            <span>СТРОГО ЗАПРЕЩЕННЫЕ СЦЕНАРИИ ИСПОЛЬЗОВАНИЯ (EULA TERMS OF SERVICE)</span>
          </div>
          <ul className="text-xs text-rose-200/90 space-y-1.5 list-disc list-inside leading-relaxed text-[11.5px]">
            <li>
              <strong>Запрет разработки игровых читов</strong>: Категорически запрещено использовать SuperCodeX для создания обходов античитов (EAC, BattlEye, Vanguard), модов, трейнеров и инжекторов.
            </li>
            <li>
              <strong>Запрет кражи авторского кода</strong>: Запрещено применять декомпилятор для дезассемблирования и несанкционированного копирования чужой интеллектуальной собственности, коммерческого софта и проприетарных алгоритмов.
            </li>
            <li>
              <strong>Запрет создания вредоносного ПО</strong>: Инструмент предназначен исключительно для анализа и защиты, а не для модификации или обхода антивирусов.
            </li>
          </ul>
        </div>

        {/* Purpose & Legal Intent */}
        <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-500/10 space-y-2">
          <div className="text-xs font-bold text-emerald-300 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4" />
            <span>НАЗНАЧЕНИЕ И ПРЕВОСХОДСТВО НАД ГИГАНТАМИ РЫНКА</span>
          </div>
          <p className="text-xs text-emerald-200/90 leading-relaxed text-[11.5px]">
            SuperCodeX v9.281.492 создан для <strong>исследования реальных угроз, анализа вредоносного кода (Malware Reverse Engineering) и аудита безопасности</strong>. Архитектура движка разработана для технологического превосходства над JVM-декомпилятором Ghidra 11.2 и IDA Pro 8.4 за счёт скорости работы (~1.8 мс vs 5700 мс) и 100% гарантии отсутствия потерь C++ AST (0% удаленного кода).
          </p>
        </div>

        {/* Privacy & Confidentiality Guarantee */}
        <div className="p-4 rounded-xl border border-cyan-500/30 bg-cyan-500/10 space-y-2">
          <div className="text-xs font-bold text-cyan-300 flex items-center gap-2">
            <Lock className="w-4 h-4" />
            <span>100% ГАРАНТИЯ КОНФИДЕНЦИАЛЬНОСТИ И ИЗОЛЯЦИИ ИСХОДНОГО КОДА</span>
          </div>
          <p className="text-xs text-cyan-200/90 leading-relaxed text-[11.5px]">
            Все операции анализа, деассемблирования и декомпиляции выполняются <strong>строго локально</strong>. Загружаемые бинарные файлы, исходный код и восстановленные C++ AST граф-структуры никогда не передаются на сторонние сервера или в облака.
            <br />
            <strong>Защита собственников</strong>: Исходные коммерческие алгоритмы и ядра защиты SuperCodeX v9 защищены от утечки и не публицируются в открытом виде.
          </p>
        </div>

        {/* Footer Actions */}
        <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs text-slate-500">
          <div>Лицензия: SuperCodeX Enterprise Security EULA v9.281.492</div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                onClose();
                onNavigateToBenchmarks();
              }}
              className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <BarChart3 className="w-3.5 h-3.5" />
              <span>Бенчмарки SuperCodeX</span>
            </button>
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors cursor-pointer"
            >
              Закрыть
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
