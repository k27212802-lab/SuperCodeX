import React, { useEffect, useState } from 'react';
import { Terminal, AlertCircle, CheckCircle2, RefreshCw } from 'lucide-react';

interface GhidraStatusResponse {
  installed: boolean;
  path: string | null;
  message: string;
  output?: string;
}

export const RealGhidraBenchView: React.FC = () => {
  const [status, setStatus] = useState<GhidraStatusResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  const checkGhidra = async () => {
    setLoading(true);
    try {
      const res = await fetch('/api/ghidra-status');
      if (res.ok) {
        const data = await res.json();
        setStatus(data);
      } else {
        setStatus({
          installed: false,
          path: null,
          message: 'Ghidra не установлена, сравнение недоступно',
        });
      }
    } catch {
      setStatus({
        installed: false,
        path: null,
        message: 'Ghidra не установлена, сравнение недоступно',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkGhidra();
  }, []);

  return (
    <div className="space-y-6">
      <div className="bg-zinc-900/60 border border-zinc-800 rounded-xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-zinc-800 pb-4">
          <div>
            <div className="flex items-center gap-2 text-zinc-300 text-xs font-mono uppercase tracking-wider mb-1">
              <Terminal className="w-4 h-4 text-emerald-400" />
              Проверка установленного бинарника analyzeHeadless (child_process)
            </div>
            <h2 className="text-xl font-bold text-white">
              Сравнение с Ghidra Headless Decompiler
            </h2>
          </div>
          <button
            onClick={checkGhidra}
            disabled={loading}
            className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Проверить наличие analyzeHeadless
          </button>
        </div>

        <div className="mt-6">
          {loading ? (
            <div className="text-sm text-zinc-400 font-mono">
              Проверка наличия `analyzeHeadless` в системном PATH через `child_process`...
            </div>
          ) : status?.installed ? (
            <div className="bg-emerald-950/30 border border-emerald-500/30 rounded-lg p-4 space-y-2">
              <div className="flex items-center gap-2 text-emerald-300 font-semibold text-sm">
                <CheckCircle2 className="w-4 h-4" />
                <span>Найдена установленная Ghidra: {status.path}</span>
              </div>
              {status.output && (
                <pre className="text-xs font-mono text-zinc-200 bg-black/50 p-3 rounded border border-zinc-800 overflow-x-auto">
                  {status.output}
                </pre>
              )}
            </div>
          ) : (
            <div className="bg-amber-950/30 border border-amber-500/30 rounded-lg p-5 flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="text-sm font-semibold text-amber-300">
                  {status?.message || 'Ghidra не установлена, сравнение недоступно'}
                </div>
                <p className="text-xs text-zinc-400">
                  Все зашитые вручную сравнения и метрики (`ghidraDurationMs`, `speedupFactor`, `ghidraReconstructedCode`) удалены. Сравнение выполняется только при наличии реального исполняемого файла `analyzeHeadless` в системе. Для проверки декомпилятора на реальных скомпилированных бинарниках `g++ -O0` и `g++ -O2` запустите `npm run bench`.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
