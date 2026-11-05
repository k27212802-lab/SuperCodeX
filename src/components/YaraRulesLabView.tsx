import React, { useState } from 'react';
import { BUILTIN_YARA_RULES, YaraRule } from '../engine/scanner';
import { Plus, Trash2, Shield } from 'lucide-react';

interface YaraRulesLabViewProps {
  customRules: YaraRule[];
  onAddCustomRule: (rule: YaraRule) => void;
  onRemoveCustomRule: (id: string) => void;
}

export const YaraRulesLabView: React.FC<YaraRulesLabViewProps> = ({
  customRules,
  onAddCustomRule,
  onRemoveCustomRule,
}) => {
  const [name, setName] = useState('');
  const [patternsInput, setPatternsInput] = useState('');
  const [description, setDescription] = useState('');
  const [scoreWeight, setScoreWeight] = useState(60);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const trimmedName = name.trim();
    const patterns = patternsInput
      .split(',')
      .map((p) => p.trim())
      .filter(Boolean);

    if (!trimmedName || patterns.length === 0) {
      setErrorMsg('Укажите название правила и хотя бы одну сигнатуру (подстроку) для поиска.');
      return;
    }

    setErrorMsg(null);
    const newRule: YaraRule = {
      id: `CUST-${(customRules.length + 1).toString().padStart(3, '0')}`,
      name: trimmedName,
      category: 'Custom',
      severity: scoreWeight >= 70 ? 'critical' : scoreWeight >= 45 ? 'high' : 'medium',
      scoreWeight: Math.min(100, Math.max(10, Number(scoreWeight) || 50)),
      description: description.trim() || 'Пользовательское сигнатурное правило',
      patterns,
      minMatches: 1,
      mitreTechnique: 'Custom Rule',
    };

    onAddCustomRule(newRule);
    setName('');
    setPatternsInput('');
    setDescription('');
  };

  const allRules = [...BUILTIN_YARA_RULES, ...customRules];

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Form to add a real custom YARA signature rule */}
        <form
          onSubmit={handleSubmit}
          className="lg:col-span-5 border border-slate-800 bg-slate-900/60 rounded-lg p-6 space-y-4"
        >
          <div>
            <h2 className="text-base font-semibold text-white">
              Конструктор пользовательских YARA-сигнатур
            </h2>
            <p className="text-xs text-slate-400 mt-1">
              Добавьте собственную сигнатуру — она сразу начнет проверяться при сканировании любых файлов и
              внутри распакованных Base64-блоков.
            </p>
          </div>

          {errorMsg && (
            <div className="p-3 rounded bg-red-950/60 border border-red-800 text-xs text-red-300">
              {errorMsg}
            </div>
          )}

          <div>
            <label htmlFor="yara-rule-name" className="block text-xs font-medium text-slate-300 mb-1">
              Название сигнатуры (идентификатор)
            </label>
            <input
              id="yara-rule-name"
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Напр.: Custom_ReverseShell_Socket"
              className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div>
            <label htmlFor="yara-rule-patterns" className="block text-xs font-medium text-slate-300 mb-1">
              Искомые строки / API через запятую
            </label>
            <input
              id="yara-rule-patterns"
              type="text"
              value={patternsInput}
              onChange={(e) => setPatternsInput(e.target.value)}
              placeholder="Напр.: /bin/bash -i, /dev/tcp/, nc -e"
              className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="yara-rule-weight" className="block text-xs font-medium text-slate-300 mb-1">
                Вес угрозы (10–100 баллов)
              </label>
              <input
                id="yara-rule-weight"
                type="number"
                min={10}
                max={100}
                value={scoreWeight}
                onChange={(e) => setScoreWeight(Number(e.target.value))}
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-sm font-mono text-slate-100 focus:outline-none focus:border-emerald-500 tabular-nums"
              />
            </div>
            <div>
              <label htmlFor="yara-rule-desc" className="block text-xs font-medium text-slate-300 mb-1">
                Краткое описание
              </label>
              <input
                id="yara-rule-desc"
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Обратный шелл bash/netcat"
                className="w-full px-3 py-2 rounded bg-slate-950 border border-slate-800 text-sm text-slate-100 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>

          <button
            type="submit"
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors cursor-pointer"
          >
            <Plus className="w-4 h-4" />
            <span>Добавить правило в боевое ядро</span>
          </button>
        </form>

        {/* Active Rules Table */}
        <div className="lg:col-span-7 border border-slate-800 bg-slate-900/60 rounded-lg overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
              <h3 className="text-sm font-semibold text-white">
                Активная база сигнатур и эвристических правил ({allRules.length})
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-400 tabular-nums whitespace-nowrap">
              Встроенных: {BUILTIN_YARA_RULES.length} · Пользовательских: {customRules.length}
            </span>
          </div>

          <div className="max-h-[520px] overflow-y-auto">
            <table className="w-full text-left border-collapse text-xs table-fixed">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60 sticky top-0">
                  <th className="py-2.5 px-3 w-24">ID</th>
                  <th className="py-2.5 px-3">Правило и паттерны</th>
                  <th className="py-2.5 px-2 w-16 text-right">Совп.</th>
                  <th className="py-2.5 px-2 w-16 text-right">Вес</th>
                  <th className="py-2.5 px-3 w-24 text-right">Тип</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {allRules.map((rule) => {
                  const isCustom = rule.id.startsWith('CUST-');
                  return (
                    <tr key={rule.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-3 font-mono text-emerald-400 whitespace-nowrap align-top">
                        {rule.id}
                      </td>
                      <td className="py-3 px-3 align-top break-words min-w-0">
                        <div className="font-semibold text-slate-100 break-all">{rule.name}</div>
                        <div className="text-slate-400 mt-0.5">{rule.description}</div>
                        <div className="font-mono text-[11px] text-amber-300/90 mt-1 break-all">
                          Паттерны: {rule.patterns.slice(0, 5).join(' · ')}
                          {rule.patterns.length > 5 ? ` (+${rule.patterns.length - 5})` : ''}
                        </div>
                      </td>
                      <td className="py-3 px-2 font-mono text-right text-slate-300 tabular-nums align-top">
                        {rule.minMatches}
                      </td>
                      <td className="py-3 px-2 font-mono text-right font-bold text-slate-100 tabular-nums align-top">
                        +{rule.scoreWeight}
                      </td>
                      <td className="py-3 px-3 text-right align-top">
                        {isCustom ? (
                          <button
                            type="button"
                            onClick={() => onRemoveCustomRule(rule.id)}
                            aria-label={`Удалить правило ${rule.name}`}
                            className="p-1.5 rounded hover:bg-red-950/60 text-red-400 transition-colors cursor-pointer"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        ) : (
                          <span className="text-slate-500 font-mono">Базовое</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
};
