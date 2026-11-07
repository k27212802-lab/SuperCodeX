import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { execSync, spawnSync } from 'node:child_process';
import { analyzeFileBytes, DEFAULT_ENGINE_CONFIG } from '../src/engine/scanner';

interface SourceCounts {
  loops: number;
  branches: number;
  switches: number;
  calls: number;
}

function countSourceConstructs(src: string): SourceCounts {
  // Strip single-line and multi-line comments and string literals
  const stripped = src
    .replace(/\/\/.*$/gm, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/"(?:\\.|[^"\\])*"/g, '""');

  const forCount = (stripped.match(/\bfor\s*\(/g) || []).length;
  const doCount = (stripped.match(/\bdo\s*\{/g) || []).length;
  const allWhileCount = (stripped.match(/\bwhile\s*\(/g) || []).length;
  const doWhileCount = (stripped.match(/\}\s*while\s*\(/g) || []).length;
  const whileCount = Math.max(0, allWhileCount - doWhileCount);

  const ifCount = (stripped.match(/\bif\s*\(/g) || []).length;
  const ternaryCount = (stripped.match(/\?/g) || []).length;
  const switchCount = (stripped.match(/\bswitch\s*\(/g) || []).length;

  // Count function calls (excluding control keywords and function definitions)
  const callMatches = stripped.match(/\b([A-Za-z_][A-Za-z0-9_]*)\s*\(/g) || [];
  const keywords = new Set(['if', 'for', 'while', 'switch', 'return', 'sizeof', 'alignas', '__attribute__']);
  let rawCalls = 0;
  for (const m of callMatches) {
    const name = m.replace(/\s*\($/, '');
    if (!keywords.has(name)) rawCalls++;
  }
  // Subtract function definitions (approx number of top-level functions)
  const funcDefs = (stripped.match(/\)\s*\{/g) || []).length - forCount - whileCount - ifCount - switchCount;
  const calls = Math.max(0, rawCalls - Math.max(1, funcDefs));

  return {
    loops: forCount + doCount + whileCount,
    branches: ifCount + ternaryCount,
    switches: switchCount,
    calls,
  };
}

interface BenchRow {
  file: string;
  opt: string;
  verdict: string;
  expectedLoops: number;
  foundLoops: number;
  expectedBranches: number;
  foundBranches: number;
  expectedSwitches: number;
  foundSwitches: number;
  expectedCalls: number;
  foundCalls: number;
  compilesSyntax: boolean;
  compilesBinary: boolean;
  matchedInputs: number;
  totalInputs: number;
  errorNote?: string;
}

function runProgramWithInput(binPath: string, arg: string): { stdout: string; status: number } {
  const res = spawnSync(binPath, [arg], {
    encoding: 'utf-8',
    timeout: 4000,
  });
  return {
    stdout: (res.stdout || '').trim(),
    status: res.status ?? -1,
  };
}

async function main() {
  const cliArgs = process.argv.slice(2);
  const corpusDir = path.resolve(process.cwd(), 'tests/corpus');
  const files: string[] =
    cliArgs.length > 0
      ? cliArgs.map((p) => path.resolve(process.cwd(), p))
      : fs
          .readdirSync(corpusDir)
          .filter((f) => f.endsWith('.cpp') || f.endsWith('.c'))
          .sort()
          .map((f) => path.join(corpusDir, f));

  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'supercodex_bench_'));
  const rows: BenchRow[] = [];
  const testInputs = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10'];

  console.log(`\n=== БЕНЧМАРК ДЕКОМПИЛЯТОРА x86_64 ELF (g++ -O0 и g++ -O2, 10 входов на бинарник) ===`);
  console.log(`Корпус: ${files.length} программ (${files.length * 2} ELF64 бинарников)\n`);

  for (const filePath of files) {
    const fileName = path.basename(filePath);
    const src = fs.readFileSync(filePath, 'utf-8');
    const expected = countSourceConstructs(src);

    for (const opt of ['-O0', '-O2']) {
      const baseId = `${fileName.replace(/\.(cpp|c)$/, '')}_${opt.replace('-', '')}`;
      const origElf = path.join(workDir, `${baseId}_orig.elf`);
      const decompCpp = path.join(workDir, `${baseId}_decomp.cpp`);
      const decompElf = path.join(workDir, `${baseId}_decomp.elf`);

      let compilesSyntax = false;
      let compilesBinary = false;
      let matchedInputs = 0;
      let errorNote = '';

      try {
        execSync(`g++ ${opt} "${filePath}" -o "${origElf}"`, { stdio: 'pipe' });
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : String(e);
        console.error(`Ошибка компиляции оригинала ${fileName} (${opt}): ${msg}`);
        continue;
      }

      const elfBytes = new Uint8Array(fs.readFileSync(origElf));
      const report = await analyzeFileBytes(`${baseId}.elf`, elfBytes, DEFAULT_ENGINE_CONFIG);
      const stats = report.decompilation.cfgStats;
      const code = report.decompilation.reconstructedCode;

      fs.writeFileSync(decompCpp, code, 'utf-8');

      try {
        execSync(`g++ -std=c++20 -fsyntax-only "${decompCpp}"`, { stdio: 'pipe' });
        compilesSyntax = true;
      } catch (e: unknown) {
        const errObj = e as { stderr?: Buffer };
        errorNote = (errObj.stderr ? errObj.stderr.toString() : String(e)).split('\n')[0];
      }

      if (compilesSyntax) {
        try {
          execSync(`g++ -std=c++20 "${decompCpp}" -o "${decompElf}"`, { stdio: 'pipe' });
          compilesBinary = true;
        } catch (e: unknown) {
          const errObj = e as { stderr?: Buffer };
          errorNote = (errObj.stderr ? errObj.stderr.toString() : String(e)).split('\n')[0];
        }
      }

      if (compilesBinary) {
        for (const inp of testInputs) {
          const origOut = runProgramWithInput(origElf, inp);
          const decompOut = runProgramWithInput(decompElf, inp);
          if (origOut.stdout === decompOut.stdout && origOut.status === decompOut.status) {
            matchedInputs++;
          } else if (!errorNote) {
            errorNote = `in=${inp}: orig="${origOut.stdout}"(${origOut.status}) != decomp="${decompOut.stdout}"(${decompOut.status})`;
          }
        }
      }

      rows.push({
        file: fileName,
        opt,
        verdict: report.verdict,
        expectedLoops: expected.loops,
        foundLoops: stats.loopsCount,
        expectedBranches: expected.branches,
        foundBranches: stats.ifElseBranchesCount,
        expectedSwitches: expected.switches,
        foundSwitches: stats.switchBlocksCount ?? 0,
        expectedCalls: expected.calls,
        foundCalls: stats.callsCount ?? 0,
        compilesSyntax,
        compilesBinary,
        matchedInputs,
        totalInputs: testInputs.length,
        errorNote: errorNote || undefined,
      });
    }
  }

  // Print Markdown table
  const pad = (s: string, w: number) => s.padEnd(w, ' ');
  const header = [
    pad('Файл', 25),
    pad('Опт', 4),
    pad('Вердикт', 7),
    pad('Циклы(ож/найд)', 14),
    pad('Ветвл(ож/найд)', 14),
    pad('Switch(ож/найд)', 15),
    pad('Вызовы(ож/найд)', 15),
    pad('g++ синтаксис', 13),
    pad('Совпал результат', 16),
  ].join(' | ');

  console.log(header);
  console.log('-'.repeat(header.length));

  let syntaxPassCount = 0;
  let fullMatchCount = 0;
  let cleanVerdictCount = 0;

  for (const r of rows) {
    if (r.compilesSyntax) syntaxPassCount++;
    if (r.matchedInputs === r.totalInputs) fullMatchCount++;
    if (r.verdict === 'CLEAN') cleanVerdictCount++;

    const line = [
      pad(r.file, 25),
      pad(r.opt, 4),
      pad(r.verdict, 7),
      pad(`${r.expectedLoops} / ${r.foundLoops}`, 14),
      pad(`${r.expectedBranches} / ${r.foundBranches}`, 14),
      pad(`${r.expectedSwitches} / ${r.foundSwitches}`, 15),
      pad(`${r.expectedCalls} / ${r.foundCalls}`, 15),
      pad(r.compilesSyntax ? 'OK' : 'FAIL', 13),
      pad(`${r.matchedInputs}/${r.totalInputs} (${r.matchedInputs === r.totalInputs ? 'OK' : 'FAIL'})`, 16),
    ].join(' | ');
    console.log(line);
    if (r.errorNote) {
      console.log(`   -> Примечание: ${r.errorNote}`);
    }
  }

  console.log('-'.repeat(header.length));
  console.log(
    `ИТОГО: Бинарников: ${rows.length} | Вердикт CLEAN: ${cleanVerdictCount}/${rows.length} | Компилируется (g++ -fsyntax-only): ${syntaxPassCount}/${rows.length} | Совпал результат (10/10 входов): ${fullMatchCount}/${rows.length}\n`
  );

  fs.rmSync(workDir, { recursive: true, force: true });

  if (syntaxPassCount < rows.length || fullMatchCount < rows.length) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
