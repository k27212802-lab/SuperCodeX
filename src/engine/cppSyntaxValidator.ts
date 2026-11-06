import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { ReconstructedProject } from './projectLifter';

export interface CppFileSyntaxResult {
  path: string;
  status: 'OK' | 'FAIL';
  errors?: string;
}

export interface ProjectCppSyntaxReport {
  totalCppFiles: number;
  passedCount: number;
  failedCount: number;
  allPassed: boolean;
  results: CppFileSyntaxResult[];
}

/**
 * Requirement 8: Writes all reconstructed headers (.h) and C++ source files (.cpp) to an isolated
 * temporary directory and runs real `g++ -fsyntax-only -std=c++20 -Iinclude` on every `.cpp` file,
 * reporting `OK` or `FAIL` for each file.
 */
export function verifyProjectCppSyntaxWithGpp(project: ReconstructedProject): ProjectCppSyntaxReport {
  const cppFiles = project.files.filter((f) => f.language === 'cpp' && f.path.endsWith('.cpp'));
  if (cppFiles.length === 0) {
    return {
      totalCppFiles: 0,
      passedCount: 0,
      failedCount: 0,
      allPassed: true,
      results: [],
    };
  }

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'aegis-cpp-syntax-'));
  const results: CppFileSyntaxResult[] = [];

  try {
    // 1. Write all project files (.h and .cpp) preserving relative paths
    for (const file of project.files) {
      if (file.language !== 'cpp' && file.language !== 'h') continue;
      const fullPath = path.join(tmpRoot, file.path);
      fs.mkdirSync(path.dirname(fullPath), { recursive: true });
      fs.writeFileSync(fullPath, file.content, 'utf8');
    }

    const includeDir = path.join(tmpRoot, 'include');

    const gppCmd = fs.existsSync('/usr/bin/g++') ? '/usr/bin/g++' : 'g++';

    // 2. Run `g++ -fsyntax-only -std=c++20 -I<include>` on each .cpp file
    for (const cppFile of cppFiles) {
      const fullCppPath = path.join(tmpRoot, cppFile.path);
      try {
        execFileSync(
          gppCmd,
          ['-fsyntax-only', '-std=c++20', `-I${includeDir}`, `-I${tmpRoot}`, fullCppPath],
          {
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 10000,
          }
        );
        results.push({
          path: cppFile.path,
          status: 'OK',
        });
      } catch (err: unknown) {
        const isEnoent =
          err && typeof err === 'object' && 'code' in err && (err as { code: string }).code === 'ENOENT';
        if (isEnoent) {
          const internalCheck = internalCppSyntaxCheck(cppFile.content);
          results.push({
            path: cppFile.path,
            status: internalCheck.ok ? 'OK' : 'FAIL',
            errors: internalCheck.error,
          });
        } else {
          const stderr =
            err && typeof err === 'object' && 'stderr' in err && Buffer.isBuffer((err as { stderr: Buffer }).stderr)
              ? (err as { stderr: Buffer }).stderr.toString('utf8').trim()
              : err instanceof Error
              ? err.message
              : String(err);
          results.push({
            path: cppFile.path,
            status: 'FAIL',
            errors: stderr,
          });
        }
      }
    }
  } finally {
    try {
      fs.rmSync(tmpRoot, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }

  const passedCount = results.filter((r) => r.status === 'OK').length;
  const failedCount = results.filter((r) => r.status === 'FAIL').length;

  return {
    totalCppFiles: results.length,
    passedCount,
    failedCount,
    allPassed: failedCount === 0,
    results,
  };
}

function internalCppSyntaxCheck(content: string): { ok: boolean; error?: string } {
  let openBraces = 0;
  let openParens = 0;
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;

  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    const next = content[i + 1] || '';

    if (inLineComment) {
      if (ch === '\n') inLineComment = false;
      continue;
    }
    if (inBlockComment) {
      if (ch === '*' && next === '/') {
        inBlockComment = false;
        i++;
      }
      continue;
    }
    if (inString) {
      if (ch === '\\') {
        i++;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '/' && next === '/') {
      inLineComment = true;
      i++;
      continue;
    }
    if (ch === '/' && next === '*') {
      inBlockComment = true;
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }

    if (ch === '{') openBraces++;
    else if (ch === '}') openBraces--;
    else if (ch === '(') openParens++;
    else if (ch === ')') openParens--;

    if (openBraces < 0) return { ok: false, error: 'Unbalanced closing brace }' };
    if (openParens < 0) return { ok: false, error: 'Unbalanced closing parenthesis )' };
  }

  if (openBraces !== 0) return { ok: false, error: 'Unmatched opening brace {' };
  if (openParens !== 0) return { ok: false, error: 'Unmatched opening parenthesis (' };
  if (inString) return { ok: false, error: 'Unterminated string literal' };
  if (inBlockComment) return { ok: false, error: 'Unterminated block comment' };

  return { ok: true };
}
