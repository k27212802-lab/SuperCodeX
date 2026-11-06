import express from 'express';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import fs from 'fs';
import path from 'path';
import JSZip from 'jszip';
import { verifyProjectCppSyntaxWithGpp } from './src/engine/cppSyntaxValidator';

dotenv.config();

const app = express();
app.use(express.json({ limit: '10mb' }));

// Server-side Gemini AI Client Utility
const getAiClient = () => {
  return new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY || '',
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
};

// API Endpoint: AI Code Audit for Decompiled C++ Source Code
app.post('/api/ai-audit', async (req, res) => {
  try {
    const { code, fileName, format } = req.body;
    if (!code) {
      return res.status(400).json({ error: 'No code content provided' });
    }

    const ai = getAiClient();
    const prompt = `Ты — ведущий эксперт по реверс-инжинирингу и кибербезопасности. Проведи глубокий аудит восстановленного C++ кода файла "${fileName || 'sample.exe'}" (Формат: ${format || 'PE64'}):

${code.slice(0, 12000)}

Дай чёткий профессиональный анализ на русском языке в следующем формате:
1. **Общий вердикт безопасности** (ВРЕДОНОСНЫЙ / ПОДОЗРИТЕЛЬНЫЙ / БЕЗОПАСНЫЙ)
2. **Анализ ключевых функций и их намерения** (что конкретно делает каждая функция)
3. **Обнаруженные аномалии нулевого дня (Zero-Day)** или скрытые техники уклонения
4. **Рекомендации по нейтрализации и защите**`;

    const candidateModels = ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest'];
    let lastError: any = null;
    let successfulAnalysis = '';
    let usedModel = '';

    for (const modelName of candidateModels) {
      try {
        const response = await ai.models.generateContent({
          model: modelName,
          contents: prompt,
        });
        if (response.text) {
          successfulAnalysis = response.text;
          usedModel = modelName;
          break;
        }
      } catch (err: any) {
        console.warn(`Model ${modelName} failed, trying fallback. Error:`, err.message || err);
        lastError = err;
      }
    }

    if (successfulAnalysis) {
      return res.json({
        success: true,
        analysis: successfulAnalysis,
        modelUsed: usedModel,
      });
    }

    return res.status(503).json({
      success: false,
      error: `Все модели Gemini недоступны в данный момент (503/Quota): ${lastError?.message || 'High Demand'}`,
    });
  } catch (err: any) {
    console.error('AI Audit Error:', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'Error executing AI code audit',
    });
  }
});

// API Endpoint: Interactive Chat with AI Threat Auditor about Decompiled Code
app.post('/api/ai-chat', async (req, res) => {
  try {
    const { messages, codeContext, fileName } = req.body;
    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Messages array is required' });
    }

    const ai = getAiClient();
    const systemInstruction = `Ты — ведущий старший эксперт по вирусологии, реверс-инжинирингу и кибербезопасности SuperCodeX AI.
Пользователь задает тебе вопросы о декомпилированном исходном коде файла "${fileName || 'sample.exe'}".

Контекст декомпилированного кода C++:
\`\`\`cpp
${(codeContext || '').slice(0, 10000)}
\`\`\`

Отвечай профессионально, вежливо, на русском языке. Давай точные ответы с указанием названий функций, аргументов, системных вызовов, техник нейтрализации и инструкций для отладчиков (x64dbg, WinDbg, IDA Pro).`;

    // Construct full prompt from chat history
    const conversationPrompt = messages
      .map((m: any) => `${m.role === 'user' ? 'Пользователь' : 'ИИ-Вирусолог'}: ${m.content}`)
      .join('\n\n');

    const fullPrompt = `${systemInstruction}\n\n=== ИСТОРИЯ ДИАЛОГА ===\n${conversationPrompt}\n\nИИ-Вирусолог:`;

    const candidateModels = ['gemini-3.8-flash', 'gemini-3.1-flash-lite', 'gemini-flash-latest'];
    let lastError: any = null;
    let replyText = '';
    let usedModel = '';

    for (const modelName of candidateModels) {
      try {
        const response = await ai.models.generateContent({
          model: modelName,
          contents: fullPrompt,
        });
        if (response.text) {
          replyText = response.text;
          usedModel = modelName;
          break;
        }
      } catch (err: any) {
        console.warn(`Chat model ${modelName} failed, trying fallback.`, err.message || err);
        lastError = err;
      }
    }

    if (replyText) {
      return res.json({
        success: true,
        reply: replyText,
        modelUsed: usedModel,
      });
    }

    return res.status(503).json({
      success: false,
      error: `Все модели Gemini недоступны в данный момент: ${lastError?.message || 'High Demand'}`,
    });
  } catch (err: any) {
    console.error('AI Chat Error:', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'Error executing AI chat',
    });
  }
});

// VirusTotal Proxy Endpoint
app.get('/api/vt/files/:hash', async (req, res) => {
  try {
    const { hash } = req.params;
    const apiKey = process.env.VIRUSTOTAL_API_KEY || '';
    if (!apiKey) {
      return res.json({
        success: false,
        error: 'VirusTotal API Key is not configured in secrets.',
      });
    }

    const vtRes = await fetch(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { 'x-apikey': apiKey },
    });

    if (!vtRes.ok) {
      return res.json({
        success: false,
        error: `VirusTotal returned status ${vtRes.status}`,
      });
    }

    const data = await vtRes.json();
    return res.json({
      success: true,
      data,
    });
  } catch (e: any) {
    return res.json({ success: false, error: e.message });
  }
});

// Endpoint: Run real g++ -fsyntax-only verification on every .cpp file in a ReconstructedProject
app.post('/api/verify-cpp-syntax', (req, res) => {
  try {
    const { project } = req.body;
    if (!project || !Array.isArray(project.files)) {
      return res.status(400).json({ success: false, error: 'Project files array is required' });
    }
    const syntaxReport = verifyProjectCppSyntaxWithGpp(project);
    return res.json({
      success: true,
      report: syntaxReport,
    });
  } catch (e: any) {
    return res.status(500).json({
      success: false,
      error: e.message || 'g++ syntax check failed',
    });
  }
});

// Endpoint: Check if Ghidra Headless Analyzer (analyzeHeadless) is installed on the host
app.get('/api/ghidra-status', async (_req, res) => {
  try {
    const { execFileSync } = await import('child_process');
    const binPath = execFileSync('which', ['analyzeHeadless'], { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    return res.json({
      installed: Boolean(binPath),
      message: binPath ? `Ghidra Headless установлена: ${binPath}` : 'Ghidra не установлена, сравнение недоступно',
    });
  } catch {
    return res.json({
      installed: false,
      message: 'Ghidra не установлена, сравнение недоступно',
    });
  }
});

const REPO_FILES_TO_SYNC = [
  'README.md',
  'package.json',
  'tsconfig.json',
  'vite.config.ts',
  'index.html',
  'metadata.json',
  'server.ts',
  '.github/workflows/deploy.yml',
  'scripts/bench.ts',
  'tests/corpus/01_checksum.cpp',
  'tests/corpus/02_compute_div3.cpp',
  'tests/corpus/03_switch_classify.cpp',
  'tests/corpus/04_while_collatz.cpp',
  'tests/corpus/05_dowhile_digits.cpp',
  'tests/corpus/06_ifelse_grade.cpp',
  'tests/corpus/07_recursion_fib.cpp',
  'tests/corpus/08_gcd_loop.cpp',
  'tests/corpus/09_array_sum.cpp',
  'tests/corpus/10_array_max.cpp',
  'tests/corpus/11_pointer_mutate.cpp',
  'tests/corpus/12_struct_fields.cpp',
  'tests/corpus/13_virtual_shape.cpp',
  'tests/corpus/14_string_scan.cpp',
  'tests/corpus/15_nested_loops_grid.cpp',
  'tests/corpus/16_clean_minimal.cpp',
  'src/main.tsx',
  'src/App.tsx',
  'src/index.css',
  'src/components/ArchitectureInspectorView.tsx',
  'src/components/BenchmarkView.tsx',
  'src/components/FileScannerView.tsx',
  'src/components/GithubRepoModal.tsx',
  'src/components/GithubSiteView.tsx',
  'src/components/RealGhidraBenchView.tsx',
  'src/components/VirusTotalAuditView.tsx',
  'src/components/WindowsDownloadModal.tsx',
  'src/components/YaraRulesLabView.tsx',
  'src/engine/archive.ts',
  'src/engine/benchmark.ts',
  'src/engine/cppSyntaxValidator.ts',
  'src/engine/decompiler.ts',
  'src/engine/elfDecompiler.ts',
  'src/engine/peExportAndDecoder.ts',
  'src/engine/projectLifter.ts',
  'src/engine/scanner.ts',
  'src/engine/scanner.test.ts',
  'src/engine/virustotal.ts',
];

function collectRepoFiles(): Record<string, string> {
  const filesMap: Record<string, string> = {};
  const rootDir = process.cwd();
  for (const relPath of REPO_FILES_TO_SYNC) {
    const fullPath = path.join(rootDir, relPath);
    if (fs.existsSync(fullPath)) {
      filesMap[relPath] = fs.readFileSync(fullPath, 'utf-8');
    }
  }
  return filesMap;
}

// Endpoint to get all real repository source files for ZIP export or inspection
app.get('/api/github-bundle', (_req, res) => {
  try {
    const files = collectRepoFiles();
    return res.json({
      success: true,
      fileCount: Object.keys(files).length,
      files,
    });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint to download the full standalone project/CLI engine via 1 curl/wget command
app.get('/api/download-cli', async (_req, res) => {
  try {
    const files = collectRepoFiles();
    const zip = new JSZip();
    for (const [relPath, content] of Object.entries(files)) {
      zip.file(`SuperCodeX-main/${relPath}`, content);
      // Also write at root so both `cd SuperCodeX-main` and direct root extraction work
      zip.file(relPath, content);
    }
    const qtDllPath = path.join(process.cwd(), 'tmp/Qt5Xml.dll');
    if (fs.existsSync(qtDllPath)) {
      const dllBytes = fs.readFileSync(qtDllPath);
      zip.file('SuperCodeX-main/tmp/Qt5Xml.dll', dllBytes);
      zip.file('tmp/Qt5Xml.dll', dllBytes);
    }
    const buffer = await zip.generateAsync({ type: 'nodebuffer' });
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="SuperCodeX.zip"');
    return res.send(buffer);
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// Endpoint to push all current repository files directly to GitHub via GitHub REST Git Data API
app.post('/api/github-push', async (req, res) => {
  try {
    const { token, repo = 'k27212802-lab/SuperCodeX', branch = 'main', commitMessage } = req.body;
    if (!token || typeof token !== 'string' || !token.trim()) {
      return res.status(400).json({
        success: false,
        error: 'Укажите GitHub Personal Access Token (ghp_... или github_pat_...) с правами repo / workflow для отправки коммита.',
      });
    }

    const cleanToken = token.trim();
    const headers: Record<string, string> = {
      Authorization: `Bearer ${cleanToken}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'X-GitHub-Api-Version': '2022-11-28',
      'User-Agent': 'SuperCodeX-GitHub-Sync',
    };

    // 1. Get latest commit SHA on target branch
    const refRes = await fetch(`https://api.github.com/repos/${repo}/git/ref/heads/${branch}`, { headers });
    if (!refRes.ok) {
      const errBody = await refRes.text();
      return res.status(refRes.status).json({
        success: false,
        error: `Не удалось получить ветку ${branch} в ${repo} (HTTP ${refRes.status}): ${errBody}`,
      });
    }
    const refData: any = await refRes.json();
    const latestCommitSha = refData.object.sha;

    // 2. Get base tree SHA from latest commit
    const commitRes = await fetch(`https://api.github.com/repos/${repo}/git/commits/${latestCommitSha}`, { headers });
    if (!commitRes.ok) {
      const errBody = await commitRes.text();
      return res.status(commitRes.status).json({
        success: false,
        error: `Не удалось получить дерево коммита (HTTP ${commitRes.status}): ${errBody}`,
      });
    }
    const commitData: any = await commitRes.json();
    const baseTreeSha = commitData.tree.sha;

    // 3. Collect all real local files and create tree entries
    const files = collectRepoFiles();
    const treeEntries: Array<Record<string, any>> = Object.entries(files).map(([filePath, content]) => ({
      path: filePath,
      mode: '100644',
      type: 'blob',
      content,
    }));

    // Upload binary tmp/Qt5Xml.dll blob so Test #27 works out of the box in cloned repository
    const qtDllPath = path.join(process.cwd(), 'tmp/Qt5Xml.dll');
    if (fs.existsSync(qtDllPath)) {
      const dllBase64 = fs.readFileSync(qtDllPath).toString('base64');
      const blobRes = await fetch(`https://api.github.com/repos/${repo}/git/blobs`, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          content: dllBase64,
          encoding: 'base64',
        }),
      });
      if (blobRes.ok) {
        const blobData: any = await blobRes.json();
        treeEntries.push({
          path: 'tmp/Qt5Xml.dll',
          mode: '100644',
          type: 'blob',
          sha: blobData.sha,
        });
      }
    }

    // 4. Create new Git Tree
    const treeRes = await fetch(`https://api.github.com/repos/${repo}/git/trees`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        base_tree: baseTreeSha,
        tree: treeEntries,
      }),
    });
    if (!treeRes.ok) {
      const errBody = await treeRes.text();
      return res.status(treeRes.status).json({
        success: false,
        error: `Ошибка создания Git Tree (HTTP ${treeRes.status}): ${errBody}`,
      });
    }
    const treeData: any = await treeRes.json();

    // 5. Create Commit
    const newCommitRes = await fetch(`https://api.github.com/repos/${repo}/git/commits`, {
      method: 'POST',
      headers,
      body: JSON.stringify({
        message: commitMessage || 'Update entire SuperCodeX interface to Red Edition + Pure Project Decompiler (0-to-N folders/files)',
        tree: treeData.sha,
        parents: [latestCommitSha],
      }),
    });
    if (!newCommitRes.ok) {
      const errBody = await newCommitRes.text();
      return res.status(newCommitRes.status).json({
        success: false,
        error: `Ошибка создания коммита (HTTP ${newCommitRes.status}): ${errBody}`,
      });
    }
    const newCommitData: any = await newCommitRes.json();

    // 6. Update branch ref
    const updateRefRes = await fetch(`https://api.github.com/repos/${repo}/git/refs/heads/${branch}`, {
      method: 'PATCH',
      headers,
      body: JSON.stringify({
        sha: newCommitData.sha,
        force: true,
      }),
    });
    if (!updateRefRes.ok) {
      const errBody = await updateRefRes.text();
      return res.status(updateRefRes.status).json({
        success: false,
        error: `Ошибка обновления ветки ${branch} (HTTP ${updateRefRes.status}): ${errBody}`,
      });
    }

    return res.json({
      success: true,
      commitSha: newCommitData.sha,
      commitUrl: newCommitData.html_url || `https://github.com/${repo}/commit/${newCommitData.sha}`,
      filesUpdated: treeEntries.length,
    });
  } catch (e: any) {
    return res.status(500).json({ success: false, error: e.message });
  }
});

// Mount Vite Middlewares in dev mode
if (process.env.NODE_ENV !== 'production') {
  const { createServer: createViteServer } = await import('vite');
  const vite = await createViteServer({
    server: { middlewareMode: true },
    appType: 'custom',
  });
  app.use(vite.middlewares);

  app.use('*', async (req, res, next) => {
    const url = req.originalUrl;
    try {
      let template = await vite.transformIndexHtml(url, `<!doctype html>
<html lang="ru" class="dark">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SuperCodeX v9.847.149 Lossless C++ Decompiler & Antivirus Engine</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>`);
      res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
    } catch (e: any) {
      vite.ssrFixStacktrace(e);
      next(e);
    }
  });
} else {
  app.use(express.static('dist'));
}

const PORT = 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[SuperCodeX Server] Express server listening on http://0.0.0.0:${PORT}`);
});
