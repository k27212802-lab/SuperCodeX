import express from 'express';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

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

    const response = await ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
    });

    return res.json({
      success: true,
      analysis: response.text,
      modelUsed: 'gemini-3.8-flash',
    });
  } catch (err: any) {
    console.error('AI Audit Error:', err);
    return res.status(500).json({
      success: false,
      error: err.message || 'Error executing AI code audit',
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
