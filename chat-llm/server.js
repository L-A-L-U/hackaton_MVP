// server.js — REST v1 puro (sin SDK), con autodiscovery, fallback y backoff
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import fetch from 'node-fetch';

const {
  PORT = 8787,
  GEMINI_API_KEY,
  GEMINI_MODEL, // opcional: ej "gemini-2.5-flash"
} = process.env;

if (!GEMINI_API_KEY) {
  console.error('❌ Falta GEMINI_API_KEY en .env');
  process.exit(1);
}

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(
  cors({
    origin: [/^http:\/\/localhost(:\d+)?$/],
    credentials: false,
  })
);
app.use(
  rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true, legacyHeaders: false })
);

// =============== Utilidades ===============
const API_BASE = 'https://generativelanguage.googleapis.com/v1';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (base) => Math.round(base * (0.8 + Math.random() * 0.4));
const normalizeModelId = (m) => (m || '').replace(/^models\//, '').trim();

function safeSlice(obj, maxItems = 6) {
  try {
    if (!obj) return null;
    if (Array.isArray(obj)) return obj.slice(0, maxItems);
    if (typeof obj === 'object') {
      const out = {};
      let i = 0;
      for (const k of Object.keys(obj)) {
        if (i >= maxItems) break;
        out[k] = obj[k];
        i++;
      }
      return out;
    }
    return obj;
  } catch {
    return null;
  }
}

function buildPrompt(userQuery, ctx) {
  const wallet = ctx?.wallet || {};
  const total = wallet?.total_disponible;
  const cuentas = safeSlice(wallet?.cuentas, 8);

  const walletStr = JSON.stringify(
    {
      total_disponible: total,
      cuentas: (cuentas || []).map((c) => ({
        tipo: c?.tipo,
        alias: c?.alias,
        numero: c?.numero,
        disponible: c?.disponible,
        saldo: c?.saldo,
        limite: c?.limite,
        moneda: c?.moneda,
        tags: c?.tags,
      })),
    },
    null,
    2
  );

  return `
Eres un asistente bancario SPEI. Responde en español, claro y accionable.
No inventes cifras: usa SOLO el contexto.

Contexto (wallet del usuario):
${walletStr}

Consulta:
"${userQuery}"

Guías:
- Saldo/total/cuentas: usa el contexto.
- Transferencias: requieren CURP destino (18), monto > 0 y Token = SHA-256 del RFC (64 hex). El cliente envía el token en header "X-User-Token".
- Si piden el token, explica que es SHA-256(RFC) y debe tener 64 hex.
- Si falta info, dilo y pide el dato mínimo faltante.
`;
}

// =============== Descubrimiento de modelos ===============
let MODEL_CANDIDATES = []; // se rellena en bootstrap

async function listModelsV1() {
  const url = `${API_BASE}/models?key=${encodeURIComponent(GEMINI_API_KEY)}`;
  const r = await fetch(url);
  if (!r.ok) throw new Error(`ListModels HTTP ${r.status}`);
  const j = await r.json();
  return Array.isArray(j?.models) ? j.models : [];
}

function scoreModelName(name) {
  // Mayor score = mayor prioridad
  const n = name.toLowerCase();
  let s = 0;
  if (n.includes('2.5')) s += 200;
  if (n.includes('2.0')) s += 150;
  if (n.includes('flash')) s += 50; // rápido/barato
  if (n.includes('pro')) s += 25;   // más capaz
  // multimodal / token context etc podría sumarse aquí si quisieras
  return s;
}

async function bootstrapModels() {
  try {
    const models = await listModelsV1();
    const supportsGen = models
      .filter((m) => Array.isArray(m.supportedGenerationMethods) && m.supportedGenerationMethods.includes('generateContent'))
      .map((m) => ({
        id: normalizeModelId(m.name), // "models/gemini-2.5-flash" -> "gemini-2.5-flash"
        score: scoreModelName(m.name),
      }));

    const envFirst = normalizeModelId(GEMINI_MODEL);
    const pool = supportsGen
      .filter((m) => m.id) // solo id válidos
      .sort((a, b) => b.score - a.score)
      .map((m) => m.id);

    // Si .env especifica un modelo y existe, ponlo hasta adelante
    if (envFirst) {
      const idx = pool.indexOf(envFirst);
      if (idx > -1) {
        pool.splice(idx, 1);
        pool.unshift(envFirst);
      } else {
        // si el env no está listado por la API, igual lo probamos de primero
        pool.unshift(envFirst);
      }
    }

    // Dedup
    MODEL_CANDIDATES = [...new Set(pool)];
    if (MODEL_CANDIDATES.length === 0) {
      // fallback seguro mínimo
      MODEL_CANDIDATES = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
    }
    console.log('🧠 Modelos candidatos:', MODEL_CANDIDATES.join(' → '));
  } catch (e) {
    console.warn('⚠️ No se pudo autodiscover models. Usaré defaults.');
    MODEL_CANDIDATES = [normalizeModelId(GEMINI_MODEL) || 'gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-1.5-flash'];
  }
}

// =============== Llamada REST v1 con backoff ===============
async function callGeminiV1Generate({ model, text, tries = 3 }) {
  const modelId = normalizeModelId(model);
  const url = `${API_BASE}/models/${encodeURIComponent(modelId)}:generateContent?key=${encodeURIComponent(GEMINI_API_KEY)}`;

  let lastErr;
  for (let i = 0; i < tries; i++) {
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text }]}],
        }),
      });
      const j = await r.json().catch(() => ({}));

      if (!r.ok) {
        const code = j?.error?.code || r.status;
        const msg = j?.error?.message || r.statusText || `HTTP ${r.status}`;

        // 503 (overloaded) → reintento con backoff
        if (code === 503) {
          const base = 500 * Math.pow(2, i); // 500, 1000, 2000…
          await sleep(jitter(base));
          continue;
        }

        // 404 (modelo no soporta v1/generateContent) → no más reintentos para este modelo
        if (code === 404) {
          throw Object.assign(new Error(`404 Not Found: ${msg}`), { fatal: true, status: 404 });
        }

        // otros errores → un par de reintentos suaves
        if (i < tries - 1) {
          await sleep(jitter(400 * (i + 1)));
          continue;
        }
        throw new Error(msg);
      }

      // Extraer texto
      const textResp =
        j?.candidates?.[0]?.content?.parts?.[0]?.text ||
        j?.promptFeedback?.blockReason ||
        '';

      if (!textResp) throw new Error('Respuesta vacía del modelo');
      return textResp;
    } catch (e) {
      lastErr = e;
      if (e?.fatal) throw e;
      if (i < tries - 1) continue;
    }
  }
  throw lastErr || new Error('Fallo desconocido en llamada a Gemini');
}

async function generateWithFallback({ prompt }) {
  let lastErr;
  for (const model of MODEL_CANDIDATES) {
    try {
      const answer = await callGeminiV1Generate({ model, text: prompt, tries: 3 });
      return { answer, usedModel: model };
    } catch (e) {
      lastErr = e;
      console.warn(`⚠️ Falló "${model}" → ${e?.message || e}`);
      // si es 404, pasamos al siguiente de inmediato
      if (e?.status === 404) continue;
      // si fue 503, ya se reintenta dentro de callGeminiV1Generate
      // seguimos al siguiente candidato
    }
  }
  throw lastErr || new Error('No fue posible generar respuesta con la IA');
}

// =============== Rutas ===============
app.get('/health', async (_req, res) => {
  res.json({ ok: true, service: 'chat-llm', models: MODEL_CANDIDATES });
});

app.get('/models', async (_req, res) => {
  try {
    const url = `${API_BASE}/models?key=${encodeURIComponent(GEMINI_API_KEY)}`;
    const r = await fetch(url);
    const j = await r.json();
    res.json(j);
  } catch (e) {
    res.status(500).json({ error: 'No se pudieron listar modelos', detail: String(e) });
  }
});

app.post('/chat', async (req, res) => {
  try {
    const { q, context } = req.body || {};
    if (!q || typeof q !== 'string' || !q.trim()) {
      return res.status(400).json({ error: 'Falta "q" (consulta de usuario).' });
    }
    const prompt = buildPrompt(q.trim(), context || {});
    const { answer, usedModel } = await generateWithFallback({ prompt });
    res.json({ answer, model: usedModel });
  } catch (err) {
    const msg = err?.message || 'Fallo generando respuesta';
    const status =
      err?.status ||
      (msg.includes('404') ? 404 : msg.includes('503') ? 503 : 502);

    const hint =
      status === 404
        ? 'El modelo no está disponible en v1 o no soporta generateContent. Revisa /models.'
        : status === 401
        ? 'Revisa GEMINI_API_KEY en .env.'
        : status === 503
        ? 'El modelo está sobrecargado. Se intentó con backoff y fallback.'
        : undefined;

    console.error('LLM error:', err);
    res.status(502).json({ error: 'No pude generar respuesta con la IA.', code: status, hint });
  }
});

// =============== Arranque ===============
app.listen(Number(PORT), async () => {
  console.log(`✅ Chat LLM listo en http://localhost:${PORT}`);
  await bootstrapModels();
});
