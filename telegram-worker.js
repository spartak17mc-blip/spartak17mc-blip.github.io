/**
 * Прокси для заявок с сайта → Telegram (Cloudflare Workers, бесплатный тариф).
 *
 * Что он защищает:
 *  - токен бота и chat_id живут только здесь, в секретах воркера; сайт их не знает;
 *  - заявки можно отправить только с вашего сайта (проверка Origin), только POST и только JSON;
 *  - сайт присылает сырые поля, а текст сообщения собирает и экранирует сам воркер:
 *    подделать разметку, ссылки или «чужой» текст в вашем Telegram нельзя;
 *  - длина каждого поля и размер запроса ограничены; пустые и кривые заявки отклоняются;
 *  - ловушка для ботов (honeypot), отсев «мгновенных» отправок и лимит частоты по IP.
 *
 * Как подключить (≈10 минут):
 *  1. Создайте бота у @BotFather и получите токен.
 *  2. Напишите своему боту любое сообщение, затем откройте
 *     https://api.telegram.org/bot<ТОКЕН>/getUpdates — в ответе найдите "chat":{"id": ...} — это CHAT_ID.
 *  3. dash.cloudflare.com → Workers & Pages → Create → Worker → вставьте этот файл целиком → Deploy.
 *  4. Settings → Variables and Secrets → добавьте (тип Secret):
 *       BOT_TOKEN      = токен бота
 *       CHAT_ID        = ваш chat id
 *       ALLOWED_ORIGIN = https://spartak17mc-blip.github.io      (без слеша на конце; ваш домен, если появится)
 *  5. Адрес воркера (https://….workers.dev) впишите в index.html → LEADS.endpoint.
 *  6. (Рекомендуется) Security → WAF → Rate limiting rules: не больше 10 запросов в минуту с одного IP
 *     на адрес воркера — это надёжный серверный лимит поверх встроенного.
 */

const MAX_BODY = 8 * 1024;                                 // bytes
const FIELDS = {                                           // whitelist: field → max length
  "Имя": 60, "Контакт": 100, "Задача": 40, "Сфера": 60, "Готово": 60, "Сроки": 60,
  "Бюджет": 40, "Ориентир": 60, "Валюта": 10, "О проекте": 2000
};
const TITLES = { form: "🚀 Новая заявка с сайта", quiz: "🧭 Заявка из опросника" };
const WINDOW_MS = 10 * 60 * 1000, MAX_PER_WINDOW = 5;     // per IP, best effort (per worker instance)
const hits = new Map();

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const clean = (s, max) => String(s ?? "")
  .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​-‏‪-‮⁦-⁩]/g, "")
  .replace(/[ \t]{2,}/g, " ").replace(/\n{3,}/g, "\n\n").trim().slice(0, max);

export default {
  async fetch(request, env) {
    const allowed = env.ALLOWED_ORIGIN;
    const cors = {
      "Access-Control-Allow-Origin": allowed || "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
      "X-Content-Type-Options": "nosniff"
    };
    const reply = (msg, status) => new Response(msg, { status, headers: cors });

    if (!allowed || !env.BOT_TOKEN || !env.CHAT_ID) return reply("Not configured", 500);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return reply("Method not allowed", 405);
    // only our own site may submit (browsers always send Origin on cross-site POST)
    if (request.headers.get("Origin") !== allowed) return reply("Forbidden", 403);
    if (!(request.headers.get("Content-Type") || "").includes("application/json")) return reply("Unsupported media type", 415);

    // rate limit per IP
    const ip = request.headers.get("CF-Connecting-IP") || "unknown", now = Date.now();
    const recent = (hits.get(ip) || []).filter(t => now - t < WINDOW_MS);
    if (recent.length >= MAX_PER_WINDOW) return reply("Too many requests", 429);

    // size-limited JSON
    const raw = await request.text();
    if (raw.length > MAX_BODY) return reply("Payload too large", 413);
    let data;
    try { data = JSON.parse(raw); } catch { return reply("Bad request", 400); }
    if (!data || typeof data !== "object" || typeof data.fields !== "object" || data.fields === null) return reply("Bad request", 400);

    // bots: honeypot filled or submitted faster than a human could → accept silently, send nothing
    if (data.hp || Number(data.elapsed) < 3000) return reply("ok", 200);

    const title = TITLES[data.kind];
    if (!title) return reply("Bad request", 400);
    const rows = [];
    for (const [key, max] of Object.entries(FIELDS)) {
      const v = clean(data.fields[key], max);
      if (v) rows.push(`<b>${esc(key)}:</b> ${esc(v)}`);
    }
    const contact = clean(data.fields["Контакт"], FIELDS["Контакт"]);
    if (contact.length < 3) return reply("Bad request", 400);

    recent.push(now); hits.set(ip, recent);
    if (hits.size > 5000) hits.clear();                    // keep memory bounded

    const text = `<b>${title}</b>\n\n${rows.join("\n")}\n\n<i>${esc(new URL(allowed).host)} · ${new Date().toISOString().replace("T", " ").slice(0, 16)} UTC</i>`;
    const tg = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.CHAT_ID, text, parse_mode: "HTML", disable_web_page_preview: true })
    });
    return reply(tg.ok ? "ok" : "telegram error", tg.ok ? 200 : 502);
  }
};
