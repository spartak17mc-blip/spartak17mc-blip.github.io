/**
 * Backend для заявок с сайта → ваш личный Telegram (Cloudflare Workers, бесплатный тариф).
 *
 * Что он защищает:
 *  - токен бота и chat_id живут только здесь, в секретах воркера; сайт и посетители их не видят;
 *  - заявки уходят только в один чат — CHAT_ID (ваш личный), отправить «куда-то ещё» нельзя;
 *  - принимаются только POST-запросы с JSON и только с вашего сайта (проверка Origin);
 *  - сайт присылает сырые поля, а текст сообщения собирает и экранирует сам воркер:
 *    подделать разметку, ссылки или «чужой» текст в вашем Telegram нельзя;
 *  - каждое поле проверяется заново (браузерную проверку можно обойти), длина и размер запроса ограничены;
 *  - ловушка для ботов (honeypot), отсев «мгновенных» отправок и лимит частоты по IP.
 *
 * Как подключить (≈10 минут) — подробная инструкция в README.md, раздел «Заявки в Telegram»:
 *  1. @BotFather → /newbot → получите токен бота.
 *  2. Напишите своему боту /start, затем узнайте свой chat id (например, у @userinfobot — строка «Id»).
 *  3. dash.cloudflare.com → Workers & Pages → Create → Worker → вставьте этот файл целиком → Deploy.
 *  4. Settings → Variables and Secrets → добавьте (тип Secret):
 *       BOT_TOKEN      = токен бота
 *       CHAT_ID        = ваш chat id (число)
 *       ALLOWED_ORIGIN = https://spartak17mc-blip.github.io      (без слеша на конце; ваш домен, если появится)
 *  5. Адрес воркера (https://….workers.dev) впишите в index.html → LEADS.endpoint.
 *  6. (Рекомендуется) Security → WAF → Rate limiting rules: не больше 10 запросов в минуту с одного IP.
 *
 * Проверка: откройте адрес воркера в браузере — ответ «Method not allowed» значит, что он запущен
 * и секреты заданы («Not configured» — какого-то секрета не хватает).
 */

const MAX_BODY = 16 * 1024;                                // bytes
const WINDOW_MS = 10 * 60 * 1000, MAX_PER_WINDOW = 5;     // per IP, best effort (per worker instance)
const hits = new Map();

/* main form: Telegram, budget, specialization, description */
const ORDER = { telegram: 64, budget: 40, spec: 60, message: 3500, lang: 5 };
// @username, username, t.me/username or https://t.me/username → "username"
const TG_RE = /^(?:@|(?:https?:\/\/)?(?:www\.)?(?:t|telegram)\.me\/)?([A-Za-z][A-Za-z0-9_]{3,31})\/?$/;

/* mini-quiz on the site (kept as before) */
const QUIZ = {
  "Имя": 60, "Контакт": 100, "Задача": 40, "Сфера": 60, "Готово": 60, "Сроки": 60,
  "Бюджет": 40, "Ориентир": 60, "Валюта": 10, "Язык": 5, "О проекте": 2000
};

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const clean = (s, max, multiline = false) => {
  let v = String(s ?? "").normalize("NFC").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F\u200B-\u200F\u202A-\u202E\u2066-\u2069]/g, "");
  v = multiline ? v.replace(/\r\n?/g, "\n").replace(/[ \t]{2,}/g, " ").replace(/\n{4,}/g, "\n\n\n") : v.replace(/\s+/g, " ");
  return v.trim().slice(0, max);
};

// → { text, buttons } or null when the lead is invalid
function buildOrder(f) {
  const tg = TG_RE.exec(clean(f.telegram, ORDER.telegram).replace(/\s+/g, ""));
  const budget = clean(f.budget, ORDER.budget);
  const spec = clean(f.spec, ORDER.spec);
  const message = clean(f.message, ORDER.message, true);
  const lang = clean(f.lang, ORDER.lang).toUpperCase();
  if (!tg || !/\d/.test(budget) || spec.length < 2 || message.length < 10) return null;
  const user = tg[1];
  const text = [
    "📩 <b>НОВАЯ ЗАЯВКА</b>",
    "",
    `👤 <b>Telegram:</b> @${esc(user)}`,
    `💰 <b>Бюджет:</b> ${esc(budget)}`,
    `🎯 <b>Специализация:</b> ${esc(spec)}`,
    `📝 <b>Описание:</b> ${esc(message)}`
  ];
  if (lang && lang !== "RU") text.push("", `🌐 <b>Язык сайта:</b> ${esc(lang)}`);
  return { text: text.join("\n"), buttons: [[{ text: "✉️ Написать клиенту", url: `https://t.me/${user}` }]] };
}

function buildQuiz(f) {
  const rows = [];
  for (const [key, max] of Object.entries(QUIZ)) {
    const v = clean(f[key], max, key === "О проекте");
    if (v) rows.push(`<b>${esc(key)}:</b> ${esc(v)}`);
  }
  if (clean(f["Контакт"], QUIZ["Контакт"]).length < 3) return null;
  return { text: `🧭 <b>ЗАЯВКА ИЗ ОПРОСНИКА</b>\n\n${rows.join("\n")}` };
}

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

    const lead = data.kind === "form" ? buildOrder(data.fields) : data.kind === "quiz" ? buildQuiz(data.fields) : null;
    if (!lead) return reply("Bad request", 400);

    recent.push(now); hits.set(ip, recent);
    if (hits.size > 5000) hits.clear();                    // keep memory bounded

    const stamp = new Date(now + 3 * 3600e3).toISOString().replace("T", " ").slice(0, 16);   // Moscow time
    const text = `${lead.text}\n\n<i>${esc(new URL(allowed).host)} · ${stamp} МСК</i>`;
    const body = { chat_id: env.CHAT_ID, text, parse_mode: "HTML", link_preview_options: { is_disabled: true } };
    if (lead.buttons) body.reply_markup = { inline_keyboard: lead.buttons };
    const tg = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    if (!tg.ok) console.error("Telegram error", tg.status, await tg.text());
    return reply(tg.ok ? "ok" : "telegram error", tg.ok ? 200 : 502);
  }
};
