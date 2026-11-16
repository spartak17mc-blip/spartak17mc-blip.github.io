// Backend для заявок с сайта → ваш Telegram (Cloudflare Workers, бесплатный тариф).
//
// Что он защищает:
//  - токен бота живёт только здесь, в секретах воркера; сайт и посетители его не видят;
//  - заявки получают ТОЛЬКО ID из CHAT_ID (вы и те, кого вы добавили), отправить «куда-то ещё» нельзя;
//  - бот закрытый: всем остальным он отвечает «это закрытый бот» и ничего не показывает,
//    из групп и каналов выходит сам — встроить его в чужой чат и читать заявки нельзя;
//  - webhook защищён секретом, который вычисляется из токена: подделать «сообщение от Telegram» нельзя;
//  - заявки принимаются только POST + JSON и только с адресов из ALLOWED_ORIGIN;
//  - текст сообщения собирает и экранирует сам воркер: подделать разметку или ссылки нельзя;
//  - каждое поле проверяется заново, длина и размер ограничены; honeypot, отсев «мгновенных»
//    отправок и лимит частоты по IP.
//
// Секреты (Settings → Variables and Secrets):
//   BOT_TOKEN      = токен бота от @BotFather
//   CHAT_ID        = кто получает заявки: ваш ID; несколько — через запятую: 8426313033, 123456789
//   ALLOWED_ORIGIN = адреса сайта через запятую, без слеша на конце
//
// После деплоя один раз откройте https://<адрес-воркера>/setup — воркер подключит webhook бота.
// Подробности — README.md, раздел «Заявки в Telegram».

const MAX_BODY = 16 * 1024;                                // bytes
const WINDOW_MS = 10 * 60 * 1000, MAX_PER_WINDOW = 5;     // per IP, best effort (per worker instance)
const hits = new Map();

// main form: Telegram, budget, specialization, description
const ORDER = { telegram: 64, budget: 40, spec: 60, message: 3500, lang: 5 };
// @username, username, t.me/username or https://t.me/username → "username"
const TG_RE = /^(?:@|(?:https?:\/\/)?(?:www\.)?(?:t|telegram)\.me\/)?([A-Za-z][A-Za-z0-9_]{3,31})\/?$/;

// mini-quiz on the site
const QUIZ = {
  "Имя": 60, "Контакт": 100, "Задача": 40, "Сфера": 60, "Готово": 60, "Сроки": 60,
  "Бюджет": 40, "Ориентир": 60, "Валюта": 10, "Язык": 5, "О проекте": 2000
};

const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const clean = (s, max, multiline = false) => {
  let v = String(s ?? "").normalize("NFC").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F​-‏‪-‮⁦-⁩]/g, "");
  v = multiline ? v.replace(/\r\n?/g, "\n").replace(/[ \t]{2,}/g, " ").replace(/\n{4,}/g, "\n\n\n") : v.replace(/\s+/g, " ");
  return v.trim().slice(0, max);
};
// "8426313033, 123456789" → ["8426313033", "123456789"]; anything that is not a numeric id is ignored
const recipients = env => String(env.CHAT_ID || "").split(",").map(s => s.trim()).filter(s => /^\d{3,20}$/.test(s));

// webhook secret derived from the bot token: nothing extra to store, and it changes if the token is revoked
async function hookSecret(env) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("leads-webhook:" + env.BOT_TOKEN));
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, "0")).join("").slice(0, 64);
}
// constant-time comparison for the webhook header
const same = (a, b) => {
  if (typeof a !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
};
const tgApi = (env, method, payload) => fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(payload)
});

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

// messages to the bot itself (via webhook): only trusted ids get an answer about leads
async function onUpdate(update, env) {
  const ids = recipients(env);
  // added to a group or channel → leave at once: nobody can plug the bot into their own chat
  const member = update.my_chat_member;
  if (member && member.chat.type !== "private") {
    if (member.new_chat_member?.status !== "left" && member.new_chat_member?.status !== "kicked") await tgApi(env, "leaveChat", { chat_id: member.chat.id });
    return;
  }
  const msg = update.message;
  if (!msg?.chat) return;
  if (msg.chat.type !== "private") { await tgApi(env, "leaveChat", { chat_id: msg.chat.id }); return; }
  const id = String(msg.from?.id ?? msg.chat.id);
  const trusted = ids.includes(id);
  const text = trusted
    ? "✅ <b>Вы получатель заявок.</b>\n\nНовые заявки с сайта будут приходить в этот чат. Бот закрытый: посторонним он ничего не показывает.\n\nВаш ID: <code>" + esc(id) + "</code>"
    : "⛔ <b>Это закрытый бот.</b>\n\nОн доставляет заявки с сайта только своему владельцу и не ведёт переписку с клиентами.\n\nВаш ID: <code>" + esc(id) + "</code>";
  await tgApi(env, "sendMessage", { chat_id: msg.chat.id, text, parse_mode: "HTML" });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    // one or several site addresses, comma-separated: "https://a.github.io, https://a.vercel.app"
    const origins = String(env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim().replace(/\/+$/, "")).filter(Boolean);
    const origin = request.headers.get("Origin") || "";
    const allowed = origins.includes(origin) ? origin : origins[0];
    const cors = {
      "Access-Control-Allow-Origin": allowed || "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
      "X-Content-Type-Options": "nosniff"
    };
    const reply = (msg, status) => new Response(msg, { status, headers: cors });
    const ids = recipients(env);

    if (!allowed || !env.BOT_TOKEN || !ids.length) return reply("Not configured", 500);

    // Telegram → bot (webhook): accepted only with the secret header
    if (url.pathname === "/tg") {
      if (request.method !== "POST" || !same(request.headers.get("X-Telegram-Bot-Api-Secret-Token"), await hookSecret(env))) return reply("Forbidden", 403);
      try { await onUpdate(await request.json(), env); } catch (e) { console.error("update", e); }
      return reply("ok", 200);                             // always 200, so Telegram does not resend
    }
    // one-time setup: points the bot's webhook at this worker (safe to repeat, reveals nothing)
    if (url.pathname === "/setup") {
      const res = await tgApi(env, "setWebhook", {
        url: `${url.origin}/tg`, secret_token: await hookSecret(env),
        allowed_updates: ["message", "my_chat_member"], drop_pending_updates: true
      });
      const data = await res.json().catch(() => ({}));
      return reply(data.ok ? "Webhook подключён ✓" : "Ошибка: " + (data.description || res.status), data.ok ? 200 : 502);
    }

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return reply("Method not allowed", 405);
    // only our own site may submit (browsers always send Origin on cross-site POST)
    if (!origins.includes(origin)) return reply("Forbidden", 403);
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
    // every trusted recipient gets the lead; it counts as delivered if at least one got it
    const sent = await Promise.all(ids.map(async chat_id => {
      const body = { chat_id, text, parse_mode: "HTML", link_preview_options: { is_disabled: true } };
      if (lead.buttons) body.reply_markup = { inline_keyboard: lead.buttons };
      const tg = await tgApi(env, "sendMessage", body);
      if (!tg.ok) console.error("Telegram error", chat_id, tg.status, await tg.text());
      return tg.ok;
    }));
    const ok = sent.some(Boolean);
    return reply(ok ? "ok" : "telegram error", ok ? 200 : 502);
  }
};
