/**
 * Прокси для заявок с сайта → Telegram (Cloudflare Workers, бесплатный тариф).
 *
 * Зачем: токен бота хранится на сервере как секрет и не виден в коде сайта.
 *
 * Как подключить (≈10 минут):
 *  1. Создайте бота у @BotFather и получите токен.
 *  2. Напишите своему боту любое сообщение, затем откройте
 *     https://api.telegram.org/bot<ТОКЕН>/getUpdates — в ответе найдите "chat":{"id": ...} — это CHAT_ID.
 *  3. На dash.cloudflare.com → Workers & Pages → Create → Worker, вставьте этот файл целиком, Deploy.
 *  4. В настройках воркера → Settings → Variables and Secrets добавьте секреты:
 *       BOT_TOKEN = токен бота
 *       CHAT_ID   = ваш chat id
 *       ALLOWED_ORIGIN = https://spartak17mc-blip.github.io   (или ваш домен)
 *  5. Адрес воркера (https://….workers.dev) впишите в index.html → LEADS.endpoint.
 */
export default {
  async fetch(request, env) {
    const origin = env.ALLOWED_ORIGIN || "*";
    const cors = {
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    };
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (request.method !== "POST") return new Response("Method not allowed", { status: 405, headers: cors });
    if (origin !== "*" && request.headers.get("Origin") !== origin) return new Response("Forbidden", { status: 403, headers: cors });

    let text = "";
    try { ({ text } = await request.json()); } catch { /* bad JSON */ }
    if (typeof text !== "string" || !text.trim()) return new Response("Bad request", { status: 400, headers: cors });

    const tg = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ chat_id: env.CHAT_ID, text: text.slice(0, 3800), parse_mode: "HTML", disable_web_page_preview: true })
    });
    return new Response(tg.ok ? "ok" : "telegram error", { status: tg.ok ? 200 : 502, headers: cors });
  }
};
