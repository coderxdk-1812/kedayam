# Metrics & Cloudflare setup (threats prevented, downloads)

This is the guidance you asked for. It covers **(1)** how the "threats prevented"
number now works, **(2)** where "downloads" actually comes from, and **(3)** how to
wire a Cloudflare SSL endpoint *if* you decide you want cross-user aggregate
counters — with copy-paste Worker code.

> **Read this first — the privacy trade-off.** Kedayam's entire pitch (and its
> Chrome Web Store data-handling disclosure) is *"nothing leaves your device, no
> telemetry endpoint"* — see `src/routes/privacy.tsx` and `PRIVACY.md`. The
> moment the extension POSTs anything to a server, that promise changes and the
> store review gets harder. So the default, recommended design keeps counters
> **local**. Only add the server piece if you consciously accept that trade-off.

---

## 1. "Threats prevented" — now a local counter (no server, no privacy cost)

This shipped in this change. The extension keeps three monotonic tallies **on the
user's own device** (`chrome.storage.local`, key `kedayam:v1:metrics`), with **no
URLs, no timestamps, no PII, and nothing uploaded**:

| Counter           | Bumped when…                                             |
| ----------------- | -------------------------------------------------------- |
| `threatsPrevented`| a fresh scan returns a **dangerous** verdict             |
| `pastesBlocked`   | a sensitive-data paste is withheld (`paste-blocked`)     |
| `clickfixBlocked` | a ClickFix / fake-CAPTCHA clipboard attack is defused    |

- Source of truth: `bumpMetric()` / `getMetrics()` in `extension/lib/storage.js`.
- Bumped in `extension/background.js` (scan verdict + `logEvent`).
- Shown to the user in the popup's **Activity** tab (the three stat tiles).

For most extensions this is all "threats prevented" ever needs to be — the user
sees their own protection count, and you never touch the privacy promise.

## 2. "Downloads" — this is a store/website metric, not something the extension collects

- **Chrome Web Store installs/uninstalls/weekly users**: already available, for
  free, in the **Chrome Web Store Developer Dashboard → your item → Stats**. The
  extension neither can nor should count its own installs. (Same for the Edge and
  Firefox add-on dashboards.)
- **Landing-page downloads / "Add to Chrome" clicks** on `kedayam.lovable.app`:
  that's a *website* analytics metric. The cheapest, no-code, privacy-friendly
  option is **Cloudflare Web Analytics** (§3a). If you want a public "N downloads"
  badge on the site, use the aggregate Worker in §3b.

---

## 3. If you still want a Cloudflare endpoint

You already have Cloudflare wired for the marketing app (`wrangler.jsonc`,
`src/server.ts`). Two paths:

### 3a. Zero-code website analytics + automatic SSL (recommended for "downloads")

You don't write any endpoint for this. "SSL connection" on Cloudflare just means:
put the site's domain behind Cloudflare and let it terminate TLS.

1. In the Cloudflare dashboard: **Add a site** → enter your domain → pick Free.
2. Change your domain's **nameservers** at your registrar to the two Cloudflare
   gives you. (If the site is on Lovable/another host, keep the existing `A` /
   `CNAME` records — Cloudflare proxies them; the orange cloud = proxied.)
3. **SSL/TLS → Overview → set encryption mode to _Full (strict)_.** This is the
   correct mode when your origin already serves HTTPS (Lovable does). "Flexible"
   is insecure — avoid it. Cloudflare issues+renews the edge cert automatically.
4. **Analytics → Web Analytics → Add a site** → drop the one-line beacon snippet
   into the landing page. You now get visits, and you can track "Add to Chrome"
   clicks as a custom event. No PII, no cookies, GDPR-friendly.

That covers SSL + traffic/downloads with zero backend code.

### 3b. Opt-in aggregate counters (only if you want a cross-user "threats blocked" number)

If you want a *global* "Kedayam has blocked N threats across all users" figure,
you need each install to report an **anonymous, aggregate-only** increment. Do it
opt-in, with **no URL and no identifier** — just a bare event name.

**Worker** (`workers/metrics/src/index.ts`) — uses Workers KV, ~20 lines:

```ts
// A minimal, privacy-preserving counter. Accepts POST { event } for a small
// allowlist of event names and increments a KV counter. Stores NOTHING that
// identifies a user or a page — no URL, no IP retention, no cookie.
const ALLOWED = new Set(["threat_blocked", "download", "install"]);

export default {
  async fetch(req: Request, env: { METRICS: KVNamespace }): Promise<Response> {
    const cors = {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "content-type",
    };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });

    if (req.method === "GET") {
      const out: Record<string, number> = {};
      for (const k of ALLOWED) out[k] = Number((await env.METRICS.get(`c:${k}`)) || 0);
      return Response.json(out, { headers: cors });
    }

    if (req.method === "POST") {
      let event = "";
      try {
        ({ event } = (await req.json()) as { event: string });
      } catch {}
      if (!ALLOWED.has(event)) return new Response("bad event", { status: 400, headers: cors });
      const key = `c:${event}`;
      const next = Number((await env.METRICS.get(key)) || 0) + 1;
      await env.METRICS.put(key, String(next));
      return Response.json({ ok: true }, { headers: cors });
    }
    return new Response("method not allowed", { status: 405, headers: cors });
  },
};
```

**`workers/metrics/wrangler.jsonc`:**

```jsonc
{
  "name": "kedayam-metrics",
  "main": "src/index.ts",
  "compatibility_date": "2025-09-24",
  "kv_namespaces": [{ "binding": "METRICS", "id": "<paste-id-from-create>" }]
}
```

**Deploy:**

```bash
cd workers/metrics
npx wrangler kv namespace create METRICS   # copy the id into wrangler.jsonc
npx wrangler deploy                        # prints https://kedayam-metrics.<you>.workers.dev
```

Cloudflare serves the Worker over HTTPS automatically (that's the "SSL
connection" — nothing else to configure). Map a custom route like
`https://api.kedayam.app/metric` under **Workers → your worker → Triggers** if you
want a branded URL.

**Extension side (only if you accept the privacy trade-off):** gate it behind an
explicit opt-in setting and send the bare event — never a URL:

```js
// background.js — ONLY inside `if (settings.privacy.shareAnonymousStats)`.
fetch("https://api.kedayam.app/metric", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ event: "threat_blocked" }), // no URL, no id, no PII
  credentials: "omit",
  keepalive: true,
}).catch(() => {});
```

Then, if you add that, update `PRIVACY.md`, `src/routes/privacy.tsx`, and the
store data-handling disclosure to say a **single anonymous counter** is sent when
the user opts in. Read the public total from the Worker's `GET` for a site badge.

---

## TL;DR

- **Threats prevented** → already local (this change). No server needed. Shown in the popup.
- **Installs/uninstalls** → Chrome Web Store dashboard, free. The extension can't count these.
- **Site downloads + SSL** → Cloudflare Web Analytics + _Full (strict)_ TLS. Zero backend code (§3a).
- **Global aggregate counter** → optional opt-in Worker + KV (§3b). Changes the privacy story — update the disclosures if you ship it.
