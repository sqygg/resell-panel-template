# Reseller Panel → SellAuth Store (Blog Page) Embed

Surfaces the FastAPI reseller-panel storefront **inside your free `/blog` page**
on SellAuth — no paid custom-page plan required. `custom.js` runs site-wide for
free, so the embed is gated to the `/blog` path only.

## What it does
- On `https://<yourstore>/blog`, replaces the "No Blog Posts Yet." placeholder
  with the reseller panel (iframe) + an "Open in new tab ↗" fallback button.

## Files
- `inject.js` — blog-scoped mount (path gate + iframe).
- `custom.css` — upgrade-safe styling.
- `README.md` — this file.

## Install (SellAuth dashboard)
1. **Set `PANEL_URL`** in `inject.js` to your panel's `PUBLIC_URL`
   (e.g. `https://panel.dtfmarket.com`). Deploy the panel so it is reachable.
2. **dash.sellauth.com → Themes → pro → Code Editor**
   - `assets/custom.css` → paste `custom.css`, Save.
   - `master.njk` → after the AlpineJS `<script>` line, add:
     ```html
     <script src="{{ 'inject.js' | assetUrl }}" defer></script>
     ```
   - Create `assets/inject.js` (New File) with the contents of `inject.js`, Save.
3. Visit `/blog` → the panel renders there.

## Caveats
- `master.njk` is **overwritten on SellAuth theme updates** → re-paste the one
  `<script>` line after any update. `custom.css` + `assets/inject.js` survive.
- **Cross-origin iframe cookie auth**: the panel uses a `store_session` cookie.
  Safari ITP and strict Chrome block third-party cookies in iframes, so the
  in-iframe login may fail. The "Open in new tab ↗" button always works.
  To make in-iframe login work in Chrome/Edge, harden the panel:
  - Set the session cookie to `SameSite=None; Secure` (FastAPI
    `response.set_cookie(..., samesite="none", secure=True)`).
  - Add CSP `frame-ancestors https://astr0.mysellauth.com` and
    `Cross-Origin-Resource-Policy: cross-origin` on the panel.
  (Safari will still block — the new-tab fallback covers that.)

## Notes
- The panel already creates real SellAuth checkout sessions, so resellers sell
  YOUR products end-to-end; this embed is purely a free storefront entry point.
- If you later want a real nav link too, see the earlier version's navbar-link
  mode (still in git history / ask for it).
