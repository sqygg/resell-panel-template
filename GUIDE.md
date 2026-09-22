# SkriptX Reseller Panel — Complete Setup Guide (Friend Edition)

This edition has **no email login and no email codes**. Resellers sign in with the
**API key the store owner gives them**, and link their SellAuth customer email
directly (one click, no verification code). That means **no Brevo, no SMTP, no
email configuration is needed anywhere**.

What you'll build: a web panel where your resellers see your product catalog at
their discount, buy keys from your SellAuth stock (or receive them automatically
when their own customers buy), and spend from a prepaid balance that mirrors
their SellAuth customer balance.

```
Reseller's customer buys on the reseller's own SellAuth store
  → reseller's store calls YOUR panel's delivery URL
  → panel dispenses a real key from YOUR SellAuth stock
  → reseller's SellAuth balance + panel balance are both deducted
  → the customer gets the key
```

---

## Part 0 — What you need

| Thing | Where | Notes |
|---|---|---|
| GitHub account | github.com | You'll be invited to the private repo |
| Railway account | railway.app | Free trial credit, then ~$5/mo Hobby plan is enough |
| A SellAuth shop | dash.sellauth.com | The shop whose stock the panel dispenses from |
| 15 minutes | — | Deploy itself takes ~5 min |

No email service, no domain purchase, no server needed.

---

## Part 1 — Get the code

1. The repo owner (whoever gave you this guide) invites you:
   GitHub repo → **Settings → Collaborators → Add people** → your GitHub username.
2. Accept the invite from your email.
3. Download the code — either:
   - **No git experience:** green **Code** button → **Download ZIP** → unzip, or
   - With git: `git clone https://github.com/sqygg/resell-panel.git` (branch: `friend-edition`)

> The `friend-edition` branch is the one with API-key login. `main` is the
> original email-OTP version — don't deploy that one.

---

## Part 2 — Get your SellAuth credentials

Two values from SellAuth:

1. **API key**: dash.sellauth.com → **Account** (bottom-left) → **API** → create/copy the key.
2. **Shop ID**: dash.sellauth.com → your store → the number in the URL
   (`dash.sellauth.com/dashboard/shop/253462/...` → shop ID is `253462`).

Keep both for Part 3. The panel needs this key to read products and dispense
keys from your stock — it never leaves your Railway variables.

---

## Part 3 — Deploy to Railway

1. Push the code to **your own GitHub repo** (or ask the owner to add you to
   his — then skip to step 2 directly from his repo):
   - GitHub → New repository (private) → upload/push the code (branch `friend-edition`).
2. railway.app → **New Project** → **Deploy from GitHub repo** → pick your repo.
   - If asked for a branch, choose **`friend-edition`**.
   - Railway auto-detects the `Dockerfile`. The healthcheck (`/health`) is already configured in `railway.json`.
3. When the first deploy fails (it will — variables are missing), open the
   service → **Variables** and add:

```
SELLAUTH_API_KEY=<your key from Part 2>
SELLAUTH_SHOP_ID=<your shop id from Part 2>
ADMIN_PASSWORD=<a long password YOU choose — this is the owner login>
SESSION_SECRET=<see note below>
PUBLIC_URL=https://<your-railway-domain>.up.railway.app
BRAND_NAME=Your Panel Name
BRAND_TAGLINE=Your tagline here
DEBUG=false
ENVIRONMENT=production
```

   - **SESSION_SECRET**: any long random string, e.g. run
     `python3 -c "import secrets; print(secrets.token_hex(32))"` once.
     **Never change it after the first deploy** — reseller API keys are
     encrypted with it. Losing it means every reseller needs a new key.
   - **PUBLIC_URL**: set it AFTER Railway assigns your domain (step 4), using
     the exact domain, no trailing slash.

4. Railway → your service → **Settings → Networking → Generate Domain** → note
   the URL (e.g. `https://resell-panel-production.up.railway.app`). Put that
   exact URL into `PUBLIC_URL`, then **Deploy** again (Deploy button).

5. Verify: open the URL → you should see the landing page. `/health` should
   return `{"status":"ok"}`.

Optional variables (all fine to skip):

```
DISCORD_WEBHOOK_URL=      # Discord channel ping when someone applies via /apply
DISCORD_LOG_WEBHOOK_URL=  # Discord channel audit trail of every admin action + errors
FRAME_ANCESTORS=          # only if you embed the panel in a SellAuth custom page
REFERRAL_COMMISSION_PERCENT=5
DEFAULT_APPLICATION_DISCOUNT=30
```

There are **no** SMTP/BREVO variables in this edition — do not add any.

---

## Part 4 — Owner setup (you)

1. Go to `https://your-domain/login`, sign in with `ADMIN_PASSWORD`.
2. **Resellers → create** your first reseller:
   - Name: anything (e.g. the friend's store name)
   - Discount %: their discount off your prices
   - **The API key is shown once in a popup — copy it immediately.** This key
     is both their login and their API credential. There is no email involved.
3. Give the reseller: their API key + your panel URL.
4. (Optional) balance without SellAuth link: the Edit modal has **Add Funds**
   to put panel-side credit on their account manually.

### The two ledgers (important)

- **Panel balance** — stored in the panel's own database.
- **SellAuth balance** — the reseller's customer balance in your SellAuth shop
  (they appear as a customer there when you add them / they buy).

Purchases deduct **both**. If the reseller links their SellAuth customer email
(next part), the panel auto-reconciles the panel balance UP to their SellAuth
balance before a purchase — so SellAuth stays the source of truth and the panel
never blocks a purchase the SellAuth side can afford.

To top a reseller up: add balance to their **customer in SellAuth** (or panel
Add Funds), then hit **Sync Balance** (or let the auto-reconcile do it at
purchase time).

---

## Part 5 — Reseller setup (your friend, ~2 minutes)

1. Open `https://your-domain/auth` → paste the **API key** → Sign in.
2. **API & Connections** (in the ☰ menu) → **SellAuth Connection**:
   - Enter the **customer email** they use in your SellAuth shop → **Link account**.
     Done — no code, no email. The panel now mirrors their SellAuth balance.
   - Click **Sync now** to pull the balance immediately (or it auto-reconciles
     at the next purchase).
3. **Catalog** (in the menu): every product/variant with their discounted price
   and a ready-made delivery URL. URLs are blurred — **Show key / Show URLs**
   to reveal.
4. **Buy Keys**: manual purchases, keys shown instantly.

---

## Part 6 — Wire the delivery URLs (the automation)

The reseller's own SellAuth store needs one URL per product variant so THEIR
customers get keys automatically:

1. Reseller logs into the panel → **Catalog** → **Bulk export (txt)** (or
   **Catalog JSON**).
2. In THEIR shop: dash.sellauth.com → each product → variant → **Delivery
   method: Dynamic / URL** → paste the matching line from the export
   (`https://your-domain/api/deliver/<their-key>/product/<id>?variant_id=<v>`).
3. When a customer buys on their store, SellAuth calls that URL → the panel
   dispenses a real key from YOUR stock → both balances deduct → the key lands
   on the customer's order. Zero manual work after setup.

**Webhook (dynamic/generator products, stock = infinite):** reseller sets the
delivery URL to `https://your-domain/api/deliver/dynamic/<their-api-key>` and
pastes their SellAuth webhook secret into **API & Connections → SellAuth
Webhook Secret** (recommended — HMAC-verified). SellAuth POSTs the purchase,
the panel answers with fresh keys.

**Generator / infinite-stock products** (stock shows −1): these are fulfilled
through SellAuth's Reseller API — the reseller must be an approved reseller of
your shop with balance, and store a **SellAuth Reseller Token** in API &
Connections (from `https://your-shop.mysellauth.com/customer/reseller`). The
panel mirrors the order through SellAuth and SellAuth itself mints the key.

---

## Part 7 — Run it locally instead (optional)

```bash
cd resell-panel
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export SELLAUTH_API_KEY=your_key
export SELLAUTH_SHOP_ID=your_shop_id
export ADMIN_PASSWORD=devpass
export SESSION_SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
uvicorn main:app --host 0.0.0.0 --port 8000
# open http://localhost:8000
```

SQLite database (`resellers.db`) is created automatically on first start.

### Optional: use MySQL instead of SQLite (data survives every redeploy)

By default Railway's SQLite file is wiped on each redeploy unless you add a
volume. The simplest fix that needs no Railway volume: a free external MySQL
(e.g. freesqldatabase.com, or any MariaDB/MySQL host). Set ALL four variables
in Railway → Variables and the panel switches to MySQL automatically on next
deploy — it creates its own tables on first start (idempotent, safe):

```
MYSQL_HOST=sql.freesqldatabase.com      # host from your DB provider
MYSQL_PORT=3306                          # default; provider may differ
MYSQL_USER=your_db_username
MYSQL_PASSWORD=your_db_password
MYSQL_DATABASE=your_database_name
```

- Tables (`resellers`, `orders`, `balance_transactions`, `audit_log`, …) are
  created automatically on first boot — no SQL to run by hand.
- Set these variables BEFORE creating real resellers, or existing SQLite data
  won't carry over (it's a fresh database — re-create resellers and re-issue
  their keys, or copy rows manually).
- `SESSION_SECRET` still governs API-key encryption: keep it unchanged forever.
- Verified working: the panel runs its full schema + CRUD on MariaDB 11.4.

Docker: `docker compose up --build` (uses the included `Dockerfile`).

---

## Part 8 — Day-to-day & maintenance

| Task | How |
|---|---|
| Onboard a reseller | Admin → Resellers → Create → hand over the key (shown once) |
| Reseller lost their key | Admin → Resellers → Reveal (owner can always see it), or Regen |
| Top up a reseller | Add balance to their SellAuth customer, then Sync (or panel Add Funds) |
| Approve an application | Admin → Applications → Approve (creates the reseller; Discord ping if webhook set) |
| Set a custom price | Admin → Manual Pricing → pick product/variant → set price or % |
| Check orders | Admin → Orders (all channels: webhook + manual) |
| Update the panel | push to GitHub → Railway auto-redeploys; DB survives (Railway volume or SQLite in repo dir — add a volume for safety) |
| Rotate a reseller key | Resellers → Regen → give them the new key (old dies instantly; their delivery URLs must be updated in their store) |

### Troubleshooting

| Symptom | Fix |
|---|---|
| Catalog empty / "No products configured" | Wrong `SELLAUTH_API_KEY` or `SELLAUTH_SHOP_ID` (401/403 in Railway logs). Fix the variables, redeploy. |
| "Product not found" on delivery | The product lives in a different shop than the one being queried. The webhook payload's shop ID is the source of truth — the panel already handles multi-shop. |
| Login says "Invalid API key" | Key wrong, reseller set Inactive, or key was regenerated. Check Admin → Resellers. |
| Delivery returns a JSON blob | Never happens in this edition — all delivery routes return plain-text keys. If you see JSON, you're hitting the wrong URL. |
| 422 error file from a webhook | You pasted the flat URL. Use `/api/deliver/dynamic/<key>` for SellAuth webhooks. |
| Railway deploy stuck "Deploying" | `DEBUG` must not be `true`. Start command is already correct in `railway.json`/`Dockerfile`. |
| Reseller paid but no key | Check Admin → Orders for the attempt; Railway logs show the exact SellAuth error (402 = reseller balance too low). |

---

## What's different from the original panel (for the record)

- **Login is API-key only.** The email/6-digit-code flow (`/auth/verify`,
  `/auth/resend`) and the code-verified SellAuth linking are removed.
- **SellAuth linking is one click** — the customer email is saved directly.
- **`services/mailer.py` is deleted** — the codebase has zero email code.
  Adding email features back would mean porting the mailer from `main`.
- Everything else — balance model, delivery, referrals, admin, Discord
  logging, audit trail — is identical to `main` at `version 2.24`.
