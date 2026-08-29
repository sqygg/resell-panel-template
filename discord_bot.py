"""
Discord bot for Reseller Panel admin.
Slash commands to manage resellers, view stock, and dashboard stats.
Runs alongside the FastAPI server in the same process.
"""
import discord
from discord import app_commands
from discord.ext import commands
import database as db
from services.sellauth import client as sellauth
from config import settings

# ---------- Bot setup ----------

intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents)

# Who can use admin commands (set your Discord user ID in .env)
OWNER_ID = int(settings.DISCORD_OWNER_ID or "0")


def is_owner(interaction: discord.Interaction) -> bool:
    """Only the owner can use admin commands."""
    if OWNER_ID and interaction.user.id != OWNER_ID:
        return False
    return True


async def owner_only(interaction: discord.Interaction):
    """Check guard — sends ephemeral error if not owner."""
    if not is_owner(interaction):
        await interaction.response.send_message("⛔ Owner only.", ephemeral=True)
        return False
    return True


# ---------- Bot events ----------

@bot.event
async def on_ready():
    print(f"🤖 Reseller Bot online as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"  Synced {len(synced)} slash commands")
    except Exception as e:
        print(f"  Sync failed: {e}")


# ============================================================
# SLASH COMMANDS
# ============================================================

# --- Dashboard ---

@bot.tree.command(name="dashboard", description="Show reseller panel overview")
async def cmd_dashboard(interaction: discord.Interaction):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    products = sellauth.get_products_for_webhook()
    resellers = db.list_resellers()
    active = sum(1 for r in resellers if r["active"])
    total_stock = sum(p.get("stock", 0) for p in products)

    embed = discord.Embed(
        title="📊 Reseller Panel Dashboard",
        color=0x6366f1,
    )
    embed.add_field(name="Active Resellers", value=str(active), inline=True)
    embed.add_field(name="Total Products", value=str(len(products)), inline=True)
    embed.add_field(name="Total Stock", value=str(total_stock), inline=True)

    if resellers:
        lines = []
        for r in resellers[:10]:
            status = "🟢" if r["active"] else "🔴"
            lines.append(f"{status} **{r['name']}** — {r['discount_percent']}% off — `{r.get('api_key_prefix','???')}...`")
        embed.add_field(name=f"Resellers ({len(resellers)})", value="\n".join(lines), inline=False)

    await interaction.followup.send(embed=embed, ephemeral=True)


# --- Stock ---

@bot.tree.command(name="stock", description="View stock from SellAuth")
async def cmd_stock(interaction: discord.Interaction):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    products = sellauth.get_products_for_webhook()
    if not products:
        await interaction.followup.send("No products loaded. Check SellAuth credentials.", ephemeral=True)
        return

    embed = discord.Embed(title="📦 Stock", color=0x22c55e)
    for p in products[:15]:
        stock_str = f"**{p['stock']}**" if p['stock'] > 0 else "❌ **OUT**"
        embed.add_field(
            name=p['name'],
            value=f"${p['price']:.2f} | {stock_str} | `{p['type']}`",
            inline=True,
        )
    if len(products) > 15:
        embed.set_footer(text=f"+ {len(products) - 15} more products")
    await interaction.followup.send(embed=embed, ephemeral=True)


# --- Resellers ---

reseller_group = app_commands.Group(name="reseller", description="Manage resellers")


@reseller_group.command(name="list", description="List all resellers")
async def cmd_reseller_list(interaction: discord.Interaction):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    resellers = db.list_resellers()
    if not resellers:
        await interaction.followup.send("No resellers yet.", ephemeral=True)
        return

    embed = discord.Embed(title="🏪 Resellers", color=0x6366f1)
    for r in resellers:
        status = "🟢 Active" if r["active"] else "🔴 Inactive"
        embed.add_field(
            name=f"#{r['id']} {r['name']}",
            value=(
                f"**Discount:** {r['discount_percent']}%\n"
                f"**Prefix:** `{r.get('api_key_prefix','???')}...`\n"
                f"**Requests:** {r.get('request_count',0)}\n"
                f"**Status:** {status}"
            ),
            inline=True,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


@reseller_group.command(name="add", description="Add a new reseller")
@app_commands.describe(
    name="Reseller name",
    discount="Discount percentage (0-100)",
    webhook="Optional webhook URL",
)
async def cmd_reseller_add(
    interaction: discord.Interaction,
    name: str,
    discount: float = 0.0,
    webhook: str = "",
):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    try:
        result = db.create_reseller(name.strip(), discount, webhook.strip())
    except ValueError as e:
        await interaction.followup.send(f"❌ {e}", ephemeral=True)
        return

    embed = discord.Embed(
        title="✅ Reseller Created",
        description=f"**{result['name']}** — {result['discount_percent']}% off",
        color=0x22c55e,
    )
    embed.add_field(name="ID", value=str(result['id']), inline=True)
    embed.add_field(name="Prefix", value=f"`{result['api_key_prefix']}...`", inline=True)
    embed.add_field(
        name="⚠️ API Key (shown once)",
        value=f"```{result['api_key']}```\nCopy now — it will never be shown again.",
        inline=False,
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


@reseller_group.command(name="edit", description="Edit a reseller")
@app_commands.describe(
    id="Reseller ID",
    name="New name (leave empty to keep)",
    discount="New discount % (leave 0 to keep)",
    webhook="New webhook URL (leave empty to keep)",
    active="Active or inactive",
)
@app_commands.choices(active=[
    app_commands.Choice(name="Active", value="active"),
    app_commands.Choice(name="Inactive", value="inactive"),
])
async def cmd_reseller_edit(
    interaction: discord.Interaction,
    id: int,
    name: str = "",
    discount: float = -1.0,
    webhook: str = "",
    active: app_commands.Choice[str] | None = None,
):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    updates = {}
    if name:
        updates["name"] = name.strip()
    if discount >= 0:
        updates["discount_percent"] = discount
    if webhook:
        updates["webhook_url"] = webhook.strip()
    if active:
        updates["active"] = active.value == "active"

    if not updates:
        await interaction.followup.send("No changes provided.", ephemeral=True)
        return

    try:
        result = db.update_reseller(id, **updates)
    except ValueError as e:
        await interaction.followup.send(f"❌ {e}", ephemeral=True)
        return

    if not result:
        await interaction.followup.send(f"❌ Reseller #{id} not found.", ephemeral=True)
        return

    await interaction.followup.send(f"✅ Reseller #{id} updated.", ephemeral=True)


@reseller_group.command(name="delete", description="Delete a reseller")
@app_commands.describe(id="Reseller ID to delete")
async def cmd_reseller_delete(interaction: discord.Interaction, id: int):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    ok = db.delete_reseller(id)
    if ok:
        await interaction.followup.send(f"🗑️ Reseller #{id} deleted.", ephemeral=True)
    else:
        await interaction.followup.send(f"❌ Reseller #{id} not found.", ephemeral=True)


@reseller_group.command(name="key", description="Regenerate a reseller's API key (old key stops immediately)")
@app_commands.describe(id="Reseller ID")
async def cmd_reseller_key(interaction: discord.Interaction, id: int):
    if not await owner_only(interaction):
        return
    await interaction.response.defer(ephemeral=True)

    result = db.regenerate_api_key(id)
    if not result:
        await interaction.followup.send(f"❌ Reseller #{id} not found.", ephemeral=True)
        return

    embed = discord.Embed(
        title="🔄 Key Regenerated",
        description=f"**{result['name']}** — old key is now invalid.",
        color=0xf59e0b,
    )
    embed.add_field(
        name="⚠️ New API Key (shown once)",
        value=f"```{result['api_key']}```\nCopy now — never shown again.",
        inline=False,
    )
    await interaction.followup.send(embed=embed, ephemeral=True)


# --- Health ---

@bot.tree.command(name="health", description="Check if the panel is running")
async def cmd_health(interaction: discord.Interaction):
    if not await owner_only(interaction):
        return
    resellers = len(db.list_resellers())
    products = len(sellauth.get_products_for_webhook())
    await interaction.response.send_message(
        f"✅ Panel online\n📦 {products} products\n🏪 {resellers} resellers",
        ephemeral=True,
    )


# Register the reseller group
bot.tree.add_command(reseller_group)


# ---------- Runner ----------

async def start_bot():
    """Start the Discord bot. Called from main.py startup.

    Runs in the background; never lets a Discord failure crash the web server.
    """
    token = settings.DISCORD_BOT_TOKEN
    if not token:
        print("[Discord] DISCORD_BOT_TOKEN not set — bot disabled")
        return
    if not OWNER_ID:
        print("[Discord] DISCORD_OWNER_ID not set — bot disabled")
        return
    try:
        await bot.start(token)
    except Exception as e:
        # A bad/expired token or network error must not take down the API.
        print(f"[Discord] bot failed to start (disabled): {type(e).__name__}: {e}")


async def stop_bot():
    """Stop the Discord bot. Called from main.py shutdown."""
    await bot.close()
