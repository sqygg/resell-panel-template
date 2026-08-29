/* ============================================================
   reseller-panel → SellAuth BLOG embed (pro theme)
   Mounts the panel (hosted on Railway) into the FREE /blog page
   via iframe, placed BELOW the site nav (full width, centered).
   custom.js runs site-wide for free, so we gate on
   pathname === "/blog". No paid custom-page plan needed.
   ------------------------------------------------------------
   CONFIG — set this:
     PANEL_URL : your Railway panel PUBLIC_URL (no trailing /)
   CAVEATS:
     - Cross-origin iframe cookie auth is blocked by Safari /
       strict Chrome → in-iframe login may fail. The
       "Open in new tab ↗" button always works.
   ============================================================ */
(function () {
  const PANEL_URL = "https://resell-panel-production.up.railway.app"; // <-- SET TO YOUR RAILWAY URL
  const LABEL = "Reseller Panel";

  function onBlog() {
    const p = window.location.pathname;
    return p === "/blog" || p.startsWith("/blog/");
  }

  function mount() {
    if (!onBlog()) return true;
    if (document.getElementById("reseller-portal-holder")) return true;

    // Hide the "No Blog Posts Yet." placeholder
    const noPosts = Array.from(document.querySelectorAll("p"))
      .find(p => /no blog posts yet/i.test(p.textContent || ""));
    if (noPosts) noPosts.style.display = "none";

    const holder = document.createElement("div");
    holder.id = "reseller-portal-holder";
    holder.className = "reseller-portal-holder";
    holder.innerHTML =
      '<div class="reseller-portal-bar">' +
        '<span class="reseller-portal-title">' + LABEL + '</span>' +
        '<a class="reseller-portal-open" href="' + PANEL_URL + '/" ' +
        'target="_blank" rel="noopener noreferrer">Open in new tab ↗</a>' +
        '</div>' +
        '<iframe class="reseller-portal-frame" src="' + PANEL_URL + '/" ' +
      'title="' + LABEL + '"></iframe>';

    // Mount directly BELOW the site nav so it spans full width (not a sidebar column)
    const header = document.querySelector("header") ||
                   document.querySelector("nav") ||
                   document.querySelector(".navbar");
    if (header) header.insertAdjacentElement("afterend", holder);
    else document.body.appendChild(holder);
    return true;
  }

  let tries = 0;
  (function loop() { if (mount() || tries++ > 80) return; setTimeout(loop, 100); })();
})();
