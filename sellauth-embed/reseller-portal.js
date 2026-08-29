(function () {
  const PANEL_URL = "https://resell-panel-production.up.railway.app";
  const LABEL = "Reseller Panel";
  function onBlog() {
    const p = window.location.pathname;
    return p === "/blog" || p.startsWith("/blog/");
  }
  function mount() {
    if (!onBlog()) return true;
    if (document.getElementById("reseller-panel-frame")) return true;
    const heading = Array.from(document.querySelectorAll("h1, h2, h3"))
      .find(h => /blog/i.test(h.textContent || ""));
    const mountPoint = (heading && heading.parentElement) ||
      document.querySelector("main .container") ||
      document.querySelector(".container") || document.body;
    const noPosts = Array.from(document.querySelectorAll("p"))
      .find(p => /no blog posts yet/i.test(p.textContent || ""));
    if (noPosts) noPosts.style.display = "none";
    const holder = document.createElement("div");
    holder.className = "reseller-portal-holder";
    holder.innerHTML =
      '<div class="reseller-portal-bar"><span class="reseller-portal-title">' + LABEL + '</span>' +
      '<a class="reseller-portal-open" href="' + PANEL_URL + '/" ' +
      'target="_blank" rel="noopener noreferrer">Open in new tab ↗</a></div>' +
      '<iframe class="reseller-portal-frame" src="' + PANEL_URL + '/" ' +
      'title="' + LABEL + '"></iframe>';
    mountPoint.appendChild(holder);
    return true;
  }
  let tries = 0;
  (function loop() { if (mount() || tries++ > 80) return; setTimeout(loop, 100); })();
})();
