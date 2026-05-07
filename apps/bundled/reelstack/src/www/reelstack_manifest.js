(() => {
  "use strict";

  async function loadManifestVersion() {
    const el = document.getElementById("rsManifestVersion");
    if (!el) return;

    try {
      const r = await fetch("../manifest.json", {
        credentials: "include",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });

      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.version) return;

      const version = String(j.version || "").trim();
      if (!version) return;

      el.textContent = `v${version}`;
      el.title = `${j.name || "Reel Stack"} ${version}`;
    } catch (_) {
      // Non-fatal: app still works without version badge.
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", loadManifestVersion, { once: true });
  } else {
    loadManifestVersion();
  }
})();
