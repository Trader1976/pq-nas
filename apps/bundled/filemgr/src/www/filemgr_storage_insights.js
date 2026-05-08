window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
  "use strict";

  const FM = window.PQNAS_FILEMGR;

  const REFRESH_MS = 30 * 1000;
  const TRASH_RETENTION_DAYS = 30;

  let lastRefreshAt = 0;
  let refreshing = false;
  let lastStats = {
    count: 0,
    bytes: 0,
    nextPurgeAfterEpoch: 0,
    versionsCount: 0,
    versionsBytes: 0,
    versionsLoaded: false
  };

  function el(id) {
    return document.getElementById(id);
  }

  function isWorkspaceScope() {
    return !!(FM && typeof FM.isWorkspaceScope === "function" && FM.isWorkspaceScope());
  }

  function getWorkspaceId() {
    if (!FM || typeof FM.getWorkspaceId !== "function") return "";
    return String(FM.getWorkspaceId() || "");
  }

  function fmtSize(n) {
    if (FM && typeof FM.fmtSize === "function") return FM.fmtSize(n);
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = Number(n || 0);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) {
      v /= 1024;
      i++;
    }
    return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
  }

  function fmtDate(epoch) {
    const n = Number(epoch || 0);
    if (!Number.isFinite(n) || n <= 0) return "";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return "";
    }
  }

  function trashListUrl() {
    const qs = new URLSearchParams();
    qs.set("limit", "500");

    if (isWorkspaceScope()) {
      qs.set("scope", "workspace");
      qs.set("workspace_id", getWorkspaceId());
    } else {
      qs.set("scope", "user");
    }

    return `/api/v4/trash/list?${qs.toString()}`;
  }

  function versionsSummaryUrl() {
    if (isWorkspaceScope()) {
      const qs = new URLSearchParams();
      qs.set("workspace_id", getWorkspaceId());
      return `/api/v4/workspaces/files/versions/summary?${qs.toString()}`;
    }
    return `/api/v4/files/versions/summary`;
  }

  async function fetchVersionStats() {
    const r = await fetch(versionsSummaryUrl(), {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }

    return {
      versionsCount: Number(j.versions_count || 0),
      versionsBytes: Number(j.versions_bytes || 0),
      versionsLoaded: true
    };
  }

  async function fetchTrashStats() {
    const r = await fetch(trashListUrl(), {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok || !Array.isArray(j.items)) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }

    let bytes = 0;
    let nextPurge = 0;

    for (const item of j.items) {
      if (!item || typeof item !== "object") continue;

      const b = Number(item.size_bytes || 0);
      if (Number.isFinite(b) && b > 0) bytes += b;

      const p = Number(item.purge_after_epoch || 0);
      if (Number.isFinite(p) && p > 0 && (nextPurge === 0 || p < nextPurge)) {
        nextPurge = p;
      }
    }

    return {
      count: j.items.length,
      bytes,
      nextPurgeAfterEpoch: nextPurge
    };
  }

  function ensureTrashBadge() {
    const btn = el("trashBtn");
    if (!btn) return null;

    let badge = btn.querySelector(".pqsiTrashBadge");
    if (!badge) {
      badge = document.createElement("span");
      badge.className = "pqsiTrashBadge";
      badge.setAttribute("aria-label", "Trash item count");
      badge.hidden = true;
      btn.appendChild(badge);
    }

    return badge;
  }

  function updateTrashButton(stats) {
    const badge = ensureTrashBadge();
    if (!badge) return;

    const count = Number(stats && stats.count || 0);
    if (count > 0) {
      badge.hidden = false;
      badge.textContent = String(count);
      badge.title = `${count} item(s) in trash`;
    } else {
      badge.hidden = true;
      badge.textContent = "";
      badge.title = "";
    }
  }

  function ensureTrashStrip() {
    const list = el("trashList");
    const status = el("trashStatus");
    if (!list || !list.parentNode) return null;

    let strip = el("pqsiTrashStrip");
    if (!strip) {
      strip = document.createElement("div");
      strip.id = "pqsiTrashStrip";
      strip.className = "pqsiTrashStrip";
      strip.innerHTML = `
        <div class="pqsiTrashMetrics">
          <span class="pqsiMetric" id="pqsiTrashItems">Trash: —</span>
          <span class="pqsiMetric" id="pqsiTrashBytes">Space: —</span>
          <span class="pqsiMetric" id="pqsiTrashNextPurge">Next auto-delete: —</span>
          <span class="pqsiMetric" id="pqsiVersionsBytes">Versions: separate</span>
        </div>
        <div class="pqsiNote">
          <strong>Note:</strong> Items in trash are automatically deleted after ${TRASH_RETENTION_DAYS} days.
          File versions are stored separately and are not removed by trash cleanup.
        </div>
      `;

      if (status && status.parentNode === list.parentNode) {
        status.insertAdjacentElement("afterend", strip);
      } else {
        list.parentNode.insertBefore(strip, list);
      }
    }

    return strip;
  }

  function updateTrashStrip(stats) {
    ensureTrashStrip();

    const countEl = el("pqsiTrashItems");
    const bytesEl = el("pqsiTrashBytes");
    const nextEl = el("pqsiTrashNextPurge");
    const versionsEl = el("pqsiVersionsBytes");

    const count = Number(stats && stats.count || 0);
    const bytes = Number(stats && stats.bytes || 0);
    const next = Number(stats && stats.nextPurgeAfterEpoch || 0);

    if (countEl) countEl.textContent = `Trash: ${count} item(s)`;
    if (bytesEl) bytesEl.textContent = `Trash uses: ${fmtSize(bytes)}`;

    if (nextEl) {
      const d = fmtDate(next);
      nextEl.textContent = d ? `Next auto-delete: ${d}` : "Next auto-delete: —";
    }

    if (versionsEl) {
      if (stats && stats.versionsLoaded) {
        versionsEl.textContent = `Versions use: ${fmtSize(stats.versionsBytes || 0)}`;
        versionsEl.title = `${stats.versionsCount || 0} preserved file version(s)`;
      } else {
        versionsEl.textContent = "Versions: —";
        versionsEl.title = "Version storage summary unavailable.";
      }
    }
  }

  function applyStats(stats) {
    lastStats = stats || lastStats;
    updateTrashButton(lastStats);
    updateTrashStrip(lastStats);
  }

  async function refresh(force = false) {
    const now = Date.now();
    if (!force && (now - lastRefreshAt) < REFRESH_MS) {
      applyStats(lastStats);
      return lastStats;
    }

    if (refreshing) return lastStats;
    refreshing = true;

    try {
      const trashStats = await fetchTrashStats();

      let versionStats = {
        versionsCount: lastStats.versionsCount || 0,
        versionsBytes: lastStats.versionsBytes || 0,
        versionsLoaded: false
      };

      try {
        versionStats = await fetchVersionStats();
      } catch (e) {
        console.warn("[filemgr storage insights] version stats failed:", e);
      }

      const stats = { ...trashStats, ...versionStats };
      lastRefreshAt = Date.now();
      applyStats(stats);
      return stats;
    } catch (e) {
      console.warn("[filemgr storage insights] trash stats failed:", e);
      applyStats(lastStats);
      return lastStats;
    } finally {
      refreshing = false;
    }
  }

  function wireEvents() {
    el("trashBtn")?.addEventListener("click", () => {
      setTimeout(() => refresh(true), 150);
    });

    el("trashRefreshBtn")?.addEventListener("click", () => {
      setTimeout(() => refresh(true), 300);
    });

    el("trashEmptyBtn")?.addEventListener("click", () => {
      setTimeout(() => refresh(true), 800);
      setTimeout(() => refresh(true), 2500);
    });

    const modal = el("trashModal");
    if (modal) {
      const mo = new MutationObserver(() => {
        if (modal.classList.contains("show")) {
          refresh(true);
        }
      });
      mo.observe(modal, { attributes: true, attributeFilter: ["class"] });
    }

    const scopeSelect = el("scopeSelect");
    if (scopeSelect) {
      scopeSelect.addEventListener("change", () => {
        lastRefreshAt = 0;
        lastStats = {
          count: 0,
          bytes: 0,
          nextPurgeAfterEpoch: 0,
          versionsCount: 0,
          versionsBytes: 0,
          versionsLoaded: false
        };
        setTimeout(() => refresh(true), 350);
      });
    }

    window.addEventListener("focus", () => refresh(false));
  }

  FM.storageInsights = {
    refresh,
    getTrashStats: () => ({ ...lastStats })
  };

  document.addEventListener("DOMContentLoaded", () => {
    ensureTrashBadge();
    ensureTrashStrip();
    wireEvents();
    refresh(true);
  });
})();
