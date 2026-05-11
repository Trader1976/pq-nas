(() => {
  "use strict";

  const STYLE_ID = "pqnasFileLocksStyle";
  const PANEL_ID = "fmFileLockPanel";

  function $(id) {
    return document.getElementById(id);
  }

  function esc(s) {
    return String(s || "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c]));
  }

  function installStyle() {
    if ($(STYLE_ID)) return;

    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      #${PANEL_ID}{
        grid-column:1 / -1;
        width:100%;
        box-sizing:border-box;
        margin-top:14px;
        padding:14px;
        border:1px solid rgba(var(--fg-rgb),0.14);
        border-radius:14px;
        background:rgba(255,255,255,0.035);
        display:grid;
        gap:10px;
      }
      #${PANEL_ID} .fmLockHead{
        display:flex;
        align-items:center;
        justify-content:space-between;
        gap:10px;
        min-width:0;
      }
      #${PANEL_ID} .fmLockTitle{
        font-weight:900;
        font-size:13px;
      }
      #${PANEL_ID} .fmLockStatus{
        font-size:11px;
        opacity:.76;
        text-align:right;
        overflow-wrap:anywhere;
      }
      #${PANEL_ID} .fmLockInfo{
        display:grid;
        gap:4px;
        font-size:12px;
        line-height:1.45;
      }
      #${PANEL_ID} .fmLockControls{
        display:flex;
        align-items:center;
        gap:8px;
        flex-wrap:wrap;
      }
      #${PANEL_ID} textarea{
        display:block;
        width:100%;
        min-height:54px;
        resize:vertical;
        box-sizing:border-box;
        border-radius:10px;
        padding:9px 10px;
        font:inherit;
        font-size:13px;
        line-height:1.35;
        background:rgba(0,0,0,0.10);
        color:inherit;
        border:1px solid rgba(var(--fg-rgb),0.18);
      }
      #${PANEL_ID} select{
        min-width:120px;
      }
      html[data-theme="win_classic"] #${PANEL_ID}{
        background:#fff;
        border-color:#b8b8b8;
      }
      html[data-theme="win_classic"] #${PANEL_ID} textarea{
        background:#fff;
        border-color:#9a9a9a;
      }
    `;
    document.head.appendChild(style);
  }

  function currentScope() {
    const FM = window.PQNAS_FILEMGR || {};
    const scope = FM.scope || {};

    if (scope.mode === "workspace" && scope.workspaceId) {
      const role = String(scope.workspaceRole || "").toLowerCase();
      return {
        scope_type: "workspace",
        scope_id: String(scope.workspaceId || ""),
        can_write: role === "owner" || role === "editor",
        can_override: role === "owner"
      };
    }

    return {
      scope_type: "user",
      scope_id: "",
      can_write: true,
      can_override: true
    };
  }

  function propsPathToRel() {
    const txt = String($("propsPath")?.textContent || "").trim();
    if (!txt || txt === "/" || txt === ".") return ".";
    return txt.replace(/^\/+/, "") || ".";
  }

  function propsItemKind() {
    const title = String($("propsTitle")?.textContent || "").toLowerCase();
    if (title.includes("folder")) return "dir";
    if (title.includes("file")) return "file";
    return "unknown";
  }

  function shouldAttach() {
    const modal = $("propsModal");
    const body = $("propsBody");
    const title = String($("propsTitle")?.textContent || "");
    if (!modal || !body || !modal.classList.contains("show")) return false;
    if (!/^(File|Folder|Item) properties/i.test(title)) return false;
    return true;
  }

  function expiryLabel(epoch) {
    const n = Number(epoch || 0);
    if (!n) return "Manual";
    try {
      return new Date(n * 1000).toLocaleString();
    } catch (_) {
      return String(n);
    }
  }

  async function apiStatus(scope, path) {
    const qs = new URLSearchParams();
    qs.set("scope_type", scope.scope_type);
    if (scope.scope_id) qs.set("scope_id", scope.scope_id);
    qs.set("path", path);

    const r = await fetch(`/api/v4/file-locks/status?${qs.toString()}`, {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
    return j;
  }

  async function apiLock(scope, path, itemKind, note, expiresInSeconds) {
    const r = await fetch("/api/v4/file-locks/lock", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        scope_type: scope.scope_type,
        scope_id: scope.scope_id,
        path,
        item_kind: itemKind,
        note,
        expires_in_seconds: Number(expiresInSeconds || 0)
      })
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = (j && (j.message || j.error)) || `HTTP ${r.status}`;
      const e = new Error(msg);
      e.payload = j;
      throw e;
    }
    return j;
  }

  async function apiUnlock(scope, path) {
    const r = await fetch("/api/v4/file-locks/unlock", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify({
        scope_type: scope.scope_type,
        scope_id: scope.scope_id,
        path
      })
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
    return j;
  }

  let activeSignature = "";

  function attachPanelSoon() {
    window.setTimeout(attachPanel, 0);
  }

  function attachPanel() {
    if (!shouldAttach()) return;

    installStyle();

    const body = $("propsBody");
    if (!body) return;

    const scope = currentScope();
    const path = propsPathToRel();
    const itemKind = propsItemKind();
    const signature = `${scope.scope_type}:${scope.scope_id}:${path}:${itemKind}`;

    const existing = $(PANEL_ID);
    if (existing && existing.dataset.signature === signature) return;
    if (existing) existing.remove();

    const panel = document.createElement("section");
    panel.id = PANEL_ID;
    panel.dataset.signature = signature;
    panel.innerHTML = `
      <div class="fmLockHead">
        <div class="fmLockTitle">Lock</div>
        <div class="fmLockStatus mono">Loading…</div>
      </div>
      <div class="fmLockInfo"></div>
      <textarea class="fmLockNote" maxlength="2000" placeholder="Optional lock note, e.g. editing metadata now…"></textarea>
      <div class="fmLockControls">
        <select class="fmLockExpiry">
          <option value="86400">24 hours</option>
          <option value="604800">7 days</option>
          <option value="0">Manual</option>
        </select>
        <button class="btn secondary fmLockBtn" type="button">Lock item</button>
        <button class="btn secondary fmUnlockBtn" type="button" style="display:none;">Unlock</button>
        <button class="btn secondary fmLockReloadBtn" type="button">Reload</button>
      </div>
    `;

    body.appendChild(panel);

    const status = panel.querySelector(".fmLockStatus");
    const info = panel.querySelector(".fmLockInfo");
    const noteEl = panel.querySelector(".fmLockNote");
    const expiryEl = panel.querySelector(".fmLockExpiry");
    const lockBtn = panel.querySelector(".fmLockBtn");
    const unlockBtn = panel.querySelector(".fmUnlockBtn");
    const reloadBtn = panel.querySelector(".fmLockReloadBtn");

    function changed() {
      window.dispatchEvent(new CustomEvent("pqnas:fileLocksChanged", {
        detail: { scope, path, itemKind }
      }));
    }

    function renderStatus(j) {
      const lock = j && j.lock;
      const locked = !!(j && j.locked && lock);

      if (!locked) {
        status.textContent = "Not locked";
        info.innerHTML = `<div class="mini">No active lock for this ${esc(itemKind === "dir" ? "folder" : "file")}.</div>`;
        lockBtn.style.display = scope.can_write ? "" : "none";
        expiryEl.style.display = scope.can_write ? "" : "none";
        noteEl.style.display = scope.can_write ? "" : "none";
        unlockBtn.style.display = "none";
        noteEl.value = "";
        return;
      }

      const by = lock.locked_by_label || lock.locked_by_fp_short || "Someone";
      const own = !!lock.own_lock;
      const canUnlock = !!lock.can_unlock;

      status.textContent = own ? "Locked by you" : `Locked by ${by}`;
      info.innerHTML = `
        <div><b>Locked by:</b> ${esc(by)} ${own ? "(you)" : ""}</div>
        <div><b>Expires:</b> ${esc(expiryLabel(lock.expires_at_epoch))}</div>
        ${lock.note ? `<div><b>Note:</b> ${esc(lock.note)}</div>` : ""}
      `;

      lockBtn.style.display = "none";
      expiryEl.style.display = "none";
      noteEl.style.display = "none";
      unlockBtn.style.display = canUnlock ? "" : "none";
      unlockBtn.textContent = own ? "Unlock" : "Force unlock";
    }

    async function load() {
      activeSignature = signature;
      status.textContent = "Loading…";
      info.innerHTML = "";
      try {
        const j = await apiStatus(scope, path);
        if (activeSignature !== signature || !document.body.contains(panel)) return;
        renderStatus(j);
      } catch (e) {
        status.textContent = `Load failed: ${String(e && e.message ? e.message : e)}`;
      }
    }

    lockBtn.addEventListener("click", async () => {
      const old = lockBtn.textContent;
      lockBtn.disabled = true;
      lockBtn.textContent = "Locking…";
      status.textContent = "Locking…";

      try {
        const j = await apiLock(scope, path, itemKind, noteEl.value, expiryEl.value);
        renderStatus(j);
        changed();
      } catch (e) {
        const lock = e && e.payload && e.payload.lock;
        if (lock) {
          renderStatus({ locked: true, lock });
        }
        status.textContent = `Lock failed: ${String(e && e.message ? e.message : e)}`;
      } finally {
        lockBtn.disabled = false;
        lockBtn.textContent = old;
      }
    });

    unlockBtn.addEventListener("click", async () => {
      const label = unlockBtn.textContent || "Unlock";
      if (label.toLowerCase().includes("force") &&
          !confirm("Force unlock this item?\n\nThis removes another user's lock.")) {
        return;
      }

      const old = unlockBtn.textContent;
      unlockBtn.disabled = true;
      unlockBtn.textContent = "Unlocking…";
      status.textContent = "Unlocking…";

      try {
        const j = await apiUnlock(scope, path);
        renderStatus(j);
        changed();
      } catch (e) {
        status.textContent = `Unlock failed: ${String(e && e.message ? e.message : e)}`;
      } finally {
        unlockBtn.disabled = false;
        unlockBtn.textContent = old;
      }
    });

    reloadBtn.addEventListener("click", load);
    load();
  }

  const mo = new MutationObserver(attachPanelSoon);

  window.addEventListener("DOMContentLoaded", () => {
    const modal = $("propsModal");
    const body = $("propsBody");
    const title = $("propsTitle");
    const path = $("propsPath");

    if (modal) mo.observe(modal, { attributes: true, attributeFilter: ["class", "aria-hidden"] });
    if (body) mo.observe(body, { childList: true });
    if (title) mo.observe(title, { childList: true, characterData: true, subtree: true });
    if (path) mo.observe(path, { childList: true, characterData: true, subtree: true });

    attachPanelSoon();
  });
})();


// ---- lock tile/list badges v1 ----
(() => {
  "use strict";

  const STYLE_ID = "pqnasFileLockBadgeStyle";
  let refreshTimer = 0;
  let refreshSeq = 0;
  let observerMuted = false;

  function installLockBadgeStyle() {
    if (document.getElementById(STYLE_ID)) return;

    const style = document.createElement("style");
    style.id = STYLE_ID;
    style.textContent = `
      .tile.fmLockLocked{
        outline:2px solid rgba(255,190,80,.72);
        box-shadow:
          inset 0 0 0 1px rgba(255,190,80,.35),
          0 0 0 1px rgba(255,190,80,.18),
          0 0 18px rgba(255,190,80,.16);
      }

      .tile.fmLockLocked::before{
        content:"";
        position:absolute;
        inset:0;
        pointer-events:none;
        border-radius:inherit;
        background:
          linear-gradient(135deg, rgba(255,190,80,.22), transparent 46%),
          linear-gradient(0deg, rgba(255,190,80,.08), rgba(255,190,80,.08));
        z-index:1;
      }

      .tile.fmLockLocked > *{
        position:relative;
        z-index:2;
      }

      .fmLockTileBadge{
        position:absolute;
        left:50%;
        top:7px;
        transform:translateX(-50%);
        min-width:22px;
        height:22px;
        padding:0 7px;
        box-sizing:border-box;
        border-radius:999px;
        display:flex;
        align-items:center;
        justify-content:center;
        font-size:13px;
        line-height:1;
        background:rgba(255,190,80,.94);
        color:#111;
        border:1px solid rgba(0,0,0,.35);
        box-shadow:0 2px 8px rgba(0,0,0,.28);
        z-index:30;
        pointer-events:none;
      }

      .tile.fmLockLocked.list .fmLockTileBadge,
      .list .tile.fmLockLocked .fmLockTileBadge{
        left:auto;
        right:44px;
        top:50%;
        transform:translateY(-50%);
      }

      html[data-theme="cpunk_orange"] .tile.fmLockLocked,
      html[data-theme="dark"] .tile.fmLockLocked{
        outline-color:rgba(255,138,31,.9);
        box-shadow:
          inset 0 0 0 1px rgba(255,138,31,.55),
          0 0 0 1px rgba(255,138,31,.28),
          0 0 20px rgba(255,138,31,.24);
      }

      html[data-theme="cpunk_orange"] .fmLockTileBadge,
      html[data-theme="dark"] .fmLockTileBadge{
        background:rgba(255,138,31,.96);
        color:#160800;
      }

      html[data-theme="win_classic"] .tile.fmLockLocked{
        outline:2px solid #a86b00;
        box-shadow:inset 0 0 0 1px #ffd17a;
      }

      html[data-theme="win_classic"] .tile.fmLockLocked::before{
        background:rgba(255,220,120,.22);
      }

      html[data-theme="win_classic"] .fmLockTileBadge{
        background:#ffe08a;
        color:#111;
        border-color:#8a6500;
        box-shadow:none;
      }
    `;
    document.head.appendChild(style);
  }

  function currentScopeForLockBadges() {
    const FM = window.PQNAS_FILEMGR || {};
    const scope = FM.scope || {};

    if (scope.mode === "workspace" && scope.workspaceId) {
      return {
        scope_type: "workspace",
        scope_id: String(scope.workspaceId || "")
      };
    }

    return {
      scope_type: "user",
      scope_id: ""
    };
  }

  function tileRelPath(tile) {
    if (!tile) return "";

    const direct =
      tile.dataset.relPath ||
      tile.dataset.rel ||
      tile.dataset.path ||
      "";

    if (direct) return String(direct).replace(/^\/+/, "") || ".";

    const key = String(tile.dataset.key || "");
    const idx = key.indexOf(":");
    if (idx >= 0 && idx + 1 < key.length) {
      return key.slice(idx + 1).replace(/^\/+/, "") || ".";
    }

    const name = tile.querySelector(".name")?.textContent || "";
    return String(name).trim().replace(/^\/+/, "") || "";
  }

  function lockOwnerLabel(lock) {
    if (!lock || typeof lock !== "object") return "";
    return String(
      lock.locked_by_label ||
      lock.locked_by_display_name ||
      lock.locked_by_name ||
      lock.owner_label ||
      lock.owner_display_name ||
      lock.locked_by_fp_short ||
      lock.updated_by_fp_short ||
      ""
    );
  }

  function lockNote(lock) {
    if (!lock || typeof lock !== "object") return "";
    return String(lock.note || lock.reason || lock.message || "");
  }

  function isLockedStatus(j) {
    if (!j || typeof j !== "object") return false;
    if (j.locked === true) return true;
    if (j.resolved === true && j.lock) return true;
    if (j.lock && typeof j.lock === "object") return true;
    return false;
  }

  function lockObject(j) {
    if (!j || typeof j !== "object") return null;
    if (j.lock && typeof j.lock === "object") return j.lock;
    return null;
  }

  async function fetchLockStatus(scope, path) {
    const qs = new URLSearchParams();
    qs.set("scope_type", scope.scope_type);
    if (scope.scope_id) qs.set("scope_id", scope.scope_id);
    qs.set("path", path || ".");

    const r = await fetch(`/api/v4/file-locks/status?${qs.toString()}`, {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || j.ok === false) return null;
    return j;
  }

  function setTileLocked(tile, locked, lock) {
    observerMuted = true;

    try {
      tile.classList.toggle("fmLockLocked", !!locked);

      let badge = tile.querySelector(":scope > .fmLockTileBadge");
      if (!locked) {
        if (badge) badge.remove();
        tile.removeAttribute("data-lock-state");
        return;
      }

      tile.dataset.lockState = "locked";

      if (!badge) {
        badge = document.createElement("div");
        badge.className = "fmLockTileBadge";
        badge.textContent = "🔒";
        tile.appendChild(badge);
      }

      const owner = lockOwnerLabel(lock);
      const note = lockNote(lock);
      badge.title = [
        owner ? `Locked by ${owner}` : "Locked",
        note ? `Note: ${note}` : ""
      ].filter(Boolean).join("\n");
    } finally {
      window.setTimeout(() => {
        observerMuted = false;
      }, 0);
    }
  }

  async function refreshLockBadgesNow() {
    installLockBadgeStyle();

    const seq = ++refreshSeq;
    const scope = currentScopeForLockBadges();

    const tiles = Array.from(document.querySelectorAll(".tile"))
      .filter((tile) => tileRelPath(tile))
      .slice(0, 200);

    if (!tiles.length) return;

    const batchSize = 8;

    for (let i = 0; i < tiles.length; i += batchSize) {
      if (seq !== refreshSeq) return;

      const batch = tiles.slice(i, i + batchSize);

      await Promise.all(batch.map(async (tile) => {
        const rel = tileRelPath(tile);
        const j = await fetchLockStatus(scope, rel);

        if (seq !== refreshSeq) return;

        if (!j) {
          setTileLocked(tile, false, null);
          return;
        }

        const locked = isLockedStatus(j);
        setTileLocked(tile, locked, locked ? lockObject(j) : null);
      }));
    }
  }

  function scheduleLockBadgeRefresh(delay = 250) {
    if (refreshTimer) window.clearTimeout(refreshTimer);
    refreshTimer = window.setTimeout(() => {
      refreshTimer = 0;
      refreshLockBadgesNow().catch(() => {});
    }, delay);
  }

  window.addEventListener("pqnas:file-locks-changed", () => scheduleLockBadgeRefresh(150));
  window.addEventListener("pqnas:filemgr:loaded", () => scheduleLockBadgeRefresh(250));
  window.addEventListener("pqnas:filemgr:rendered", () => scheduleLockBadgeRefresh(250));

  document.addEventListener("click", (ev) => {
    const target = ev.target;
    if (!target || !target.closest) return;

    if (target.closest(".fmLockBtn") || target.closest(".fmUnlockBtn")) {
      scheduleLockBadgeRefresh(900);
      scheduleLockBadgeRefresh(1800);
    }
  }, true);

  window.addEventListener("DOMContentLoaded", () => {
    installLockBadgeStyle();
    scheduleLockBadgeRefresh(500);

    const mo = new MutationObserver(() => {
      if (observerMuted) return;
      scheduleLockBadgeRefresh(350);
    });

    mo.observe(document.body, {
      childList: true,
      subtree: true
    });
  });
})();

