window.PQNAS_FILEMGR = window.PQNAS_FILEMGR || {};

(() => {
  "use strict";
  const el = (id) => document.getElementById(id);

  function tr(key, vars = null, fallback = "") {
    try {
      if (window.PQNAS_I18N && typeof window.PQNAS_I18N.t === "function") {
        return window.PQNAS_I18N.t(key, vars, fallback || key);
      }
    } catch (_) {}
    return fallback || key;
  }

  function applyI18n(root = document) {
    try {
      if (window.PQNAS_I18N && typeof window.PQNAS_I18N.apply === "function") {
        window.PQNAS_I18N.apply(root || document);
      }
    } catch (_) {}
  }

  try {
    if (window.self !== window.top) document.body.classList.add("embedded");
  } catch (_) {
    document.body.classList.add("embedded");
  }

  // ---- DOM handles ----------------------------------------------------------
  const gridEl = document.getElementById("grid");
  const gridWrap = document.getElementById("gridWrap");
  const dropOverlay = document.getElementById("dropOverlay");

  const pathLine = document.getElementById("pathLine");
  const badge = document.getElementById("badge");
  const status = document.getElementById("status");
  const quotaLine = document.getElementById("quotaLine");
  const refreshBtn = document.getElementById("refreshBtn");
  const upBtn = document.getElementById("upBtn");
  const titleLine = document.getElementById("titleLine");
  const upIcon = document.getElementById("upIcon");

  const viewToggleBtn = document.getElementById("viewToggleBtn");
  const viewToggleTxt = document.getElementById("viewToggleTxt");

  const sortBtn = document.getElementById("sortBtn");
  const sortTxt = document.getElementById("sortTxt");
  const sortIcon = document.getElementById("sortIcon");

  // OPTIONAL: add these later in HTML if you want a toolbar favorite filter button
  const favoritesToggleBtn = document.getElementById("favoritesToggleBtn");
  const favoritesToggleTxt = document.getElementById("favoritesToggleTxt");

  const uploadBtn = document.getElementById("uploadBtn");
  const uploadFolderBtn = document.getElementById("uploadFolderBtn");
  const downloadFolderBtn = document.getElementById("downloadFolderBtn");
  const uploadConflictModal = document.getElementById("uploadConflictModal");
  const uploadConflictClose = document.getElementById("uploadConflictClose");
  const uploadConflictTitle = document.getElementById("uploadConflictTitle");
  const uploadConflictPath = document.getElementById("uploadConflictPath");
  const uploadConflictExisting = document.getElementById("uploadConflictExisting");
  const uploadConflictIncoming = document.getElementById("uploadConflictIncoming");
  const uploadConflictKeepOld = document.getElementById("uploadConflictKeepOld");
  const uploadConflictReplace = document.getElementById("uploadConflictReplace");
  const uploadConflictApplyAll = document.getElementById("uploadConflictApplyAll");
  const uploadConflictCancelBtn = document.getElementById("uploadConflictCancelBtn");
  const uploadConflictOkBtn = document.getElementById("uploadConflictOkBtn");
  const filePick = document.getElementById("filePick");
  const folderPick = document.getElementById("folderPick");

  const ctxEl = document.getElementById("ctxMenu");

  const uploadProg = el("uploadProg");
  const uploadProgText = el("uploadProgText");
  const uploadProgPill = el("uploadProgPill");
  const uploadProgPct = el("uploadProgPct");
  const uploadProgFill = el("uploadProgFill");
  const uploadCancelBtn = el("uploadCancelBtn");

  const propsModal = document.getElementById("propsModal");
  const propsClose = document.getElementById("propsClose");
  const propsTitle = document.getElementById("propsTitle");
  const propsPath = document.getElementById("propsPath");
  const propsBody = document.getElementById("propsBody");

  const shareModal = document.getElementById("shareModal");
  const shareClose = document.getElementById("shareClose");
  const shareTitle = document.getElementById("shareTitle");
  const sharePath = document.getElementById("sharePath");
  const shareExpiry = document.getElementById("shareExpiry");
  const shareCreateBtn = document.getElementById("shareCreateBtn");
  const shareOutWrap = document.getElementById("shareOutWrap");
  const shareOut = document.getElementById("shareOut");
  const shareCopyBtn = document.getElementById("shareCopyBtn");
  const shareStatus = document.getElementById("shareStatus");
  const SHARE_LINK_FIRST_OPEN_TOUR_ID = "filemgr.share_link_first_open.v1";
  const PQ_ENROLLED_SHARE_FIRST_OPEN_TOUR_ID = "filemgr.pq_enrolled_share_first_open.v1";
  const emptyState = document.getElementById("emptyState");

  const trashBtn = document.getElementById("trashBtn");
  const trashModal = document.getElementById("trashModal");
  const trashClose = document.getElementById("trashClose");
  const trashRefreshBtn = document.getElementById("trashRefreshBtn");
  const trashEmptyBtn = document.getElementById("trashEmptyBtn");
  const trashTitle = document.getElementById("trashTitle");
  const trashSub = document.getElementById("trashSub");
  const trashStatus = document.getElementById("trashStatus");
  const trashList = document.getElementById("trashList");
  const trashCount = document.getElementById("trashCount");
  // ---- Soft quota (UI-only) ---------------------------------------------------
  let quotaInfo = null;
  let quotaInfoAtMs = 0;
  let quotaInfoScopeKey = "";
  const QUOTA_TTL_MS = 15 * 1000;
  let trashItemsCache = [];
  let trashBusy = false;
  let uploadLimits = null;
  let uploadLimitsAtMs = 0;
  const UPLOAD_LIMITS_TTL_MS = 15 * 1000;

  function pickUploadLimitsFromMeStorage(j) {
    if (!j || typeof j !== "object") return null;
    const t = Number(j.transport_max_upload_bytes);
    const p = Number(j.payload_max_upload_bytes);
    const out = {};
    if (Number.isFinite(t) && t > 0) out.transport_max_upload_bytes = t;
    if (Number.isFinite(p) && p > 0) out.payload_max_upload_bytes = p;
    return Object.keys(out).length ? out : null;
  }

  function getEffectiveUploadLimitBytes() {
    if (uploadLimits && Number.isFinite(uploadLimits.transport_max_upload_bytes) && uploadLimits.transport_max_upload_bytes > 0) {
      return uploadLimits.transport_max_upload_bytes;
    }
    if (uploadLimits && Number.isFinite(uploadLimits.payload_max_upload_bytes) && uploadLimits.payload_max_upload_bytes > 0) {
      return uploadLimits.payload_max_upload_bytes;
    }
    return 0;
  }

  function showQuotaLine(kind, text) {
    if (!quotaLine) return;
    quotaLine.classList.remove("hidden");
    quotaLine.classList.toggle("warn", kind === "warn");
    quotaLine.classList.toggle("err",  kind === "err");
    quotaLine.textContent = text || "";
  }

  function hideQuotaLine() {
    if (!quotaLine) return;
    quotaLine.classList.add("hidden");
    quotaLine.classList.remove("warn", "err");
    quotaLine.textContent = "";
  }

  function quotaStateFromPct(pct) {
    if (!Number.isFinite(pct)) return "unknown";
    if (pct >= 1.0) return "over";
    if (pct >= 0.90) return "danger";
    if (pct >= 0.70) return "warn";
    return "ok";
  }

  const OFFICE_PREVIEW_EXTS = new Set([
    "doc", "docx",
    "xls", "xlsx",
    "ppt", "pptx",
    "odt", "ods", "odp",
    "rtf"
  ]);

  function isProbablyOfficePreviewableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return !!ext && OFFICE_PREVIEW_EXTS.has(ext);
  }

  async function fetchMeStorageFast(timeoutMs = 1200) {
    const controller = new AbortController();
    const t = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const r = await fetch("/api/v4/me/storage", {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: { "Accept": "application/json" },
        signal: controller.signal,
      });
      const j = await r.json().catch(() => null);
      if (!j) return null;

      const lim = pickUploadLimitsFromMeStorage(j);
      if (lim) {
        uploadLimits = lim;
        uploadLimitsAtMs = Date.now();
      }
      return j;
    } catch (_) {
      return null;
    } finally {
      clearTimeout(t);
    }
  }

  async function refreshUploadLimitsIfNeeded(force = false) {
    if (storageBlocked) return null;
    const now = Date.now();
    if (!force && uploadLimits && (now - uploadLimitsAtMs) < UPLOAD_LIMITS_TTL_MS) return uploadLimits;
    await fetchMeStorageFast(1200);
    return uploadLimits;
  }

  function fmtPct01(p) {
    if (!Number.isFinite(p)) return "";
    return `${Math.round(p * 100)}%`;
  }

  function currentQuotaScopeInfo() {
    const fm = window.PQNAS_FILEMGR || null;

    const inWorkspace =
        fm &&
        typeof fm.isWorkspaceScope === "function" &&
        fm.isWorkspaceScope();

    if (inWorkspace && typeof fm.getWorkspaceId === "function") {
      const workspaceId = String(fm.getWorkspaceId() || "").trim();
      if (workspaceId) {
        return {
          kind: "workspace",
          key: `workspace:${workspaceId}`,
          workspaceId
        };
      }
    }

    return {
      kind: "user",
      key: "user",
      workspaceId: ""
    };
  }

  function normalizeQuotaPayloadForScope(j, scope) {
    if (!j || typeof j !== "object") return null;

    const out = Object.assign({}, j);
    out.ok = true;
    out.scope_kind = scope && scope.kind ? String(scope.kind) : "user";

    if (scope && scope.workspaceId) {
      out.workspace_id = String(scope.workspaceId || "");
    }

    const usedRaw =
        out.used_bytes ??
        out.storage_used_bytes ??
        out.bytes_used ??
        out.used ??
        0;

    const quotaRaw =
        out.quota_bytes ??
        out.storage_quota_bytes ??
        out.quota ??
        0;

    out.used_bytes = Number(usedRaw || 0);
    out.quota_bytes = Number(quotaRaw || 0);

    if (!out.quota_state) {
      const pct = out.quota_bytes > 0 ? (out.used_bytes / out.quota_bytes) : 0;
      out.quota_state = quotaStateFromPct(pct);
    }

    return out;
  }

  async function fetchWorkspaceQuotaInfo(scope) {
    if (!scope || !scope.workspaceId) return null;

    const r = await fetch("/api/v4/workspaces", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) return null;

    const list = Array.isArray(j.workspaces)
        ? j.workspaces
        : Array.isArray(j.items)
            ? j.items
            : [];

    const want = String(scope.workspaceId || "");
    const ws = list.find((x) => String(
      x && (
        x.workspace_id ||
        x.workspaceId ||
        x.id ||
        ""
      )
    ) === want);

    if (!ws) return null;

    return normalizeQuotaPayloadForScope({
      ok: true,
      scope_kind: "workspace",
      workspace_id: want,
      workspace_name: ws.name || ws.workspace_name || "",
      storage_state: ws.storage_state || "",
      quota_bytes: ws.quota_bytes || 0,
      used_bytes: ws.used_bytes ?? ws.storage_used_bytes ?? 0,
      storage_used_bytes: ws.storage_used_bytes ?? ws.used_bytes ?? 0,
      pool_id: ws.pool_id || ws.storage_pool_id || ""
    }, scope);
  }

  async function refreshQuotaInfoIfNeeded(force = false) {
    if (storageBlocked) return null;

    const now = Date.now();
    const scope = currentQuotaScopeInfo();

    if (
      !force &&
      quotaInfo &&
      quotaInfoScopeKey === scope.key &&
      (now - quotaInfoAtMs) < QUOTA_TTL_MS
    ) {
      return quotaInfo;
    }

    try {
      let j = null;

      if (scope.kind === "workspace") {
        j = await fetchWorkspaceQuotaInfo(scope);
      } else {
        const r = await fetch("/api/v4/me/storage", {
          method: "GET",
          credentials: "include",
          cache: "no-store",
          headers: { "Accept": "application/json" }
        });

        j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) return null;

        const lim = pickUploadLimitsFromMeStorage(j);
        if (lim) {
          uploadLimits = lim;
          uploadLimitsAtMs = now;
        }

        j = normalizeQuotaPayloadForScope(j, scope);
      }

      if (!j || !j.ok) return null;

      quotaInfo = j;
      quotaInfoAtMs = now;
      quotaInfoScopeKey = scope.key;

      return quotaInfo;
    } catch (_) {
      return null;
    }
  }

  async function ensureUploadAllowedOrThrow(file) {
    if (!file) return;
    await refreshUploadLimitsIfNeeded(false);
    const limit = getEffectiveUploadLimitBytes();
    if (limit > 0 && file.size > limit) {
      throw new Error(`Upload too large: ${fmtSize(file.size)}. Limit is ${fmtSize(limit)}.`);
    }
  }

  function applyQuotaUi(q) {
    if (!q || typeof q !== "object") { hideQuotaLine(); return; }

    const scopeKind = String(q.scope_kind || q.scope || "").toLowerCase();
    const isWorkspaceQuota = scopeKind === "workspace";

    const quotaBytes = Number(q.quota_bytes || 0);
    const usedBytes  = Number(q.used_bytes ?? q.storage_used_bytes ?? 0);
    const storageState = String(q.storage_state || "").toLowerCase();

    if (!quotaBytes) {
      if (isWorkspaceQuota && storageState && storageState !== "allocated") {
        showQuotaLine("warn", "Workspace storage not allocated");
      } else {
        hideQuotaLine();
      }
      return;
    }

    const pct = quotaBytes > 0 ? (usedBytes / quotaBytes) : 0;
    const state = String(q.quota_state || quotaStateFromPct(pct));
    const label = isWorkspaceQuota ? "Workspace storage" : "Storage";
    const text = `${label}: ${fmtSize(usedBytes)} / ${fmtSize(quotaBytes)} (${fmtPct01(pct)})`;

    const uploadingNow = uploadProg && uploadProg.style.display !== "none";
    if (uploadingNow) {
      showQuotaLine(state === "over" ? "err" : (state === "danger" ? "warn" : ""), text);
      return;
    }

    if (state === "over") {
      setBadge("err", "storage");
      showQuotaLine("err", `${isWorkspaceQuota ? "Workspace over quota" : "Over quota (soft)"}: ${text}`);
      return;
    }
    if (state === "danger") {
      setBadge("warn", "storage");
      showQuotaLine("warn", `${isWorkspaceQuota ? "Workspace nearly full" : "Nearly full"}: ${text}`);
      return;
    }

    showQuotaLine("", text);
  }

  // ---- State ----------------------------------------------------------------
  let curPath = "";
  let storageBlocked = false;
  let lastListedItems = [];
  let loadSeq = 0;
  let activeLoadController = null;

  function currentScopeSnapshot(pathOverride) {
    const path = typeof pathOverride === "string" ? pathOverride : curPath;

    const inWorkspace =
        window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.isWorkspaceScope === "function" &&
        window.PQNAS_FILEMGR.isWorkspaceScope();

    const workspaceId =
        inWorkspace &&
        window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.getWorkspaceId === "function"
            ? String(window.PQNAS_FILEMGR.getWorkspaceId() || "")
            : "";

    return {
      path: String(path || ""),
      inWorkspace: !!inWorkspace,
      workspaceId,
      listUrl: apiListUrl(path || "")
    };
  }

  function sameScopeSnapshot(a, b) {
    return !!a && !!b &&
        a.path === b.path &&
        a.inWorkspace === b.inWorkspace &&
        a.workspaceId === b.workspaceId &&
        a.listUrl === b.listUrl;
  }

  const FILE_LIST_CACHE_TTL_MS = 15 * 1000;
  const fileListCache = new Map();

  function fileListCacheKeyFromSnap(snap) {
    if (!snap) return "";
    const scope = snap.inWorkspace ? `workspace:${snap.workspaceId}` : "user";
    return `${scope}|${snap.listUrl}`;
  }

  function cloneListResponse(j) {
    if (!j || typeof j !== "object") return j;

    return {
      ...j,
      items: Array.isArray(j.items)
          ? j.items.map((it) => it && typeof it === "object" ? { ...it } : it)
          : []
    };
  }

  function clearFileListCache() {
    fileListCache.clear();
  }

  async function fetchFileListForSnapshot(snap, opts = {}) {
    const force = opts.force === true;
    const key = fileListCacheKeyFromSnap(snap);
    const now = Date.now();

    if (!force && key) {
      const cached = fileListCache.get(key);
      if (cached && (now - cached.ts) < FILE_LIST_CACHE_TTL_MS) {
        return {
          ...cloneListResponse(cached.body),
          _cache: "memory"
        };
      }
    }

    const r = await fetch(snap.listUrl, {
      credentials: "include",
      cache: "no-store",
      signal: opts.signal
    });

    const j = await r.json().catch(() => null);

    if (r.ok && j && j.ok && key) {
      fileListCache.set(key, {
        ts: now,
        body: cloneListResponse(j)
      });
    }

    return j;
  }

  const VIEW_KEY = "pqnas_filemgr_view_mode";
  let viewMode = "grid";

  function loadViewMode() {
    try {
      const v = String(localStorage.getItem(VIEW_KEY) || "").toLowerCase();
      if (v === "list" || v === "grid") viewMode = v;
    } catch (_) {}
  }

  function saveViewMode() {
    try { localStorage.setItem(VIEW_KEY, viewMode); } catch (_) {}
  }

  function applyViewModeToDom() {
    if (gridEl) gridEl.classList.toggle("list", viewMode === "list");
    if (viewToggleTxt) viewToggleTxt.textContent = (viewMode === "list") ? "Grid" : "List";
    if (viewToggleBtn) viewToggleBtn.title = (viewMode === "list")
        ? "Switch to grid view"
        : "Switch to list view";
  }

  function setViewMode(next) {
    const n = (next === "list") ? "list" : "grid";
    if (viewMode === n) return;
    viewMode = n;
    saveViewMode();
    applyViewModeToDom();
    applySelectionToDom();
  }
  function sortApi() {
    return (window.PQNAS_FILEMGR && window.PQNAS_FILEMGR.sort)
        ? window.PQNAS_FILEMGR.sort
        : null;
  }

  function applySortUi() {
    const s = sortApi();
    if (!s) return;
    s.applyButtonUi(sortBtn, sortTxt, sortIcon);
  }
  loadViewMode();

  // ---- Favorites ------------------------------------------------------------
  const FAVORITES_ONLY_KEY = "pqnas_filemgr_favorites_only_v1";

  // stored as: { "file:path/to/a.txt": 1, "dir:docs": 1 }
  let favoritesMap = new Map();
  let favoritesOnly = false;

  const FAVORITES_CACHE_TTL_MS = 15 * 1000;
  let favoritesLoadedOnce = false;
  let favoritesLoadedAt = 0;

  function favoriteTypeNorm(type) {
    return type === "dir" ? "dir" : "file";
  }

  function favoriteKey(type, relPath) {
    const t = favoriteTypeNorm(type);
    const p = normalizeRelPath(relPath || "");
    return `${t}:${p}`;
  }
  async function fetchFavoritesFromServer(force = false) {
    const now = Date.now();
    if (!force && favoritesLoadedOnce && (now - favoritesLoadedAt) < FAVORITES_CACHE_TTL_MS) {
      return;
    }
    const r = await fetch("/api/v4/files/favorites", {
      method: "GET",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok || !Array.isArray(j.items)) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }

    favoritesMap = new Map();
    for (const it of j.items) {
      if (!it || typeof it !== "object") continue;
      const p = normalizeRelPath(it.path || "");
      const t = it.type === "dir" ? "dir" : "file";
      if (!p) continue;
      favoritesMap.set(`${t}:${p}`, 1);
    }
    favoritesLoadedOnce = true;
    favoritesLoadedAt = Date.now();
  }
  async function favoriteAddServer(relPath, type) {
    const r = await fetch("/api/v4/files/favorites/add", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ path: relPath, type })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
  }
  async function favoriteRemoveServer(relPath, type) {
    const r = await fetch("/api/v4/files/favorites/remove", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ path: relPath, type })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      throw new Error((j && (j.message || j.error)) || `HTTP ${r.status}`);
    }
  }


  function loadFavoritesOnly() {
    try {
      favoritesOnly = localStorage.getItem(FAVORITES_ONLY_KEY) === "1";
    } catch (_) {
      favoritesOnly = false;
    }
  }


  function isFavoriteRelPath(relPath, type) {
    return favoritesMap.has(favoriteKey(type, relPath));
  }

  function isFavoriteItem(item) {
    if (!item) return false;
    return isFavoriteRelPath(currentRelPathFor(item), item.type);
  }

  function selectedFavoriteStats() {
    let fav = 0;
    const paths = selectedRelPaths();
    for (const rel of paths) {
      const key = Array.from(selectedKeys).find((k) => keyToItemRelPath(k) === rel);
      const type = key && String(key).startsWith("dir:") ? "dir" : "file";
      if (isFavoriteRelPath(rel, type)) fav++;
    }
    return { total: paths.length, fav };
  }

  async function addSelectionToFavorites() {
    const paths = selectedRelPaths();
    if (!paths.length) return;

    let done = 0;
    for (const k of selectedKeys) {
      const rel = keyToItemRelPath(k);
      if (!rel) continue;
      const type = String(k).startsWith("dir:") ? "dir" : "file";
      await favoriteAddServer(rel, type);
      favoritesMap.set(favoriteKey(type, rel), 1);
      done++;
    }

    applySelectionToDom();
    setBadge("ok", "ready");
    status.textContent = `Added ${done} item(s) to favorites.`;
    await load();
  }
  async function toggleFavoriteRelPath(relPath, type) {
    const on = !isFavoriteRelPath(relPath, type);
    if (on) {
      await favoriteAddServer(relPath, type);
      favoritesMap.set(favoriteKey(type, relPath), 1);
    } else {
      await favoriteRemoveServer(relPath, type);
      favoritesMap.delete(favoriteKey(type, relPath));
    }
    return on;
  }
  function saveFavoritesOnly() {
    try {
      localStorage.setItem(FAVORITES_ONLY_KEY, favoritesOnly ? "1" : "0");
    } catch (_) {}
  }
  async function removeSelectionFromFavorites() {
    const paths = selectedRelPaths();
    if (!paths.length) return;

    let done = 0;
    for (const k of selectedKeys) {
      const rel = keyToItemRelPath(k);
      if (!rel) continue;
      const type = String(k).startsWith("dir:") ? "dir" : "file";
      await favoriteRemoveServer(rel, type);
      favoritesMap.delete(favoriteKey(type, rel));
      done++;
    }

    applySelectionToDom();
    setBadge("ok", "ready");
    status.textContent = `Removed ${done} item(s) from favorites.`;
    await load();
  }

  function applyFavoritesFilterUi() {
    if (favoritesToggleTxt) favoritesToggleTxt.textContent = favoritesOnly ? "All" : "Favorites";
    if (favoritesToggleBtn) {
      favoritesToggleBtn.title = favoritesOnly ? "Show all items" : "Show favorites only";
      favoritesToggleBtn.classList.toggle("active", favoritesOnly);
    }
  }
  function cleanupLegacyFavoriteStorage() {
    try {
      localStorage.removeItem("pqnas_filemgr_favorites_v1");
    } catch (_) {}
  }
  function setFavoritesOnly(next) {
    favoritesOnly = !!next;
    saveFavoritesOnly();
    applyFavoritesFilterUi();
    clearSelection();
    load();
  }

  function toggleFavoritesOnly() {
    setFavoritesOnly(!favoritesOnly);
  }

  loadFavoritesOnly();
  cleanupLegacyFavoriteStorage();

  let selectedKeys = new Set();
  let selectionAnchorKey = "";

  let shareCountByPath = new Map();
  let shareTokensByPath = new Map();
  let sharesLoadedAt = 0;
  let ctxOpenForKey = "";
  let propsShareTimer = null;
  let longPressTimer = null;

  function detectVersionFromUrl() {
    const p = String(location.pathname || "");
    const m = p.match(/\/apps\/[^/]+\/([^/]+)\/www\//);
    return m ? m[1] : "";
  }

  const appVer = detectVersionFromUrl();
  if (titleLine && appVer) titleLine.textContent = `File Manager • ${appVer}`;

  function getActiveThemeName() {
    const dt = document.documentElement.getAttribute("data-theme") || "";
    if (dt) return dt;
    try { return localStorage.getItem("pqnas_theme") || ""; } catch (_) { return ""; }
  }

  function iconBase() {
    const t = String(getActiveThemeName() || "").toLowerCase();
    return (t === "cpunk_orange") ? "./icons/orange/" : "./icons/";
  }

  function applyIconsNow() {
    if (upIcon) upIcon.src = iconBase() + "updir_small.png";
  }

  applyIconsNow();

  window.addEventListener("storage", (e) => {
    if (!e) return;

    if (e.key === "pqnas_theme") {
      applyIconsNow();
      load();
      return;
    }

    if (e.key === FAVORITES_ONLY_KEY) {
      loadFavoritesOnly();
      applyFavoritesFilterUi();
      load();
      return;
    }

    const s = sortApi();
    if (s && e.key === s.STORAGE_KEY) {
      s.loadMode();
      applySortUi();
      load();
      return;
    }
  });

  window.addEventListener("focus", () => applyIconsNow());

  function setPathAndLoad(p) {
    curPath = p || "";
    clearSelection();
    load();
  }

  function renderBreadcrumb() {
    if (!pathLine) return;

    pathLine.classList.add("mono");
    pathLine.replaceChildren();

    const root = document.createElement("span");
    root.className = "crumb";
    root.textContent = "/";
    root.title = "Go to root";
    root.addEventListener("click", () => setPathAndLoad(""));
    pathLine.appendChild(root);

    if (!curPath) {
      root.classList.add("active");
      return;
    }

    const parts = String(curPath).split("/").filter(Boolean);
    let acc = "";

    for (let i = 0; i < parts.length; i++) {
      const sep = document.createElement("span");
      sep.className = "crumbSep";
      sep.textContent = "›";
      pathLine.appendChild(sep);

      const name = parts[i];
      acc = acc ? `${acc}/${name}` : name;

      const crumbEl = document.createElement("span");
      crumbEl.className = "crumb";
      if (i === parts.length - 1) crumbEl.classList.add("active");

      const txt = document.createElement("span");
      txt.className = "crumbText";
      txt.textContent = name;
      crumbEl.appendChild(txt);

      const target = acc;
      crumbEl.title = "/" + target;

      if (i !== parts.length - 1) {
        crumbEl.addEventListener("click", () => setPathAndLoad(target));
      }

      pathLine.appendChild(crumbEl);
    }
  }

  function joinPath(base, name) {
    if (!base) return name;
    return `${base}/${name}`;
  }


  function isInternalPqnasFileManagerEntry(item) {
    if (!item || typeof item !== "object") return false;

    const rawName = String(item.name || item.filename || "").trim();
    const rawPath = String(item.path || item.rel || item.rel_path || "").trim();
    const leaf = (rawName || rawPath).split("/").filter(Boolean).pop() || "";

    // Hide PQ-NAS owned per-user/app metadata folders from normal File Manager.
    // Do not hide all dotfiles; user-created .env/.ssh/etc. may be legitimate.
    return leaf === ".pqnas_activity" ||
           leaf === ".pqnas_echostack" ||
           leaf.startsWith(".pqnas_");
  }

  function filterInternalPqnasFileManagerEntries(items) {
    if (!Array.isArray(items)) return [];
    return items.filter((it) => !isInternalPqnasFileManagerEntry(it));
  }

  function parentPath(p) {
    if (!p) return "";
    const i = p.lastIndexOf("/");
    if (i < 0) return "";
    return p.slice(0, i);
  }

  function fmApi() {
    return (window.PQNAS_FILEMGR && window.PQNAS_FILEMGR.api) ? window.PQNAS_FILEMGR.api : null;
  }

  function fmCaps() {
    if (window.PQNAS_FILEMGR && typeof window.PQNAS_FILEMGR.getCapabilities === "function") {
      return window.PQNAS_FILEMGR.getCapabilities() || {};
    }
    return {};
  }

  function canWriteCurrentScope() {
    if (window.PQNAS_FILEMGR && typeof window.PQNAS_FILEMGR.canCurrentScopeWrite === "function") {
      return !!window.PQNAS_FILEMGR.canCurrentScopeWrite();
    }
    return true;
  }

  function requireWritableScopeOrExplain(actionLabel) {
    if (!canWriteCurrentScope()) {
      setBadge("warn", "read-only");
      status.textContent = actionLabel
          ? `${actionLabel} not available: current workspace is read-only.`
          : "Current workspace is read-only.";
      return false;
    }
    return requireStorageOrExplain(actionLabel);
  }

  function apiListUrl(path) {
    const api = fmApi();
    if (api && typeof api.listUrl === "function") return api.listUrl(path || "");
    return path ? `/api/v4/files/list?path=${encodeURIComponent(path)}` : `/api/v4/files/list`;
  }

  function apiMkdirUrl(path) {
    const api = fmApi();
    if (api && typeof api.mkdirUrl === "function") return api.mkdirUrl(path || "");
    return `/api/v4/files/mkdir?path=${encodeURIComponent(path || "")}`;
  }

  function apiPutUrl(path, overwrite) {
    const api = fmApi();
    if (api && typeof api.putUrl === "function") return api.putUrl(path || "", !!overwrite);

    const qs = new URLSearchParams();
    qs.set("path", path || "");
    if (overwrite) qs.set("overwrite", "1");
    return `/api/v4/files/put?${qs.toString()}`;
  }

  function apiGetUrl(path) {
    const api = fmApi();
    if (api && typeof api.getUrl === "function") return api.getUrl(path || "");
    return `/api/v4/files/get?path=${encodeURIComponent(path || "")}`;
  }

  function apiDeleteUrl(path) {
    const api = fmApi();
    if (api && typeof api.deleteUrl === "function") return api.deleteUrl(path || "");
    return `/api/v4/files/delete?path=${encodeURIComponent(path || "")}`;
  }

  function apiMoveUrl(from, to) {
    const api = fmApi();
    if (api && typeof api.moveUrl === "function") return api.moveUrl(from || "", to || "");
    return `/api/v4/files/move?from=${encodeURIComponent(from || "")}&to=${encodeURIComponent(to || "")}`;
  }

  function apiCopyUrl(from, to) {
    const api = fmApi();
    if (api && typeof api.copyUrl === "function") return api.copyUrl(from || "", to || "");
    return `/api/v4/files/copy?from=${encodeURIComponent(from || "")}&to=${encodeURIComponent(to || "")}`;
  }

  function apiStatUrl(path) {
    const api = fmApi();
    if (api && typeof api.statUrl === "function") return api.statUrl(path || ".");
    const qs = new URLSearchParams();
    qs.set("path", path || ".");
    return `/api/v4/files/stat?${qs.toString()}`;
  }

  function apiStatSelUrl() {
    const api = fmApi();
    if (api && typeof api.statSelUrl === "function") return api.statSelUrl();
    return `/api/v4/files/stat_sel`;
  }

  function apiHashUrl(path, algo) {
    const api = fmApi();
    if (api && typeof api.hashUrl === "function") return api.hashUrl(path || "", algo || "sha256");
    const qs = new URLSearchParams();
    qs.set("path", path || "");
    qs.set("algo", algo || "sha256");
    return `/api/v4/files/hash?${qs.toString()}`;
  }
  function apiZipUrl(path, maxBytes) {
    const api = fmApi();
    if (api && typeof api.zipUrl === "function") return api.zipUrl(path || "", maxBytes || 0);

    const qs = new URLSearchParams();
    qs.set("path", path || "");
    if (maxBytes && Number(maxBytes) > 0) qs.set("max_bytes", String(maxBytes));
    return `/api/v4/files/zip?${qs.toString()}`;
  }

  function apiZipSelUrl() {
    const api = fmApi();
    if (api && typeof api.zipSelUrl === "function") return api.zipSelUrl();
    return `/api/v4/files/zip_sel`;
  }
  function fmtSize(n) {
    const u = ["B", "KiB", "MiB", "GiB", "TiB"];
    let v = Number(n || 0);
    let i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return i === 0 ? `${v | 0} ${u[i]}` : `${v.toFixed(1)} ${u[i]}`;
  }

  function fmtSpeed(bytesPerSec) {
    const v = Number(bytesPerSec || 0);
    if (!Number.isFinite(v) || v <= 0) return "—";
    return `${fmtSize(v)}/s`;
  }

  function fmtTime(unix) {
    if (!unix) return "";
    const d = new Date(unix * 1000);
    return d.toISOString().replace("T", " ").replace("Z", "");
  }
  function currentTrashScopeInfo() {
    const inWorkspace =
        window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.isWorkspaceScope === "function" &&
        window.PQNAS_FILEMGR.isWorkspaceScope();

    const workspaceId =
        window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.getWorkspaceId === "function"
            ? String(window.PQNAS_FILEMGR.getWorkspaceId() || "").trim()
            : "";

    if (inWorkspace && workspaceId) {
      return {
        scope: "workspace",
        workspaceId,
        label: tr("filemgr.trash.workspace_label", { id: workspaceId }, `Workspace trash • ${workspaceId}`),
        canWrite: canWriteCurrentScope()
      };
    }

    return {
      scope: "user",
      workspaceId: "",
      label: tr("filemgr.trash.my_trash", null, "My trash"),
      canWrite: true
    };
  }

  function trashListUrl(includeInactive = false) {
    const info = currentTrashScopeInfo();
    const qs = new URLSearchParams();
    qs.set("scope", info.scope);
    if (info.scope === "workspace") qs.set("workspace_id", info.workspaceId);
    if (includeInactive) qs.set("include_inactive", "1");
    return `/api/v4/trash/list?${qs.toString()}`;
  }

  function openTrashModal() {
    if (!trashModal) return;
    trashModal.classList.add("show");
    trashModal.setAttribute("aria-hidden", "false");
  }

  function closeTrashModal() {
    if (!trashModal) return;
    trashModal.classList.remove("show");
    trashModal.setAttribute("aria-hidden", "true");
  }

  function fmtTrashWhen(epoch) {
    return fmtEpochLocal(epoch);
  }

  function renderTrashItems() {
    if (!trashList) return;

    const info = currentTrashScopeInfo();
    if (trashTitle) trashTitle.textContent = tr("filemgr.trash", null, "Trash");
    if (trashSub) trashSub.textContent = info.label;
    if (trashCount) trashCount.textContent = tr("filemgr.trash.count", { count: trashItemsCache.length }, `${trashItemsCache.length} item(s)`);

    trashList.innerHTML = "";

    if (!trashItemsCache.length) {
      const empty = document.createElement("div");
      empty.className = "trashEmpty";
      empty.textContent = tr("filemgr.trash.empty_state", null, "Trash is empty.");
      trashList.appendChild(empty);
      if (trashEmptyBtn) trashEmptyBtn.disabled = true;
      return;
    }

    if (trashEmptyBtn) trashEmptyBtn.disabled = !info.canWrite || trashBusy;

    for (const rec of trashItemsCache) {
      const row = document.createElement("div");
      row.className = "trashRow";

      const main = document.createElement("div");
      main.className = "trashMain";

      const name = document.createElement("div");
      name.className = "trashName";
      name.textContent = rec.original_rel_path || rec.trash_id;

      const meta = document.createElement("div");
      meta.className = "trashMeta";
      meta.innerHTML =
          `<span>${escapeHtml(rec.item_type === "dir" ? tr("filemgr.trash.folder", null, "Folder") : tr("filemgr.trash.file", null, "File"))}</span>` +
          `<span>${escapeHtml(fmtSize(rec.size_bytes || 0))}</span>` +
          `<span>${escapeHtml(tr("filemgr.trash.deleted", { time: fmtTrashWhen(rec.deleted_epoch) }, `Deleted: ${fmtTrashWhen(rec.deleted_epoch)}`))}</span>` +
          `<span>${escapeHtml(tr("filemgr.trash.purge_after", { time: fmtTrashWhen(rec.purge_after_epoch) }, `Purge after: ${fmtTrashWhen(rec.purge_after_epoch)}`))}</span>`;

      const path = document.createElement("div");
      path.className = "trashPath";
      path.textContent = rec.original_rel_path || "";

      main.appendChild(name);
      main.appendChild(meta);
      main.appendChild(path);

      const actions = document.createElement("div");
      actions.className = "trashActions";

      const restoreBtn = document.createElement("button");
      restoreBtn.type = "button";
      restoreBtn.className = "btn secondary";
      restoreBtn.textContent = tr("filemgr.trash.restore", null, "Restore");
      restoreBtn.disabled = !info.canWrite || trashBusy;
      restoreBtn.onclick = async () => {
        await restoreTrashItem(rec);
      };

      const purgeBtn = document.createElement("button");
      purgeBtn.type = "button";
      purgeBtn.className = "btn secondary";
      purgeBtn.textContent = tr("filemgr.trash.delete_permanently", null, "Delete permanently");
      purgeBtn.disabled = !info.canWrite || trashBusy;
      purgeBtn.onclick = async () => {
        await purgeTrashItem(rec);
      };

      actions.appendChild(restoreBtn);
      actions.appendChild(purgeBtn);

      row.appendChild(main);
      row.appendChild(actions);
      trashList.appendChild(row);
    }
  }

  async function renderItemsChunked(items, mySeq, loadSnap, loadPath) {
    items = filterInternalPqnasFileManagerEntries(items);
    if (!gridEl) return false;

    const chunkSize = 250;
    let frag = document.createDocumentFragment();

    for (let i = 0; i < items.length; i++) {
      if (mySeq !== loadSeq) return false;
      if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return false;

      frag.appendChild(tile(items[i]));

      if ((i + 1) % chunkSize === 0) {
        gridEl.appendChild(frag);
        frag = document.createDocumentFragment();

        await new Promise((resolve) => requestAnimationFrame(resolve));
      }
    }

    gridEl.appendChild(frag);
    return true;
  }

  async function loadTrashItems() {
    if (!trashStatus) return;

    const info = currentTrashScopeInfo();
    trashBusy = true;
    if (trashStatus) trashStatus.textContent = tr("filemgr.trash.loading", { label: info.label }, `Loading ${info.label}…`);
    if (trashEmptyBtn) trashEmptyBtn.disabled = true;
    renderTrashItems();

    try {
      const r = await fetch(trashListUrl(false), {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });

      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.ok || !Array.isArray(j.items)) {
        const msg = j && (j.message || j.error)
            ? `${j.error || ""} ${j.message || ""}`.trim()
            : `HTTP ${r.status}`;
        throw new Error(msg || `HTTP ${r.status}`);
      }

      trashItemsCache = j.items.slice();
      if (trashStatus) trashStatus.textContent = tr("filemgr.trash.loaded", { count: trashItemsCache.length }, `Loaded ${trashItemsCache.length} item(s).`);
    } catch (e) {
      trashItemsCache = [];
      if (trashStatus) {
        trashStatus.textContent = tr("filemgr.trash.load_failed", { error: String(e && e.message ? e.message : e) }, `Trash load failed: ${String(e && e.message ? e.message : e)}`);
      }
    } finally {
      trashBusy = false;
      renderTrashItems();
    }
  }

  async function restoreTrashItem(rec) {
    if (!rec || !rec.trash_id) return;

    trashBusy = true;
    renderTrashItems();
    if (trashStatus) trashStatus.textContent = tr("filemgr.trash.restoring", { path: rec.original_rel_path || rec.trash_id }, `Restoring ${rec.original_rel_path || rec.trash_id}…`);

    try {
      const r = await fetch("/api/v4/trash/restore", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          trash_id: rec.trash_id,
          rename_if_conflict: true
        })
      });

      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.ok) {
        const msg = j && (j.message || j.error || j.detail)
            ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
            : `HTTP ${r.status}`;
        throw new Error(msg || `HTTP ${r.status}`);
      }

      setBadge("ok", "ready");
      status.textContent = tr("filemgr.trash.restored", { path: j.restored_rel_path || rec.original_rel_path }, `Restored: ${j.restored_rel_path || rec.original_rel_path}`);
      await loadTrashItems();
      clearFileListCache();
      await load(true);
    } catch (e) {
      setBadge("err", "error");
      if (trashStatus) {
        trashStatus.textContent = tr("filemgr.trash.restore_failed", { error: String(e && e.message ? e.message : e) }, `Restore failed: ${String(e && e.message ? e.message : e)}`);
      }
    } finally {
      trashBusy = false;
      renderTrashItems();
    }
  }

  async function purgeTrashItem(rec) {
    if (!rec || !rec.trash_id) return;

    const ok = await fmConfirmModal({
      title: tr("filemgr.trash.purge_title", null, "Delete permanently?"),
      subtitle: tr("filemgr.trash.purge_subtitle", null, "This item will be permanently deleted from Trash."),
      rows: [
        {
          label: tr("filemgr.delete.item", null, "Item"),
          value: (typeof item !== "undefined" && item && item.name) ? item.name : tr("filemgr.delete.selected_item", null, "Selected item"),
          mono: true
        },
      ],
      note: tr("filemgr.trash.purge_note", null, "This cannot be undone."),
      confirmText: tr("filemgr.trash.purge_confirm", null, "Delete permanently"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      danger: true,
    });
    if (!ok) return;

    trashBusy = true;
    renderTrashItems();
    if (trashStatus) trashStatus.textContent = tr("filemgr.trash.purging", { path: rec.original_rel_path || rec.trash_id }, `Deleting permanently ${rec.original_rel_path || rec.trash_id}…`);

    try {
      const r = await fetch("/api/v4/trash/purge", {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ trash_id: rec.trash_id })
      });

      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.ok) {
        const msg = j && (j.message || j.error || j.detail)
            ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
            : `HTTP ${r.status}`;
        throw new Error(msg || `HTTP ${r.status}`);
      }

      setBadge("ok", "ready");
      status.textContent = tr("filemgr.trash.purged", { path: rec.original_rel_path || rec.trash_id }, `Deleted permanently: ${rec.original_rel_path || rec.trash_id}`);
      await loadTrashItems();
      clearFileListCache();
      await load(true);
    } catch (e) {
      setBadge("err", "error");
      if (trashStatus) {
        trashStatus.textContent = tr("filemgr.trash.purge_failed", { error: String(e && e.message ? e.message : e) }, `Permanent delete failed: ${String(e && e.message ? e.message : e)}`);
      }
    } finally {
      trashBusy = false;
      renderTrashItems();
    }
  }

  async function emptyTrashScope() {
    const active = trashItemsCache.filter((x) => x && x.restore_status === "trashed");
    if (!active.length) return;

    const ok = await fmConfirmModal({
      title: tr("filemgr.delete.title", null, "Move to trash?"),
      subtitle: tr("filemgr.delete.subtitle", null, "The selected item will be moved to Trash."),
      rows: [
        {
          label: tr("filemgr.delete.item", null, "Item"),
          value: (typeof item !== "undefined" && item && item.name) ? item.name : tr("filemgr.delete.selected_item", null, "Selected item"),
          mono: true
        },
      ],
      note: tr("filemgr.delete.note", null, "You can restore it later from Trash until it is permanently deleted."),
      confirmText: tr("filemgr.delete.confirm", null, "Move to trash"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      danger: true,
    });
    if (!ok) return;

    trashBusy = true;
    renderTrashItems();

    let done = 0;
    let failed = 0;

    for (const rec of active) {
      if (trashStatus) {
        trashStatus.textContent = tr("filemgr.trash.emptying", { done: done + failed, total: active.length }, `Emptying trash ${done + failed}/${active.length}…`);
      }

      try {
        const r = await fetch("/api/v4/trash/purge", {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          headers: { "Content-Type": "application/json", "Accept": "application/json" },
          body: JSON.stringify({ trash_id: rec.trash_id })
        });

        const j = await r.json().catch(() => null);
        if (!r.ok || !j || !j.ok) throw new Error(`HTTP ${r.status}`);
        done++;
      } catch (_) {
        failed++;
      }
    }

    trashBusy = false;
    await loadTrashItems();
    clearFileListCache();
    await load(true);

    if (failed > 0) {
      setBadge("warn", "partial");
      status.textContent = tr("filemgr.trash.emptied_partial", { done, failed }, `Trash emptied partially. Deleted permanently: ${done}. Failed: ${failed}.`);
    } else {
      setBadge("ok", "ready");
      status.textContent = tr("filemgr.trash.emptied", { done }, `Trash emptied. Deleted permanently: ${done}.`);
    }
  }
  function filetypeIconBase() {
    return "./icons/filetypes/";
  }

  function fileExtLower(name) {
    const n = String(name || "").toLowerCase().trim();
    const slash = Math.max(n.lastIndexOf("/"), n.lastIndexOf("\\"));
    const base = slash >= 0 ? n.slice(slash + 1) : n;

    if (base.startsWith(".") && base.indexOf(".", 1) === -1) return "";

    if (base.endsWith(".tar.gz")) return "gz";
    if (base.endsWith(".tar.bz2")) return "bz2";
    if (base.endsWith(".tar.xz")) return "xz";

    const dot = base.lastIndexOf(".");
    if (dot <= 0 || dot === base.length - 1) return "";
    return base.slice(dot + 1);
  }

  function normalizeIconExt(ext) {
    const e = String(ext || "").toLowerCase();

    const alias = {
      jpeg: "jpg",
      htm: "html",
      yml: "yaml",
      cxx: "cpp",
      hh: "hpp",
      hxx: "hpp",
      markdown: "md",
      text: "txt",
      cfg: "conf"
    };

    return alias[e] || e;
  }

  const TEXT_EDIT_EXTS = new Set([
    "txt","md","json","js","ts","jsx","tsx","html","htm","css",
    "xml","yml","yaml","toml","ini","conf","log",
    "c","cc","cpp","cxx","h","hh","hpp","hxx",
    "py","sh","bash","zsh","sql","csv","tsv",
    "java","go","rs","rb","php","lua","swift","kt"
  ]);

  function isProbablyTextEditableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return !!ext && TEXT_EDIT_EXTS.has(ext);
  }

  const IMAGE_PREVIEW_EXTS = new Set([
    "png", "jpg", "jpeg", "gif", "webp", "svg", "bmp", "ico"
  ]);

  function isProbablyImagePreviewableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return !!ext && IMAGE_PREVIEW_EXTS.has(ext);
  }
  function isProbablyPdfPreviewableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return ext === "pdf";
  }
  const VIDEO_PREVIEW_EXTS = new Set([
    "mp4", "webm", "ogv", "mov", "m4v"
  ]);

  function isProbablyVideoPreviewableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return !!ext && VIDEO_PREVIEW_EXTS.has(ext);
  }
  const AUDIO_PREVIEW_EXTS = new Set([
    "mp3", "wav", "ogg", "oga", "m4a", "aac", "flac", "opus"
  ]);

  function isProbablyAudioPreviewableName(name) {
    const ext = normalizeIconExt(fileExtLower(name));
    return !!ext && AUDIO_PREVIEW_EXTS.has(ext);
  }
  function iconMap() {
    return (window.PQNAS_FILE_ICONS && typeof window.PQNAS_FILE_ICONS === "object")
        ? window.PQNAS_FILE_ICONS
        : {};
  }
  const svgNodeCache = new Map();

  function getIconNode(svg) {
    if (!svg) return null;
    if (!svgNodeCache.has(svg)) {
      const tpl = document.createElement("template");
      tpl.innerHTML = svg.trim();
      svgNodeCache.set(svg, tpl.content.firstElementChild);
    }
    return svgNodeCache.get(svg)?.cloneNode(true);
  }
  function iconMarkupFor(item) {
    const icons = iconMap();

    if (item.type === "dir") {
      return icons.folder || icons.directory || icons.default || "";
    }

    const ext = normalizeIconExt(fileExtLower(item.name));
    if (ext && icons[ext]) return icons[ext];

    const genericMap = {
      mp4: "generic_video",
      mov: "generic_video",
      mkv: "generic_video",
      avi: "generic_video",
      webm: "generic_video",

      mp3: "generic_audio",
      wav: "generic_audio",
      flac: "generic_audio",
      ogg: "generic_audio",
      m4a: "generic_audio",
      aac: "generic_audio",

      js: "generic_code",
      jsx: "generic_code",
      ts: "generic_code",
      tsx: "generic_code",
      py: "generic_code",
      c: "generic_code",
      cc: "generic_code",
      cpp: "generic_code",
      cxx: "generic_code",
      h: "generic_code",
      hh: "generic_code",
      hpp: "generic_code",
      hxx: "generic_code",
      java: "generic_code",
      php: "generic_code",
      go: "generic_code",
      rs: "generic_code",
      rb: "generic_code",
      lua: "generic_code",
      swift: "generic_code",
      kt: "generic_code",
      sh: "generic_code",
      bash: "generic_code",
      ps1: "generic_code",
      zsh: "generic_code",
      css: "generic_code",
      html: "generic_code",
      htm: "generic_code",
      json: "generic_code",
      xml: "generic_code",
      yaml: "generic_code",
      yml: "generic_code",
      toml: "generic_code",
      sql: "generic_code",

      zip: "generic_archive",
      rar: "generic_archive",
      gz: "generic_archive",
      bz2: "generic_archive",
      xz: "generic_archive",
      tgz: "generic_archive",
      tar: "generic_archive",
      "7z": "generic_archive",

      png: "generic_image",
      jpg: "generic_image",
      jpeg: "generic_image",
      gif: "generic_image",
      bmp: "generic_image",
      tiff: "generic_image",
      webp: "generic_image",
      heic: "generic_image",
      svg: "generic_image",
      ico: "generic_image",

      pdf: "generic_document",
      txt: "generic_document",
      md: "generic_document",
      doc: "generic_document",
      docx: "generic_document",
      odt: "generic_document",
      rtf: "generic_document",

      xls: "generic_spreadsheet",
      xlsx: "generic_spreadsheet",
      csv: "generic_spreadsheet",
      tsv: "generic_spreadsheet",
      ods: "generic_spreadsheet",

      ppt: "generic_presentation",
      pptx: "generic_presentation",
      odp: "generic_presentation",

      db: "generic_database",
      sqlite: "generic_database"
    };

    if (ext && genericMap[ext] && icons[genericMap[ext]]) {
      return icons[genericMap[ext]];
    }

    return icons.default || "";
  }
  function clearSelectionDom() {
    for (const el of gridEl.querySelectorAll(".tile")) el.classList.remove("sel");
  }

  function fmtEpochLocal(sec) {
    const n = Number(sec || 0);
    if (!Number.isFinite(n) || n <= 0) return "—";
    const d = new Date(n * 1000);
    if (isNaN(d.getTime())) return "—";
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

  function fmtBrowserFileTime(ms) {
    const n = Number(ms || 0);
    if (!Number.isFinite(n) || n <= 0) return "—";
    const d = new Date(n);
    if (isNaN(d.getTime())) return "—";
    const pad = (x) => String(x).padStart(2, "0");
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  }

    function openUploadConflictModal() {
    if (!uploadConflictModal) return;

    // Avoid stacking the new upload progress modal over the old conflict modal.
    setFileMgrUploadProgressVisible(false);

    uploadConflictModal.classList.add("show");
    uploadConflictModal.setAttribute("aria-hidden", "false");
  }

    function closeUploadConflictModal() {
    if (!uploadConflictModal) return;
    uploadConflictModal.classList.remove("show");
    uploadConflictModal.setAttribute("aria-hidden", "true");

    // Restore progress modal after conflict dialog closes, if upload is still active.
    if (uploadProg && uploadProg.style.display !== "none") {
      setFileMgrUploadProgressVisible(true);
    }
  }

  function describeExistingConflict(existing) {
    if (!existing || typeof existing !== "object") return tr("filemgr.upload.unknown", null, "Unknown");
    const parts = [];
    if (existing.size_bytes != null) parts.push(tr("filemgr.upload.size", { size: fmtSize(existing.size_bytes) }, `Size: ${fmtSize(existing.size_bytes)}`));
    if (existing.mtime_epoch) parts.push(tr("filemgr.upload.modified", { time: fmtEpochLocal(existing.mtime_epoch) }, `Modified: ${fmtEpochLocal(existing.mtime_epoch)}`));
    return parts.length ? parts.join(" • ") : tr("filemgr.upload.unknown", null, "Unknown");
  }

  function describeIncomingConflict(file) {
    if (!file) return tr("filemgr.upload.unknown", null, "Unknown");
    const parts = [];
    if (file.size != null) parts.push(tr("filemgr.upload.size", { size: fmtSize(file.size) }, `Size: ${fmtSize(file.size)}`));
    if (file.lastModified) parts.push(tr("filemgr.upload.modified", { time: fmtBrowserFileTime(file.lastModified) }, `Modified: ${fmtBrowserFileTime(file.lastModified)}`));
    return parts.length ? parts.join(" • ") : tr("filemgr.upload.unknown", null, "Unknown");
  }

  function isFileExistsConflict(errLike) {
    if (!errLike) return false;
    if (errLike.error === "file_exists") return true;
    if (errLike.details && errLike.details.error === "file_exists") return true;
    return false;
  }

  function askUploadConflictDecision(rel, file, existing) {
    return new Promise((resolve) => {
      if (!uploadConflictModal) {
        resolve({ action: "cancel", applyAll: false });
        return;
      }

      if (uploadConflictTitle) uploadConflictTitle.textContent = tr("filemgr.upload.file_exists", null, "File already exists");
      if (uploadConflictPath) uploadConflictPath.textContent = "/" + String(rel || "");
      if (uploadConflictExisting) uploadConflictExisting.textContent = describeExistingConflict(existing);
      if (uploadConflictIncoming) uploadConflictIncoming.textContent = describeIncomingConflict(file);

      if (uploadConflictKeepOld) uploadConflictKeepOld.checked = true;
      if (uploadConflictReplace) uploadConflictReplace.checked = false;
      if (uploadConflictApplyAll) uploadConflictApplyAll.checked = false;

      let settled = false;

      const finish = (result) => {
        if (settled) return;
        settled = true;
        closeUploadConflictModal();
        cleanup();
        resolve(result);
      };

      const onOk = () => {
        const action = uploadConflictReplace && uploadConflictReplace.checked ? "replace" : "keep_old";
        const applyAll = !!(uploadConflictApplyAll && uploadConflictApplyAll.checked);
        finish({ action, applyAll });
      };

      const onCancel = () => finish({ action: "cancel", applyAll: false });

      const onBackdrop = (e) => {
        if (e.target === uploadConflictModal) onCancel();
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          onCancel();
        }
      };

      const cleanup = () => {
        if (activeUploadConflictCancel === onCancel) {
          activeUploadConflictCancel = null;
        }

        uploadConflictOkBtn?.removeEventListener("click", onOk);
        uploadConflictCancelBtn?.removeEventListener("click", onCancel);
        uploadConflictClose?.removeEventListener("click", onCancel);
        uploadConflictModal?.removeEventListener("click", onBackdrop);
        document.removeEventListener("keydown", onKey);
      };

      activeUploadConflictCancel = onCancel;

      uploadConflictOkBtn?.addEventListener("click", onOk);
      uploadConflictCancelBtn?.addEventListener("click", onCancel);
      uploadConflictClose?.addEventListener("click", onCancel);
      uploadConflictModal?.addEventListener("click", onBackdrop);
      document.addEventListener("keydown", onKey);

      openUploadConflictModal();
    });
  }

  function applySelectionToDom() {
    for (const el of gridEl.querySelectorAll(".tile")) {
      el.classList.toggle("sel", selectedKeys.has(el.dataset.key));
    }
  }

  function visibleKeysInOrder() {
    return Array.from(gridEl.querySelectorAll(".tile")).map(el => String(el.dataset.key || ""));
  }

  function selectRange(fromKey, toKey, additive) {
    const keys = visibleKeysInOrder();
    const a = keys.indexOf(String(fromKey || ""));
    const b = keys.indexOf(String(toKey || ""));
    if (a < 0 || b < 0) {
      setSingleSelection(String(toKey || fromKey || ""));
      selectionAnchorKey = String(toKey || fromKey || "");
      return;
    }

    const lo = Math.min(a, b);
    const hi = Math.max(a, b);

    const next = additive ? new Set(selectedKeys) : new Set();
    for (let i = lo; i <= hi; i++) {
      const k = keys[i];
      if (k) next.add(k);
    }

    selectedKeys = next;
    applySelectionToDom();
    selectionAnchorKey = String(toKey || "");
  }

  function clearSelection() {
    selectedKeys.clear();
    clearSelectionDom();
  }

  function setSingleSelection(key) {
    selectedKeys = new Set([key]);
    applySelectionToDom();
  }

  function toggleSelection(key) {
    if (selectedKeys.has(key)) selectedKeys.delete(key);
    else selectedKeys.add(key);
    applySelectionToDom();
  }

  function ensureSelected(key) {
    if (!selectedKeys.has(key)) setSingleSelection(key);
  }

  const marquee = document.createElement("div");
  marquee.style.position = "absolute";
  marquee.style.border = "1px solid rgba(var(--fg-rgb),0.45)";
  marquee.style.background = "rgba(var(--fg-rgb),0.12)";
  marquee.style.borderRadius = "10px";
  marquee.style.pointerEvents = "none";
  marquee.style.display = "none";
  marquee.style.zIndex = "9999";
  document.body.appendChild(marquee);

  let marqueeOn = false;
  let marqueeStartX = 0;
  let marqueeStartY = 0;
  let marqueeBaseSelection = null;

  function tileRects() {
    const out = [];
    for (const tileEl of gridEl.querySelectorAll(".tile")) {
      out.push({ key: tileEl.dataset.key, rect: tileEl.getBoundingClientRect() });
    }
    return out;
  }

  function rectIntersects(a, b) {
    return !(a.right < b.left || a.left > b.right || a.bottom < b.top || a.top > b.bottom);
  }

  function endMarquee() {
    if (!marqueeOn) return;
    marqueeOn = false;
    marquee.style.display = "none";
    marqueeBaseSelection = null;
  }

  gridWrap?.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    if (e.target && e.target.closest && e.target.closest(".tile")) return;
    if (ctxEl && ctxEl.classList.contains("show")) return;

    marqueeOn = true;
    marqueeStartX = e.clientX;
    marqueeStartY = e.clientY;
    marqueeBaseSelection = (e.ctrlKey || e.metaKey) ? new Set(selectedKeys) : null;
    if (!marqueeBaseSelection) clearSelection();

    marquee.style.left = `${marqueeStartX}px`;
    marquee.style.top = `${marqueeStartY}px`;
    marquee.style.width = "0px";
    marquee.style.height = "0px";
    marquee.style.display = "block";

    try { gridWrap.setPointerCapture(e.pointerId); } catch (_) {}
    e.preventDefault();
  });

  gridWrap?.addEventListener("pointermove", (e) => {
    if (!marqueeOn) return;

    const x = e.clientX;
    const y = e.clientY;

    const left = Math.min(marqueeStartX, x);
    const top = Math.min(marqueeStartY, y);
    const right = Math.max(marqueeStartX, x);
    const bottom = Math.max(marqueeStartY, y);

    marquee.style.left = `${left}px`;
    marquee.style.top = `${top}px`;
    marquee.style.width = `${right - left}px`;
    marquee.style.height = `${bottom - top}px`;

    const selRect = { left, top, right, bottom };
    const rects = tileRects();
    const next = marqueeBaseSelection ? new Set(marqueeBaseSelection) : new Set();

    for (const t of rects) {
      if (rectIntersects(selRect, t.rect)) next.add(t.key);
    }

    selectedKeys = next;
    applySelectionToDom();
  });

  uploadConflictClose?.addEventListener("click", closeUploadConflictModal);
  uploadConflictModal?.addEventListener("click", (e) => {
    if (e.target === uploadConflictModal) closeUploadConflictModal();
  });

  gridWrap?.addEventListener("pointerup", endMarquee);
  gridWrap?.addEventListener("pointercancel", endMarquee);
  window.addEventListener("blur", endMarquee);

  function showDropOverlay(show) {
    if (!dropOverlay) return;
    dropOverlay.classList.toggle("show", !!show);
    dropOverlay.setAttribute("aria-hidden", show ? "false" : "true");
  }

  function normalizeRelPath(rel) {
    rel = String(rel || "").replace(/\\/g, "/");
    rel = rel.replace(/^\/+/, "");
    rel = rel.split("/").filter(Boolean).join("/");
    return rel;
  }

  function validateRelPath(rel) {
    const parts = String(rel || "").split("/").filter(Boolean);
    if (!parts.length) return false;
    for (const p of parts) {
      if (p === "." || p === "..") return false;
      if (p.includes("/") || p.includes("\\")) return false;
    }
    return true;
  }

  let fmUploadModalTotals = {
    fileCount: 0,
    totalBytes: 0
  };

  function ensureFileMgrUploadProgressModal() {
    let backdrop = document.getElementById("fmUploadProgressBackdrop");
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.id = "fmUploadProgressBackdrop";
    backdrop.className = "fmUploadProgressBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="fmUploadProgressCard" role="dialog" aria-modal="true" aria-labelledby="fmUploadProgressTitle">
        <div class="fmUploadProgressHead">
          <div>
            <div class="fmUploadProgressKicker">DNA-Nexus upload</div>
            <h2 id="fmUploadProgressTitle">Uploading files</h2>
            <p id="fmUploadProgressSub">Preparing upload…</p>
          </div>
          <button id="fmUploadProgressCancelTop" class="fmUploadProgressClose" type="button">Cancel</button>
        </div>

        <div class="fmUploadProgressBody">
          <div class="fmUploadProgressFile" id="fmUploadProgressFile">Waiting…</div>

          <div class="fmUploadProgressRow">
            <div id="fmUploadProgressText" class="fmUploadProgressText">0 B / 0 B</div>
            <div id="fmUploadProgressPct" class="fmUploadProgressPct">0%</div>
          </div>

          <div class="fmUploadProgressBar" aria-hidden="true">
            <div id="fmUploadProgressFill" class="fmUploadProgressFill"></div>
          </div>

          <div id="fmUploadProgressMeta" class="fmUploadProgressMeta">Ready.</div>
        </div>

        <div class="fmUploadProgressFoot">
          <button id="fmUploadProgressCancel" class="fmUploadProgressBtn secondary" type="button">Cancel upload</button>
          <button id="fmUploadProgressCloseBtn" class="fmUploadProgressBtn primary" type="button" hidden>Close</button>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);

    refreshFileMgrUploadProgressLabels(backdrop);

    const requestCancel = () => cancelCurrentUpload();

    backdrop.querySelector("#fmUploadProgressCancel")?.addEventListener("click", requestCancel);
    backdrop.querySelector("#fmUploadProgressCancelTop")?.addEventListener("click", requestCancel);
    backdrop.querySelector("#fmUploadProgressCloseBtn")?.addEventListener("click", () => {
      backdrop.hidden = true;
    });

    return backdrop;
  }

  function refreshFileMgrUploadProgressLabels(backdrop) {
    if (!backdrop) return;

    const kicker = backdrop.querySelector(".fmUploadProgressKicker");
    const title = backdrop.querySelector("#fmUploadProgressTitle");
    const close = backdrop.querySelector("#fmUploadProgressCloseBtn");
    const cancel = backdrop.querySelector("#fmUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#fmUploadProgressCancelTop");

    if (kicker) kicker.textContent = tr("filemgr.upload.kicker", null, "DNA-Nexus upload");
    if (title) title.textContent = tr("filemgr.upload.title", null, "Uploading files");
    if (close) close.textContent = tr("filemgr.upload.close", null, "Close");
    if (cancel) cancel.textContent = tr("filemgr.upload.cancel_upload", null, "Cancel upload");
    if (cancelTop) cancelTop.textContent = tr("filemgr.upload.cancel", null, "Cancel");
  }

  function openFileMgrUploadProgressModal(fileCount, totalBytes) {
    fmUploadModalTotals = {
      fileCount: Number(fileCount || 0),
      totalBytes: Number(totalBytes || 0)
    };

    const backdrop = ensureFileMgrUploadProgressModal();
    refreshFileMgrUploadProgressLabels(backdrop);

    const sub = backdrop.querySelector("#fmUploadProgressSub");
    const fileEl = backdrop.querySelector("#fmUploadProgressFile");
    const textEl = backdrop.querySelector("#fmUploadProgressText");
    const pctEl = backdrop.querySelector("#fmUploadProgressPct");
    const fillEl = backdrop.querySelector("#fmUploadProgressFill");
    const metaEl = backdrop.querySelector("#fmUploadProgressMeta");
    const close = backdrop.querySelector("#fmUploadProgressCloseBtn");
    const cancel = backdrop.querySelector("#fmUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#fmUploadProgressCancelTop");

    if (sub) {
      const n = fmUploadModalTotals.fileCount;
      sub.textContent = tr(
        "filemgr.upload.summary",
        {
          count: n,
          plural: n === 1 ? "" : "s",
          size: fmtSize(fmUploadModalTotals.totalBytes)
        },
        `${n} file${n === 1 ? "" : "s"} · ${fmtSize(fmUploadModalTotals.totalBytes)} total`
      );
    }

    if (fileEl) {
      fileEl.textContent = tr("filemgr.upload.preparing", null, "Preparing upload…");
      fileEl.classList.remove("fmUploadProgressOk", "fmUploadProgressFail");
    }

    if (textEl) textEl.textContent = `0 B / ${fmtSize(fmUploadModalTotals.totalBytes)}`;
    if (pctEl) pctEl.textContent = "0%";
    if (fillEl) fillEl.style.width = "0%";
    if (metaEl) metaEl.textContent = tr("filemgr.upload.ready", null, "Ready.");

    if (close) close.hidden = true;
    if (cancel) {
      cancel.hidden = false;
      cancel.disabled = false;
      cancel.textContent = tr("filemgr.upload.cancel_upload", null, "Cancel upload");
    }
    if (cancelTop) {
      cancelTop.hidden = false;
      cancelTop.disabled = false;
      cancelTop.textContent = tr("filemgr.upload.cancel", null, "Cancel");
    }

    backdrop.hidden = false;
  }

  function setFileMgrUploadProgressVisible(show) {
    const backdrop = document.getElementById("fmUploadProgressBackdrop");
    if (!backdrop) return;

    if (!show) {
      backdrop.hidden = true;
    } else {
      backdrop.hidden = false;
    }
  }

  function classifyFileMgrUploadModalKind(text, pillKind) {
    const k = String(pillKind || "").trim().toLowerCase();
    if (k) return k;

    const t = String(text || "").toLowerCase();
    if (t.includes("failed") || t.includes("error") || t.includes("quota") || t.includes("too large")) return "err";
    if (t.includes("cancelled") || t.includes("skipped") || t.includes("conflict")) return "warn";
    if (t.includes("finished") || t.includes("uploaded")) return "ok";
    return "";
  }

  function updateFileMgrUploadProgressModal(pct, text, pillText = "", pillKind = "") {
    const backdrop = document.getElementById("fmUploadProgressBackdrop");
    if (!backdrop || backdrop.hidden) return;

    pct = Math.max(0, Math.min(100, Number(pct || 0)));

    const fileEl = backdrop.querySelector("#fmUploadProgressFile");
    const textEl = backdrop.querySelector("#fmUploadProgressText");
    const pctEl = backdrop.querySelector("#fmUploadProgressPct");
    const fillEl = backdrop.querySelector("#fmUploadProgressFill");
    const metaEl = backdrop.querySelector("#fmUploadProgressMeta");

    const shownText = String(text || tr("filemgr.upload.default", null, "Uploading…"));
    const kind = classifyFileMgrUploadModalKind(shownText, pillKind);

    if (fileEl) {
      fileEl.textContent = shownText;
      fileEl.classList.toggle("fmUploadProgressOk", kind === "ok");
      fileEl.classList.toggle("fmUploadProgressFail", kind === "err");
    }

    if (textEl) {
      const loaded = Math.round((pct / 100) * Math.max(0, fmUploadModalTotals.totalBytes || 0));
      textEl.textContent = `${fmtSize(loaded)} / ${fmtSize(fmUploadModalTotals.totalBytes || 0)}`;
    }

    if (pctEl) pctEl.textContent = `${Math.round(pct)}%`;
    if (fillEl) fillEl.style.width = `${pct.toFixed(1)}%`;

    if (metaEl) {
      metaEl.textContent = String(pillText || "").trim() || tr("filemgr.upload.default", null, "Uploading…");
      metaEl.classList.toggle("fmUploadProgressMetaErr", kind === "err");
    }
  }

  function updateFileMgrUploadProgressCancelable(on) {
    const backdrop = document.getElementById("fmUploadProgressBackdrop");
    if (!backdrop) return;

    const cancel = backdrop.querySelector("#fmUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#fmUploadProgressCancelTop");
    const close = backdrop.querySelector("#fmUploadProgressCloseBtn");

    if (cancel) {
      cancel.hidden = !on;
      cancel.disabled = !on;
      if (on) cancel.textContent = tr("filemgr.upload.cancel_upload", null, "Cancel upload");
    }

    if (cancelTop) {
      cancelTop.hidden = !on;
      cancelTop.disabled = !on;
      if (on) cancelTop.textContent = tr("filemgr.upload.cancel", null, "Cancel");
    }

    if (close) close.hidden = !!on;
  }

  function markFileMgrUploadCancelling() {
    const backdrop = document.getElementById("fmUploadProgressBackdrop");
    if (!backdrop) return;

    const cancel = backdrop.querySelector("#fmUploadProgressCancel");
    const cancelTop = backdrop.querySelector("#fmUploadProgressCancelTop");
    const metaEl = backdrop.querySelector("#fmUploadProgressMeta");

    if (cancel) {
      cancel.disabled = true;
      cancel.textContent = tr("filemgr.upload.cancelling", null, "Cancelling…");
    }

    if (cancelTop) {
      cancelTop.disabled = true;
      cancelTop.textContent = tr("filemgr.upload.cancelling", null, "Cancelling…");
    }

    if (metaEl) metaEl.textContent = tr("filemgr.upload.cancelling_upload", null, "Cancelling upload…");
  }

  function showUploadProgress(show) {
    if (uploadProg) {
      uploadProg.style.display = show ? "block" : "none";
      uploadProg.setAttribute("aria-hidden", show ? "false" : "true");
    }

    setFileMgrUploadProgressVisible(!!show);

    if (!show) {
      if (uploadProgFill) uploadProgFill.style.width = "0%";
      if (uploadProgPct) uploadProgPct.textContent = "0%";
      if (uploadProgText) uploadProgText.textContent = "";
      setUploadCancelable(false);
    }
  }

  async function deleteSelection() {
    if (!requireWritableScopeOrExplain(tr("filemgr.action.delete", null, "Delete"))) return;
    const paths = selectedRelPaths();
    if (!paths.length) {
      status.textContent = tr("filemgr.common.nothing_selected", null, "Nothing selected.");
      return;
    }

    const ok = await fmConfirmModal({
      title: tr("filemgr.trash.purge_title", null, "Delete permanently?"),
      subtitle: tr("filemgr.trash.purge_subtitle", null, "This item will be permanently deleted from Trash."),
      rows: [
        {
          label: tr("filemgr.delete.item", null, "Item"),
          value: (typeof item !== "undefined" && item && item.name) ? item.name : tr("filemgr.delete.selected_item", null, "Selected item"),
          mono: true
        },
      ],
      note: tr("filemgr.trash.purge_note", null, "This cannot be undone."),
      confirmText: tr("filemgr.trash.purge_confirm", null, "Delete permanently"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      danger: true,
    });
    if (!ok) return;

    setBadge("warn", "moving to trash…");
    status.textContent = `Moving to trash 0/${paths.length}…`;

    let done = 0;
    let failed = 0;
    const failures = [];

    for (const rel of paths) {
      try {
        const key = Array.from(selectedKeys).find((k) => keyToItemRelPath(k) === rel);

        const url = apiDeleteUrl(rel);
        const r = await fetch(url, {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          body: ""
        });
        const j = await r.json().catch(() => null);

        if (!r.ok || !j || !j.ok) {
          failed++;
          const msg = j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : `HTTP ${r.status}`;
          failures.push(`${rel} — ${msg}`);
          continue;
        }
      } catch (e) {
        failed++;
        failures.push(`${rel} — ${String(e && e.message ? e.message : e)}`);
        continue;
      }

      done++;
      status.textContent = `Moving to trash ${done}/${paths.length}…`;
    }

    clearSelection();

    if (failed > 0) {
      setBadge("err", "partial");
      status.textContent = `Moved ${done}/${paths.length} item(s) to trash. Failed: ${failed}. See console.`;
      console.warn("Multi-delete failures:", failures);
    } else {
      setBadge("ok", "ready");
      status.textContent = `Moved ${done} item(s) to trash.`;
    }
    try {
      await fetchFavoritesFromServer();
    } catch (e) {
      console.warn("Favorites refresh after multi-delete failed:", e);
    }

    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    clearFileListCache();
    await load(true);
  }

  function ensureUploadPill() {
    if (!uploadProgText) return null;

    let pill = document.getElementById("uploadProgPill");
    if (pill) return pill;

    pill = document.createElement("div");
    pill.id = "uploadProgPill";
    pill.style.display = "none";
    pill.style.marginBottom = "6px";
    pill.style.alignSelf = "center";
    pill.style.maxWidth = "92%";
    pill.style.padding = "6px 10px";
    pill.style.borderRadius = "999px";
    pill.style.border = "1px solid rgba(255,255,255,0.18)";
    pill.style.background = "rgba(0,0,0,0.55)";
    pill.style.color = "var(--fg)";
    pill.style.fontSize = "12px";
    pill.style.lineHeight = "1.2";
    pill.style.whiteSpace = "nowrap";
    pill.style.overflow = "hidden";
    pill.style.textOverflow = "ellipsis";
    pill.style.boxShadow = "0 8px 20px rgba(0,0,0,0.35)";
    pill.style.pointerEvents = "none";

    uploadProgText.parentElement?.insertBefore(pill, uploadProgText);
    return pill;
  }

  function classifyUploadMsg(text) {
    const t = String(text || "").toLowerCase();
    if (!t) return "info";
    if (t.includes("quota") || t.includes("failed") || t.includes("error") || t.includes("blocked") || t.includes("http 4")) return "err";
    if (t.includes("uploading") || t.includes("upload…")) return "warn";
    if (t.includes("uploaded") || t.includes("finished") || t.includes("ready") || t.includes("ok")) return "ok";
    return "info";
  }

  function applyUploadPillStyle(pill, kind) {
    const ok = "var(--ok, rgba(42,161,152,1))";
    const warn = "var(--warn, rgba(181,137,0,1))";
    const err = "var(--bad, rgba(220,50,47,1))";
    const info = "var(--fg, rgba(255,255,255,0.92))";

    let accent = info;
    if (kind === "ok") accent = ok;
    else if (kind === "warn") accent = warn;
    else if (kind === "err") accent = err;

    pill.style.borderColor = `color-mix(in srgb, ${accent} 55%, rgba(255,255,255,0.18))`;
    pill.style.color = accent;
    pill.style.background = "rgba(0,0,0,0.60)";
  }

  function setUploadProgress(pct, text, pillText = "", pillKind = "") {
    pct = Math.max(0, Math.min(100, Number(pct || 0)));
    if (uploadProgFill) uploadProgFill.style.width = `${pct.toFixed(1)}%`;
    if (uploadProgPct) uploadProgPct.textContent = `${Math.round(pct)}%`;
    if (uploadProgText && text != null) uploadProgText.textContent = String(text);

    updateFileMgrUploadProgressModal(pct, text, pillText, pillKind);

    if (uploadProgPill) {
      const t = (pillText || "").trim();
      if (!t) {
        uploadProgPill.className = "upPill hidden";
        uploadProgPill.textContent = "";
      } else {
        uploadProgPill.className = `upPill ${pillKind || "err"}`;
        uploadProgPill.textContent = t;
      }
    }
  }

  let lastUploadError = null;
  let activeUploadXhr = null;
  let uploadCancelRequested = false;
  let activeUploadConflictCancel = null;

  function extractHttpStatusFromMsg(msg) {
    const m = String(msg || "").match(/\bHTTP\s+(\d{3})\b/i);
    return m ? Number(m[1]) : 0;
  }

  function uploadErrorBlob(errLike) {
    const parts = [];

    const push = (x) => {
      if (x === undefined || x === null) return;
      if (typeof x === "string") {
        parts.push(x);
        return;
      }

      try {
        parts.push(JSON.stringify(x));
      } catch (_) {}
    };

    push(errLike && errLike.message ? errLike.message : errLike);
    push(errLike && errLike.error);
    push(errLike && errLike.kind);
    push(errLike && errLike.source);
    push(errLike && errLike.details);

    return parts.join(" ").toLowerCase();
  }

  function isUploadQuotaError(errLike) {
    const low = uploadErrorBlob(errLike);

    return low.includes("quota_exceeded") ||
      low.includes("quota exceeded") ||
      low.includes("user quota exceeded") ||
      low.includes("storage quota") ||
      low.includes("workspace quota") ||
      low.includes("user quota") ||
      low.includes("insufficient quota") ||
      low.includes("insufficient storage") ||
      low.includes("storage limit") ||
      low.includes("not enough space");
  }

  function uploadQuotaDetailText(errLike) {
    const j = errLike && errLike.details && typeof errLike.details === "object"
      ? errLike.details
      : null;

    if (!j) return "Quota exceeded";

    const parts = [];

    if (j.used_bytes != null && j.quota_bytes != null) {
      parts.push(`used ${fmtSize(j.used_bytes)} / ${fmtSize(j.quota_bytes)}`);
    }

    if (j.incoming_bytes != null) {
      parts.push(`incoming ${fmtSize(j.incoming_bytes)}`);
    }

    if (j.existing_bytes != null && Number(j.existing_bytes || 0) > 0) {
      parts.push(`replacing ${fmtSize(j.existing_bytes)}`);
    }

    return parts.length ? `Quota exceeded: ${parts.join(" · ")}` : "Quota exceeded";
  }

  function classifyUploadSummary(errLike) {
    const msg = String(errLike && errLike.message ? errLike.message : errLike || "").trim();
    const http = (errLike && Number.isFinite(errLike.http)) ? errLike.http : extractHttpStatusFromMsg(msg);
    const low = msg.toLowerCase();

    if (errLike && errLike.kind === "workspace_large_upload_not_chunked_yet") return "Workspace quota/upload limit exceeded";
    if (errLike && errLike.error === "workspace_upload_limit") return "Workspace quota/upload limit exceeded";
    if (errLike && errLike.error === "file_exists") return "File already exists";
    if (errLike && errLike.kind === "file_exists") return "File already exists";
    if (low.includes("file already exists")) return "File already exists";
    if (isUploadQuotaError(errLike)) return "Quota exceeded";
    if (http === 400 || low.includes("gateway") || low.includes("before pq-nas")) return "Gateway rejected before PQ-NAS";
    if (http === 413 || low.includes("too large")) return "Quota/upload limit exceeded";
    if (http >= 400) return `Upload failed (HTTP ${http})`;
    return "Upload failed";
  }

  function uploadModalFailureText(summary, msg) {
    summary = String(summary || "Upload failed").trim();
    msg = String(msg || "").trim();

    if (!msg) return summary;
    if (msg.toLowerCase() === summary.toLowerCase()) return summary;

    // Keep quota/workspace reasons visible in the main modal line.
    return `${summary}: ${msg}`;
  }

  function uploadModalFailureMeta(e, rel, msg) {
    if (typeof isUploadQuotaError === "function" && isUploadQuotaError(e)) {
      return typeof uploadQuotaDetailText === "function"
        ? uploadQuotaDetailText(e)
        : "Quota exceeded";
    }

    msg = String(msg || "").trim();
    if (msg) return msg;

    return rel ? `Last: ${rel}` : "Upload failed";
  }

  function showUploadErrorDetailsModal() {
    if (!lastUploadError) return;
    if (!propsTitle || !propsPath || !propsBody) return;

    propsTitle.textContent = "Upload error details";
    propsPath.textContent = lastUploadError.file ? `/${lastUploadError.file}` : "(unknown file)";
    propsBody.innerHTML = "";

    const rows = [];
    rows.push(["File", lastUploadError.file || ""]);
    rows.push(["Summary", lastUploadError.summary || "Upload failed"]);
    if (lastUploadError.kind) rows.push(["Kind", lastUploadError.kind]);
    if (lastUploadError.source) rows.push(["Source", lastUploadError.source]);
    if (lastUploadError.http) rows.push(["HTTP", String(lastUploadError.http)]);
    rows.push(["Message", lastUploadError.message || ""]);

    for (const [k, v] of rows) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    openPropsModal();
  }

  function setUploadPillClickable(on) {
    if (!uploadProgPill) return;
    uploadProgPill.onclick = null;

    if (!on) {
      uploadProgPill.style.cursor = "";
      uploadProgPill.title = "";
      return;
    }

    uploadProgPill.style.cursor = "pointer";
    uploadProgPill.title = "Click for details";
    uploadProgPill.onclick = (e) => {
      e.preventDefault();
      e.stopPropagation();
      showUploadErrorDetailsModal();
    };
  }

  function setUploadCancelable(on) {
    if (uploadCancelBtn) {
      uploadCancelBtn.classList.toggle("hidden", !on);
      uploadCancelBtn.disabled = !on;
    }

    updateFileMgrUploadProgressCancelable(!!on);
  }

    function cancelCurrentUpload() {
    uploadCancelRequested = true;
    markFileMgrUploadCancelling();

    if (activeUploadConflictCancel) {
      try { activeUploadConflictCancel(); } catch (_) {}
    }

    closeUploadConflictModal();

    if (activeUploadXhr) {
      try { activeUploadXhr.abort(); } catch (_) {}
    }
  }

  uploadCancelBtn?.addEventListener("click", () => {
    cancelCurrentUpload();
  });

  async function mkdirIfNeeded(relDir, created) {
    if (!relDir) return;
    const norm = normalizeRelPath(relDir);
    if (!norm) return;

    const parts = norm.split("/").filter(Boolean);
    let acc = "";
    for (const part of parts) {
      acc = acc ? `${acc}/${part}` : part;
      const full = curPath ? `${curPath}/${acc}` : acc;
      if (created.has(full)) continue;

      const url = apiMkdirUrl(full);
      const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
      const j = await r.json().catch(() => null);
      created.add(full);
    }
  }

  const CHUNKED_UPLOAD_THRESHOLD_BYTES = 16 * 1024 * 1024;

  function isWorkspaceUploadScope() {
    try {
      if (
        window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.isWorkspaceScope === "function" &&
        window.PQNAS_FILEMGR.isWorkspaceScope()
      ) {
        return true;
      }
    } catch (_) {}

    try {
      const snap = typeof currentScopeSnapshot === "function" ? currentScopeSnapshot() : null;
      if (snap && (snap.scope === "workspace" || snap.scope_type === "workspace" || snap.workspace_id || snap.workspaceId)) {
        return true;
      }
    } catch (_) {}

    return false;
  }

  function currentWorkspaceIdForUpload() {
    try {
      const fm = window.PQNAS_FILEMGR || null;

      if (fm && fm.scope && fm.scope.workspaceId) {
        return String(fm.scope.workspaceId || "");
      }

      if (fm && typeof fm.getWorkspaceId === "function") {
        const v = String(fm.getWorkspaceId() || "");
        if (v) return v;
      }
    } catch (_) {}

    try {
      const snap = typeof currentScopeSnapshot === "function" ? currentScopeSnapshot() : null;
      const v = snap && (snap.workspace_id || snap.workspaceId);
      if (v) return String(v || "");
    } catch (_) {}

    return "";
  }

  function shouldUseChunkedUpload(file, opts = {}) {
    const size = Number(file && file.size != null ? file.size : 0);
    return size > CHUNKED_UPLOAD_THRESHOLD_BYTES;
  }

  function assertWorkspaceLargeUploadSupported(file) {
    // Workspace chunked upload is now supported through /api/v4/workspaces/uploads/*.
    return;
  }

  async function postUploadJson(url, body) {
    const r = await fetch(url, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body: JSON.stringify(body || {})
    });

    const text = await r.text().catch(() => "");
    let j = null;
    try { j = text ? JSON.parse(text) : null; } catch (_) {}

    if (!r.ok || !j || j.ok !== true) {
      const err = new Error(
          j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : (text ? shorten(text.replace(/\s+/g, " "), 200) : `HTTP ${r.status}`)
      );
      err.http = r.status;
      err.kind = j && j.error ? String(j.error) : "pqnas_error";
      err.source = "pqnas";
      err.error = j && j.error ? j.error : "";
      err.details = j;
      throw err;
    }

    return j;
  }

  function xhrPutBlob(url, blob, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      activeUploadXhr = xhr;

      const clearActive = () => {
        if (activeUploadXhr === xhr) activeUploadXhr = null;
      };

      xhr.open("PUT", url, true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/octet-stream");
      xhr.timeout = 60 * 60 * 1000;

      xhr.upload.onprogress = (e) => {
        if (!onProgress) return;
        if (e.lengthComputable) onProgress(e.loaded, e.total);
        else onProgress(e.loaded, blob.size || 0);
      };

      xhr.ontimeout = () => {
        clearActive();
        reject(Object.assign(new Error("upload chunk failed (timeout)"), { kind: "network", source: "client" }));
      };

      xhr.onerror = () => {
        clearActive();
        reject(Object.assign(new Error("upload chunk failed (network)"), { kind: "network", source: "client" }));
      };

      xhr.onabort = () => {
        clearActive();
        if (uploadCancelRequested) {
          reject(Object.assign(new Error("upload cancelled"), { kind: "cancelled", source: "client" }));
        } else {
          reject(Object.assign(new Error("upload chunk aborted"), { kind: "network", source: "client" }));
        }
      };

      xhr.onload = () => {
        const status = xhr.status || 0;
        const raw = String(xhr.responseText || "").trim();
        let j = null;
        if (raw && (raw.startsWith("{") || raw.startsWith("["))) {
          try { j = JSON.parse(raw); } catch (_) {}
        }

        if (status >= 200 && status < 300 && j && j.ok) {
          clearActive();
          resolve(j);
          return;
        }

        const err = new Error(
            j && (j.message || j.error)
                ? `${j.error || ""} ${j.message || ""}`.trim()
                : (raw ? shorten(raw.replace(/\s+/g, " "), 200) : `HTTP ${status}`)
        );
        err.http = status;
        err.kind = j && j.error ? j.error : "pqnas_error";
        err.source = "pqnas";
        err.details = j;
        clearActive();
        reject(err);
      };

      xhr.send(blob);
    });
  }

  async function cancelChunkedUploadBestEffort(uploadId, workspaceId = "") {
    if (!uploadId) return;

    const inWorkspace = !!workspaceId;
    const url = inWorkspace
        ? "/api/v4/workspaces/uploads/cancel"
        : "/api/v4/uploads/cancel";

    const body = inWorkspace
        ? { workspace_id: workspaceId, upload_id: uploadId }
        : { upload_id: uploadId };

    try {
      await fetch(url, {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify(body)
      });
    } catch (_) {}
  }

  async function xhrUploadFileChunkedTo(relPath, file, onProgress, opts = {}) {
    const full = curPath ? `${curPath}/${relPath}` : relPath;
    const size = Number(file && file.size != null ? file.size : 0);

    const workspaceScope = isWorkspaceUploadScope();
    const workspaceId = workspaceScope ? currentWorkspaceIdForUpload() : "";
    if (workspaceScope && !workspaceId) {
      throw Object.assign(new Error("missing workspace_id for workspace chunked upload"), {
        kind: "workspace_upload_missing_id",
        source: "client"
      });
    }

    const inWorkspace = !!workspaceId;

    let uploadId = "";
    let uploadedCommitted = 0;

    try {
      const start = await postUploadJson(
          inWorkspace ? "/api/v4/workspaces/uploads/start" : "/api/v4/uploads/start",
          inWorkspace
              ? {
                  workspace_id: workspaceId,
                  path: full,
                  size_bytes: size,
                  overwrite: !!(opts && opts.overwrite)
                }
              : {
                  path: full,
                  size_bytes: size,
                  overwrite: !!(opts && opts.overwrite)
                }
      );

      uploadId = String(start.upload_id || "");

      const chunkSize = Math.max(1, Number(start.chunk_size || CHUNKED_UPLOAD_THRESHOLD_BYTES));
      const chunksTotal = Math.max(0, Number(start.chunks_total || Math.ceil(size / chunkSize)));

      if (!uploadId || chunksTotal < 1) {
        throw Object.assign(new Error("invalid chunked upload session"), {
          kind: "pqnas_error",
          source: "pqnas",
          details: start
        });
      }

      for (let index = 0; index < chunksTotal; index++) {
        if (uploadCancelRequested) {
          throw Object.assign(new Error("upload cancelled"), { kind: "cancelled", source: "client" });
        }

        const begin = index * chunkSize;
        const end = Math.min(size, begin + chunkSize);
        const blob = file.slice(begin, end);

        const url = inWorkspace
            ? `/api/v4/workspaces/uploads/chunk?workspace_id=${encodeURIComponent(workspaceId)}&upload_id=${encodeURIComponent(uploadId)}&index=${encodeURIComponent(String(index))}`
            : `/api/v4/uploads/chunk?upload_id=${encodeURIComponent(uploadId)}&index=${encodeURIComponent(String(index))}`;

        await xhrPutBlob(url, blob, (loaded) => {
          const totalLoaded = uploadedCommitted + Math.max(0, Number(loaded || 0));
          if (onProgress) onProgress(totalLoaded, size, {
            chunkIndex: index,
            chunksTotal,
            chunkLoaded: loaded,
            chunkSize: blob.size
          });
        });

        uploadedCommitted += blob.size;
        if (onProgress) onProgress(uploadedCommitted, size, {
          chunkIndex: index,
          chunksTotal,
          chunkLoaded: blob.size,
          chunkSize: blob.size
        });
      }

      if (uploadCancelRequested) {
        throw Object.assign(new Error("upload cancelled"), { kind: "cancelled", source: "client" });
      }

      const finish = await postUploadJson(
          inWorkspace ? "/api/v4/workspaces/uploads/finish" : "/api/v4/uploads/finish",
          inWorkspace
              ? { workspace_id: workspaceId, upload_id: uploadId }
              : { upload_id: uploadId }
      );

      uploadId = "";
      return finish;
    } catch (e) {
      if (uploadId) await cancelChunkedUploadBestEffort(uploadId, workspaceId);
      throw e;
    }
  }

  async function uploadFileSmartTo(relPath, file, onProgress, opts = {}) {
    assertWorkspaceLargeUploadSupported(file);

    if (shouldUseChunkedUpload(file, opts)) {
      return await xhrUploadFileChunkedTo(relPath, file, onProgress, opts);
    }

    return await xhrPutFileTo(relPath, file, onProgress, opts);
  }

  function xhrPutFileTo(relPath, file, onProgress, opts = {}) {
    return new Promise((resolve, reject) => {
      const full = curPath ? `${curPath}/${relPath}` : relPath;
      const url = apiPutUrl(full, !!(opts && opts.overwrite));

      const xhr = new XMLHttpRequest();
      activeUploadXhr = xhr;

      const clearActive = () => {
        if (activeUploadXhr === xhr) activeUploadXhr = null;
      };

      xhr.open("PUT", url, true);
      xhr.withCredentials = true;
      xhr.setRequestHeader("Content-Type", "application/octet-stream");

      xhr.timeout = 60 * 60 * 1000;
      xhr.ontimeout = () => {
        clearActive();
        reject(Object.assign(new Error("upload failed (timeout)"), { kind: "network", source: "client" }));
      };

      let lastProgressTs = 0;

      xhr.upload.onprogress = (e) => {
        if (!onProgress) return;
        const now = performance.now();
        if (now - lastProgressTs < 80) return;
        lastProgressTs = now;

        if (e.lengthComputable) onProgress(e.loaded, e.total);
        else onProgress(e.loaded, file.size || 0);
      };

      xhr.onerror = () => {
        clearActive();

        const size = Number(file && file.size != null ? file.size : 0);
        if (isWorkspaceUploadScope() && size > CHUNKED_UPLOAD_THRESHOLD_BYTES) {
          reject(Object.assign(
            new Error(
              `Workspace quota/upload limit exceeded. This large file is ${fmtSize(size)}. ` +
              `Workspace uploads are not chunked yet, so the request can fail before PQ-NAS returns a normal error.`
            ),
            {
              kind: "workspace_large_upload_not_chunked_yet",
              source: "client",
              error: "workspace_upload_limit"
            }
          ));
          return;
        }

        reject(Object.assign(new Error("upload failed (network)"), { kind: "network", source: "client" }));
      };

      xhr.onabort = () => {
        clearActive();
        if (uploadCancelRequested) {
          reject(Object.assign(new Error("upload cancelled"), { kind: "cancelled", source: "client" }));
        } else {
          reject(Object.assign(new Error("upload aborted"), { kind: "network", source: "client" }));
        }
      };

      xhr.onload = () => {
        const status = xhr.status || 0;
        const ct = (xhr.getResponseHeader("Content-Type") || "").toLowerCase();
        const raw = String(xhr.responseText || "").trim();

        let j = null;
        const looksJson = ct.includes("application/json") || raw.startsWith("{") || raw.startsWith("[");
        if (looksJson && raw) {
          try { j = JSON.parse(raw); } catch (_) { j = null; }
        }

        if (status >= 200 && status < 300 && j && j.ok) {
          clearActive();
          resolve(j);
          return;
        }

        if (j && j.error === "file_exists") {
          const err = new Error(j.message || "file already exists");
          err.http = status || 409;
          err.kind = "file_exists";
          err.source = "pqnas";
          err.error = "file_exists";
          err.details = j;
          clearActive();
          reject(err);
          return;
        }

        if (j && isUploadQuotaError({ message: j.message || "", error: j.error || "", details: j })) {
          const err = new Error(uploadQuotaDetailText({ details: j }));
          err.http = status;
          err.kind = "quota_exceeded";
          err.source = "pqnas";
          err.error = j.error || "quota_exceeded";
          err.details = j;
          clearActive();
          reject(err);
          return;
        }

        if (status === 0) {
          const err = new Error("upload failed (network/proxy blocked)");
          err.http = 0;
          err.kind = "network";
          err.source = "gateway";
          clearActive();
          reject(err);
          return;
        }

        if (status === 413) {
          const size = fmtSize(file && file.size != null ? file.size : 0);
          const limit = getEffectiveUploadLimitBytes();
          const limTxt = (limit > 0) ? ` Current upload limit is ${fmtSize(limit)}.` : "";
          const err = new Error(`Quota/upload limit exceeded. File size ${size}.${limTxt}`);
          err.http = 413;
          err.kind = "quota_or_upload_limit";
          err.source = "pqnas";
          clearActive();
          reject(err);
          return;
        }

        if (status === 400) {
          const size = fmtSize(file && file.size != null ? file.size : 0);

          if (j && (j.message || j.error)) {
            const msg = `${j.error || ""} ${j.message || ""}`.trim();
            const err = new Error(msg || "Bad request");
            err.http = status;
            err.kind = "pqnas_error";
            err.source = "pqnas";
            err.details = j;
            clearActive();
            reject(err);
            return;
          }

          const snippet = raw ? shorten(raw.replace(/\s+/g, " "), 200) : "";
          const err = new Error(
              snippet
                  ? `Upload failed (HTTP 400). Server said: ${snippet}`
                  : `Upload failed (HTTP 400). File size ${size}.`
          );
          err.http = 400;
          err.kind = "bad_request";
          err.source = "unknown";
          if (snippet) err.details = snippet;
          clearActive();
          reject(err);
          return;
        }

        if (j && (j.message || j.error)) {
          const msg = `${j.error || ""} ${j.message || ""}`.trim();
          const err = new Error(msg || `HTTP ${status}`);
          err.http = status;
          err.kind = "pqnas_error";
          err.source = "pqnas";
          err.details = j;
          clearActive();
          reject(err);
          return;
        }

        if (raw) {
          const oneLine = shorten(raw.replace(/\s+/g, " "), 160);
          const prefix = ct ? `${ct} ` : "";
          const err = new Error(`${prefix}${oneLine}`.trim() || `HTTP ${status}`);
          err.http = status;
          err.kind = "gateway_error";
          err.source = "gateway";
          clearActive();
          reject(err);
          return;
        }

        const err = new Error(`HTTP ${status}`);
        err.http = status;
        err.kind = "unknown";
        err.source = "unknown";
        clearActive();
        reject(err);
      };

      Promise.resolve()
          .then(() => ensureUploadAllowedOrThrow(file))
          .then(() => xhr.send(file))
          .catch(reject);
    });
  }

  function shorten(s, n) {
    s = String(s || "");
    if (s.length <= n) return s;
    return s.slice(0, Math.max(0, n - 1)) + "…";
  }

  async function uploadRelFiles(relFiles) {
    if (!relFiles.length) return;

    const created = new Set();
    const items = [];
    for (const it of relFiles) {
      const rel = normalizeRelPath(it.rel);
      if (!validateRelPath(rel)) continue;
      items.push({
        rel,
        file: it.file,
        source: it.source || ""
      });
    }

    if (!items.length) {
      setBadge("err", "error");
      status.textContent = "Upload skipped (no valid paths).";
      return;
    }

    const totalFiles = items.length;
    const totalBytes = items.reduce((a, it) => a + (Number(it.file.size) || 0), 0) || 1;

    let doneFiles = 0;
    let uploadedBytesCommitted = 0;
    let failedFiles = 0;
    let skippedFiles = 0;
    const failures = [];
    const uploadBatchStartedAt = performance.now();

    let conflictApplyAll = false;
    let conflictActionAll = ""; // "", "keep_old", "replace"

    lastUploadError = null;
    setUploadPillClickable(false);
    uploadCancelRequested = false;
    activeUploadXhr = null;

    openFileMgrUploadProgressModal(totalFiles, totalBytes);
    setUploadCancelable(true);

    showUploadProgress(true);
    setBadge("warn", "upload…");
    setUploadProgress(0, `Uploading 0/${totalFiles}…`);

    for (let idx = 0; idx < items.length; idx++) {
      const { rel, file } = items[idx];
      if (uploadCancelRequested) break;

      const dir = parentPath(rel);
      if (dir) await mkdirIfNeeded(dir, created);

      let lastLoaded = 0;

      try {
        status.textContent = `Uploading: ${rel} (${fmtSize(file.size)})`;

        const runUpload = async (overwrite = false) => {
          await uploadFileSmartTo(rel, file, (loaded) => {
            lastLoaded = Math.max(lastLoaded, loaded || 0);
            const overall = uploadedBytesCommitted + lastLoaded;
            const pct = (overall / totalBytes) * 100;
            const elapsedSec = Math.max(0.001, (performance.now() - uploadBatchStartedAt) / 1000);
            const speedBps = overall / elapsedSec;

            setBadge("warn", "upload…");
            setUploadProgress(
                pct,
                `Uploading ${doneFiles}/${totalFiles} • ${rel} • ${fmtSize(overall)} / ${fmtSize(totalBytes)} • ${fmtSpeed(speedBps)}`
            );
          }, { overwrite });
        };

        let finishedThisFile = false;
        let skipThisFile = false;

        while (!finishedThisFile && !skipThisFile) {
          try {
            const autoOverwrite = conflictApplyAll && conflictActionAll === "replace";
            await runUpload(autoOverwrite);
            finishedThisFile = true;
          } catch (e) {
            if (e && e.kind === "cancelled") throw e;

            if (isFileExistsConflict(e)) {
              let decision = null;

              if (conflictApplyAll && conflictActionAll) {
                decision = { action: conflictActionAll, applyAll: true };
              } else {
                setBadge("warn", "conflict");
                setUploadProgress(
                    (uploadedBytesCommitted / totalBytes) * 100,
                    `Conflict: ${rel}`,
                    `Already exists: ${rel}`,
                    "warn"
                );

                decision = await askUploadConflictDecision(
                    rel,
                    file,
                    e && e.details ? e.details.existing : null
                );
              }

              if (!decision || decision.action === "cancel") {
                uploadCancelRequested = true;
                throw Object.assign(new Error("upload cancelled"), { kind: "cancelled", source: "client" });
              }

              if (decision.applyAll) {
                conflictApplyAll = true;
                conflictActionAll = decision.action;
              }

              if (decision.action === "keep_old") {
                skipThisFile = true;
                skippedFiles++;
                status.textContent = `Skipped existing file: ${rel}`;
                setBadge("warn", "skipped");
                setUploadProgress(
                    (uploadedBytesCommitted / totalBytes) * 100,
                    `Skipped existing file • ${rel}`,
                    `Kept existing: ${rel}`,
                    "warn"
                );
                break;
              }

              if (decision.action === "replace") {
                await runUpload(true);
                finishedThisFile = true;
                break;
              }
            }

            throw e;
          }
        }

        if (skipThisFile) {
          continue;
        }

        uploadedBytesCommitted += (Number(file.size) || lastLoaded || 0);
        doneFiles++;

        const pct = (uploadedBytesCommitted / totalBytes) * 100;
        const elapsedSec = Math.max(0.001, (performance.now() - uploadBatchStartedAt) / 1000);
        const speedBps = uploadedBytesCommitted / elapsedSec;

        setUploadProgress(
            pct,
            `Uploaded ${doneFiles}/${totalFiles} • ${rel} • ${fmtSpeed(speedBps)}`
        );
      } catch (e) {
        if (e && e.kind === "cancelled") {
          setBadge("warn", "cancelled");
          status.textContent = `Upload cancelled. Uploaded ${doneFiles}/${totalFiles}, skipped ${skippedFiles}.`;

          const pct = (uploadedBytesCommitted / totalBytes) * 100;
          setUploadProgress(
              pct,
              `Upload cancelled • Uploaded ${doneFiles}/${totalFiles} • Skipped ${skippedFiles}`,
              "",
              "warn"
          );

          setTimeout(() => {
            refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
            load().catch(() => {});
          }, 500);

          break;
        }

        failedFiles++;

        const msg = String(e && e.message ? e.message : e);
        const http = (e && Number.isFinite(e.http)) ? e.http : extractHttpStatusFromMsg(msg);
        const errSource = e && e.source ? String(e.source) : "";
        const kind = e && e.kind ? String(e.kind) : "";

        const summary = classifyUploadSummary(e);

        failures.push({ rel, message: msg, http, kind, source: errSource });

        lastUploadError = {
          file: rel,
          summary,
          message: msg,
          http,
          kind,
          source: errSource,
          error: e && e.error ? e.error : "",
          details: e && e.details ? e.details : null,
          atMs: Date.now()
        };

        setBadge("err", "error");
        status.textContent = `Upload failed: ${rel} — ${msg}`;

        const isHardStop =
            (summary === "Quota exceeded") ||
            (summary === "Quota/upload limit exceeded") ||
            (summary === "Gateway rejected before PQ-NAS");

        const pct = isHardStop ? 100 : (uploadedBytesCommitted / totalBytes) * 100;

        const pillText = uploadModalFailureMeta(e, rel, msg);

        setUploadProgress(
            pct,
            uploadModalFailureText(summary, msg),
            pillText,
            "err"
        );

        setUploadPillClickable(true);
      }
    }

    if (failedFiles > 0) {
      setBadge("err", "partial");

      const pct = (uploadedBytesCommitted > 0) ? (uploadedBytesCommitted / totalBytes) * 100 : 100;
      const lastSummary = lastUploadError ? lastUploadError.summary : "Upload failed";
      const pillText = lastUploadError
          ? uploadModalFailureMeta(lastUploadError, lastUploadError.file, lastUploadError.message)
          : "";

      const finalLine = lastUploadError
          ? uploadModalFailureText(lastSummary, lastUploadError.message)
          : `Upload finished • Uploaded ${doneFiles}/${totalFiles} • Skipped ${skippedFiles} • Failed ${failedFiles} • ${lastSummary}`;

      setUploadProgress(
          pct,
          finalLine,
          pillText,
          "err"
      );

      const full = lastUploadError
          ? lastUploadError.message
          : (failures.length ? failures[failures.length - 1].message : "Upload failed");

      status.textContent =
          `Upload finished with errors. Uploaded ${doneFiles}/${totalFiles}, skipped ${skippedFiles}, failed ${failedFiles}. ` +
          `Last error: ${String(full || "").trim()}`;

      console.warn("Upload failures:", failures);
      setUploadPillClickable(!!lastUploadError);

    } else {
      setBadge("ok", "ready");
      setUploadProgress(
          100,
          `Upload finished • Uploaded ${doneFiles}/${totalFiles} • Skipped ${skippedFiles}`
      );
      status.textContent = `Upload finished. Uploaded: ${doneFiles}/${totalFiles}. Skipped: ${skippedFiles}.`;
      lastUploadError = null;
      setUploadPillClickable(false);
      setTimeout(() => showUploadProgress(false), 900);
    }

    setUploadCancelable(false);
    activeUploadXhr = null;
    uploadCancelRequested = false;
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    clearFileListCache();
    await load(true);
  }

  function pickFiles() {
    if (!requireWritableScopeOrExplain("Upload")) return;
    if (!filePick) return;
    filePick.value = "";
    filePick.click();
  }

  function pickFolder() {
    if (!requireWritableScopeOrExplain("Upload folder")) return;
    if (!folderPick) return;
    folderPick.value = "";
    folderPick.click();
  }

  filePick?.addEventListener("change", async () => {
    const files = Array.from(filePick.files || []);
    const relFiles = files.map(f => ({ rel: f.name, file: f, source: "picker" }));
    await uploadRelFiles(relFiles);
    filePick.value = "";
  });

  folderPick?.addEventListener("change", async () => {
    const files = Array.from(folderPick.files || []);
    const relFiles = files.map(f => ({
      rel: f.webkitRelativePath || f.name,
      file: f,
      source: "picker"
    }));
    await uploadRelFiles(relFiles);
    folderPick.value = "";
  });

  function hasFiles(dt) {
    if (!dt) return false;
    try { if (dt.files && dt.files.length > 0) return true; } catch (_) {}
    try { if (dt.items && dt.items.length > 0) return true; } catch (_) {}
    try {
      const types = Array.from(dt.types || []);
      return types.includes("Files") || types.includes("application/x-moz-file");
    } catch (_) {}
    return false;
  }

  function readEntryAsFile(entry) {
    return new Promise((resolve) => {
      entry.file((file) => resolve(file), () => resolve(null));
    });
  }

  async function walkEntry(entry, prefix, out) {
    if (!entry) return;

    if (entry.isFile) {
      const f = await readEntryAsFile(entry);
      if (f) out.push({ rel: prefix + f.name, file: f, source: "drop" });
      return;
    }

    if (entry.isDirectory) {
      const dirReader = entry.createReader();
      const name = entry.name ? (entry.name + "/") : "";
      const nextPrefix = prefix + name;

      while (true) {
        const batch = await new Promise((resolve) => {
          dirReader.readEntries(resolve, () => resolve([]));
        });
        if (!batch || !batch.length) break;
        for (const child of batch) await walkEntry(child, nextPrefix, out);
      }
    }
  }

  async function collectDroppedFiles(dt) {
    const out = [];
    const items = dt && dt.items ? Array.from(dt.items) : [];
    const hasEntryApi = items.some(it => it && typeof it.webkitGetAsEntry === "function");
    if (hasEntryApi) {
      for (const it of items) {
        if (!it) continue;
        const entry = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
        if (!entry) continue;
        await walkEntry(entry, "", out);
      }
      return out;
    }

    const files = Array.from(dt.files || []);
    for (const f of files) out.push({ rel: f.name, file: f, source: "drop" });
    return out;
  }

  gridWrap?.addEventListener("dragenter", (e) => {
    e.preventDefault();
    if (storageBlocked) return;
    if (hasFiles(e.dataTransfer)) showDropOverlay(true);
  });

  gridWrap?.addEventListener("dragover", (e) => {
    e.preventDefault();
    if (storageBlocked) {
      if (e.dataTransfer) e.dataTransfer.dropEffect = "none";
      showDropOverlay(false);
      return;
    }
    if (e.dataTransfer) e.dataTransfer.dropEffect = "copy";
    showDropOverlay(true);
  });

  gridWrap?.addEventListener("dragleave", (e) => {
    if (e.target === gridWrap) showDropOverlay(false);
  });

  gridWrap?.addEventListener("drop", async (e) => {
    e.preventDefault();
    showDropOverlay(false);

    if (!requireWritableScopeOrExplain("Upload")) return;

    try {
      const dt = e.dataTransfer;
      if (!dt || (!dt.files || dt.files.length === 0)) {
        showTransientWarning(
            "Drag & drop did not provide files. Firefox on Linux may block file drops here — use Upload instead."
        );
        return;
      }

      const relFiles = await collectDroppedFiles(dt);

      if (!relFiles || relFiles.length === 0) {
        setBadge("err", "error");
        status.textContent = "Drop contained no files.";
        return;
      }

      await uploadRelFiles(relFiles);
    } catch (err) {
      setBadge("err", "error");
      const msg = String(err && err.message ? err.message : err);
      const low = msg.toLowerCase();

      if (low.includes("aborted")) {
        status.textContent = "Firefox drag & drop failed while reading the dropped file. Use Upload files… instead.";
      } else {
        status.textContent = `Drop upload failed: ${msg}`;
      }

      console.error("Drop failed:", err);
    }
  });

  function closeMenu() {
    if (!ctxEl) return;
    ctxEl.classList.remove("show");
    ctxEl.setAttribute("aria-hidden", "true");
    ctxEl.innerHTML = "";
    ctxOpenForKey = "";
  }

  function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

  function placeMenu(x, y) {
    ctxEl.style.left = "0px";
    ctxEl.style.top = "0px";
    ctxEl.classList.add("show");

    const rect = ctxEl.getBoundingClientRect();
    const pad = 8;
    const nx = clamp(x, pad, window.innerWidth - rect.width - pad);
    const ny = clamp(y, pad, window.innerHeight - rect.height - pad);

    ctxEl.style.left = `${nx}px`;
    ctxEl.style.top = `${ny}px`;
  }

  function menuItem(label, rightHint, onClick, opts = {}) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = `ctxItem${opts.danger ? " danger" : ""}`;
    b.textContent = label;

    if (rightHint) {
      const r = document.createElement("span");
      r.style.opacity = "0.7";
      r.style.fontWeight = "800";
      r.textContent = rightHint;
      b.appendChild(r);
    }

    b.addEventListener("click", () => {
      closeMenu();
      onClick();
    });

    return b;
  }

  function menuSep() {
    const d = document.createElement("div");
    d.className = "ctxSep";
    return d;
  }

  function buildSelectionMenuOnly() {
    if (!ctxEl) return;

    const stats = selectedFavoriteStats();
    const caps = fmCaps();
    const allFav = stats.total > 0 && stats.fav === stats.total;
    const someFav = stats.fav > 0 && stats.fav < stats.total;

    ctxEl.innerHTML = "";
    if (caps.properties !== false) {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.selection_properties", null, "Properties (selection)…"), "", () => showSelectionProperties()));
      ctxEl.appendChild(menuSep());
    }

    if (caps.favorites !== false) {
      if (!allFav) ctxEl.appendChild(menuItem(tr("filemgr.menu.add_selection_favorites", { count: stats.total }, `Add selection to favorites (${stats.total})`), "", async () => await addSelectionToFavorites()));
      if (someFav || allFav) ctxEl.appendChild(menuItem(tr("filemgr.menu.remove_selection_favorites", { count: stats.fav }, `Remove selection from favorites (${stats.fav})`), "", async () => await removeSelectionFromFavorites()));
      ctxEl.appendChild(menuSep());
    }

    if (caps.zipSelection !== false) {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.download_selection_zip", { count: selectedKeys.size }, `Download selection (zip) (${selectedKeys.size})`), "", () => downloadSelectionZip()));
    }

    if (canWriteCurrentScope()) {
      ctxEl.appendChild(menuSep());
      if (caps.copy !== false) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.copy_selection", { count: selectedKeys.size }, `Copy selection… (${selectedKeys.size})`), "", () => openCopyModalForSelection()));
      }
      if (caps.move !== false) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.move_selection", { count: selectedKeys.size }, `Move selection… (${selectedKeys.size})`), "", () => openMoveModalForSelection()));
      }
      ctxEl.appendChild(menuItem(tr("filemgr.menu.move_selection_trash", { count: selectedKeys.size }, `Move selection to trash (${selectedKeys.size})…`), "🗑", () => deleteSelection(), { danger: true }));
    }
  }

  function currentRelPathFor(item) {
    return joinPath(curPath, item.name);
  }

  function doDownload(item) {
    const p = currentRelPathFor(item);
    window.location.href = apiGetUrl(p);
  }
  function doOpenOriginal(item) {
    const p = currentRelPathFor(item);
    window.open(apiGetUrl(p), "_blank", "noopener");
  }
  function downloadFolderZip(relDir) {
    const p = relDir || "";
    window.location.href = apiZipUrl(p);
  }
  function keyToItemRelPath(key) {
    const s = String(key || "");
    const i = s.indexOf(":");
    if (i < 0) return null;
    const name = s.slice(i + 1);
    if (!name) return null;
    return curPath ? `${curPath}/${name}` : name;
  }

  async function showSelectionProperties() {
    const paths = selectedRelPaths();
    if (!paths.length) return;

    if (propsTitle) propsTitle.textContent = `Selection properties`;
    if (propsPath) propsPath.textContent = `${paths.length} item(s)`;
    if (propsBody) propsBody.innerHTML = "";

    const rows = [];
    rows.push(["Items", String(paths.length)]);
    rows.push(["Favorites", String(selectedFavoriteStats().fav)]);
    rows.push([propLabel("details"), tr("filemgr.props.loading", null, "Loading…")]);

    if (propsBody) {
      for (const [k, v] of rows) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    let st = null;
    try {
      const r = await fetch(apiStatSelUrl(), {
        method: "POST",
        credentials: "include",
        cache: "no-store",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({ paths })
      });
      st = await r.json().catch(() => null);
    } catch (e) {
      st = { ok: false, error: "client_error", message: String(e && e.message ? e.message : e) };
    }

    if (!propsBody) { openPropsModal(); return; }
    propsBody.innerHTML = "";

    if (!st || !st.ok) {
      const msg = (st && (st.message || st.error))
          ? `${st.error || "error"}: ${st.message || ""}`.trim()
          : "Failed to load selection properties";

      for (const [k, v] of [["Items", String(paths.length)], ["Favorites", String(selectedFavoriteStats().fav)], ["Error", msg]]) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
      openPropsModal();
      return;
    }

    const pushRow = (arr, k, v) => {
      if (v === undefined || v === null || v === "") return;
      arr.push([k, v]);
    };

    const rows2 = [];
    pushRow(rows2, "Items", String(st.count != null ? st.count : paths.length));
    pushRow(rows2, "Favorites", String(selectedFavoriteStats().fav));
    pushRow(rows2, "Files", st.files != null ? String(st.files) : "");
    pushRow(rows2, "Folders", st.dirs != null ? String(st.dirs) : "");
    if (st.other != null && st.other !== 0) pushRow(rows2, "Other", String(st.other));
    if (st.bytes_total != null) pushRow(rows2, "Total size", fmtSize(st.bytes_total));

    if (typeof st.partial === "boolean") {
      pushRow(rows2, "Complete", st.partial ? "No (partial)" : "Yes");
    }

    if (st.limits) {
      if (st.limits.max_items != null) pushRow(rows2, "Max items", String(st.limits.max_items));
      if (st.limits.time_cap_ms != null) pushRow(rows2, "Dir scan time cap", `${st.limits.time_cap_ms} ms`);
      if (st.limits.scan_cap != null) pushRow(rows2, "Dir scan entry cap", String(st.limits.scan_cap));
    }

    const errCount = Array.isArray(st.errors) ? st.errors.length : 0;
    if (errCount) pushRow(rows2, "Errors", String(errCount));

    const rawDetails = document.createElement("details");
    const summary = document.createElement("summary");
    summary.textContent = tr("filemgr.props.raw_json", null, "Raw JSON");
    rawDetails.appendChild(summary);

    const pre = document.createElement("pre");
    pre.className = "pre mono";
    pre.textContent = JSON.stringify(st, null, 2);
    rawDetails.appendChild(pre);

    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    {
      const kEl = document.createElement("div");
      kEl.className = "k";
      kEl.textContent = "";
      const vEl = document.createElement("div");
      vEl.className = "v mono";
      vEl.appendChild(rawDetails);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    openPropsModal();
  }

  function isoUtcToMs(iso) {
    if (!iso) return 0;
    const t = Date.parse(iso);
    return Number.isFinite(t) ? t : 0;
  }

  function fmtCountdown(msLeft) {
    if (msLeft <= 0) return "expired";
    const sec = Math.floor(msLeft / 1000);
    const d = Math.floor(sec / 86400);
    const h = Math.floor((sec % 86400) / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;

    if (d > 0) return `${d}d ${h}h ${m}m`;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function fullShareUrl(urlPath) {
    if (!urlPath) return "";
    if (urlPath.startsWith("http://") || urlPath.startsWith("https://")) return urlPath;
    return `${window.location.origin}${urlPath}`;
  }

  function selectedRelPaths() {
    const out = [];
    for (const k of selectedKeys) {
      const p = keyToItemRelPath(k);
      if (p) out.push(p);
    }
    out.sort((a, b) => String(a).localeCompare(String(b)));
    return out;
  }

  async function downloadSelectionZip() {
    const paths = selectedRelPaths();
    if (!paths.length) {
      status.textContent = tr("filemgr.common.nothing_selected", null, "Nothing selected.");
      return;
    }

    setBadge("warn", "zip…");
    status.textContent = `Preparing zip (${paths.length} items)…`;

    const r = await fetch(apiZipSelUrl(), {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ paths, base: curPath })
    });

    if (!r.ok) {
      const t = await r.text().catch(() => "");
      setBadge("err", "error");
      status.textContent = `Zip failed: HTTP ${r.status}${t ? " — " + t : ""}`;
      return;
    }

    const blob = await r.blob();

    const cd = r.headers.get("Content-Disposition") || "";
    let filename = "pqnas_selection.zip";
    const m = cd.match(/filename="([^"]+)"/i);
    if (m && m[1]) filename = m[1];

    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    setBadge("ok", "ready");
    status.textContent = `Downloaded: ${filename}`;
  }



  async function fmConfirmModal(opts) {
    return new Promise((resolve) => {
      const options = opts || {};

      const modal = document.createElement("div");
      modal.className = "modal show";
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");

      const card = document.createElement("div");
      card.className = "modalCard";
      card.style.width = "min(560px, calc(100vw - 24px))";

      const head = document.createElement("div");
      head.className = "modalHead";

      const headText = document.createElement("div");

      const title = document.createElement("div");
      title.className = "modalTitle";
      title.textContent = options.title || "Confirm action";

      const sub = document.createElement("div");
      sub.className = "modalSub";
      sub.textContent = options.subtitle || "";

      headText.appendChild(title);
      if (sub.textContent) headText.appendChild(sub);
      head.appendChild(headText);

      const body = document.createElement("div");
      body.className = "modalBody";
      body.style.gridTemplateColumns = "130px 1fr";

      const rows = Array.isArray(options.rows) ? options.rows : [];
      for (const row of rows) {
        const k = document.createElement("div");
        k.className = "k";
        k.textContent = String(row.label || "");

        const v = document.createElement("div");
        v.className = row.mono ? "v mono" : "v";
        v.textContent = String(row.value || "");

        body.appendChild(k);
        body.appendChild(v);
      }

      if (options.warning) {
        const warn = document.createElement("div");
        warn.className = "v";
        warn.style.gridColumn = "1 / -1";
        warn.style.padding = "10px 12px";
        warn.style.border = "1px solid rgba(var(--warn-rgb),0.35)";
        warn.style.borderRadius = "14px";
        warn.style.background = "rgba(var(--warn-rgb),0.10)";
        warn.style.color = "var(--fg)";
        warn.style.fontWeight = "850";
        warn.textContent = String(options.warning || "");
        body.appendChild(warn);
      }

      if (options.note) {
        const note = document.createElement("div");
        note.className = "v";
        note.style.gridColumn = "1 / -1";
        note.style.opacity = "0.9";
        note.textContent = String(options.note || "");
        body.appendChild(note);
      }

      const foot = document.createElement("div");
      foot.className = "modalFoot";

      const spacer = document.createElement("div");
      spacer.style.flex = "1 1 auto";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn secondary";
      cancelBtn.textContent = options.cancelText || "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "btn";
      okBtn.textContent = options.confirmText || "OK";

      if (options.danger) {
        okBtn.style.borderColor = "rgba(var(--fail-rgb),0.45)";
        okBtn.style.background = "rgba(var(--fail-rgb),0.14)";
        okBtn.style.color = "var(--fg)";
      }

      foot.appendChild(spacer);
      foot.appendChild(cancelBtn);
      foot.appendChild(okBtn);

      card.appendChild(head);
      card.appendChild(body);
      card.appendChild(foot);
      modal.appendChild(card);
      document.body.appendChild(modal);

      const finish = (value) => {
        document.removeEventListener("keydown", onKey, true);
        modal.remove();
        resolve(!!value);
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
          finish(false);
          return;
        }

        if (e.key === "Enter") {
          e.preventDefault();
          e.stopPropagation();
          finish(true);
        }
      };

      document.addEventListener("keydown", onKey, true);

      modal.addEventListener("click", (e) => {
        if (e.target === modal) finish(false);
      });

      cancelBtn.addEventListener("click", () => finish(false));
      okBtn.addEventListener("click", () => finish(true));

      setTimeout(() => {
        if (options.danger) cancelBtn.focus();
        else okBtn.focus();
      }, 0);
    });
  }

  async function fmPromptModal(opts) {
    return new Promise((resolve) => {
      const options = opts || {};

      const modal = document.createElement("div");
      modal.className = "modal show";
      modal.setAttribute("role", "dialog");
      modal.setAttribute("aria-modal", "true");

      const card = document.createElement("div");
      card.className = "modalCard";
      card.style.width = "min(560px, calc(100vw - 24px))";

      const head = document.createElement("div");
      head.className = "modalHead";

      const headText = document.createElement("div");

      const title = document.createElement("div");
      title.className = "modalTitle";
      title.textContent = options.title || "Enter value";

      const sub = document.createElement("div");
      sub.className = "modalSub";
      sub.textContent = options.subtitle || "";

      headText.appendChild(title);
      if (sub.textContent) headText.appendChild(sub);
      head.appendChild(headText);

      const body = document.createElement("div");
      body.className = "modalBody";
      body.style.gridTemplateColumns = "1fr";

      const label = document.createElement("label");
      label.className = "k";
      label.textContent = options.label || "Name";

      const input = document.createElement("input");
      input.type = "text";
      input.value = options.value || "";
      input.placeholder = options.placeholder || "";
      input.autocomplete = "off";
      input.spellcheck = false;
      input.style.width = "100%";
      input.style.padding = "10px 12px";
      input.style.borderRadius = "12px";
      input.style.border = "1px solid var(--border2)";
      input.style.background = "rgba(0,0,0,0.22)";
      input.style.color = "var(--fg)";
      input.style.font = "inherit";
      input.style.fontFamily = "var(--mono)";

      const help = document.createElement("div");
      help.className = "v";
      help.style.opacity = "0.78";
      help.style.fontSize = "12px";
      help.textContent = options.help || "";

      const err = document.createElement("div");
      err.className = "v";
      err.style.display = "none";
      err.style.padding = "8px 10px";
      err.style.border = "1px solid rgba(var(--fail-rgb),0.35)";
      err.style.borderRadius = "12px";
      err.style.background = "rgba(var(--fail-rgb),0.10)";
      err.style.color = "var(--fg)";
      err.style.fontWeight = "850";

      body.appendChild(label);
      body.appendChild(input);
      if (help.textContent) body.appendChild(help);
      body.appendChild(err);

      const foot = document.createElement("div");
      foot.className = "modalFoot";

      const spacer = document.createElement("div");
      spacer.style.flex = "1 1 auto";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "btn secondary";
      cancelBtn.textContent = options.cancelText || "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "btn";
      okBtn.textContent = options.confirmText || "OK";

      foot.appendChild(spacer);
      foot.appendChild(cancelBtn);
      foot.appendChild(okBtn);

      card.appendChild(head);
      card.appendChild(body);
      card.appendChild(foot);
      modal.appendChild(card);
      document.body.appendChild(modal);

      const showError = (text) => {
        err.textContent = text || "";
        err.style.display = text ? "block" : "none";
      };

      const finish = (value) => {
        document.removeEventListener("keydown", onKey, true);
        modal.remove();
        resolve(value);
      };

      const submit = () => {
        const raw = input.value || "";
        const value = raw.trim();

        if (options.required !== false && !value) {
          showError(options.requiredMessage || "Name is required.");
          input.focus();
          return;
        }

        if (typeof options.validate === "function") {
          const msg = options.validate(value, raw);
          if (msg) {
            showError(msg);
            input.focus();
            return;
          }
        }

        finish(value);
      };

      const onKey = (e) => {
        if (e.key === "Escape") {
          e.preventDefault();
          e.stopPropagation();
          finish(null);
          return;
        }

        if (e.key === "Enter") {
          e.preventDefault();
          e.stopPropagation();
          submit();
        }
      };

      document.addEventListener("keydown", onKey, true);

      modal.addEventListener("click", (e) => {
        if (e.target === modal) finish(null);
      });

      cancelBtn.addEventListener("click", () => finish(null));
      okBtn.addEventListener("click", submit);

      setTimeout(() => {
        input.focus();
        input.select();
      }, 0);
    });
  }

  async function doRename(item) {
    if (!requireWritableScopeOrExplain(tr("filemgr.action.rename", null, "Rename"))) return;
    const oldRel = currentRelPathFor(item);
    const oldName = String(item.name || "");
    const newName = await fmPromptModal({
      title: tr("filemgr.rename.title", null, "Rename item"),
      subtitle: tr("filemgr.rename.subtitle", null, "Choose a new name for this file or folder."),
      label: tr("filemgr.rename.label", null, "New name"),
      value: oldName,
      help: tr("filemgr.rename.help", null, "Use only the item name, not a full path."),
      confirmText: tr("filemgr.rename.confirm", null, "Rename"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      validate(value) {
        if (!value) return tr("filemgr.rename.required", null, "Name is required.");
        if (value === oldName) return tr("filemgr.rename.unchanged", null, "Name is unchanged.");
        if (value.includes("/") || value.includes("\\")) return tr("filemgr.rename.path_separators", null, "Name cannot contain path separators.");
        if (value === "." || value === "..") return tr("filemgr.rename.invalid", null, "Invalid name.");
        return "";
      },
    });
    if (!newName) return;

    if (newName.includes("/") || newName.includes("\\")) {
      alert(tr("filemgr.rename.path_separators", null, "Name cannot contain path separators."));
      return;
    }

    const base = parentPath(oldRel);
    const newRel = base ? `${base}/${newName}` : newName;
    if (newRel === oldRel) return;

    setBadge("warn", "working…");
    status.textContent = tr("filemgr.rename.working", null, "Renaming…");

    const url = apiMoveUrl(oldRel, newRel);
    const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      setBadge("err", "error");
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = tr("filemgr.rename.failed", { error: msg }, `Rename failed: ${msg}`);
      return;
    }

    try {
      await fetchFavoritesFromServer();
    } catch (e) {
      console.warn("Favorites refresh after rename failed:", e);
    }

    status.textContent = tr("filemgr.rename.done", null, "Renamed.");
    setBadge("ok", "ready");
    clearSelection();
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    clearFileListCache();
    await load(true);
  }

  // ---- Move modal ------------------------------------------------------------

  let moveItems = [];
  let moveDestPath = "";

  function basenamePath(p) {
    const parts = normalizeRelPath(p).split("/").filter(Boolean);
    return parts.length ? parts[parts.length - 1] : "";
  }

  function pathEq(a, b) {
    return normalizeRelPath(a) === normalizeRelPath(b);
  }

  function isSameOrDescendant(path, ancestor) {
    const p = normalizeRelPath(path);
    const a = normalizeRelPath(ancestor);
    if (!a) return false;
    return p === a || p.startsWith(a + "/");
  }

  function destinationInsideSelectedDir(destPath, items) {
    const dest = normalizeRelPath(destPath);
    for (const it of items || []) {
      if (it && it.type === "dir" && isSameOrDescendant(dest, it.rel)) return true;
    }
    return false;
  }

  function moveDestinationProblem(destPath, items, modeOpts = {}) {
    const dest = normalizeRelPath(destPath);
    const list = Array.isArray(items) ? items : [];

    if (!list.length) return tr("filemgr.common.nothing_selected", null, "Nothing selected.");

    if (destinationInsideSelectedDir(dest, list)) {
      return tr("filemgr.move.cannot_move_inside_self", null, "Cannot move a folder into itself or one of its subfolders.");
    }

    const allAlreadyHere = list.every((it) => pathEq(parentPath(it.rel), dest));
    if (modeOpts.sameScope !== false && allAlreadyHere) {
      return tr("filemgr.common.choose_different_destination", null, "Choose a different destination folder.");
    }

    return "";
  }
function describeMoveItems(items) {
    const list = Array.isArray(items) ? items : [];
    if (list.length === 1) return tr("filemgr.move.single_source", { path: list[0].rel }, `Move: /${list[0].rel}`);

    const names = list.slice(0, 4).map((it) => it.name || basenamePath(it.rel)).join(", ");
    const more = list.length > 4 ? tr("filemgr.move.more", { count: list.length - 4 }, `, +${list.length - 4} more`) : "";
    return tr("filemgr.move.multi_source", { count: list.length, names, more }, `Move ${list.length} item(s): ${names}${more}`);
  }

  async function collectAffectedSharesForMove(items) {
    const list = Array.isArray(items) ? items : [];
    const out = [];
    const seen = new Set();

    try {
      await refreshSharesCache(true);
    } catch (e) {
      console.warn("Share refresh before move warning failed:", e);
      return {
        ok: false,
        items: [],
        error: String(e && e.message ? e.message : e)
      };
    }

    for (const share of sharesByKey.values()) {
      if (!share || typeof share !== "object") continue;
      if (isShareExpired(share)) continue;

      const sharePath = normalizeRelPath(share.path || "");
      if (!sharePath) continue;

      const shareType = share.type === "dir" ? "dir" : "file";
      const token = String(share.token || "");
      const dedupeKey = token || `${shareType}:${sharePath}:${String(share.mode || "")}`;
      if (seen.has(dedupeKey)) continue;

      let affected = false;

      for (const it of list) {
        if (!it || !it.rel) continue;
        const src = normalizeRelPath(it.rel);

        if (it.type === "dir") {
          if (sharePath === src || sharePath.startsWith(src + "/")) {
            affected = true;
            break;
          }
        } else if (sharePath === src) {
          affected = true;
          break;
        }
      }

      if (!affected) continue;

      seen.add(dedupeKey);
      out.push({
        path: sharePath,
        type: shareType,
        mode: String(share.mode || share.share_mode || ""),
        token
      });
    }

    return {
      ok: true,
      items: out,
      error: ""
    };
  }

  function shareMoveWarningLabel(share) {
    const mode = String(share && share.mode ? share.mode : "").toLowerCase();
    const isPq = mode.includes("pq");
    const kind = isPq ? tr("filemgr.move.share_kind_pq", null, "PQ share") : tr("filemgr.move.share_kind_standard", null, "Share link");
    const path = share && share.path ? share.path : "";
    return `${kind}: /${path}`;
  }

  function buildMoveConfirmText(destShown, affectedSharesResult) {
    const base = tr(
        "filemgr.move.confirm",
        { count: moveItems.length, dest: destShown },
        `Move ${moveItems.length} item(s) to:\n\n${destShown}\n\nExisting destination names will fail; nothing is overwritten.`
    );

    if (!affectedSharesResult || affectedSharesResult.ok !== true) {
      return tr("filemgr.move.confirm_unverified", { base }, `${base}\n\nWarning:\nCould not verify whether selected items have active share links.`);
    }

    const affected = affectedSharesResult.items || [];
    if (!affected.length) return base;

    const preview = affected.slice(0, 6).map(shareMoveWarningLabel).join("\n");
    const more = affected.length > 6
        ? tr("filemgr.move.more_shares", { count: affected.length - 6 }, `\n… plus ${affected.length - 6} more`)
        : "";

    return tr(
        "filemgr.move.confirm_breaks_shares",
        { base, count: affected.length, preview, more },
        `${base}\n\nWarning:\nMoving these item(s) will break ${affected.length} active share/PQ share link(s). The old public URLs will return Not found after the move.\n\n${preview}${more}`
    );
  }

  function collectSelectedMoveItems() {
    const out = [];

    for (const k of selectedKeys) {
      const rel = keyToItemRelPath(k);
      if (!rel) continue;

      const type = String(k).startsWith("dir:") ? "dir" : "file";
      const name = basenamePath(rel);

      if (!name) continue;
      out.push({ rel: normalizeRelPath(rel), type, name });
    }

    out.sort((a, b) => String(a.rel).localeCompare(String(b.rel)));
    return out;
  }

  async function openMoveModalForItems(items) {
    if (!requireWritableScopeOrExplain(tr("filemgr.move.title", null, "Move"))) return;

    const picker = window.PQNAS_FOLDER_PICKER;
    if (!picker || typeof picker.open !== "function") {
      status.textContent = tr("filemgr.move.dialog_missing", null, "Move dialog failed: shared folder picker module is not loaded. Refresh the page.");
      return;
    }

    const clean = (Array.isArray(items) ? items : [])
      .map((it) => {
        const rawRel = it && (it.rel || it.path || it.relPath || "");
        const rel = normalizeRelPath(rawRel || (it ? currentRelPathFor(it) : ""));
        if (!rel) return null;

        const type = String((it && it.type) || "file") === "dir" ? "dir" : "file";
        return Object.assign({}, it || {}, { rel, type });
      })
      .filter(Boolean);

    if (!clean.length) {
      status.textContent = tr("filemgr.common.nothing_selected", null, "Nothing selected.");
      return;
    }

    moveItems = clean;

    const blockedPaths = clean
      .filter((it) => it.type === "dir")
      .map((it) => it.rel);

    const picked = await picker.open({
      title: tr("filemgr.move.title", null, "Move"),
      subtitle: tr("filemgr.move.subtitle", null, "Select destination folder"),
      source: describeMoveItems(clean),
      initialPath: curPath || "",
      chooseLabel: tr("filemgr.move.choose_here", null, "Move here"),
      canCreate: canWriteCurrentScope(),
      blockedPaths,
      listUrl: (path) => apiListUrl(path || ""),
      mkdirUrl: (path) => apiMkdirUrl(path || "")
    });

    if (picked === null) {
      status.textContent = tr("filemgr.move.cancelled", null, "Move cancelled.");
      return;
    }

    moveDestPath = normalizeRelPath(picked);

    const problem = moveDestinationProblem(moveDestPath, moveItems);
    if (problem) {
      status.textContent = problem;
      return;
    }

    const destShown = moveDestPath ? `/${moveDestPath}` : "/";

    status.textContent = tr("filemgr.move.checking_shares", null, "Checking share links…");
    const affectedSharesResult = await collectAffectedSharesForMove(moveItems);

    const ok = confirm(buildMoveConfirmText(destShown, affectedSharesResult));
    if (!ok) {
      status.textContent = tr("filemgr.move.cancelled", null, "Move cancelled.");
      return;
    }

    await moveItemsToDestination(moveItems, moveDestPath);
  }

  function openMoveModalForItem(item) {
    if (!item) return;

    const rel = currentRelPathFor(item);
    openMoveModalForItems([{
      rel,
      type: item.type === "dir" ? "dir" : "file",
      name: item.name || basenamePath(rel)
    }]);
  }

  function openMoveModalForSelection() {
    openMoveModalForItems(collectSelectedMoveItems());
  }

  function copyDestinationProblem(destPath, items, modeOpts = {}) {
    const dest = normalizeRelPath(destPath);
    const list = Array.isArray(items) ? items : [];

    if (!list.length) return tr("filemgr.common.nothing_selected", null, "Nothing selected.");

    const firstDir = list.find((it) => it && it.type === "dir");
    if (firstDir && modeOpts.crossScope) {
      return tr("filemgr.copy.cross_scope_files_only", null, "Cross-scope copy currently supports files only. Folder copy comes next.");
    }

    const allAlreadyHere = list.every((it) => pathEq(parentPath(it.rel), dest));
    if (modeOpts.sameScope !== false && allAlreadyHere) {
      return tr("filemgr.common.choose_different_destination", null, "Choose a different destination folder.");
    }

    return "";
  }

  function describeCopyItems(items) {
    const list = Array.isArray(items) ? items : [];
    if (list.length === 1) return tr("filemgr.copy.single_source", { path: list[0].rel }, `Copy: /${list[0].rel}`);

    const names = list.slice(0, 4).map((it) => it.name || basenamePath(it.rel)).join(", ");
    const more = list.length > 4 ? tr("filemgr.move.more", { count: list.length - 4 }, `, +${list.length - 4} more`) : "";
    return tr("filemgr.copy.multi_source", { count: list.length, names, more }, `Copy ${list.length} item(s): ${names}${more}`);
  }

  function collectSelectedCopyItems() {
    return collectSelectedMoveItems();
  }

  function copyScopeIdFromSnapshot(snap) {
    if (!snap || !snap.inWorkspace) return "user";
    return `workspace:${String(snap.workspaceId || "")}`;
  }

  function copyScopeNameFromSnapshot(snap) {
    if (!snap || !snap.inWorkspace) return tr("filemgr.my_files", null, "My Files");
    return `Workspace ${String(snap.workspaceId || "?")}`;
  }

  function sameLogicalScopeSnapshot(a, b) {
    if (!a || !b) return false;
    if (!!a.inWorkspace !== !!b.inWorkspace) return false;
    if (!a.inWorkspace) return true;
    return String(a.workspaceId || "") === String(b.workspaceId || "");
  }

  function apiCopyScopeUrl(sourceSnap, destSnap, from, to) {
    const qs = new URLSearchParams();

    const fromScope = sourceSnap && sourceSnap.inWorkspace ? "workspace" : "user";
    const toScope = destSnap && destSnap.inWorkspace ? "workspace" : "user";

    qs.set("from_scope", fromScope);
    qs.set("to_scope", toScope);

    if (fromScope === "workspace") {
      qs.set("from_workspace_id", String(sourceSnap.workspaceId || ""));
    }
    if (toScope === "workspace") {
      qs.set("to_workspace_id", String(destSnap.workspaceId || ""));
    }

    qs.set("from", from || "");
    qs.set("to", to || "");

    return `/api/v4/files/copy_scope?${qs.toString()}`;
  }

  function workspaceListUrlForCopy(workspaceId, path) {
    const qs = new URLSearchParams();
    qs.set("workspace_id", workspaceId || "");
    if (path) qs.set("path", path);
    return `/api/v4/workspaces/files/list?${qs.toString()}`;
  }

  function workspaceMkdirUrlForCopy(workspaceId, path) {
    const qs = new URLSearchParams();
    qs.set("workspace_id", workspaceId || "");
    qs.set("path", path || "");
    return `/api/v4/workspaces/files/mkdir?${qs.toString()}`;
  }

  function userListUrlForCopy(path) {
    return path
        ? `/api/v4/files/list?path=${encodeURIComponent(path)}`
        : `/api/v4/files/list`;
  }

  function userMkdirUrlForCopy(path) {
    return `/api/v4/files/mkdir?path=${encodeURIComponent(path || "")}`;
  }

  function buildCopyDestinationScopes() {
    const scopes = [];

    scopes.push({
      id: "user",
      kind: "user",
      label: tr("filemgr.my_files", null, "My Files"),
      canCreate: true,
      canChoose: true,
      listUrl: (path) => userListUrlForCopy(path || ""),
      mkdirUrl: (path) => userMkdirUrlForCopy(path || "")
    });

    const sel = document.getElementById("scopeSelect");
    const opts = sel && sel.options ? Array.from(sel.options) : [];

    for (const opt of opts) {
      const v = String(opt.value || "");
      if (!v.startsWith("workspace:")) continue;

      const workspaceId = v.slice("workspace:".length);
      if (!workspaceId) continue;

      const role = String(opt.dataset.role || "").toLowerCase();
      const canWrite = role === "owner" || role === "editor";
      if (!canWrite) continue;

      const label = String(opt.dataset.name || opt.textContent || workspaceId);

      scopes.push({
        id: `workspace:${workspaceId}`,
        kind: "workspace",
        workspaceId,
        label,
        canCreate: true,
        canChoose: true,
        description: role ? `${label} (${role})` : label,
        listUrl: (path) => workspaceListUrlForCopy(workspaceId, path || ""),
        mkdirUrl: (path) => workspaceMkdirUrlForCopy(workspaceId, path || "")
      });
    }

    return scopes;
  }

  function snapshotFromCopyScope(scope, path) {
    const p = normalizeRelPath(path || "");
    if (!scope || scope.kind !== "workspace") {
      return {
        path: p,
        inWorkspace: false,
        workspaceId: "",
        listUrl: userListUrlForCopy(p)
      };
    }

    return {
      path: p,
      inWorkspace: true,
      workspaceId: String(scope.workspaceId || ""),
      listUrl: workspaceListUrlForCopy(scope.workspaceId || "", p)
    };
  }

  async function copyItemsToScopedDestination(items, destPath, sourceSnap, destSnap) {
    const sameScope = sameLogicalScopeSnapshot(sourceSnap, destSnap);

    if (sameScope) {
      await copyItemsToDestination(items, destPath);
      return;
    }

    const list = Array.isArray(items) ? items.slice() : [];
    const dest = normalizeRelPath(destPath);

    if (!list.length) return;

    const firstDir = list.find((it) => it && it.type === "dir");
    if (firstDir) {
      throw new Error(tr("filemgr.copy.cross_scope_files_only", null, "Cross-scope copy currently supports files only."));
    }

    setBadge("warn", "copying…");
    status.textContent = tr("filemgr.copy.progress", { done: 0, total: list.length }, `Copying 0/${list.length}…`);

    let done = 0;
    let skipped = 0;
    let failed = 0;
    const failures = [];

    for (const it of list) {
      const from = normalizeRelPath(it.rel);
      const name = it.name || basenamePath(from);
      const to = dest ? `${dest}/${name}` : name;

      if (!from || !name) {
        skipped++;
        continue;
      }

      try {
        const r = await fetch(apiCopyScopeUrl(sourceSnap, destSnap, from, to), {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          body: ""
        });

        const j = await r.json().catch(() => null);

        if (!r.ok || !j || !j.ok) {
          const msg = j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : `HTTP ${r.status}`;
          throw new Error(msg || `HTTP ${r.status}`);
        }

        done++;
      } catch (e) {
        failed++;
        failures.push(`${from} → ${to} — ${String(e && e.message ? e.message : e)}`);
      }

      status.textContent = tr("filemgr.copy.progress", { done: done + failed + skipped, total: list.length }, `Copying ${done + failed + skipped}/${list.length}…`);
    }

    clearSelection();
    clearFileListCache();
    await load();

    if (failed) {
      setBadge("err", "partial");
      status.textContent =
          `Copied ${done}, skipped ${skipped}, failed ${failed}. ` +
          failures.slice(0, 2).join(" | ");
    } else {
      setBadge("ok", "ready");
      status.textContent = `Copied ${done} item(s).`;
    }
  }

  async function openCopyModalForItems(items) {
    const picker = window.PQNAS_FOLDER_PICKER;
    if (!picker || typeof picker.open !== "function") {
      status.textContent = tr("filemgr.copy.dialog_missing", null, "Copy dialog failed: shared folder picker module is not loaded. Refresh the page.");
      return;
    }

    const clean = (Array.isArray(items) ? items : [])
      .map((it) => {
        const rawRel = it && (it.rel || it.path || it.relPath || "");
        const rel = normalizeRelPath(rawRel || (it ? currentRelPathFor(it) : ""));
        if (!rel) return null;

        const type = String((it && it.type) || "file") === "dir" ? "dir" : "file";
        return Object.assign({}, it || {}, {
          rel,
          type,
          name: (it && it.name) || basenamePath(rel)
        });
      })
      .filter(Boolean);

    if (!clean.length) {
      status.textContent = tr("filemgr.common.nothing_selected", null, "Nothing selected.");
      return;
    }

    const sourceSnap = currentScopeSnapshot(curPath || "");
    const scopes = buildCopyDestinationScopes();

    if (!scopes.length) {
      status.textContent = tr("filemgr.copy.no_destinations", null, "No writable copy destinations available.");
      return;
    }

    const initialScopeId = copyScopeIdFromSnapshot(sourceSnap);

    const picked = await picker.open({
      title: tr("filemgr.copy.title", null, "Copy"),
      subtitle: tr("filemgr.copy.subtitle", null, "Select destination location and folder"),
      source: describeCopyItems(clean),
      initialScopeId,
      initialPath: curPath || "",
      chooseLabel: tr("filemgr.copy.choose_here", null, "Copy here"),
      canCreate: true,
      blockedPaths: [],
      scopes
    });

    if (picked === null) {
      status.textContent = tr("filemgr.copy.cancelled", null, "Copy cancelled.");
      return;
    }

    const pickedPath = (picked && typeof picked === "object")
        ? picked.path
        : picked;

    const pickedScopeId = (picked && typeof picked === "object")
        ? String(picked.scopeId || "")
        : initialScopeId;

    const destScope = scopes.find((s) => String(s.id) === pickedScopeId) || scopes[0];
    const destPath = normalizeRelPath(pickedPath || "");
    const destSnap = snapshotFromCopyScope(destScope, destPath);

    const sameScope = sameLogicalScopeSnapshot(sourceSnap, destSnap);
    const problem = copyDestinationProblem(destPath, clean, {
      sameScope,
      crossScope: !sameScope
    });

    if (problem) {
      status.textContent = problem;
      return;
    }

    const destShown = destPath ? `/${destPath}` : "/";
    const ok = confirm(tr(
        "filemgr.copy.confirm",
        {
          count: clean.length,
          dest: `${destScope.label || copyScopeNameFromSnapshot(destSnap)} ${destShown}`
        },
        `Copy ${clean.length} item(s) to:\n\n${destScope.label || copyScopeNameFromSnapshot(destSnap)} ${destShown}\n\nExisting destination names will fail; nothing is overwritten.`
    ));

    if (!ok) {
      status.textContent = tr("filemgr.copy.cancelled", null, "Copy cancelled.");
      return;
    }

    await copyItemsToScopedDestination(clean, destPath, sourceSnap, destSnap);
  }

  function openCopyModalForItem(item) {
    if (!item) return;

    const rel = currentRelPathFor(item);
    openCopyModalForItems([{
      rel,
      type: item.type === "dir" ? "dir" : "file",
      name: item.name || basenamePath(rel)
    }]);
  }

  function openCopyModalForSelection() {
    openCopyModalForItems(collectSelectedCopyItems());
  }

  function friendlyMoveCopyFailureReason(raw) {
    const s = String(raw || "").trim();

    if (!s) return tr("filemgr.copy.reason.unknown", null, "unknown error");

    const lower = s.toLowerCase();

    if (lower.includes("dest_exists") || lower.includes("destination already exists")) {
      return tr("filemgr.copy.reason.dest_exists", null, "destination already exists");
    }

    if (lower.includes("locked") || lower.includes("item is locked")) {
      return tr("filemgr.copy.reason.locked", null, "item is locked");
    }

    if (lower.includes("quota") || lower.includes("storage limit")) {
      return tr("filemgr.copy.reason.quota", null, "storage quota would be exceeded");
    }

    if (lower.includes("not_found") || lower.includes("source not found")) {
      return tr("filemgr.copy.reason.not_found", null, "source file was not found");
    }

    if (lower.includes("forbidden") || lower.includes("permission")) {
      return tr("filemgr.copy.reason.permission", null, "permission denied");
    }

    if (lower.includes("source must be a file") || lower.includes("directories not supported")) {
      return tr("filemgr.copy.reason.folder_copy", null, "folder copy is not supported yet");
    }

    return s
      .replace(/\bok\b/gi, "")
      .replace(/\bdest_exists\b/gi, "")
      .replace(/\bbad_request\b/gi, "")
      .replace(/\bserver_error\b/gi, "")
      .replace(/\s+/g, " ")
      .trim() || s;
  }

  function friendlyMoveCopyFailureLine(raw) {
    const s = String(raw || "").trim();
    if (!s) return "unknown item";

    const parts = s.split("—");
    const itemPart = String(parts[0] || "").trim();
    const reasonPart = parts.slice(1).join("—").trim();

    const reason = friendlyMoveCopyFailureReason(reasonPart || s);

    if (itemPart) {
      return `${itemPart} — ${reason}`;
    }

    return reason;
  }

  function friendlyMoveCopyStatus(actionPast, done, total, failed, skipped, failures) {
    const list = Array.isArray(failures) ? failures : [];
    const first = list.length ? friendlyMoveCopyFailureLine(list[0]) : "";
    const skippedPart = skipped
        ? tr("filemgr.copy.status_skipped_part", { skipped }, `, ${skipped} skipped`)
        : "";

    if (failed > 0 && done === 0) {
      const problem = first || `${failed} item(s) failed`;
      return tr("filemgr.copy.status_failed", { action: actionPast, problem }, `${actionPast} failed: ${problem}`);
    }

    if (failed > 0) {
      const firstProblem = first
          ? tr("filemgr.copy.status_first_problem", { problem: first }, `First problem: ${first}`)
          : "";
      return tr(
          "filemgr.copy.status_partial",
          { action: actionPast, done, total, failed, skippedPart, firstProblem },
          `${actionPast} partially completed: ${done}/${total} succeeded, ${failed} failed${skippedPart}. ${firstProblem}`
      ).trim();
    }

    if (skipped) {
      return actionPast === "Move"
          ? tr("filemgr.move.done_skipped", { done, skipped }, `Moved ${done} item(s). Skipped: ${skipped}.`)
          : tr("filemgr.copy.done_skipped", { done, skipped }, `Copied ${done} item(s). Skipped: ${skipped}.`);
    }

    return actionPast === "Move"
        ? tr("filemgr.move.done", { done }, `Moved ${done} item(s).`)
        : tr("filemgr.copy.done", { done }, `Copied ${done} item(s).`);
  }

  async function copyItemsToDestination(items, destPath) {
    const list = Array.isArray(items) ? items.slice() : [];
    const dest = normalizeRelPath(destPath);

    if (!list.length) return;

    setBadge("warn", "copying…");
    status.textContent = tr("filemgr.copy.progress", { done: 0, total: list.length }, `Copying 0/${list.length}…`);

    let done = 0;
    let skipped = 0;
    let failed = 0;
    const failures = [];

    for (const it of list) {
      const from = normalizeRelPath(it.rel);
      const name = it.name || basenamePath(from);
      const to = dest ? `${dest}/${name}` : name;

      if (!from || !name) {
        skipped++;
        continue;
      }

      if (pathEq(from, to)) {
        skipped++;
        continue;
      }

      try {
        const r = await fetch(apiCopyUrl(from, to), {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          body: ""
        });

        const j = await r.json().catch(() => null);

        if (!r.ok || !j || !j.ok) {
          const msg = j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : `HTTP ${r.status}`;
          throw new Error(msg || `HTTP ${r.status}`);
        }

        done++;
      } catch (e) {
        failed++;
        failures.push(`${from} → ${to} — ${String(e && e.message ? e.message : e)}`);
      }

      status.textContent = tr("filemgr.copy.progress", { done: done + failed + skipped, total: list.length }, `Copying ${done + failed + skipped}/${list.length}…`);
    }

    clearSelection();
    clearFileListCache();
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    await load(true);

    if (failed > 0) {
      setBadge("err", done > 0 ? "partial" : "error");
      status.textContent = friendlyMoveCopyStatus("Copy", done, list.length, failed, skipped, failures);
      console.warn("Copy failures:", failures);
    } else {
      setBadge("ok", "ready");
      status.textContent = skipped > 0
          ? tr("filemgr.copy.done_skipped", { done, skipped }, `Copied ${done} item(s). Skipped: ${skipped}.`)
          : tr("filemgr.copy.done", { done }, `Copied ${done} item(s).`);
    }
  }

  async function moveItemsToDestination(items, destPath) {
    const list = Array.isArray(items) ? items.slice() : [];
    const dest = normalizeRelPath(destPath);

    if (!list.length) return;
    setBadge("warn", "moving…");
    status.textContent = tr("filemgr.move.progress", { done: 0, total: list.length }, `Moving 0/${list.length}…`);

    let done = 0;
    let skipped = 0;
    let failed = 0;
    const failures = [];

    for (const it of list) {
      const from = normalizeRelPath(it.rel);
      const name = it.name || basenamePath(from);
      const to = dest ? `${dest}/${name}` : name;

      if (!from || !name) {
        skipped++;
        continue;
      }

      if (pathEq(from, to)) {
        skipped++;
        continue;
      }

      try {
        const r = await fetch(apiMoveUrl(from, to), {
          method: "POST",
          credentials: "include",
          cache: "no-store",
          body: ""
        });

        const j = await r.json().catch(() => null);

        if (!r.ok || !j || !j.ok) {
          const msg = j && (j.message || j.error)
              ? `${j.error || ""} ${j.message || ""}`.trim()
              : `HTTP ${r.status}`;
          throw new Error(msg || `HTTP ${r.status}`);
        }

        done++;
      } catch (e) {
        failed++;
        failures.push(`${from} → ${to} — ${String(e && e.message ? e.message : e)}`);
      }

      status.textContent = tr("filemgr.move.progress", { done: done + failed + skipped, total: list.length }, `Moving ${done + failed + skipped}/${list.length}…`);
    }
    clearSelection();

    try {
      await fetchFavoritesFromServer(true);
    } catch (e) {
      console.warn("Favorites refresh after move failed:", e);
    }

    clearFileListCache();
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    await load(true);

    if (failed > 0) {
      setBadge("err", done > 0 ? "partial" : "error");
      status.textContent = friendlyMoveCopyStatus("Move", done, list.length, failed, skipped, failures);
      console.warn("Move failures:", failures);
    } else {
      setBadge("ok", "ready");
      status.textContent = skipped > 0
          ? tr("filemgr.move.done_skipped", { done, skipped }, `Moved ${done} item(s). Skipped: ${skipped}.`)
          : tr("filemgr.move.done", { done }, `Moved ${done} item(s).`);
    }
  }


  function fmLooksLikeLockedFailure(j, httpStatus) {
    const hay = [
      httpStatus === 409 ? "409" : "",
      j && j.error,
      j && j.message,
      j && j.detail
    ].filter(Boolean).join(" ").toLowerCase();

    return hay.includes("locked") || hay.includes("lock");
  }

  async function doDelete(item) {
    if (!requireWritableScopeOrExplain(tr("filemgr.action.delete", null, "Delete"))) return;
    const rel = currentRelPathFor(item);
    const isDir = item.type === "dir";

    const ok = await fmConfirmModal({
      title: tr("filemgr.delete.title", null, "Move to trash?"),
      subtitle: tr("filemgr.delete.subtitle", null, "The selected item will be moved to Trash."),
      rows: [
        {
          label: tr("filemgr.delete.item", null, "Item"),
          value: (typeof item !== "undefined" && item && item.name) ? item.name : tr("filemgr.delete.selected_item", null, "Selected item"),
          mono: true
        },
      ],
      note: tr("filemgr.delete.note", null, "You can restore it later from Trash until it is permanently deleted."),
      confirmText: tr("filemgr.delete.confirm", null, "Move to trash"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      danger: true,
    });
    if (!ok) return;

    setBadge("warn", "moving to trash…");
    status.textContent = tr("filemgr.delete.working", null, "Moving to trash…");

    const url = apiDeleteUrl(rel);
    const r = await fetch(url, {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      body: ""
    });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      const locked = fmLooksLikeLockedFailure(j, r.status);
      setBadge(locked ? "locked" : "err", locked ? "locked" : "error");
      const msg = j && (j.message || j.error || j.detail)
          ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
          : `HTTP ${r.status}`;
      status.textContent = locked
          ? msg
          : tr("filemgr.delete.failed", { error: msg }, `Move to trash failed: ${msg}`);
      return;
    }

    try {
      await fetchFavoritesFromServer();
    } catch (e) {
      console.warn("Favorites refresh after delete failed:", e);
    }

    status.textContent = tr("filemgr.delete.done", null, "Moved to trash.");
    setBadge("ok", "ready");
    clearSelection();
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    clearFileListCache();
    await load(true);
  }

  async function doMkdirAt(relDir) {
    if (!requireWritableScopeOrExplain(tr("filemgr.action.create_folder", null, "Create folder"))) return;
    const baseShown = relDir ? `/${relDir}` : curPath ? `/${curPath}` : "/";
    const name = await fmPromptModal({
      title: tr("filemgr.mkdir.title", null, "New folder"),
      subtitle: tr("filemgr.mkdir.subtitle", { path: baseShown }, `Create a folder in ${baseShown}.`),
      label: tr("filemgr.mkdir.label", null, "Folder name"),
      value: tr("filemgr.mkdir.default_name", null, "New Folder"),
      help: tr("filemgr.mkdir.help", null, "Use only the folder name, not a full path."),
      confirmText: tr("filemgr.mkdir.confirm", null, "Create folder"),
      cancelText: tr("filemgr.cancel", null, "Cancel"),
      validate(value) {
        if (!value) return tr("filemgr.mkdir.required", null, "Folder name is required.");
        if (value.includes("/") || value.includes("\\")) return tr("filemgr.mkdir.path_separators", null, "Folder name cannot contain path separators.");
        if (value === "." || value === "..") return tr("filemgr.mkdir.invalid", null, "Invalid folder name.");
        return "";
      },
    });
    if (!name) return;

    if (name.includes("/") || name.includes("\\")) {
      alert(tr("filemgr.mkdir.path_separators", null, "Folder name cannot contain path separators."));
      return;
    }

    const base = relDir != null ? relDir : curPath;
    const newRel = base ? `${base}/${name}` : name;

    setBadge("warn", "working…");
    status.textContent = tr("filemgr.mkdir.working", null, "Creating folder…");

    const url = apiMkdirUrl(newRel);
    const r = await fetch(url, { method: "POST", credentials: "include", cache: "no-store" });
    const j = await r.json().catch(() => null);

    if (!r.ok || !j || !j.ok) {
      setBadge("err", "error");
      const msg = j && (j.message || j.error) ? `${j.error || ""} ${j.message || ""}`.trim() : `HTTP ${r.status}`;
      status.textContent = tr("filemgr.mkdir.failed", { error: msg }, `mkdir failed: ${msg}`);
      return;
    }

    setBadge("ok", "ready");
    status.textContent = tr("filemgr.mkdir.done", null, "Folder created.");
    clearSelection();
    await refreshQuotaInfoIfNeeded(true).then(applyQuotaUi).catch(() => {});
    clearFileListCache();
    await load(true);
  }

  function expiresSecFromPreset(v) {
    if (v === "1h") return 3600;
    if (v === "24h") return 86400;
    if (v === "7d") return 7 * 86400;
    return 0;
  }

  async function createShareLinkFor(relPath, type, expiresSec, opts = {}) {
    const body = {
      path: relPath,
      expires_sec: expiresSec,
      mode: opts.mode || "standard"
    };

    if (opts.inviteExpiresSec != null) body.invite_expires_sec = opts.inviteExpiresSec;
    if (opts.recipientLabelHint) body.recipient_label_hint = opts.recipientLabelHint;

    if (window.PQNAS_FILEMGR &&
        typeof window.PQNAS_FILEMGR.isWorkspaceScope === "function" &&
        window.PQNAS_FILEMGR.isWorkspaceScope() &&
        typeof window.PQNAS_FILEMGR.getWorkspaceId === "function") {
      const workspaceId = String(window.PQNAS_FILEMGR.getWorkspaceId() || "").trim();
      if (workspaceId) body.workspace_id = workspaceId;
    }

    const r = await fetch("/api/v4/shares/create", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify(body)
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.detail || j.message || j.error)
          ? [j.error, j.message, j.detail].filter(Boolean).join(" ")
          : `HTTP ${r.status}`;
      throw new Error(msg || "share create failed");
    }

    return j;
  }

  async function copyText(s) {
    try {
      await navigator.clipboard.writeText(s);
      return true;
    } catch (_) {
      const ta = document.createElement("textarea");
      ta.value = s;
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand("copy");
      ta.remove();
      return ok;
    }
  }


  function maybeStartShareLinkFirstOpenTour(attempt = 0) {
    const maxAttempts = 10;
    const delayMs = attempt === 0 ? 120 : 250;

    window.setTimeout(() => {
      if (!shareModal || !shareModal.classList.contains("show")) {
        return;
      }

      const guide = window.DNANexusGuidedTours;
      if (!guide || typeof guide.startTourByIdOnce !== "function") {
        if (attempt < maxAttempts) {
          maybeStartShareLinkFirstOpenTour(attempt + 1);
        }
        return;
      }

      const started = guide.startTourByIdOnce(SHARE_LINK_FIRST_OPEN_TOUR_ID);

      // Usually the manifest is loaded before a user opens the context menu.
      // This retry covers very fast clicks immediately after page load.
      if (!started && attempt < 3) {
        maybeStartShareLinkFirstOpenTour(attempt + 1);
      }
    }, delayMs);
  }


  function maybeStartPqEnrolledShareFirstOpenTour(attempt = 0) {
    const maxAttempts = 10;
    const delayMs = attempt === 0 ? 120 : 250;

    window.setTimeout(() => {
      if (!shareModal || !shareModal.classList.contains("show")) {
        return;
      }

      const guide = window.DNANexusGuidedTours;
      if (!guide || typeof guide.startTourByIdOnce !== "function") {
        if (attempt < maxAttempts) {
          maybeStartPqEnrolledShareFirstOpenTour(attempt + 1);
        }
        return;
      }

      const started = guide.startTourByIdOnce(PQ_ENROLLED_SHARE_FIRST_OPEN_TOUR_ID);

      // Usually the manifest is loaded before a user opens the context menu.
      // This retry covers very fast clicks immediately after page load.
      if (!started && attempt < 3) {
        maybeStartPqEnrolledShareFirstOpenTour(attempt + 1);
      }
    }, delayMs);
  }

  function openShareDialogFor(item, opts = {}) {
    const rel = currentRelPathFor(item);
    const type = (item.type === "dir") ? "dir" : "file";
    const isPq = !!(opts && opts.forceMode === "pq_recipient_enrolled_v1");

    const existing = existingShareFor(rel, type);

    if (shareTitle) {
      shareTitle.textContent = isPq
          ? tr("filemgr.share.pq_title", null, "PQ recipient-enrolled share")
          : tr("filemgr.share.title", null, "Share link");
    }

    if (sharePath) sharePath.textContent = "/" + (rel || "");
    if (shareStatus) {
      shareStatus.textContent = isPq
          ? tr("filemgr.share.pq_hint", null, "Creates an invite URL for recipient enrollment. Files only.")
          : "";
    }

    if (shareOutWrap) shareOutWrap.classList.add("hidden");
    if (shareOut) shareOut.value = "";
    if (shareExpiry) shareExpiry.value = "24h";

    if (existing && !isPq) {
      const full = fullShareUrl(existing.url || ("/s/" + (existing.token || "")));
      if (shareOut) shareOut.value = full;
      if (shareOutWrap) shareOutWrap.classList.remove("hidden");

      if (shareStatus) {
        shareStatus.textContent = existing.expires_at
            ? tr("filemgr.share.already_shared_expires", { expires: existing.expires_at }, `Already shared • expires ${existing.expires_at}.`)
            : tr("filemgr.share.already_shared_no_expiry", null, "Already shared • no expiry.");
      }

      if (shareCreateBtn) shareCreateBtn.textContent = tr("filemgr.share.rotate", null, "Create new link (rotate)…");
    } else {
      if (shareCreateBtn) {
        shareCreateBtn.textContent = isPq
            ? tr("filemgr.share.create_pq_invite", null, "Create PQ invite")
            : tr("filemgr.share.create", null, "Create link");
      }
    }

    if (shareCreateBtn) {
      shareCreateBtn.onclick = async () => {
        try {
          if (shareStatus) shareStatus.textContent = isPq ? tr("filemgr.share.creating_pq", null, "Creating PQ invite…") : tr("filemgr.share.creating", null, "Creating…");

          const expiresSec = expiresSecFromPreset(shareExpiry ? shareExpiry.value : "24h");

          if (existing && existing.token) {
            try { await revokeShareToken(existing.token); } catch (_) {}
          }

          const shareType = type === "folder" ? "dir" : type;

          const resp = await createShareLinkFor(
              rel,
              shareType,
              expiresSec,
              isPq
                  ? {
                    mode: "pq_recipient_enrolled_v1",
                    inviteExpiresSec: 24 * 3600
                  }
                  : {
                    mode: "standard"
                  }
          );

          const publicUrl = fullShareUrl(resp.url || ("/s/" + (resp.token || "")));
          const inviteUrl = resp.invite_url ? fullShareUrl(resp.invite_url) : "";

          const outUrl = (isPq && inviteUrl) ? inviteUrl : publicUrl;

          if (shareOut) shareOut.value = outUrl;
          if (shareOutWrap) shareOutWrap.classList.remove("hidden");

          if (shareStatus) {
            if (isPq) {
              shareStatus.textContent = inviteUrl
                  ? tr("filemgr.share.pq_invite_created", null, "PQ invite created. Copy this invite URL and send it to the recipient.")
                  : tr("filemgr.share.pq_created", null, "PQ share created.");
            } else {
              shareStatus.textContent = existing
                  ? tr("filemgr.share.new_link_created", null, "New link created (old revoked).")
                  : tr("filemgr.share.link_created", null, "Link created.");
            }
          }

          await refreshSharesCache(true);
          await load();
        } catch (e) {
          if (shareStatus) {
            shareStatus.textContent = tr("filemgr.share.error", { error: String(e && e.message ? e.message : e) }, `Error: ${String(e && e.message ? e.message : e)}`);
          }
        }
      };
    }

    if (shareCopyBtn) {
      shareCopyBtn.onclick = async () => {
        const link = shareOut ? shareOut.value : "";
        const ok = link ? await copyText(link) : false;
        if (shareStatus) shareStatus.textContent = ok ? tr("filemgr.share.copied", null, "Copied.") : tr("filemgr.share.copy_failed", null, "Copy failed.");
      };
    }

    openShareModal({
      shareMode: isPq ? "pq-enrolled" : "standard",
      shareTourId: isPq ? PQ_ENROLLED_SHARE_FIRST_OPEN_TOUR_ID : SHARE_LINK_FIRST_OPEN_TOUR_ID
    });
  }

  function openPropsModal() {
    if (!propsModal) return;
    propsModal.classList.add("show");
    propsModal.setAttribute("aria-hidden", "false");
  }

  function closePropsModal() {
    if (propsShareTimer) {
      clearInterval(propsShareTimer);
      propsShareTimer = null;
    }

    if (!propsModal) return;
    propsModal.classList.remove("show");
    propsModal.setAttribute("aria-hidden", "true");
  }

  function openShareModal(opts = {}) {
    if (!shareModal) return;

    const shareMode = opts && opts.shareMode
        ? String(opts.shareMode)
        : "standard";

    shareModal.dataset.shareMode = shareMode;
    shareModal.classList.add("show");
    shareModal.setAttribute("aria-hidden", "false");

    if (!opts || opts.startShareLinkTour !== false) {
      const tourId = opts && opts.shareTourId
          ? String(opts.shareTourId)
          : SHARE_LINK_FIRST_OPEN_TOUR_ID;

      if (tourId === PQ_ENROLLED_SHARE_FIRST_OPEN_TOUR_ID) {
        maybeStartPqEnrolledShareFirstOpenTour();
      } else {
        maybeStartShareLinkFirstOpenTour();
      }
    }
  }

  function closeShareModal() {
    if (!shareModal) return;
    shareModal.classList.remove("show");
    shareModal.setAttribute("aria-hidden", "true");
  }

  shareClose?.addEventListener("click", closeShareModal);
  shareModal?.addEventListener("click", (e) => {
    if (e.target === shareModal) closeShareModal();
  });

  trashBtn?.addEventListener("click", async () => {
    openTrashModal();
    await loadTrashItems();
  });

  trashClose?.addEventListener("click", closeTrashModal);
  trashModal?.addEventListener("click", (e) => {
    if (e.target === trashModal) closeTrashModal();
  });

  trashRefreshBtn?.addEventListener("click", async () => {
    await loadTrashItems();
  });

  trashEmptyBtn?.addEventListener("click", async () => {
    await emptyTrashScope();
  });

  propsClose?.addEventListener("click", closePropsModal);
  propsModal?.addEventListener("click", (e) => {
    if (e.target === propsModal) closePropsModal();
  });

  let warnTimer = null;

  function fmBadgeText(text) {
    const s = String(text || "");
    if (s === "ready") return tr("filemgr.badge.ready", null, "ready");
    if (s === "error") return tr("filemgr.badge.error", null, "error");
    if (s === "partial") return tr("filemgr.badge.partial", null, "partial");
    if (s === "storage") return tr("filemgr.badge.storage", null, "storage");
    if (s === "browser") return tr("filemgr.badge.browser", null, "browser");
    if (s === "working…") return tr("filemgr.badge.working", null, "working…");
    if (s === "moving to trash…") return tr("filemgr.badge.moving_to_trash", null, "moving to trash…");
    if (s === "copying…") return tr("filemgr.badge.copying", null, "copying…");
    if (s === "moving…") return tr("filemgr.badge.moving", null, "moving…");
    return s;
  }

  function setBadge(kind, text) {
    badge.className = `badge ${kind}`;
    badge.textContent = fmBadgeText(text);
  }

  function hideEmptyState() {
    if (emptyState) {
      emptyState.classList.add("hidden");
      emptyState.innerHTML = "";
    }
    if (gridEl) gridEl.classList.remove("hidden");
  }

  function setStorageBlocked(on, j) {
    storageBlocked = !!on;
    if (upBtn) upBtn.disabled = storageBlocked;
    if (refreshBtn) refreshBtn.disabled = false;
    if (storageBlocked) showStorageUnallocatedState(j || null);
    else hideEmptyState();
  }

  function requireStorageOrExplain(actionLabel) {
    if (!storageBlocked) return true;
    setBadge("warn", "storage");
    status.textContent = actionLabel
        ? `${actionLabel} not available: storage not allocated yet. Ask an admin to allocate quota.`
        : "Storage not allocated yet. Ask an admin to allocate quota.";
    return false;
  }

  function showStorageUnallocatedState(j) {
    hideQuotaLine();
    quotaInfo = null;
    quotaInfoAtMs = 0;

    setBadge("warn", "storage");
    status.textContent = "Storage not allocated for this user.";

    showDropOverlay(false);
    if (gridEl) gridEl.classList.add("hidden");
    if (!emptyState) return;

    const fp = (j && j.fingerprint_hex) ? String(j.fingerprint_hex) : "";
    const quota = (j && j.quota_bytes != null) ? fmtSize(Number(j.quota_bytes) || 0) : "";

    emptyState.classList.remove("hidden");
    emptyState.innerHTML = "";

    const h = document.createElement("div");
    h.className = "h";
    h.textContent = "Storage not allocated yet";

    const p = document.createElement("div");
    p.className = "p";
    p.textContent =
        "Your account exists, but no storage has been allocated for it yet. " +
        "Ask an admin to allocate storage, or if you are an admin, open User profiles and allocate quota.";

    const row = document.createElement("div");
    row.className = "row";

    const a = document.createElement("a");
    a.className = "btn";
    a.href = "/admin/users";
    a.textContent = "Open Admin → User profiles";

    const refresh = document.createElement("button");
    refresh.className = "btn secondary";
    refresh.type = "button";
    refresh.textContent = "Refresh";
    refresh.onclick = () => load();

    row.appendChild(a);
    row.appendChild(refresh);

    emptyState.appendChild(h);
    emptyState.appendChild(p);
    emptyState.appendChild(row);

    if (fp || quota) {
      const info = document.createElement("div");
      info.className = "monoBox";
      info.style.marginTop = "12px";
      info.textContent =
          (quota ? `Quota (configured): ${quota}\n` : "") +
          (fp ? `Fingerprint:\n${fp}` : "");

      emptyState.appendChild(info);

      if (fp) {
        const row2 = document.createElement("div");
        row2.className = "row";
        row2.style.marginTop = "10px";

        const copyBtn = document.createElement("button");
        copyBtn.className = "btn secondary";
        copyBtn.type = "button";
        copyBtn.textContent = "Copy fingerprint";
        copyBtn.onclick = async () => {
          const ok = await copyText(fp);
          copyBtn.textContent = ok ? "Copied" : "Copy failed";
          setTimeout(() => (copyBtn.textContent = "Copy fingerprint"), 1100);
        };

        row2.appendChild(copyBtn);
        emptyState.appendChild(row2);
      }
    }
  }

  function showTransientWarning(text, ms = 6000) {
    if (warnTimer) { clearTimeout(warnTimer); warnTimer = null; }

    const uploadingNow = uploadProg && uploadProg.style.display !== "none";
    if (!uploadingNow) setBadge("warn", "browser");
    status.textContent = text;

    warnTimer = setTimeout(() => {
      warnTimer = null;
      const stillUploading = uploadProg && uploadProg.style.display !== "none";
      if (!stillUploading) {
        setBadge("ok", "ready");
        status.textContent = "Ready.";
      }
    }, ms);
  }

  const hashCache = new Map();

  function hashCacheKey(relPath, mtimeEpoch, sizeBytes) {
    const m = Number(mtimeEpoch || 0) || 0;
    const s = Number(sizeBytes || 0) || 0;
    return `${String(relPath || "")}|m=${m}|s=${s}`;
  }

  function pickSha256FromHashResponse(j) {
    if (!j || typeof j !== "object") return "";

    if (typeof j.digest_hex === "string" && j.digest_hex) {
      const algo = String(j.algo || j.algorithm || "").toLowerCase();
      if (!algo || algo === "sha256" || algo === "sha-256") return j.digest_hex;
    }

    if (typeof j.sha256 === "string" && j.sha256) return j.sha256;

    if (j.hashes && typeof j.hashes === "object" && typeof j.hashes.sha256 === "string") {
      return j.hashes.sha256;
    }
    if (j.digests && typeof j.digests === "object" && typeof j.digests.sha256 === "string") {
      return j.digests.sha256;
    }

    if (typeof j.hash === "string" && j.hash) {
      const algo = String(j.algo || j.algorithm || "").toLowerCase();
      if (!algo || algo === "sha256" || algo === "sha-256") return j.hash;
    }

    return "";
  }

  async function fetchSha256ForRelPath(relPath) {
    const p = String(relPath || "").replace(/^\/+/, "").trim();
    if (!p) throw new Error("hash requires a file path");

    const r = await fetch(apiHashUrl(p, "sha256"), {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Accept": "application/json" }
    });

    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error)
          ? `${j.error || ""} ${j.message || ""}`.trim()
          : `HTTP ${r.status}`;
      throw new Error(msg || "hash failed");
    }

    const sha256 = pickSha256FromHashResponse(j);
    if (!sha256) throw new Error("server did not return sha256");
    return { sha256, raw: j };
  }

  let sharesByKey = new Map();
  let sharesLoadedOnce = false;
  const SHARES_CACHE_TTL_MS = 15 * 1000;

  function shareKey(type, relPath) {
    const t = (type === "dir") ? "dir" : "file";
    const p = String(relPath || "").replace(/^\/+/, "").replace(/\\/g, "/");
    return `${t}:${p}`;
  }

  function existingShareFor(relPath, type) {
    return sharesByKey.get(shareKey(type, relPath)) || null;
  }

  async function refreshSharesCache(force = false) {
    const now = Date.now();
    if (!force && sharesLoadedOnce && (now - sharesLoadedAt) < SHARES_CACHE_TTL_MS) {
      return;
    }
    try {
      const api = fmApi();
      const sharesListUrl =
          (api && typeof api.sharesListUrl === "function")
              ? api.sharesListUrl()
              : "/api/v4/shares/list";

      const r = await fetch(sharesListUrl, {
        method: "GET",
        credentials: "include",
        cache: "no-store",
        headers: { "Accept": "application/json" }
      });
      const j = await r.json().catch(() => null);
      if (!r.ok || !j || !j.ok || !Array.isArray(j.shares)) {
        sharesByKey = new Map();
        sharesLoadedOnce = true;
        return;
      }

      const m = new Map();
      for (const s of j.shares) {
        if (!s || typeof s !== "object") continue;
        const k = shareKey(s.type, s.path);
        m.set(k, s);
      }
      sharesByKey = m;
      sharesLoadedOnce = true;
      sharesLoadedAt = Date.now();
    } catch (_) {
      sharesByKey = new Map();
      sharesLoadedOnce = true;
    }
  }

  async function revokeShareToken(token) {
    const r = await fetch("/api/v4/shares/revoke", {
      method: "POST",
      credentials: "include",
      cache: "no-store",
      headers: { "Content-Type": "application/json", "Accept": "application/json" },
      body: JSON.stringify({ token })
    });
    const j = await r.json().catch(() => null);
    if (!r.ok || !j || !j.ok) {
      const msg = j && (j.message || j.error)
          ? `${j.error || ""} ${j.message || ""}`.trim()
          : `HTTP ${r.status}`;
      throw new Error(msg || "share revoke failed");
    }
  }

  function isShareExpired(share) {
    if (!share || !share.expires_at) return false;
    const ms = Date.parse(share.expires_at);
    if (!Number.isFinite(ms)) return false;
    return Date.now() >= ms;
  }
  function openMenuAt(x, y, item) {
    if (!ctxEl) return;

    if (propsModal && propsModal.classList.contains("show")) closePropsModal();

    const key = `${item.type}:${item.name}`;
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    const rel = currentRelPathFor(item);
    const caps = fmCaps();
    const canWrite = canWriteCurrentScope();
    const share = existingShareFor(rel, item.type === "dir" ? "dir" : "file");
    const shareLabel = share
        ? (isShareExpired(share)
            ? tr("filemgr.menu.manage_share_expired", null, "Manage share link… (expired)")
            : tr("filemgr.menu.manage_share", null, "Manage share link…"))
        : tr("filemgr.menu.create_share", null, "Create share link…");

    const fav = isFavoriteItem(item);
    const favLabel = fav
        ? tr("filemgr.menu.remove_favorite", null, "Remove from favorites")
        : tr("filemgr.menu.add_favorite", null, "Add to favorites");

    const selectionMode = (selectedKeys && selectedKeys.size > 1 && selectedKeys.has(key));
    if (selectionMode) {
      buildSelectionMenuOnly();
      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    if (item.type === "dir") {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.open", null, "Open"), "↩", () => {
        curPath = joinPath(curPath, item.name);
        clearSelection();
        load();
      }));

      if (caps.zipFolder !== false) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.download_folder_zip", null, "Download folder (zip)"), "", () => {
          const relDir = joinPath(curPath, item.name);
          downloadFolderZip(relDir);
        }));
      }

      if (caps.favorites !== false) {
        ctxEl.appendChild(menuItem(favLabel, "", async () => {
          try {
            const on = await toggleFavoriteRelPath(rel, item.type);
            setBadge("ok", "ready");
            status.textContent = on ? tr("filemgr.status.added_favorite", { name: item.name }, `Added to favorites: ${item.name}`) : tr("filemgr.status.removed_favorite", { name: item.name }, `Removed from favorites: ${item.name}`);
            await load();
          } catch (err) {
            setBadge("err", "error");
            status.textContent = tr("filemgr.status.favorites_failed", { error: String(err && err.message ? err.message : err) }, `Favorites update failed: ${String(err && err.message ? err.message : err)}`);
          }
        }));
      }

      if (caps.shares !== false) {
        ctxEl.appendChild(menuItem(shareLabel, "", () => openShareDialogFor(item)));
      }

      if (canWrite) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.new_folder_here", null, "New folder here…"), "", () => {
          const relDir = joinPath(curPath, item.name);
          doMkdirAt(relDir);
        }));

        ctxEl.appendChild(menuSep());
        if (caps.copy !== false && item.type !== "dir") {
          ctxEl.appendChild(menuItem(tr("filemgr.menu.copy_to", null, "Copy to…"), "", () => openCopyModalForItem(item)));
        }
        if (caps.move !== false) {
          ctxEl.appendChild(menuItem(tr("filemgr.menu.move", null, "Move…"), "", () => openMoveModalForItem(item)));
        }
        ctxEl.appendChild(menuItem(tr("filemgr.menu.rename", null, "Rename…"), "", () => doRename(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.move_to_trash", null, "Move to trash…"), "🗑", () => doDelete(item), { danger: true }));
      }

      if (caps.properties !== false && !(selectedKeys && selectedKeys.size > 1)) {
        ctxEl.appendChild(menuSep());
        ctxEl.appendChild(menuItem(tr("filemgr.menu.properties", null, "Properties…"), "", () => showProperties(item)));
      }
    } else {
      if (caps.imagePreview !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.imagePreview &&
          isProbablyImagePreviewableName(item.name)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_preview", null, "Open preview"), "", () => window.PQNAS_FILEMGR.imagePreview.open(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_original", null, "Open original"), "", () => doOpenOriginal(item)));
      }
      if (caps.pdfPreview !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.pdfPreview &&
          isProbablyPdfPreviewableName(item.name)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_pdf_preview", null, "Open PDF preview"), "", () => window.PQNAS_FILEMGR.pdfPreview.open(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_original", null, "Open original"), "", () => doOpenOriginal(item)));
      }
      if (caps.videoPreview !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.videoPreview &&
          isProbablyVideoPreviewableName(item.name)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_video_preview", null, "Open video preview"), "", () => window.PQNAS_FILEMGR.videoPreview.open(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_original", null, "Open original"), "", () => doOpenOriginal(item)));
      }
      if (caps.audioPreview !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.audioPreview &&
          isProbablyAudioPreviewableName(item.name)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_audio_preview", null, "Open audio preview"), "", () => window.PQNAS_FILEMGR.audioPreview.open(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_original", null, "Open original"), "", () => doOpenOriginal(item)));
      }

      if (caps.textEdit !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.textEdit &&
          isProbablyTextEditableName(item.name)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.open_edit_text", null, "Open / edit text?"), "", () => {
          console.log("[app.ctx.textedit] item =", item);
          console.log("[app.ctx.textedit] rel =", currentRelPathFor(item));
          window.PQNAS_FILEMGR.textEdit.open(item);
        }));
      }

      ctxEl.appendChild(menuItem(tr("filemgr.menu.download", null, "Download"), "⤓", () => doDownload(item)));

      if (caps.versions !== false &&
          window.PQNAS_FILEMGR &&
          window.PQNAS_FILEMGR.fileVersions &&
          typeof window.PQNAS_FILEMGR.fileVersions.canOpenFor === "function" &&
          window.PQNAS_FILEMGR.fileVersions.canOpenFor(item)) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.versions", null, "Versions…"), "", () => {
          window.PQNAS_FILEMGR.fileVersions.open(item);
        }));
      }

      if (caps.favorites !== false) {
        ctxEl.appendChild(menuItem(favLabel, "", async () => {
          try {
            const on = await toggleFavoriteRelPath(rel, item.type);
            setBadge("ok", "ready");
            status.textContent = on ? tr("filemgr.status.added_favorite", { name: item.name }, `Added to favorites: ${item.name}`) : tr("filemgr.status.removed_favorite", { name: item.name }, `Removed from favorites: ${item.name}`);
            await load();
          } catch (err) {
            setBadge("err", "error");
            status.textContent = tr("filemgr.status.favorites_failed", { error: String(err && err.message ? err.message : err) }, `Favorites update failed: ${String(err && err.message ? err.message : err)}`);
          }
        }));
      }

      if (caps.shares !== false) {
        ctxEl.appendChild(menuItem(shareLabel, "", () => openShareDialogFor(item)));
      }

      if (caps.pqShares !== false) {
        ctxEl.appendChild(menuItem(tr("filemgr.menu.pq_share", null, "PQ recipient-enrolled share…"), "", () => openShareDialogFor(item, {
          forceMode: "pq_recipient_enrolled_v1"
        })));
      }

      if (canWrite) {
        ctxEl.appendChild(menuSep());
        if (caps.copy !== false && item.type !== "dir") {
          ctxEl.appendChild(menuItem(tr("filemgr.menu.copy_to", null, "Copy to…"), "", () => openCopyModalForItem(item)));
        }
        if (caps.move !== false) {
          ctxEl.appendChild(menuItem(tr("filemgr.menu.move", null, "Move…"), "", () => openMoveModalForItem(item)));
        }
        ctxEl.appendChild(menuItem(tr("filemgr.menu.rename", null, "Rename…"), "", () => doRename(item)));
        ctxEl.appendChild(menuItem(tr("filemgr.menu.move_to_trash", null, "Move to trash…"), "🗑", () => doDelete(item), { danger: true }));
      }

      if (caps.properties !== false && !(selectedKeys && selectedKeys.size > 1)) {
        ctxEl.appendChild(menuSep());
        ctxEl.appendChild(menuItem(tr("filemgr.menu.properties", null, "Properties…"), "", () => showProperties(item)));
      }
    }

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }
  function openBackgroundMenuAt(x, y) {
    if (!ctxEl) return;

    if (propsModal && propsModal.classList.contains("show")) closePropsModal();

    const key = "__bg__";
    if (ctxEl.classList.contains("show") && ctxOpenForKey === key) {
      closeMenu();
      return;
    }

    ctxEl.innerHTML = "";
    ctxOpenForKey = key;

    const caps = fmCaps();
    const canWrite = canWriteCurrentScope();

    if (selectedKeys && selectedKeys.size > 0) {
      if (selectedKeys.size > 1) {
        buildSelectionMenuOnly();
      } else {
        const onlyKey = Array.from(selectedKeys)[0];
        const p = keyToItemRelPath(onlyKey);
        if (p) {
          const name = p.split("/").pop() || p;
          const type = String(onlyKey).startsWith("dir:") ? "dir" : "file";
          openMenuAt(x, y, { type, name });
          return;
        } else {
          buildSelectionMenuOnly();
        }
      }

      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    if (storageBlocked) {
      ctxEl.innerHTML = "";
      ctxOpenForKey = "__blocked__";
      ctxEl.appendChild(menuItem(tr("filemgr.menu.storage_not_allocated", null, "Storage not allocated"), "", () => {}, {}));
      ctxEl.appendChild(menuSep());
      ctxEl.appendChild(menuItem(tr("filemgr.menu.open_admin_users", null, "Open Admin → User profiles"), "", () => { window.location.href = "/admin/users"; }));
      ctxEl.appendChild(menuItem(tr("filemgr.menu.refresh", null, "Refresh"), "", () => load()));
      ctxEl.setAttribute("aria-hidden", "false");
      placeMenu(x, y);
      return;
    }

    if (canWrite) {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.upload_files", null, "Upload files…"), "", () => pickFiles()));
      ctxEl.appendChild(menuItem(tr("filemgr.menu.upload_folder", null, "Upload folder…"), "", () => pickFolder()));
      ctxEl.appendChild(menuSep());
    }

    if (caps.favorites !== false) {
      ctxEl.appendChild(menuItem(favoritesOnly ? tr("filemgr.menu.show_all", null, "Show all items") : tr("filemgr.menu.show_favorites_only", null, "Show favorites only"), "", () => toggleFavoritesOnly()));
      ctxEl.appendChild(menuSep());
    }

    if (caps.zipFolder !== false) {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.download_current_folder_zip", null, "Download current folder (zip)"), "", () => downloadFolderZip(curPath)));
    }

    if (canWrite) {
      ctxEl.appendChild(menuItem(tr("filemgr.menu.new_folder", null, "New folder…"), "", () => doMkdirAt(curPath)));
      ctxEl.appendChild(menuSep());
    }

    ctxEl.appendChild(menuItem(tr("filemgr.menu.open_trash", null, "Open trash"), "🗑", async () => {
      openTrashModal();
      await loadTrashItems();
    }));

    ctxEl.appendChild(menuItem(tr("filemgr.menu.refresh", null, "Refresh"), "", () => load()));

    ctxEl.setAttribute("aria-hidden", "false");
    placeMenu(x, y);
  }

  document.addEventListener("click", (e) => {
    if (!ctxEl || !ctxEl.classList.contains("show")) return;
    if (e.target === ctxEl || ctxEl.contains(e.target)) return;
    closeMenu();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (shareModal && shareModal.classList.contains("show")) {
        closeShareModal();
        return;
      }
      if (propsModal && propsModal.classList.contains("show")) {
        closePropsModal();
        return;
      }
      closeMenu();
      return;
    }

    if (e.key === "Delete" && selectedKeys && selectedKeys.size > 0) {
      e.preventDefault();
      deleteSelection();
      return;
    }

    if ((e.ctrlKey || e.metaKey) && e.shiftKey && String(e.key).toLowerCase() === "f") {
      e.preventDefault();
      toggleFavoritesOnly();
      return;
    }

    if ((e.ctrlKey || e.metaKey) && String(e.key).toLowerCase() === "a") {
      e.preventDefault();
      selectedKeys = new Set(
          Array.from(gridEl.querySelectorAll(".tile")).map(tileEl => tileEl.dataset.key)
      );
      applySelectionToDom();
      status.textContent = `Selected: ${selectedKeys.size}`;
    }
  });

  function filemgrLanguageChanged() {
    applyI18n(document);
    refreshFileMgrUploadProgressLabels(document.getElementById("fmUploadProgressBackdrop"));
    closeMenu();

    // Refresh favorite button titles because they are dynamic DOM nodes.
    try {
      for (const btn of document.querySelectorAll(".favBtn")) {
        const tileEl = btn.closest(".tile");
        const item = tileEl
            ? {
                type: tileEl.dataset.itemType || "file",
                name: tileEl.dataset.name || ""
              }
            : null;
        if (!item) continue;
        const fav = btn.classList.contains("isFav");
        btn.title = fav
            ? tr("filemgr.tile.favorite_remove", null, "Remove from favorites")
            : tr("filemgr.tile.favorite_add", null, "Add to favorites");
      }
    } catch (_) {}
  }

  window.addEventListener("pqnas-language-changed", filemgrLanguageChanged);

  window.addEventListener("scroll", closeMenu, true);
  window.addEventListener("resize", closeMenu);

  function installLongPress(tileEl, item) {
    tileEl.addEventListener("pointerdown", (e) => {
      if (e.pointerType === "mouse") return;
      clearTimeout(longPressTimer);

      const x = e.clientX;
      const y = e.clientY;

      longPressTimer = setTimeout(() => {
        setSingleSelection(`${item.type}:${item.name}`);
        openMenuAt(x, y, item);
      }, 520);
    });

    const cancel = () => {
      clearTimeout(longPressTimer);
      longPressTimer = null;
    };

    tileEl.addEventListener("pointerup", cancel);
    tileEl.addEventListener("pointercancel", cancel);
    tileEl.addEventListener("pointerleave", cancel);
    tileEl.addEventListener("pointermove", (e) => {
      if (Math.abs(e.movementX) + Math.abs(e.movementY) > 8) cancel();
    });
  }

  gridWrap?.addEventListener("contextmenu", (e) => {
    if (e.target?.closest?.(".tile")) return;
    e.preventDefault();
    openBackgroundMenuAt(e.clientX, e.clientY);
  });

  function tileElByKey(key) {
    if (!gridEl) return null;

    const k = String(key || "");
    const esc = (window.CSS && typeof CSS.escape === "function")
        ? CSS.escape(k)
        : k.replace(/["\\]/g, "\\$&");

    return gridEl.querySelector(`.tile[data-key="${esc}"]`);
  }

  function removeShareBadge(tileEl) {
    if (!tileEl) return;
    const b = tileEl.querySelector(".shareBadge");
    if (b) b.remove();
  }

  function ensureShareBadge(tileEl, expired) {
    if (!tileEl) return;

    const wantExpired = !!expired;
    let b = tileEl.querySelector(".shareBadge");

    if (!b) {
      b = document.createElement("div");
      b.className = "shareBadge";
      tileEl.appendChild(b);
    }

    const hasExpired = b.classList.contains("expired");
    if (hasExpired === wantExpired && b.textContent) {
      b.title = wantExpired ? "Share link expired" : "Shared";
      return;
    }

    b.className = "shareBadge" + (wantExpired ? " expired" : "");
    b.title = wantExpired ? "Share link expired" : "Shared";
    b.textContent = wantExpired ? "⏰" : "🔗";
  }

  function decorateTilesWithShareBadges(items) {
    if (!Array.isArray(items) || !gridEl) return;

    for (const item of items) {
      const key = `${item.type}:${item.name}`;
      const tileEl = tileElByKey(key);
      if (!tileEl) continue;

      const rel = currentRelPathFor(item);
      const type = (item.type === "dir") ? "dir" : "file";
      const share = existingShareFor(rel, type);

      const wantBadge = !!share;
      const wantExpired = wantBadge ? isShareExpired(share) : false;

      const b = tileEl.querySelector(".shareBadge");
      const hasBadge = !!b;
      const hasExpired = hasBadge && b.classList.contains("expired");

      if (!wantBadge && !hasBadge) continue;
      if (wantBadge && hasBadge && (hasExpired === wantExpired)) continue;

      if (wantBadge) ensureShareBadge(tileEl, wantExpired);
      else removeShareBadge(tileEl);
    }
  }

  function makeFavoriteButton(item) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "favBtn";
    btn.style.position = "absolute";
    btn.style.top = "8px";
    btn.style.left = "8px";
    btn.style.zIndex = "3";
    btn.style.width = "28px";
    btn.style.height = "28px";
    btn.style.borderRadius = "999px";
    btn.style.border = "1px solid rgba(255,255,255,0.14)";
    btn.style.background = "rgba(0,0,0,0.45)";
    btn.style.backdropFilter = "blur(2px)";
    btn.style.cursor = "pointer";
    btn.style.display = "flex";
    btn.style.alignItems = "center";
    btn.style.justifyContent = "center";
    btn.style.fontSize = "16px";
    btn.style.lineHeight = "1";
    btn.style.padding = "0";

    const refresh = () => {
      const fav = isFavoriteItem(item);
      btn.textContent = fav ? "★" : "☆";
      btn.title = fav ? tr("filemgr.tile.favorite_remove", null, "Remove from favorites") : tr("filemgr.tile.favorite_add", null, "Add to favorites");
      btn.style.opacity = fav ? "1" : "0.82";

      btn.classList.toggle("isFav", fav);

    };
    refresh();

    btn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();
      try {
        const on = await toggleFavoriteRelPath(currentRelPathFor(item), item.type);
        refresh();
        setBadge("ok", "ready");
        status.textContent = on ? tr("filemgr.status.added_favorite", { name: item.name }, `Added to favorites: ${item.name}`) : tr("filemgr.status.removed_favorite", { name: item.name }, `Removed from favorites: ${item.name}`);
        if (favoritesOnly && !on) {
          await load();
        }
      } catch (err) {
        setBadge("err", "error");
        status.textContent = tr("filemgr.status.favorites_failed", { error: String(err && err.message ? err.message : err) }, `Favorites update failed: ${String(err && err.message ? err.message : err)}`);
      }
    });

    btn.addEventListener("dblclick", (e) => {
      e.preventDefault();
      e.stopPropagation();
    });

    return btn;
  }

  function tile(item) {
    const key = `${item.type}:${item.name}`;

    const t = document.createElement("div");
    t.className = "tile";
    t.dataset.key = key;
    t.dataset.relPath = currentRelPathFor(item);
    t.dataset.itemType = item.type === "dir" ? "dir" : "file";
    t.dataset.name = item.name || "";
    t.style.position = "relative";

    const icoWrap = document.createElement("div");
    icoWrap.className = "icoWrap";
    icoWrap.setAttribute("aria-hidden", "true");

    const node = getIconNode(iconMarkupFor(item));
    if (node) icoWrap.appendChild(node);

    const nm = document.createElement("div");
    nm.className = "name";
    nm.textContent = item.name || "(unnamed)";

    const meta = document.createElement("div");
    meta.className = "meta";

    const left = document.createElement("span");
    left.textContent = item.type === "dir" ? "dir" : fmtSize(item.size_bytes || 0);

    const right = document.createElement("span");
    right.textContent = fmtTime(item.mtime_unix);

    meta.appendChild(left);
    meta.appendChild(right);

    const caps = fmCaps();
    if (caps.favorites !== false) {
      t.appendChild(makeFavoriteButton(item));
    }
    t.appendChild(icoWrap);
    t.appendChild(nm);
    t.appendChild(meta);

    t.addEventListener("click", (e) => {
      if (marqueeOn) return;
      if (e.target && e.target.closest && e.target.closest(".favBtn")) return;

      const additive = (e.ctrlKey || e.metaKey);

      if (e.shiftKey) {
        const anchor = selectionAnchorKey || (selectedKeys.size ? Array.from(selectedKeys)[0] : key);
        selectRange(anchor, key, additive);
        return;
      }

      if (additive) {
        toggleSelection(key);
        if (selectedKeys.has(key)) selectionAnchorKey = key;
      } else {
        setSingleSelection(key);
        selectionAnchorKey = key;
      }
    });

    t.addEventListener("contextmenu", (e) => {
      e.preventDefault();

      if (selectedKeys.size > 1) {
        if (!selectedKeys.has(key)) {
          setSingleSelection(key);
          selectionAnchorKey = key;
        }
      } else {
        ensureSelected(key);
        selectionAnchorKey = key;
      }

      openMenuAt(e.clientX, e.clientY, item);
    });

    installLongPress(t, item);

    t.addEventListener("dblclick", (e) => {
      if (e.target && e.target.closest && e.target.closest(".favBtn")) return;
      if (item.type === "dir") {
        curPath = joinPath(curPath, item.name);
        clearSelection();
        load();
      } else if (item.type === "file") {
        if (caps.imagePreview !== false &&
            window.PQNAS_FILEMGR &&
            window.PQNAS_FILEMGR.imagePreview &&
            isProbablyImagePreviewableName(item.name)) {
          window.PQNAS_FILEMGR.imagePreview.open(item);
        } else if (caps.pdfPreview !== false &&
            window.PQNAS_FILEMGR &&
            window.PQNAS_FILEMGR.pdfPreview &&
            isProbablyPdfPreviewableName(item.name)) {
          window.PQNAS_FILEMGR.pdfPreview.open(item);
        } else if (caps.audioPreview !== false &&
            window.PQNAS_FILEMGR &&
            window.PQNAS_FILEMGR.audioPreview &&
            isProbablyAudioPreviewableName(item.name)) {
          window.PQNAS_FILEMGR.audioPreview.open(item);
        } else if (caps.videoPreview !== false &&
            window.PQNAS_FILEMGR &&
            window.PQNAS_FILEMGR.videoPreview &&
            isProbablyVideoPreviewableName(item.name)) {
          window.PQNAS_FILEMGR.videoPreview.open(item);
        } else if (caps.officePreview !== false &&
            window.PQNAS_FILEMGR &&
            window.PQNAS_FILEMGR.officePreview &&
            isProbablyOfficePreviewableName(item.name)) {
          window.PQNAS_FILEMGR.officePreview.open(item);
        } else if (caps.textEdit !== false &&
            isProbablyTextEditableName(item.name)) {
          console.log("[app.dblclick.textedit] item =", item);
          console.log("[app.dblclick.textedit] rel =", currentRelPathFor(item));
          window.PQNAS_FILEMGR.textEdit.open(item);
        } else {
          doDownload(item);
        }
      }
    });

    return t;
  }

  function kvRow(k, v) {
    const kEl = document.createElement("div");
    kEl.className = "k";
    kEl.textContent = k;

    const vEl = document.createElement("div");
    vEl.className = "v mono";
    vEl.textContent = v == null ? "" : String(v);

    return [kEl, vEl];
  }

  function miniCopyButton(getTextFn) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn secondary";
    b.style.padding = "8px 10px";
    b.style.borderRadius = "12px";
    b.textContent = tr("filemgr.props.copy", null, "Copy");
    b.onclick = async () => {
      const text = getTextFn ? String(getTextFn() || "") : "";
      const ok = text ? await copyText(text) : false;
      b.textContent = ok ? tr("filemgr.props.copied", null, "Copied") : tr("filemgr.props.copy_failed", null, "Copy failed");
      setTimeout(() => (b.textContent = tr("filemgr.props.copy", null, "Copy")), 1100);
    };
    return b;
  }

  function propLabel(key) {
    return tr(`filemgr.props.${key}`, null, key);
  }

  function propTypeLabel(type) {
    const t = String(type || "").toLowerCase();
    if (t === "dir") return tr("filemgr.props.folder", null, "Folder");
    if (t === "file") return tr("filemgr.props.file", null, "File");
    return tr("filemgr.props.other", null, "Other");
  }

  function propYesNo(value) {
    return value
        ? tr("filemgr.props.yes", null, "Yes")
        : tr("filemgr.props.no", null, "No");
  }

  async function showProperties(item) {
    if (!item) return;

    if (propsShareTimer) {
      clearInterval(propsShareTimer);
      propsShareTimer = null;
    }

    const rel = joinPath(curPath, item.name || "");
    const isDirHint = item.type === "dir";
    const caps = fmCaps();
    const favoritesEnabled = caps.favorites !== false;
    const sharesEnabled = caps.shares !== false;
    const pqSharesEnabled = caps.pqShares !== false;

    if (propsTitle) propsTitle.textContent = isDirHint ? tr("filemgr.props.folder_title", null, "Folder properties") : tr("filemgr.props.file_title", null, "File properties");
    if (propsPath) propsPath.textContent = "/" + (rel || "");
    if (propsBody) propsBody.innerHTML = "";

    const pad2 = (n) => String(n).padStart(2, "0");

    const fmtUnix = (sec) => {
      if (!sec) return "";
      const d = new Date(Number(sec) * 1000);
      if (isNaN(d.getTime())) return String(sec);
      return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
    };

    const permsFromOctal = (modeStr) => {
      if (!modeStr || typeof modeStr !== "string") return "";
      const s = modeStr.trim();
      if (!/^[0-7]{3,4}$/.test(s)) return "";
      const oct = s.length === 4 ? s.slice(1) : s;
      const bits = oct.split("").map((c) => parseInt(c, 8));
      if (bits.length !== 3 || bits.some((x) => Number.isNaN(x))) return "";

      const rwx = (b) => {
        const r = (b & 4) ? "r" : "-";
        const w = (b & 2) ? "w" : "-";
        const x = (b & 1) ? "x" : "-";
        return r + w + x;
      };
      return rwx(bits[0]) + rwx(bits[1]) + rwx(bits[2]);
    };

    const isoUtcToMsLocal = (iso) => {
      if (!iso || typeof iso !== "string") return null;
      const ms = Date.parse(iso);
      return Number.isFinite(ms) ? ms : null;
    };

    const fmtCountdownLocal = (msLeft) => {
      if (msLeft == null) return "";
      if (msLeft <= 0) return tr("filemgr.props.expired", null, "Expired");
      const s = Math.floor(msLeft / 1000);
      const d = Math.floor(s / 86400);
      const h = Math.floor((s % 86400) / 3600);
      const m = Math.floor((s % 3600) / 60);
      const se = s % 60;
      if (d > 0) return `${d}d ${pad2(h)}:${pad2(m)}:${pad2(se)}`;
      return `${pad2(h)}:${pad2(m)}:${pad2(se)}`;
    };

    const pushRow = (rows, k, v) => {
      if (v === undefined || v === null || v === "") return;
      rows.push([k, v]);
    };

    const rows = [];
    pushRow(rows, propLabel("name"), item.name || "");
    pushRow(rows, propLabel("type"), isDirHint ? propTypeLabel("dir") : propTypeLabel("file"));
    if (favoritesEnabled) {
      pushRow(rows, propLabel("favorite"), propYesNo(isFavoriteItem(item)));
    }
    pushRow(rows, propLabel("path"), "/" + (rel || ""));

    if (!isDirHint && item.size_bytes != null) pushRow(rows, propLabel("size"), fmtSize(item.size_bytes || 0));
    if (item.mtime_unix) pushRow(rows, propLabel("modified"), fmtTime(item.mtime_unix));
    rows.push([propLabel("details"), tr("filemgr.props.loading", null, "Loading…")]);

    if (propsBody) {
      for (const [k, v] of rows) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
    }

    let st = null;
    try {
      const r = await fetch(apiStatUrl(rel ? rel : "."), {
        method: "POST",
        credentials: "include",
        headers: { "Accept": "application/json" }
      });
      st = await r.json();
    } catch (e) {
      st = { ok: false, error: "client_error", message: String(e) };
    }

    if (!propsBody) {
      openPropsModal?.();
      return;
    }

    propsBody.innerHTML = "";

    if (!st || !st.ok) {
      const msg = (st && (st.message || st.error))
          ? `${st.error || "error"}: ${st.message || ""}`.trim()
          : tr("filemgr.props.failed_load", null, "Failed to load properties");

      for (const [k, v] of [[propLabel("name"), item.name || ""], [propLabel("favorite"), propYesNo(isFavoriteItem(item))], [propLabel("path"), "/" + (rel || "")], [propLabel("error"), msg]]) {
        const [kEl, vEl] = kvRow(k, v);
        propsBody.appendChild(kEl);
        propsBody.appendChild(vEl);
      }
      openPropsModal?.();
      return;
    }

    const isDir = st.type === "dir";
    if (propsTitle) propsTitle.textContent = isDir ? tr("filemgr.props.folder_title", null, "Folder properties") : (st.type === "file" ? tr("filemgr.props.file_title", null, "File properties") : tr("filemgr.props.item_title", null, "Item properties"));
    if (propsPath) propsPath.textContent = st.path_norm || ("/" + (rel || ""));

    const rows2 = [];
    pushRow(rows2, propLabel("name"), st.name || "");
    pushRow(rows2, propLabel("type"), propTypeLabel(st.type));
    if (favoritesEnabled) {
      pushRow(rows2, propLabel("favorite"), propYesNo(isFavoriteItem(item)));
    }
    pushRow(rows2, propLabel("path"), st.path_norm || ("/" + (rel || "")));

    if (st.mode_octal) {
      const rwx = permsFromOctal(st.mode_octal);
      pushRow(rows2, propLabel("permissions"), rwx ? `${st.mode_octal} (${rwx})` : st.mode_octal);
    }

    if (st.mtime_epoch) pushRow(rows2, propLabel("modified"), fmtUnix(st.mtime_epoch));

    if (st.type === "file") {
      if (st.bytes != null) pushRow(rows2, propLabel("size"), fmtSize(st.bytes));
      if (st.mime) pushRow(rows2, propLabel("mime"), st.mime);
      if (typeof st.is_text === "boolean") pushRow(rows2, propLabel("looks_like_text"), propYesNo(st.is_text));
    }

    if (st.type === "dir") {
      if (st.children) {
        const c = st.children;
        const parts = [];
        if (c.files != null) parts.push(tr("filemgr.props.files", { count: c.files }, `${c.files} files`));
        if (c.dirs != null) parts.push(tr("filemgr.props.folders", { count: c.dirs }, `${c.dirs} folders`));
        if (c.other != null && c.other !== 0) parts.push(tr("filemgr.props.other_count", { count: c.other }, `${c.other} other`));
        pushRow(rows2, propLabel("children"), parts.join(", "));
      }
      if (st.bytes_recursive != null) pushRow(rows2, propLabel("size_recursive"), fmtSize(st.bytes_recursive));
      if (st.recursive_scanned_entries != null) pushRow(rows2, propLabel("scanned_entries"), String(st.recursive_scanned_entries));
      if (typeof st.recursive_complete === "boolean") pushRow(rows2, propLabel("scan_complete"), propYesNo(st.recursive_complete));
    }

    for (const [k, v] of rows2) {
      const [kEl, vEl] = kvRow(k, v);
      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    if (favoritesEnabled) {
      const [kEl, vEl] = kvRow(propLabel("favorite"), "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";
      vEl.style.display = "flex";
      vEl.style.alignItems = "center";
      vEl.style.gap = "8px";

      const txt = document.createElement("div");
      txt.textContent = isFavoriteItem(item) ? tr("filemgr.props.favorite_in", null, "This item is in favorites.") : tr("filemgr.props.favorite_not_in", null, "This item is not in favorites.");

      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = isFavoriteItem(item) ? tr("filemgr.tile.favorite_remove", null, "Remove from favorites") : tr("filemgr.tile.favorite_add", null, "Add to favorites");
      btn.onclick = async () => {
        try {
          const on = await toggleFavoriteRelPath(rel, item.type);
          txt.textContent = on ? tr("filemgr.props.favorite_in", null, "This item is in favorites.") : tr("filemgr.props.favorite_not_in", null, "This item is not in favorites.");
          btn.textContent = on ? tr("filemgr.tile.favorite_remove", null, "Remove from favorites") : tr("filemgr.tile.favorite_add", null, "Add to favorites");
          setBadge("ok", "ready");
          status.textContent = on ? tr("filemgr.status.added_favorite", { name: item.name }, `Added to favorites: ${item.name}`) : tr("filemgr.status.removed_favorite", { name: item.name }, `Removed from favorites: ${item.name}`);
          await load();
        } catch (err) {
          setBadge("err", "error");
          status.textContent = tr("filemgr.status.favorites_failed", { error: String(err && err.message ? err.message : err) }, `Favorites update failed: ${String(err && err.message ? err.message : err)}`);
        }
      };

      vEl.appendChild(txt);
      vEl.appendChild(btn);

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    if (st.type === "file") {
      const [kEl, vEl] = kvRow("SHA-256", "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";
      vEl.style.display = "flex";
      vEl.style.gap = "10px";
      vEl.style.alignItems = "center";
      vEl.style.flexWrap = "wrap";

      const line = document.createElement("div");
      line.className = "mono";
      line.style.wordBreak = "break-all";
      line.style.opacity = "0.92";
      line.textContent = tr("filemgr.props.computing", null, "Computing…");

      const btnCopy = miniCopyButton(() => line.textContent);
      btnCopy.disabled = true;

      vEl.appendChild(line);
      vEl.appendChild(btnCopy);

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);

      const cacheKey = hashCacheKey(rel, st.mtime_epoch, st.bytes);
      const cached = hashCache.get(cacheKey);

      if (cached && cached.sha256) {
        line.textContent = cached.sha256;
        btnCopy.disabled = false;
      } else {
        const expectedPath = propsPath ? propsPath.textContent : (st.path_norm || ("/" + (rel || "")));

        fetchSha256ForRelPath(rel)
            .then((out) => {
              hashCache.set(cacheKey, { sha256: out.sha256, raw: out.raw, atMs: Date.now() });
              const nowPath = propsPath ? propsPath.textContent : "";
              if (nowPath && nowPath !== expectedPath) return;
              line.textContent = out.sha256;
              btnCopy.disabled = false;
            })
            .catch((e) => {
              line.textContent = `Error: ${String(e && e.message ? e.message : e)}`;
              line.style.opacity = "0.85";
            });
      }
    }
    if (st.type === "file" &&
        window.PQNAS_FILEMGR &&
        window.PQNAS_FILEMGR.fileVersions &&
        typeof window.PQNAS_FILEMGR.fileVersions.canOpenFor === "function" &&
        window.PQNAS_FILEMGR.fileVersions.canOpenFor(item)) {

      const [kEl, vEl] = kvRow(tr("filemgr.props.versions", null, "Versions"), "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";
      vEl.style.display = "flex";
      vEl.style.alignItems = "center";
      vEl.style.gap = "10px";
      vEl.style.flexWrap = "wrap";

      const txt = document.createElement("div");
      txt.textContent = tr("filemgr.props.versions_desc", null, "Open preserved versions for this file and restore an older one.");

      const btn = document.createElement("button");
      btn.type = "button";
      btn.textContent = tr("filemgr.props.open_versions", null, "Open versions…");
      btn.onclick = () => {
        closePropsModal();
        window.PQNAS_FILEMGR.fileVersions.open(item);
      };

      vEl.appendChild(txt);
      vEl.appendChild(btn);

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }
    if (sharesEnabled || pqSharesEnabled) {
      const type = (item.type === "dir") ? "dir" : "file";
      const share = existingShareFor(rel, type);

      const [kEl, vEl] = kvRow(tr("filemgr.props.share", null, "Share"), "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";
      vEl.style.display = "flex";
      vEl.style.flexDirection = "column";
      vEl.style.gap = "8px";

      const topLine = document.createElement("div");
      topLine.textContent = share ? tr("filemgr.props.shared", null, "Shared") : tr("filemgr.props.not_shared", null, "Not shared");
      topLine.style.opacity = "0.92";
      vEl.appendChild(topLine);

      if (share) {
        const fullUrl = `${window.location.origin}${share.url || ("/s/" + (share.token || ""))}`;

        const urlRow = document.createElement("div");
        urlRow.style.display = "flex";
        urlRow.style.gap = "8px";
        urlRow.style.alignItems = "center";

        const inp = document.createElement("input");
        inp.type = "text";
        inp.value = fullUrl;
        inp.readOnly = true;
        inp.style.flex = "1";
        inp.style.minWidth = "0";

        const btnCopy2 = document.createElement("button");
        btnCopy2.type = "button";
        btnCopy2.textContent = tr("filemgr.props.copy", null, "Copy");
        btnCopy2.onclick = async () => {
          const ok = await copyText(fullUrl);
          btnCopy2.textContent = ok ? tr("filemgr.props.copied", null, "Copied") : tr("filemgr.props.copy_failed", null, "Copy failed");
          setTimeout(() => (btnCopy2.textContent = tr("filemgr.props.copy", null, "Copy")), 1200);
        };

        urlRow.appendChild(inp);
        urlRow.appendChild(btnCopy2);

        const expLine = document.createElement("div");
        expLine.style.display = "flex";
        expLine.style.gap = "10px";
        expLine.style.flexWrap = "wrap";
        expLine.style.opacity = "0.92";

        const expAt = share.expires_at || "";
        const expMs = isoUtcToMsLocal(expAt);

        const expLabel = document.createElement("span");
        expLabel.textContent = expAt ? tr("filemgr.props.expires_at", { time: expAt }, `Expires: ${expAt}`) : tr("filemgr.props.expires_never", null, "Expires: never");

        const cdLabel = document.createElement("span");
        cdLabel.style.fontFamily = "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace";
        cdLabel.style.opacity = "0.95";

        const updateCountdown = () => {
          if (!expMs) { cdLabel.textContent = ""; return; }
          const left = expMs - Date.now();
          cdLabel.textContent = tr("filemgr.props.remaining", { time: fmtCountdownLocal(left) }, `Remaining: ${fmtCountdownLocal(left)}`);
        };
        updateCountdown();

        if (expMs) propsShareTimer = setInterval(updateCountdown, 1000);

        expLine.appendChild(expLabel);
        expLine.appendChild(cdLabel);

        const dl = document.createElement("div");
        dl.style.opacity = "0.85";
        if (share.downloads != null) dl.textContent = tr("filemgr.props.downloads", { count: share.downloads }, `Downloads: ${share.downloads}`);

        const actions = document.createElement("div");
        actions.style.display = "flex";
        actions.style.gap = "8px";
        actions.style.alignItems = "center";

        const btnRevoke = document.createElement("button");
        btnRevoke.type = "button";
        btnRevoke.textContent = tr("filemgr.props.revoke", null, "Revoke");
        btnRevoke.onclick = async () => {
          const ok = confirm(tr("filemgr.props.revoke_confirm", null, "Revoke this share link?\n\nThis will invalidate the URL immediately."));
          if (!ok) return;

          btnRevoke.disabled = true;
          btnRevoke.textContent = tr("filemgr.props.revoking", null, "Revoking…");

          try {
            const r = await fetch("/api/v4/shares/revoke", {
              method: "POST",
              credentials: "include",
              cache: "no-store",
              headers: { "Content-Type": "application/json", "Accept": "application/json" },
              body: JSON.stringify({ token: share.token })
            });
            const j = await r.json().catch(() => null);
            if (!r.ok || !j || !j.ok) {
              const msg = j && (j.message || j.error)
                  ? `${j.error || ""} ${j.message || ""}`.trim()
                  : `HTTP ${r.status}`;
              throw new Error(msg || "revoke failed");
            }

            await refreshSharesCache(true);
            await showProperties(item);
            return;
          } catch (e) {
            btnRevoke.textContent = tr("filemgr.props.revoke_failed", null, "Revoke failed");
            setTimeout(() => {
              btnRevoke.textContent = tr("filemgr.props.revoke", null, "Revoke");
              btnRevoke.disabled = false;
            }, 1400);
            return;
          }
        };

        actions.appendChild(btnRevoke);

        vEl.appendChild(urlRow);
        vEl.appendChild(expLine);
        if (share.downloads != null) vEl.appendChild(dl);
        vEl.appendChild(actions);
      } else {
        const rowBtns = document.createElement("div");
        rowBtns.style.display = "flex";
        rowBtns.style.gap = "8px";
        rowBtns.style.flexWrap = "wrap";

        if (sharesEnabled) {
          const btn = document.createElement("button");
          btn.type = "button";
          btn.textContent = tr("filemgr.props.create_share", null, "Create share link…");
          btn.onclick = () => openShareDialogFor(item);
          rowBtns.appendChild(btn);
        }

        if (st.type === "file" && pqSharesEnabled) {
          const btnPq = document.createElement("button");
          btnPq.type = "button";
          btnPq.textContent = tr("filemgr.props.create_pq_invite", null, "Create PQ invite…");
          btnPq.onclick = () => openShareDialogFor(item, {
            forceMode: "pq_recipient_enrolled_v1"
          });
          rowBtns.appendChild(btnPq);
        }

        vEl.appendChild(rowBtns);
      }

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    {
      const [kEl, vEl] = kvRow(propLabel("details"), "");
      vEl.classList.remove("mono");
      vEl.innerHTML = "";

      const details = document.createElement("details");
      details.style.width = "100%";

      const summary = document.createElement("summary");
      summary.textContent = tr("filemgr.props.raw_json", null, "Raw JSON");
      summary.style.cursor = "pointer";
      summary.style.userSelect = "none";

      const pre = document.createElement("pre");
      pre.className = "mono pre";
      pre.style.margin = "10px 0 0 0";
      pre.style.whiteSpace = "pre-wrap";
      pre.style.wordBreak = "break-word";
      pre.textContent = JSON.stringify(st, null, 2);

      details.appendChild(summary);
      details.appendChild(pre);
      vEl.appendChild(details);

      propsBody.appendChild(kEl);
      propsBody.appendChild(vEl);
    }

    openPropsModal?.();
  }

  async function load(forceList = false) {
    forceList = forceList === true;
    const mySeq = ++loadSeq;

    if (activeLoadController) {
      try { activeLoadController.abort(); } catch (_) {}
    }

    const controller = new AbortController();
    activeLoadController = controller;

    const loadSnap = currentScopeSnapshot(curPath);

    closeMenu();
    setBadge("warn", "loading…");
    status.textContent = "Loading…";
    if (gridEl) gridEl.replaceChildren();

    const favoritesPromise = fetchFavoritesFromServer().catch((e) => {
      console.warn("Favorites load failed:", e);
    });

    if (!storageBlocked) hideEmptyState();

    const loadPath = loadSnap.path;

    if (gridEl) gridEl.classList.remove("hidden");
    applyViewModeToDom();
    applyFavoritesFilterUi();
    applySortUi();

    const sharesPromise = refreshSharesCache();
    const quotaPromise = refreshQuotaInfoIfNeeded(false);
    const caps = fmCaps();
    const favoritesEnabled = caps.favorites !== false;
    const sorter = sortApi();

    try {
      const j = await fetchFileListForSnapshot(loadSnap, {
        force: forceList,
        signal: controller.signal
      });

      if (controller.signal.aborted) return;
      if (mySeq !== loadSeq) return;
      if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return;

      if (!j || !j.ok) {
        if (j && j.error === "storage_unallocated") {
          showStorageUnallocatedState(j);
          return;
        }

        setBadge("err", "error");
        const msg = j && (j.message || j.error)
            ? `${j.error || ""} ${j.message || ""}`.trim()
            : `List failed`;
        status.textContent = msg || "List failed";

        const err = document.createElement("div");
        err.className = "tile mono";
        err.style.cursor = "default";
        err.textContent = msg || "bad response";
        gridEl.appendChild(err);
        return;
      }

      curPath = (typeof j.path === "string") ? j.path : curPath;
      renderBreadcrumb();

      const sortMode = sorter ? sorter.getMode() : null;
      const needsFavoritesReady =
          favoritesEnabled &&
          (favoritesOnly || (sortMode && sortMode.id === "favorites_first"));

      if (needsFavoritesReady) {
        await favoritesPromise;
        if (controller.signal.aborted) return;
        if (mySeq !== loadSeq) return;
        if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return;
      }

      const allItemsRaw = Array.isArray(j.items) ? j.items.slice() : [];

      const allItems = sorter
          ? sorter.sortItems(allItemsRaw, {
            currentRelPathFor,
            isFavoriteRelPath,
            isFavoriteItem
          })
          : allItemsRaw.sort((a, b) => {
            if (a.type !== b.type) return a.type === "dir" ? -1 : 1;
            return String(a.name || "").localeCompare(String(b.name || ""));
          });

      const items = (favoritesEnabled && favoritesOnly)
          ? allItems.filter((it) => isFavoriteRelPath(currentRelPathFor(it), it.type))
          : allItems;

      lastListedItems = items.slice();
      setBadge("ok", "ready");

      const sortSuffix = sortMode ? ` • Sort: ${sortMode.shortLabel}` : "";

      status.textContent = (favoritesEnabled && favoritesOnly)
          ? `Favorites: ${items.length} / ${allItems.length}${sortSuffix}`
          : `Items: ${items.length}${sortSuffix}`;

      if (!items.length) {
        const empty = document.createElement("div");
        empty.className = "tile mono";
        empty.style.cursor = "default";
        empty.textContent = (favoritesEnabled && favoritesOnly)
            ? "(no favorites in this folder)\n\nTip: click ☆ on any item or use the context menu."
            : "(empty)\n\nTip: drag & drop files/folders here to upload.";
        gridEl.appendChild(empty);

        quotaPromise
            .then((q) => {
              if (mySeq !== loadSeq) return;
              if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return;
              if (q) applyQuotaUi(q);
            })
            .catch(() => {});
        return;
      }

      const rendered = await renderItemsChunked(items, mySeq, loadSnap, loadPath);
      if (!rendered) return;

      applySelectionToDom();

      quotaPromise
          .then((q) => {
            if (mySeq !== loadSeq) return;
            if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return;
            if (q) applyQuotaUi(q);
          })
          .catch(() => {});

      sharesPromise
          .then(() => {
            if (mySeq !== loadSeq) return;
            if (!sameScopeSnapshot(loadSnap, currentScopeSnapshot(loadPath))) return;
            decorateTilesWithShareBadges(items);
          })
          .catch(() => {});
    } catch (e) {
      if (controller.signal.aborted || (e && e.name === "AbortError")) {
        return;
      }

      setBadge("err", "network");
      status.textContent = "Network error";

      const err = document.createElement("div");
      err.className = "tile mono";
      err.style.cursor = "default";
      err.textContent = String(e && e.stack ? e.stack : e);
      gridEl.appendChild(err);
    } finally {
      if (activeLoadController === controller) {
        activeLoadController = null;
      }
    }
  }

  refreshBtn?.addEventListener("click", () => load(true));
  upBtn?.addEventListener("click", () => {
    curPath = parentPath(curPath);
    clearSelection();
    load();
  });

  viewToggleBtn?.addEventListener("click", () => {
    setViewMode(viewMode === "grid" ? "list" : "grid");
  });

  sortBtn?.addEventListener("click", () => {
    const s = sortApi();
    if (!s) return;

    const mode = s.cycleMode();
    applySortUi();
    clearSelection();
    setBadge("ok", "ready");
    status.textContent = `Sort: ${mode.title}`;
    load();
  });

  favoritesToggleBtn?.addEventListener("click", () => {
    toggleFavoritesOnly();
  });

  applyViewModeToDom();
  applyFavoritesFilterUi();
  applySortUi();

  const FM = window.PQNAS_FILEMGR;
  FM.getCurPath = () => curPath;
  FM.getLastListedItems = () => lastListedItems.slice();
  FM.setPathAndLoad = setPathAndLoad;
  FM.clearSelection = clearSelection;
  FM.currentRelPathFor = currentRelPathFor;
  FM.joinPath = joinPath;
  FM.apiGetUrl = apiGetUrl;
  FM.apiCopyUrl = apiCopyUrl;
  FM.openCopyModalForItem = openCopyModalForItem;
  FM.openCopyModalForSelection = openCopyModalForSelection;
  FM.fmtSize = fmtSize;
  FM.setBadge = setBadge;
  FM.copyText = copyText;
  FM.getStatusEl = () => status;
  FM.getLoadFn = () => load;
  FM.isProbablyTextEditableName = isProbablyTextEditableName;
  FM.isProbablyImagePreviewableName = isProbablyImagePreviewableName;
  FM.isProbablyPdfPreviewableName = isProbablyPdfPreviewableName;
  FM.isProbablyVideoPreviewableName = isProbablyVideoPreviewableName;
  FM.isProbablyOfficePreviewableName = isProbablyOfficePreviewableName;
  FM.isProbablyAudioPreviewableName = isProbablyAudioPreviewableName;
  load().catch((e) => {
    console.warn("Initial load failed:", e);
  });
  
})();
