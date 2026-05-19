(() => {
  "use strict";

  const API = "/api/v4/echostack";

  const el = (id) => document.getElementById(id);

  function deepT(key, params, fallback) {
    try {
      const api = window.PQNAS_I18N;
      if (api && typeof api.t === "function") {
        return api.t(key, params || null, fallback);
      }
    } catch (_) {}

    let out = String(fallback || key || "");
    const p = params || {};
    for (const name of Object.keys(p)) {
      out = out.split(`{${name}}`).join(String(p[name]));
    }
    return out;
  }

  async function api(path, opts = {}) {
    const r = await fetch(API + path, {
      credentials: "include",
      cache: "no-store",
      headers: {
        "Accept": "application/json",
        ...(opts.body ? { "Content-Type": "application/json" } : {})
      },
      ...opts
    });

    const j = await r.json().catch(() => ({}));
    if (!r.ok || !j.ok) {
      throw new Error(j.message || j.error || `HTTP ${r.status}`);
    }

    return j;
  }

  function setDeepStatus(msg, kind) {
    const s = el("deepSearchStatus");
    if (!s) return;
    s.className = "deepSearchStatus" + (kind ? ` ${kind}` : "");
    s.textContent = msg || "";
  }

  function resultUrl(item) {
    return item.final_url || item.url || "#";
  }

  function renderResults(results) {
    const root = el("deepSearchResults");
    if (!root) return;

    root.innerHTML = "";

    if (!results.length) {
      const empty = document.createElement("div");
      empty.className = "deepSearchEmpty";
      empty.textContent = deepT("echostack.deep.no_matches", null, "No archived page text matched that search.");
      root.appendChild(empty);
      return;
    }

    for (const item of results) {
      const card = document.createElement("article");
      card.className = "deepSearchResult";

      const title = document.createElement("a");
      title.className = "deepSearchTitle";
      title.href = resultUrl(item);
      title.target = "_blank";
      title.rel = "noopener noreferrer";
      title.textContent = item.title || item.url || deepT("common.untitled", null, "Untitled");

      const url = document.createElement("div");
      url.className = "deepSearchUrl";
      url.textContent = item.url || item.final_url || "";

      const meta = document.createElement("div");
      meta.className = "deepSearchMeta";

      const parts = [];
      if (item.collection) parts.push(deepT("echostack.meta.collection", { collection: item.collection }, "Collection: {collection}"));
      if (item.tags_text) parts.push(deepT("echostack.meta.tags", { tags: item.tags_text }, "Tags: {tags}"));
      if (item.source_file) parts.push(deepT("echostack.deep.indexed_from", { source: item.source_file }, "Indexed from: {source}"));
      parts.push(deepT("echostack.deep.score", { score: Math.round(Number(item.score || 0)) }, "Score: {score}"));
      meta.textContent = parts.join(" • ");

      const snippet = document.createElement("div");
      snippet.className = "deepSearchSnippet";
      snippet.textContent = item.snippet || "";

      const actions = document.createElement("div");
      actions.className = "deepSearchActions";

      const openArchive = document.createElement("button");
      openArchive.type = "button";
      openArchive.textContent = deepT("echostack.open_archive", null, "Open archive");
      openArchive.addEventListener("click", () => {
        window.open(`${API}/archive/view?id=${encodeURIComponent(item.id)}`, "_blank", "noopener,noreferrer");
      });

      const reindex = document.createElement("button");
      reindex.type = "button";
      reindex.textContent = deepT("echostack.reindex", null, "Re-index");
      reindex.addEventListener("click", async () => {
        reindex.disabled = true;
        reindex.textContent = deepT("echostack.indexing", null, "Indexing");
        try {
          await reindexItem(item.id);
          setDeepStatus(deepT("echostack.deep.item_reindexed", null, "Item re-indexed."), "good");
          await runSearch();
        } catch (e) {
          setDeepStatus(deepT("echostack.deep.reindex_failed", { error: e.message || String(e) }, "Re-index failed: {error}"), "bad");
        } finally {
          reindex.disabled = false;
          reindex.textContent = deepT("echostack.reindex", null, "Re-index");
        }
      });

      actions.appendChild(openArchive);
      actions.appendChild(reindex);

      card.appendChild(title);
      card.appendChild(url);
      if (snippet.textContent) card.appendChild(snippet);
      card.appendChild(meta);
      card.appendChild(actions);

      root.appendChild(card);
    }
  }

  async function runSearch() {
    const q = (el("deepSearchInput")?.value || "").trim();

    if (!q) {
      renderResults([]);
      setDeepStatus(deepT("echostack.deep_search_type_phrase", null, "Type a phrase to search inside archived page text."));
      return;
    }

    setDeepStatus(deepT("echostack.deep.searching", null, "Searching archived text…"));

    const j = await api(`/search/fulltext?q=${encodeURIComponent(q)}&limit=25`);
    const results = Array.isArray(j.results) ? j.results : [];

    renderResults(results);
    setDeepStatus(deepT("echostack.result_count_dot", { count: results.length }, "{count} result(s)."), "good");
  }

  async function reindexItem(id) {
    if (!id) return false;

    await api("/search/reindex-item", {
      method: "POST",
      body: JSON.stringify({ id })
    });

    return true;
  }

  async function reindexAll() {
    const btn = el("deepReindexAllBtn");
    if (btn) {
      btn.disabled = true;
      btn.textContent = deepT("echostack.deep.indexing_archives", null, "Indexing archives");
    }

    try {
      setDeepStatus(deepT("echostack.deep.reindexing_archived_pages", null, "Re-indexing archived pages…"));
      const j = await api("/search/reindex-all", {
        method: "POST",
        body: JSON.stringify({})
      });

      setDeepStatus(
        deepT("echostack.deep.reindex_all_done", { indexed: j.indexed || 0, skipped: j.skipped || 0, failed: j.failed || 0 }, "Indexed {indexed}; skipped {skipped}; failed {failed}."),
        (j.failed || 0) ? "bad" : "good"
      );

      await runSearch();
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.textContent = deepT("echostack.reindex_archives", null, "Re-index archives");
      }
    }
  }

  function bind() {
    el("deepSearchBtn")?.addEventListener("click", () => {
      runSearch().catch((e) => setDeepStatus(e.message || String(e), "bad"));
    });

    el("deepReindexAllBtn")?.addEventListener("click", () => {
      reindexAll().catch((e) => setDeepStatus(e.message || String(e), "bad"));
    });

    el("deepSearchInput")?.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        runSearch().catch((err) => setDeepStatus(err.message || String(err), "bad"));
      }
    });
  }

  window.EchoStackFullText = {
    reindexItem,
    runSearch
  };

  document.addEventListener("DOMContentLoaded", bind);
})();
