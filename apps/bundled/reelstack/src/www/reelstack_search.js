(() => {
  "use strict";

  window.PQNAS_REELSTACK_SEARCH = window.PQNAS_REELSTACK_SEARCH || {};

  let backdrop = null;
  let input = null;
  let applyCb = null;
  let clearCb = null;

  function searchT(key, params, fallback) {
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

  function ensureModal() {
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.className = "rsSearchBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="rsSearchCard" role="dialog" aria-modal="true" aria-label="${searchT("reelstack.search.aria", null, "Search Reel Stack")}">
        <div class="rsSearchHead">
          <div>
            <div class="rsSearchKicker">${searchT("reelstack.search.kicker", null, "Reel Stack search")}</div>
            <h2>${searchT("reelstack.search.title", null, "Search videos")}</h2>
            <p>${searchT("reelstack.search.help", null, "Use one or more terms. Every term must match. Searches filenames, paths, titles, tags, notes, and loaded technical metadata.")}</p>
          </div>
          <button id="rsSearchClose" class="rsBtn" type="button">${searchT("common.close", null, "Close")}</button>
        </div>

        <label class="rsSearchField">
          <span>${searchT("reelstack.search.terms", null, "Search terms")}</span>
          <input id="rsSearchInput" class="rsInput" type="search" placeholder="${searchT("reelstack.search.placeholder", null, "family h265 4k archive")}">
        </label>

        <div class="rsSearchHints">
          ${searchT("reelstack.search.examples", null, "Examples:")} <code>family</code>, <code>4k h265</code>, <code>#archive watched</code>
        </div>

        <div class="rsSearchActions">
          <button id="rsSearchClear" class="rsBtn" type="button">${searchT("common.clear", null, "Clear")}</button>
          <button id="rsSearchApply" class="rsBtn primary" type="button">${searchT("common.search", null, "Search")}</button>
        </div>
      </div>
    `;

    document.body.appendChild(backdrop);

    input = backdrop.querySelector("#rsSearchInput");

    const close = () => {
      backdrop.hidden = true;
    };

    const apply = () => {
      const q = String(input && input.value || "").trim();
      backdrop.hidden = true;
      if (typeof applyCb === "function") applyCb(q);
    };

    const clear = () => {
      if (input) input.value = "";
      backdrop.hidden = true;

      if (typeof clearCb === "function") {
        clearCb();
      } else if (typeof applyCb === "function") {
        applyCb("");
      }
    };

    backdrop.querySelector("#rsSearchClose")?.addEventListener("click", close);
    backdrop.querySelector("#rsSearchApply")?.addEventListener("click", apply);
    backdrop.querySelector("#rsSearchClear")?.addEventListener("click", clear);

    backdrop.addEventListener("click", (ev) => {
      if (ev.target === backdrop) close();
    });

    backdrop.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") {
        ev.preventDefault();
        ev.stopPropagation();
        close();
        return;
      }

      if (ev.key === "Enter") {
        ev.preventDefault();
        ev.stopPropagation();
        apply();
      }
    }, true);

    return backdrop;
  }

  window.PQNAS_REELSTACK_SEARCH.open = function openReelStackSearch(opts) {
    opts = opts || {};
    ensureModal();

    applyCb = opts.onApply || null;
    clearCb = opts.onClear || null;

    if (input) input.value = String(opts.initialQuery || "");

    backdrop.hidden = false;

    window.setTimeout(() => {
      try {
        input?.focus();
        input?.select();
      } catch (_) {}
    }, 0);
  };
})();
