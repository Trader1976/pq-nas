(() => {
  "use strict";

  window.PQNAS_REELSTACK_SEARCH = window.PQNAS_REELSTACK_SEARCH || {};

  let backdrop = null;
  let input = null;
  let applyCb = null;
  let clearCb = null;

  function ensureModal() {
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.className = "rsSearchBackdrop";
    backdrop.hidden = true;

    backdrop.innerHTML = `
      <div class="rsSearchCard" role="dialog" aria-modal="true" aria-label="Search Reel Stack">
        <div class="rsSearchHead">
          <div>
            <div class="rsSearchKicker">Reel Stack search</div>
            <h2>Search videos</h2>
            <p>Use one or more terms. Every term must match. Searches filenames, paths, titles, tags, notes, and loaded technical metadata.</p>
          </div>
          <button id="rsSearchClose" class="rsBtn" type="button">Close</button>
        </div>

        <label class="rsSearchField">
          <span>Search terms</span>
          <input id="rsSearchInput" class="rsInput" type="search" placeholder="family h265 4k archive">
        </label>

        <div class="rsSearchHints">
          Examples: <code>family</code>, <code>4k h265</code>, <code>#archive watched</code>
        </div>

        <div class="rsSearchActions">
          <button id="rsSearchClear" class="rsBtn" type="button">Clear</button>
          <button id="rsSearchApply" class="rsBtn primary" type="button">Search</button>
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
