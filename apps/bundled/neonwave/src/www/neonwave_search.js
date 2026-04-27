(() => {
    "use strict";

    const STORAGE_KEY = "pqnas_neonwave_search_v1";

    const el = (id) => document.getElementById(id);

    let listEl = null;
    let inputEl = null;
    let clearBtn = null;
    let deepBtn = null;
    let countEl = null;
    let emptyEl = null;
    let pending = false;

    function normalizeText(s) {
        s = String(s ?? "");

        try {
            s = s.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
        } catch {
            // Older browser: plain lowercase search is still OK.
        }

        return s.toLowerCase();
    }

    function queryTokens() {
        return normalizeText(inputEl?.value || "")
            .trim()
            .split(/\s+/)
            .filter(Boolean);
    }

    function searchRows() {
        if (!listEl) return [];
        return Array.from(listEl.children).filter((n) =>
            n && n.classList && n.classList.contains("item")
        );
    }

    function saveQuery() {
        try {
            localStorage.setItem(STORAGE_KEY, inputEl?.value || "");
        } catch {
            // Ignore private-mode/storage failures.
        }
    }

    function applySearch() {
        pending = false;

        if (!listEl || !inputEl) return;

        const tokens = queryTokens();
        const rows = searchRows();

        let visible = 0;

        for (const row of rows) {
            const hay = normalizeText(row.textContent || "");
            const hit = !tokens.length || tokens.every((t) => hay.includes(t));

            row.classList.toggle("nwSearchHidden", !hit);
            if (hit) visible++;
        }

        if (countEl) {
            countEl.textContent = tokens.length
                ? `${visible}/${rows.length}`
                : `${rows.length}`;
        }

        if (emptyEl) {
            emptyEl.hidden = !(tokens.length && rows.length > 0 && visible === 0);
        }

        saveQuery();
    }

    function scheduleSearch() {
        if (pending) return;
        pending = true;
        window.requestAnimationFrame(applySearch);
    }

    function clearSearch() {
        if (!inputEl) return;
        inputEl.value = "";
        applySearch();
        inputEl.focus();
    }

    function restoreQuery() {
        try {
            const q = localStorage.getItem(STORAGE_KEY);
            if (q && inputEl) inputEl.value = q;
        } catch {
            // Ignore.
        }
    }

    function initKeyboardShortcuts() {
        document.addEventListener("keydown", (ev) => {
            const tag = String(ev.target?.tagName || "").toLowerCase();
            const typing = tag === "input" || tag === "textarea" || tag === "select" || ev.target?.isContentEditable;

            if (ev.key === "/" && !typing) {
                ev.preventDefault();
                inputEl?.focus();
                inputEl?.select();
                return;
            }

            if (ev.key === "Escape" && document.activeElement === inputEl && inputEl.value) {
                ev.preventDefault();
                clearSearch();
            }
        });
    }
    async function deepSearch() {
        const api = window.PQNAS_NEONWAVE_APP;

        if (!api || typeof api.scanCurrent !== "function") {
            alert("NeonWave scanner is not ready yet.");
            return;
        }

        try {
            if (deepBtn) {
                deepBtn.disabled = true;
                deepBtn.textContent = "Scanning…";
            }

            await api.scanCurrent();

            // MutationObserver usually handles this, but this makes it immediate.
            applySearch();
        } catch (e) {
            alert(String(e && e.message ? e.message : e));
        } finally {
            if (deepBtn) {
                deepBtn.disabled = false;
                deepBtn.textContent = "Deep";
            }
        }
    }
    function init() {
        listEl = el("list");
        inputEl = el("librarySearch");
        clearBtn = el("librarySearchClear");
        deepBtn = el("librarySearchDeep");
        countEl = el("librarySearchCount");
        emptyEl = el("librarySearchEmpty");

        if (!listEl || !inputEl) return;

        restoreQuery();

        inputEl.addEventListener("input", applySearch);
        clearBtn?.addEventListener("click", clearSearch);
        deepBtn?.addEventListener("click", deepSearch);

        const observer = new MutationObserver(scheduleSearch);
        observer.observe(listEl, { childList: true });

        initKeyboardShortcuts();
        applySearch();

        window.PQNAS_NEONWAVE_SEARCH = {
            apply: applySearch,
            clear: clearSearch
        };
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init, { once: true });
    } else {
        init();
    }
})();
