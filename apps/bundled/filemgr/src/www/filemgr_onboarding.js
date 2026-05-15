(function () {
    "use strict";

    const bootAt = Date.now();

    let ready = false;
    let storageUnallocated = false;

    function textOf(el) {
        return String((el && (el.innerText || el.textContent)) || "").toLowerCase();
    }

    function isShown(el) {
        if (!el) return false;
        if (el.classList && el.classList.contains("hidden")) return false;

        const style = window.getComputedStyle(el);
        if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
            return false;
        }

        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
    }

    function looksStorageUnallocated(text) {
        if (!text) return false;

        return text.includes("storage_unallocated") ||
            text.includes("storage unallocated") ||
            text.includes("storage not allocated") ||
            text.includes("storage has not been allocated") ||
            text.includes("no storage allocated") ||
            text.includes("not allocated yet") ||
            (text.includes("storage") && text.includes("unallocated")) ||
            (text.includes("storage") && text.includes("not allocated")) ||
            (text.includes("storage") && text.includes("admin") && text.includes("allocate"));
    }

    function emitStateChanged() {
        try {
            window.dispatchEvent(new CustomEvent("dnx:filemgr-tour-state-changed", {
                detail: {
                    ready: !!ready,
                    storageUnallocated: !!storageUnallocated
                }
            }));
        } catch (_) {
            // ignore
        }
    }

    function sync() {
        const empty = document.getElementById("emptyState");
        const gridWrap = document.getElementById("gridWrap");
        const grid = document.getElementById("grid");
        const badge = document.getElementById("badge");
        const status = document.getElementById("status");
        const pathLine = document.getElementById("pathLine");

        const beforeReady = ready;
        const beforeStorageUnallocated = storageUnallocated;

        const emptyShown = isShown(empty);
        const emptyText = textOf(empty);
        const storageBlocked = emptyShown && looksStorageUnallocated(emptyText);

        const badgeText = textOf(badge);
        const statusText = textOf(status);
        const pathText = textOf(pathLine);

        const gridHasItems = !!(grid && grid.children && grid.children.length > 0);
        const badgeLoaded = !!badgeText && !badgeText.includes("loading");
        const pathLoaded = !!pathText && !pathText.includes("loading");
        const statusLoaded = !!statusText && !statusText.includes("loading");

        storageUnallocated = !!storageBlocked;

        ready = storageBlocked ||
            emptyShown ||
            gridHasItems ||
            badgeLoaded ||
            pathLoaded ||
            statusLoaded ||
            ((Date.now() - bootAt) > 5000);

        if (empty) {
            empty.toggleAttribute("data-tour-filemgr-storage-unallocated", !!storageBlocked);
            empty.toggleAttribute("data-tour-filemgr-ready", !!ready);
        }

        if (gridWrap) {
            gridWrap.toggleAttribute("data-tour-filemgr-usable", !!(ready && !storageBlocked));
        }

        if (grid) {
            grid.toggleAttribute("data-tour-filemgr-usable", !!(ready && !storageBlocked));
        }

        if (beforeReady !== ready || beforeStorageUnallocated !== storageUnallocated) {
            emitStateChanged();
        }
    }

    function start() {
        sync();

        const observed = [
            document.getElementById("emptyState"),
            document.getElementById("gridWrap"),
            document.getElementById("grid"),
            document.getElementById("badge"),
            document.getElementById("status"),
            document.getElementById("pathLine")
        ].filter(Boolean);

        if (window.MutationObserver) {
            const observer = new MutationObserver(sync);
            for (const el of observed) {
                observer.observe(el, {
                    attributes: true,
                    childList: true,
                    characterData: true,
                    subtree: true
                });
            }
        }

        window.addEventListener("resize", sync, { passive: true });

        window.setTimeout(sync, 100);
        window.setTimeout(sync, 250);
        window.setTimeout(sync, 900);
        window.setTimeout(sync, 1800);
        window.setTimeout(sync, 5200);
    }

    window.DNANexusFileManagerTourState = {
        sync,
        isReady: function () {
            sync();
            return !!ready;
        },
        isStorageUnallocated: function () {
            sync();
            return !!storageUnallocated;
        }
    };

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once: true });
    } else {
        start();
    }
})();
