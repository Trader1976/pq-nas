(() => {
    "use strict";

    const KEY = "pqnas_lang";
    const DEFAULT_LANG = "en";
    const LANGS = new Set(["en", "fi"]);
    const cache = new Map();

    let currentLang = DEFAULT_LANG;
    let currentDict = {};
    let readyPromise = null;

    function normalizeLanguage(lang) {
        const raw = String(lang || "").trim().toLowerCase().replace("_", "-");
        if (LANGS.has(raw)) return raw;
        const base = raw.split("-")[0];
        if (LANGS.has(base)) return base;
        return DEFAULT_LANG;
    }

    function loadLocalLanguage() {
        try {
            const stored = localStorage.getItem(KEY);
            if (stored) return normalizeLanguage(stored);
        } catch (_) {}

        try {
            const nav = navigator.language || "";
            if (nav) return normalizeLanguage(nav);
        } catch (_) {}

        return DEFAULT_LANG;
    }

    function installBootHideStyle() {
        if (document.getElementById("pqnasI18nBootHideStyle")) return;

        const style = document.createElement("style");
        style.id = "pqnasI18nBootHideStyle";
        style.textContent = `
html[data-i18n-pending="1"] body{
    visibility:hidden !important;
}
`;
        document.head.appendChild(style);
    }

    function setI18nPending(on) {
        if (on) {
            installBootHideStyle();
            document.documentElement.setAttribute("data-i18n-pending", "1");
            document.documentElement.removeAttribute("data-i18n-ready");
            return;
        }

        document.documentElement.removeAttribute("data-i18n-pending");
        document.documentElement.setAttribute("data-i18n-ready", "1");
    }

    function whenDomReady() {
        if (document.readyState !== "loading") return Promise.resolve();
        return new Promise((resolve) => {
            document.addEventListener("DOMContentLoaded", resolve, { once: true });
        });
    }

    function dispatchLanguageChanged(lang) {
        try {
            window.dispatchEvent(new CustomEvent("pqnas-language-changed", {
                detail: { lang }
            }));
        } catch (_) {}
    }

    function interpolate(text, vars) {
        let out = String(text ?? "");
        if (!vars || typeof vars !== "object") return out;

        for (const [key, value] of Object.entries(vars)) {
            out = out.replaceAll(`{${key}}`, String(value ?? ""));
        }
        return out;
    }

    async function fetchDict(lang) {
        const safe = normalizeLanguage(lang);
        if (cache.has(safe)) return cache.get(safe);

        try {
            const r = await fetch(`/static/i18n/${encodeURIComponent(safe)}.json`, {
                cache: "no-store",
                headers: { "Accept": "application/json" }
            });
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            const j = await r.json();
            const dict = (j && typeof j === "object") ? j : {};
            cache.set(safe, dict);
            return dict;
        } catch (_) {
            if (safe !== DEFAULT_LANG) return fetchDict(DEFAULT_LANG);
            cache.set(DEFAULT_LANG, {});
            return {};
        }
    }

    function lookup(key, fallback) {
        const k = String(key || "");
        if (!k) return String(fallback ?? "");
        const v = currentDict && Object.prototype.hasOwnProperty.call(currentDict, k)
            ? currentDict[k]
            : undefined;
        if (typeof v === "string") return v;
        return String(fallback ?? k);
    }

    function t(key, vars, fallback) {
        return interpolate(lookup(key, fallback), vars);
    }

    function apply(root) {
        const scope = root || document;
        if (!scope || !scope.querySelectorAll) return;

        for (const el of scope.querySelectorAll("[data-i18n]")) {
            const key = el.getAttribute("data-i18n") || "";
            const fallback = el.getAttribute("data-i18n-fallback") || el.textContent || "";
            el.textContent = t(key, null, fallback);
        }

        for (const el of scope.querySelectorAll("[data-i18n-title]")) {
            const key = el.getAttribute("data-i18n-title") || "";
            const fallback = el.getAttribute("title") || "";
            el.setAttribute("title", t(key, null, fallback));
        }

        for (const el of scope.querySelectorAll("[data-i18n-placeholder]")) {
            const key = el.getAttribute("data-i18n-placeholder") || "";
            const fallback = el.getAttribute("placeholder") || "";
            el.setAttribute("placeholder", t(key, null, fallback));
        }

        for (const el of scope.querySelectorAll("[data-i18n-aria-label]")) {
            const key = el.getAttribute("data-i18n-aria-label") || "";
            const fallback = el.getAttribute("aria-label") || "";
            el.setAttribute("aria-label", t(key, null, fallback));
        }
    }

    async function setLanguage(lang, opts = {}) {
        const persist = opts.persist !== false;
        const next = normalizeLanguage(lang);

        currentLang = next;
        if (persist) {
            try { localStorage.setItem(KEY, next); } catch (_) {}
        }

        currentDict = await fetchDict(next);
        await whenDomReady();

        document.documentElement.setAttribute("lang", next);
        apply(document);
        setI18nPending(false);
        dispatchLanguageChanged(next);

        return next;
    }

    function getLanguage() {
        return currentLang;
    }

    function init() {
        currentLang = loadLocalLanguage();
        document.documentElement.setAttribute("lang", currentLang);

        // Start fetching translations immediately from the <head>.
        // Previously this waited until DOMContentLoaded, so File Manager painted
        // English fallback text first and changed to Finnish a moment later.
        setI18nPending(currentLang !== DEFAULT_LANG);

        readyPromise = (async () => {
            currentDict = await fetchDict(currentLang);
            await whenDomReady();

            document.documentElement.setAttribute("lang", currentLang);
            apply(document);
            setI18nPending(false);
            dispatchLanguageChanged(currentLang);

            return currentLang;
        })();
    }

    window.PQNAS_I18N = {
        key: KEY,
        defaultLanguage: DEFAULT_LANG,
        languages: Array.from(LANGS),
        normalizeLanguage,
        getLanguage,
        setLanguage,
        t,
        apply,
        ready: () => readyPromise || Promise.resolve(currentLang)
    };

    window.addEventListener("storage", (e) => {
        if (e && e.key === KEY) {
            setLanguage(e.newValue, { persist: false });
        }
    });

    // Start immediately. If this script is in <head>, this overlaps the JSON
    // fetch with HTML parsing and avoids the English → Finnish flicker.
    init();
})();
