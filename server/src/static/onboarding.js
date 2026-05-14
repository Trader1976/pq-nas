// DNA-Nexus Guided Tours v1
// Clean frontend-only onboarding engine.
// State is browser-local for v1. Server-side per-user state can replace this later.

(function () {
    "use strict";

    const MANIFEST_URL = "/static/onboarding_tours_v1.json";
    const STORAGE_KEY = "dnx.guidedTours.v1";
    const INLINE_MANIFEST_V1 = {
    "schema": 1,
    "name": "DNA-Nexus Guided Tours v1",
    "tours": [
        {
            "id": "shell.first_run.v1",
            "scope": "shell",
            "title": "Welcome to DNA-Nexus",
            "autoStart": true,
            "steps": [
                {
                    "id": "shell-apps",
                    "target": [
                        "[data-tour='app-launcher']",
                        "[data-tour='nav-filemgr']",
                        "#nav_filemgr",
                        "#nav_files",
                        "#nav_apps",
                        ".sidebar",
                        "nav"
                    ],
                    "placement": "right",
                    "title": "Your DNA-Nexus apps",
                    "body": "The left side is your main launch area. Apps such as File Manager, Photo Gallery, Music, Shares and Settings appear here when available."
                },
                {
                    "id": "shell-filemgr",
                    "target": [
                        "[data-tour='nav-filemgr']",
                        "#nav_filemgr",
                        "#nav_files",
                        "a[href*='filemgr']",
                        "button[data-app-id='filemgr']",
                        "[data-app-id='filemgr']"
                    ],
                    "placement": "right",
                    "title": "File Manager",
                    "body": "File Manager is the central place for browsing, uploading, downloading, sharing and organizing your files."
                },
                {
                    "id": "shell-photogallery",
                    "target": [
                        "[data-tour='nav-photogallery']",
                        "#nav_photogallery",
                        "#nav_photo_gallery",
                        "a[href*='photogallery']",
                        "button[data-app-id='photogallery']",
                        "[data-app-id='photogallery']"
                    ],
                    "placement": "right",
                    "title": "Photo Gallery",
                    "body": "Photo Gallery gives you a visual way to browse photos, open previews, search metadata and share selected pictures."
                },
                {
                    "id": "shell-workspace-invites",
                    "target": [
                        "[data-tour='workspace-invites']",
                        "#nav_workspace_invites",
                        "#nav_workspaces",
                        "a[href*='workspace']",
                        "button[id*='workspace']"
                    ],
                    "placement": "right",
                    "title": "Workspaces and invites",
                    "body": "Workspaces let users collaborate. If someone invites you, the invite area is where you can accept or decline access."
                },
                {
                    "id": "shell-admin-panel",
                    "target": [
                        "[data-tour='nav-admin']"
                    ],
                    "placement": "right",
                    "title": "Admin Panel",
                    "body": "Admins get a different first-run path. This step only appears when the real Admin button is explicitly marked with data-tour=\"nav-admin\".",
                    "when": {
                        "any": [
                            "[data-tour='nav-admin']"
                        ]
                    }
                },
                {
                    "id": "shell-activity",
                    "target": [
                        "[data-tour='activity']",
                        "#activityPane",
                        "#activityList",
                        "#activityButton",
                        "#btnActivity",
                        "button[id*='activity']",
                        "[data-tour='main-activity']",
                        "[data-tour='activity-bottom']",
                        "#nav_activity",
                        "#mainActivity",
                        "#main_activity",
                        "button[title*='Activity']",
                        "button[aria-label*='Activity']",
                        "a[title*='Activity']",
                        "a[aria-label*='Activity']",
                        "text:button:my activity",
                        "text:button:activity",
                        "text:a:my activity",
                        "text:a:activity"
                    ],
                    "placement": "left",
                    "title": "My Activity",
                    "body": "My Activity is your personal timeline. It shows useful recent events such as uploads, restored files, purged files, Drop Zone uploads and other actions as DNA-Nexus grows."
                },
                {
                    "id": "shell-activity-bottom",
                    "target": [
                        "[data-tour='activity-bottom']",
                        "[data-tour='main-activity']",
                        "[data-tour='activity']",
                        "#nav_activity",
                        "#mainActivity",
                        "#main_activity",
                        "#activityButton",
                        "#btnActivity",
                        "button[title*='Activity']",
                        "button[aria-label*='Activity']",
                        "a[title*='Activity']",
                        "a[aria-label*='Activity']",
                        "text:button:my activity",
                        "text:button:activity",
                        "text:a:my activity",
                        "text:a:activity",
                        "#activityPane",
                        "#activityList"
                    ],
                    "placement": "top",
                    "title": "Activity lives close to your daily work",
                    "body": "This bottom activity area is meant to become a quick memory of what happened recently. When users upload, restore, purge, share or receive files, this is where DNA-Nexus can explain it in plain language."
                },
                {
                    "id": "shell-settings",
                    "target": [
                        "[data-tour='nav-user-settings']",
                        "[data-tour='user-settings']",
                        "#nav_user_settings",
                        "#nav_settings",
                        "a[href*='settings']",
                        "button[id*='settings']",
                        "text:button:settings",
                        "text:a:settings",
                        "text:button:user settings",
                        "text:a:user settings"
                    ],
                    "placement": "right",
                    "title": "Your personal Settings",
                    "body": "Normal users use Settings to adjust their own DNA-Nexus experience, such as browser theme and avatar. These settings affect only their own account/session, not the whole server.",
                    "when": {
                        "none": [
                            "[data-tour='nav-admin']"
                        ]
                    }
                },
                {
                    "id": "shell-guide-button",
                    "target": [
                        ".dnx-tour-help",
                        "button.dnx-tour-help"
                    ],
                    "placement": "top",
                    "title": "You can restart the guide any time",
                    "body": "This question mark opens Nexus Guide again. Users can restart tours later, which is useful when new apps or features are added."
                }
            ]
        },
        {
            "id": "photogallery.first_run.v1",
            "scope": "photogallery",
            "title": "Photo Gallery tour",
            "autoStart": true,
            "steps": [
                {
                    "id": "photo-library",
                    "target": [
                        "[data-tour='gallery-grid']",
                        "#galleryGrid",
                        "#photoGrid",
                        ".gallery-grid",
                        ".photo-grid",
                        "main"
                    ],
                    "placement": "top",
                    "title": "Your photo library",
                    "body": "This area shows your photos and albums. Missing or unavailable controls are skipped automatically by the guide."
                },
                {
                    "id": "photo-upload",
                    "target": [
                        "[data-tour='gallery-upload']",
                        "#uploadBtn",
                        "#btnUpload",
                        "button[id*='upload']",
                        "input[type='file']"
                    ],
                    "placement": "bottom",
                    "title": "Upload photos",
                    "body": "Use upload to add new photos to your library. DNA-Nexus can later index metadata to help with search."
                },
                {
                    "id": "photo-search",
                    "target": [
                        "[data-tour='gallery-search']",
                        "#searchInput",
                        "input[type='search']",
                        "input[placeholder*='Search']",
                        "input[placeholder*='search']"
                    ],
                    "placement": "bottom",
                    "title": "Search",
                    "body": "Search helps you find images by names, tags, folders or metadata when those features are available."
                },
                {
                    "id": "photo-share",
                    "target": [
                        "[data-tour='gallery-share']",
                        "#shareBtn",
                        "#btnShare",
                        "button[id*='share']",
                        "button[class*='share']"
                    ],
                    "placement": "bottom",
                    "title": "Share selected photos",
                    "body": "After selecting photos, you can create share links when sharing is available for your account and location."
                },
                {
                    "id": "photo-selection",
                    "target": [
                        "[data-tour='gallery-selection']",
                        ".selected",
                        ".selection-toolbar",
                        ".toolbar",
                        "header"
                    ],
                    "placement": "bottom",
                    "title": "Selection tools",
                    "body": "Selection tools usually appear after you pick one or more items. If nothing is selected, this guide will skip unavailable controls."
                }
            ]
        },
        {
            "id": "settings.first_run.v1",
            "scope": "user_settings",
            "title": "User Settings tour",
            "autoStart": true,
            "steps": [
                {
                    "id": "settings-overview",
                    "target": [
                        "[data-tour='settings-screen']",
                        "[data-view='user-settings']",
                        "[data-screen='user-settings']",
                        "#userSettings",
                        "#userSettingsView",
                        "#settingsView",
                        "#settingsPanel",
                        "#settingsContent",
                        "#settingsRoot",
                        ".settings-panel",
                        ".settings-card",
                        "text:h1:user settings",
                        "text:h2:user settings",
                        "text:h3:user settings"
                    ],
                    "placement": "bottom",
                    "title": "Your personal Settings",
                    "body": "This screen is for the current user's own DNA-Nexus experience. These choices should not unexpectedly change the global server setup for everyone else."
                },
                {
                    "id": "settings-theme",
                    "target": [
                        "[data-tour='settings-theme']",
                        "[data-tour='theme-picker']",
                        "#themeSelect",
                        "#themePicker",
                        "#userTheme",
                        "select[id*='theme']",
                        "button[id*='theme']",
                        "select[name*='theme']",
                        "button[name*='theme']",
                        "text:*:theme",
                        "text:*:Theme"
                    ],
                    "placement": "bottom",
                    "title": "Theme and appearance",
                    "body": "Users can change their own browser theme here. That makes DNA-Nexus feel personal without forcing the same look on every account."
                },
                {
                    "id": "settings-avatar",
                    "target": [
                        "[data-tour='settings-avatar']",
                        "[data-tour='avatar-upload']",
                        "#avatarUpload",
                        "#avatarInput",
                        "#userAvatar",
                        "input[type='file'][accept*='image']",
                        "button[id*='avatar']",
                        "button[class*='avatar']",
                        "text:*:avatar",
                        "text:*:Avatar",
                        "text:*:upload avatar",
                        "text:*:remove avatar"
                    ],
                    "placement": "bottom",
                    "title": "Avatar",
                    "body": "Avatar controls let users personalize their account. This is especially helpful later when workspaces, activity timelines and collaboration features show people by name."
                },
                {
                    "id": "settings-personal-only",
                    "target": [
                        "text:*:These settings affect your own browser",
                        "text:*:do not change the global admin theme",
                        "text:*:own browser",
                        "text:*:global admin theme",
                        "[data-tour='settings-note']",
                        ".settings-note",
                        ".hint",
                        ".muted"
                    ],
                    "placement": "top",
                    "title": "Personal, not global",
                    "body": "This note is important: normal user settings affect only that user. Server-wide settings still belong in the Admin area."
                },
                {
                    "id": "settings-guide-restart",
                    "target": [
                        ".dnx-tour-help",
                        "button.dnx-tour-help"
                    ],
                    "placement": "top",
                    "title": "Restart help any time",
                    "body": "The question mark opens Nexus Guide again. This gives users a safe way to rediscover features after updates or after they skip the first tour."
                }
            ]
        }
    ]
};
    const AUTO_START_DELAY_MS = 1200;

    let manifest = null;
    let activeTour = null;
    let activeSteps = [];
    let activeIndex = 0;

    let backdrop = null;
    let spotlight = null;
    let bubble = null;
    let helpButton = null;
    let helpMenu = null;

    let resizeTimer = null;
    let lastScope = null;
    let observer = null;
    let scopeTimer = null;

    function readState() {
        try {
            return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}") || {};
        } catch (_) {
            return {};
        }
    }

    function writeState(state) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(state || {}));
        } catch (_) {
            // ignore
        }
    }

    function markTour(tourId, status) {
        const state = readState();
        state[tourId] = {
            status: status,
            updatedAt: Date.now()
        };
        writeState(state);
    }

    function getTourStatus(tourId) {
        const state = readState();
        return state[tourId] && state[tourId].status ? state[tourId].status : "new";
    }

    function isVisible(el) {
        if (!el) return false;

        if (el === document.body || el === document.documentElement) {
            return false;
        }

        const rect = el.getBoundingClientRect();
        const style = window.getComputedStyle(el);

        if (style.display === "none" || style.visibility === "hidden" || Number(style.opacity) === 0) {
            return false;
        }

        if (rect.width <= 0 || rect.height <= 0) {
            return false;
        }

        return rect.bottom >= 0 &&
            rect.right >= 0 &&
            rect.top <= (window.innerHeight || document.documentElement.clientHeight) &&
            rect.left <= (window.innerWidth || document.documentElement.clientWidth);
    }

    function visibleSelector(selector) {
        try {
            return isVisible(document.querySelector(selector));
        } catch (_) {
            return false;
        }
    }

    function detectScope() {
        const path = String(window.location.pathname || "").toLowerCase();
        const hash = String(window.location.hash || "").toLowerCase();
        const search = String(window.location.search || "").toLowerCase();
        const bodyText = String((document.body && document.body.innerText) || "").toLowerCase();

        if (path.includes("/photogallery/") || path.includes("photogallery")) {
            return "photogallery";
        }

        const settingsSelectors = [
            "[data-tour='settings-screen']",
            "[data-view='user-settings']",
            "[data-screen='user-settings']",
            "#userSettings",
            "#userSettingsView",
            "#settingsView",
            "#settingsPanel",
            "#settingsContent",
            "#settingsRoot",
            ".settings-panel",
            ".settings-card"
        ];

        for (const selector of settingsSelectors) {
            if (visibleSelector(selector)) {
                return "user_settings";
            }
        }

        if (path.includes("user_settings") ||
            path.includes("user-settings") ||
            path.includes("/settings") ||
            hash.includes("user_settings") ||
            hash.includes("user-settings") ||
            hash.includes("settings") ||
            search.includes("user_settings") ||
            search.includes("user-settings")) {
            return "user_settings";
        }

        if (bodyText.includes("these settings affect your own browser") ||
            bodyText.includes("do not change the global admin theme") ||
            bodyText.includes("theme saved.")) {
            return "user_settings";
        }

        return "shell";
    }

    function resolveTextTarget(selector) {
        if (!selector || !selector.startsWith("text:")) {
            return null;
        }

        const parts = selector.split(":");
        if (parts.length < 3) {
            return null;
        }

        const tag = parts[1] || "*";
        const needle = parts.slice(2).join(":").trim().toLowerCase();

        if (!needle) {
            return null;
        }

        let nodes = [];
        try {
            nodes = Array.from(document.querySelectorAll(tag));
        } catch (_) {
            return null;
        }

        const candidates = [];

        for (const node of nodes) {
            if (node === document.body || node === document.documentElement) {
                continue;
            }

            const text = String(node.textContent || "").trim().toLowerCase();
            const label = String(node.getAttribute("aria-label") || "").trim().toLowerCase();
            const title = String(node.getAttribute("title") || "").trim().toLowerCase();
            const dataTour = String(node.getAttribute("data-tour") || "").trim().toLowerCase();
            const dataAppId = String(node.getAttribute("data-app-id") || "").trim().toLowerCase();

            if ((text && text.includes(needle)) ||
                (label && label.includes(needle)) ||
                (title && title.includes(needle)) ||
                (dataTour && dataTour.includes(needle)) ||
                (dataAppId && dataAppId.includes(needle))) {
                if (isVisible(node)) {
                    candidates.push(node);
                }
            }
        }

        if (!candidates.length) {
            return null;
        }

        candidates.sort((a, b) => {
            const ar = a.getBoundingClientRect();
            const br = b.getBoundingClientRect();
            return (ar.width * ar.height) - (br.width * br.height);
        });

        return candidates[0] || null;
    }

    function resolveTarget(target) {
        const selectors = Array.isArray(target) ? target : [target];

        for (const selector of selectors) {
            if (!selector || typeof selector !== "string") continue;

            let el = null;

            if (selector.startsWith("text:")) {
                el = resolveTextTarget(selector);
            } else {
                try {
                    el = document.querySelector(selector);
                } catch (_) {
                    continue;
                }
            }

            if (isVisible(el)) {
                return el;
            }
        }

        return null;
    }

    function selectorList(value) {
        if (!value) return [];
        return Array.isArray(value) ? value : [value];
    }

    function anySelectorVisible(selectors) {
        return !!resolveTarget(selectorList(selectors));
    }

    function allSelectorsVisible(selectors) {
        const list = selectorList(selectors);
        if (!list.length) return true;

        for (const selector of list) {
            if (!resolveTarget(selector)) {
                return false;
            }
        }

        return true;
    }

    function stepAllowed(step) {
        const when = step && step.when;
        if (!when) return true;

        if (when.any && !anySelectorVisible(when.any)) {
            return false;
        }

        if (when.all && !allSelectorsVisible(when.all)) {
            return false;
        }

        if (when.none && anySelectorVisible(when.none)) {
            return false;
        }

        return true;
    }

    function getToursForCurrentScope() {
        if (!manifest || !Array.isArray(manifest.tours)) return [];

        const scope = detectScope();
        return manifest.tours.filter(tour => tour && tour.scope === scope);
    }

    function getShowableSteps(tour) {
        if (!tour || !Array.isArray(tour.steps)) return [];

        return tour.steps
            .map(step => {
                if (!stepAllowed(step)) return null;

                const el = resolveTarget(step.target);
                if (!el) return null;

                return Object.assign({}, step, { __targetEl: el });
            })
            .filter(Boolean);
    }

    function createEl(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (typeof text === "string") el.textContent = text;
        return el;
    }

    function ensureChrome() {
        if (!backdrop) {
            backdrop = createEl("div", "dnx-tour-backdrop");
            document.body.appendChild(backdrop);
        }

        if (!spotlight) {
            spotlight = createEl("div", "dnx-tour-spotlight");
            document.body.appendChild(spotlight);
        }

        if (!bubble) {
            bubble = createEl("div", "dnx-tour-bubble");
            document.body.appendChild(bubble);
        }
    }

    function removeChrome() {
        if (backdrop) {
            backdrop.remove();
            backdrop = null;
        }

        if (spotlight) {
            spotlight.remove();
            spotlight = null;
        }

        if (bubble) {
            bubble.remove();
            bubble = null;
        }
    }

    function positionStep(step) {
        if (!step || !step.__targetEl || !bubble || !spotlight) return;

        const pad = 8;
        const rect = step.__targetEl.getBoundingClientRect();

        spotlight.style.left = Math.max(8, rect.left - pad) + "px";
        spotlight.style.top = Math.max(8, rect.top - pad) + "px";
        spotlight.style.width = Math.max(8, rect.width + pad * 2) + "px";
        spotlight.style.height = Math.max(8, rect.height + pad * 2) + "px";

        const placement = step.placement || "bottom";
        bubble.dataset.placement = placement;

        const bubbleRect = bubble.getBoundingClientRect();
        const gap = 18;

        let left = rect.left;
        let top = rect.bottom + gap;

        if (placement === "right") {
            left = rect.right + gap;
            top = rect.top;
        } else if (placement === "left") {
            left = rect.left - bubbleRect.width - gap;
            top = rect.top;
        } else if (placement === "top") {
            left = rect.left;
            top = rect.top - bubbleRect.height - gap;
        }

        const margin = 14;
        left = Math.max(margin, Math.min(left, window.innerWidth - bubbleRect.width - margin));
        top = Math.max(margin, Math.min(top, window.innerHeight - bubbleRect.height - margin));

        bubble.style.left = left + "px";
        bubble.style.top = top + "px";
    }

    function renderStep() {
        if (!activeTour || !activeSteps.length) {
            stopTour(false);
            return;
        }

        if (activeIndex < 0) activeIndex = 0;

        if (activeIndex >= activeSteps.length) {
            markTour(activeTour.id, "completed");
            stopTour(false);
            return;
        }

        const step = activeSteps[activeIndex];

        if (!isVisible(step.__targetEl)) {
            const refreshed = resolveTarget(step.target);
            if (!refreshed) {
                activeSteps.splice(activeIndex, 1);
                renderStep();
                return;
            }
            step.__targetEl = refreshed;
        }

        ensureChrome();

        bubble.innerHTML = "";

        const kicker = createEl("p", "dnx-tour-kicker", activeTour.title || "Nexus Guide");
        const title = createEl("h3", "dnx-tour-title", step.title || "Guide");
        const body = createEl("p", "dnx-tour-body", step.body || "");

        const actions = createEl("div", "dnx-tour-actions");
        const left = createEl("div", "dnx-tour-actions-left");
        const right = createEl("div", "dnx-tour-actions-right");

        const progress = createEl("span", "dnx-tour-progress", `${activeIndex + 1} / ${activeSteps.length}`);

        const skip = createEl("button", "dnx-tour-btn", "Skip");
        skip.type = "button";
        skip.addEventListener("click", () => {
            markTour(activeTour.id, "dismissed");
            stopTour(false);
        });

        const back = createEl("button", "dnx-tour-btn", "Back");
        back.type = "button";
        back.disabled = activeIndex === 0;
        back.addEventListener("click", () => {
            activeIndex -= 1;
            renderStep();
        });

        const next = createEl(
            "button",
            "dnx-tour-btn dnx-tour-btn-primary",
            activeIndex >= activeSteps.length - 1 ? "Done" : "Next"
        );
        next.type = "button";
        next.addEventListener("click", () => {
            activeIndex += 1;
            renderStep();
        });

        left.appendChild(progress);
        right.appendChild(skip);
        right.appendChild(back);
        right.appendChild(next);

        actions.appendChild(left);
        actions.appendChild(right);

        bubble.appendChild(kicker);
        bubble.appendChild(title);
        bubble.appendChild(body);
        bubble.appendChild(actions);

        try {
            step.__targetEl.scrollIntoView({
                behavior: "smooth",
                block: "center",
                inline: "center"
            });
        } catch (_) {
            // ignore
        }

        window.setTimeout(() => positionStep(step), 140);
    }

    function startTour(tour, force) {
        if (!tour || !tour.id) return false;

        if (!force) {
            const status = getTourStatus(tour.id);
            if (status === "completed" || status === "dismissed") {
                return false;
            }
        }

        const steps = getShowableSteps(tour);
        if (!steps.length) {
            if (!force) {
                markTour(tour.id, "completed");
            }
            return false;
        }

        activeTour = tour;
        activeSteps = steps;
        activeIndex = 0;

        closeHelpMenu();
        renderStep();
        return true;
    }

    function stopTour() {
        activeTour = null;
        activeSteps = [];
        activeIndex = 0;
        removeChrome();
    }

    function closeHelpMenu() {
        if (helpMenu) {
            helpMenu.remove();
            helpMenu = null;
        }
    }

    function toggleHelpMenu() {
        if (helpMenu) {
            closeHelpMenu();
            return;
        }

        const tours = getToursForCurrentScope();
        if (!tours.length) return;

        helpMenu = createEl("div", "dnx-tour-menu");
        helpMenu.appendChild(createEl("div", "dnx-tour-menu-title", "Nexus Guide"));

        for (const tour of tours) {
            const btn = createEl("button", "", `Restart: ${tour.title || tour.id}`);
            btn.type = "button";
            btn.addEventListener("click", () => startTour(tour, true));
            helpMenu.appendChild(btn);
        }

        const resetAll = createEl("button", "", "Reset all guided tours on this browser");
        resetAll.type = "button";
        resetAll.addEventListener("click", () => {
            writeState({});
            closeHelpMenu();
            autoStartTours(true);
        });
        helpMenu.appendChild(resetAll);

        document.body.appendChild(helpMenu);
    }

    function ensureHelpButton() {
        if (helpButton && document.body.contains(helpButton)) {
            return;
        }

        helpButton = createEl("button", "dnx-tour-help", "?");
        helpButton.type = "button";
        helpButton.title = "Nexus Guide";
        helpButton.setAttribute("aria-label", "Nexus Guide");
        helpButton.addEventListener("click", toggleHelpMenu);
        document.body.appendChild(helpButton);
    }

    function autoStartTours(force) {
        const scope = detectScope();
        const tours = getToursForCurrentScope().filter(tour => tour.autoStart);

        lastScope = scope;

        if (!tours.length) return false;

        for (const tour of tours) {
            if (force || !["completed", "dismissed"].includes(getTourStatus(tour.id))) {
                if (startTour(tour, !!force)) {
                    return true;
                }
            }
        }

        return false;
    }

    function maybeScopeChanged() {
        ensureHelpButton();

        if (activeTour) return;

        const scope = detectScope();
        if (scope !== lastScope) {
            autoStartTours(false);
        }
    }

    function watchScopeChanges() {
        if (observer || !document.body) return;

        observer = new MutationObserver(() => {
            window.clearTimeout(scopeTimer);
            scopeTimer = window.setTimeout(maybeScopeChanged, 300);
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true,
            attributes: true,
            attributeFilter: ["class", "style", "hidden", "aria-hidden"]
        });

        window.addEventListener("hashchange", () => window.setTimeout(maybeScopeChanged, 250));
        window.addEventListener("popstate", () => window.setTimeout(maybeScopeChanged, 250));
        document.addEventListener("click", () => window.setTimeout(maybeScopeChanged, 500), true);
    }

    async function init() {
        try {
            const res = await fetch(MANIFEST_URL, {
                credentials: "same-origin",
                cache: "no-store"
            });

            if (res.ok) {
                manifest = await res.json();
            }
        } catch (_) {
            // fallback below
        }

        if (!manifest) {
            manifest = INLINE_MANIFEST_V1;
        }

        ensureHelpButton();
        watchScopeChanges();

        window.setTimeout(() => autoStartTours(false), AUTO_START_DELAY_MS);
    }

    window.addEventListener("resize", () => {
        if (!activeTour || !activeSteps.length) return;

        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(renderStep, 120);
    });

    window.addEventListener("keydown", event => {
        if (event.key === "Escape" && activeTour) {
            markTour(activeTour.id, "dismissed");
            stopTour(false);
        }
    });

    document.addEventListener("click", event => {
        if (!helpMenu || !helpButton) return;

        if (helpMenu.contains(event.target) || helpButton.contains(event.target)) {
            return;
        }

        closeHelpMenu();
    });

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

    window.DNANexusGuidedTours = {
        restartCurrentScope: function () {
            autoStartTours(true);
        },
        resetAll: function () {
            writeState({});
        },
        debug: function () {
            return {
                scope: detectScope(),
                tours: getToursForCurrentScope().map(t => t.id),
                state: readState(),
                helpButton: !!document.querySelector(".dnx-tour-help")
            };
        }
    };
})();
