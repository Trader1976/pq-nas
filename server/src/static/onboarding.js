// DNA-Nexus Guided Tours v1
// Defensive frontend-only onboarding engine.
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
                    "id": "shell-activity",
                    "target": [
                        "[data-tour='activity']",
                        "#activityPane",
                        "#activityList",
                        "#activityButton",
                        "#btnActivity",
                        "button[id*='activity']"
                    ],
                    "placement": "left",
                    "title": "My Activity",
                    "body": "My Activity shows recent actions such as uploads, restored files, Drop Zone uploads and other useful history."
                },
                {
                    "id": "shell-settings",
                    "target": [
                        "[data-tour='nav-user-settings']",
                        "#nav_user_settings",
                        "#nav_settings",
                        "a[href*='settings']",
                        "button[id*='settings']"
                    ],
                    "placement": "right",
                    "title": "User Settings",
                    "body": "Settings let each user adjust their own browser experience, such as theme and avatar, without changing the global server style."
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
        }
    ]
};
    const AUTO_START_DELAY_MS = 700;

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
            // Ignore storage failures.
        }
    }

    function markTour(tourId, status) {
        const state = readState();
        state[tourId] = {
            status,
            updatedAt: Date.now()
        };
        writeState(state);
    }

    function getTourStatus(tourId) {
        const state = readState();
        return state[tourId] && state[tourId].status ? state[tourId].status : "new";
    }

    function detectScope() {
        const path = String(window.location.pathname || "").toLowerCase();

        if (path.includes("/photogallery/") || path.includes("photogallery")) {
            return "photogallery";
        }

        const shellHints = [
            "#activityPane",
            "#nav_user_settings",
            "#nav_filemgr",
            "#nav_files",
            "[data-tour='app-launcher']",
            "[data-tour='nav-user-settings']"
        ];

        for (const selector of shellHints) {
            if (document.querySelector(selector)) {
                return "shell";
            }
        }

        // V1 fallback:
        // onboarding.js is only included by the main shell and selected app pages.
        // App pages with special scopes are detected above; otherwise assume shell.
        return "shell";
    }

    function isVisible(el) {
        if (!el) return false;

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

    function resolveTarget(target) {
        const selectors = Array.isArray(target) ? target : [target];

        for (const selector of selectors) {
            if (!selector || typeof selector !== "string") continue;

            let el = null;
            try {
                el = document.querySelector(selector);
            } catch (_) {
                continue;
            }

            if (isVisible(el)) {
                return el;
            }
        }

        return null;
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
        if (!step || !step.__targetEl) return;

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
        } else {
            left = rect.left;
            top = rect.bottom + gap;
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

        const kicker = createEl("p", "dnx-tour-kicker", activeTour.title || "DNA-Nexus Guide");
        const title = createEl("h3", "dnx-tour-title", step.title || "Guide");
        const body = createEl("p", "dnx-tour-body", step.body || "");

        const actions = createEl("div", "dnx-tour-actions");
        const left = createEl("div", "dnx-tour-actions-left");
        const right = createEl("div", "dnx-tour-actions-right");

        const progress = createEl(
            "span",
            "dnx-tour-progress",
            `${activeIndex + 1} / ${activeSteps.length}`
        );

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

        step.__targetEl.scrollIntoView({
            behavior: "smooth",
            block: "center",
            inline: "center"
        });

        window.setTimeout(() => positionStep(step), 160);
    }

    function startTour(tour, force) {
        if (!tour || !tour.id) return;

        if (!force) {
            const status = getTourStatus(tour.id);
            if (status === "completed" || status === "dismissed") {
                return;
            }
        }

        const steps = getShowableSteps(tour);
        if (!steps.length) {
            markTour(tour.id, "completed");
            return;
        }

        activeTour = tour;
        activeSteps = steps;
        activeIndex = 0;

        closeHelpMenu();
        renderStep();
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
        const title = createEl("div", "dnx-tour-menu-title", "Nexus Guide");
        helpMenu.appendChild(title);

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
            const first = getToursForCurrentScope()[0];
            if (first) startTour(first, true);
        });
        helpMenu.appendChild(resetAll);

        document.body.appendChild(helpMenu);
    }

    function ensureHelpButton() {
        if (helpButton) return;

        const tours = getToursForCurrentScope();
        if (!tours.length) return;

        helpButton = createEl("button", "dnx-tour-help", "?");
        helpButton.type = "button";
        helpButton.title = "Nexus Guide";
        helpButton.setAttribute("aria-label", "Nexus Guide");
        helpButton.addEventListener("click", toggleHelpMenu);
        document.body.appendChild(helpButton);
    }

    function autoStartTours() {
        const tours = getToursForCurrentScope().filter(tour => tour.autoStart);
        if (!tours.length) return;

        for (const tour of tours) {
            const status = getTourStatus(tour.id);
            if (status !== "completed" && status !== "dismissed") {
                startTour(tour, false);
                return;
            }
        }
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
            // Fall back to the inline manifest below.
        }

        if (!manifest) {
            manifest = INLINE_MANIFEST_V1;
        }

        ensureHelpButton();

        window.setTimeout(autoStartTours, AUTO_START_DELAY_MS);
    }

    window.addEventListener("resize", () => {
        if (!activeTour || !activeSteps.length) return;

        window.clearTimeout(resizeTimer);
        resizeTimer = window.setTimeout(() => {
            renderStep();
        }, 120);
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
            const first = getToursForCurrentScope()[0];
            if (first) startTour(first, true);
        },
        resetAll: function () {
            writeState({});
        }
    };
})();
