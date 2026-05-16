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
                    "id": "shell-trusted-devices-admin",
                    "target": [
                        "#nav_trusted_devices",
                        "button#nav_trusted_devices",
                        "text:button:Trusted Devices",
                        "text:button:Trusted devices",
                        "#nav_trusted_devices.active",
                        "[data-tour='nav-trusted-devices']",
                        "[data-tour='trusted-devices']",
                        "button[id='nav_trusted_devices']",
                        "text:button:trusted devices",
                        "[data-tour='nav-admin']"
                    ],
                    "placement": "right",
                    "title": "Trusted Devices for admins",
                    "body": "Admins can also guide or review trusted-device workflows. A paired mobile phone can be used with the DNA-Nexus mobile app for QR-based identity flows, login approval and safer account access.",
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
                    "id": "shell-trusted-devices-user",
                    "target": [
                        "#nav_trusted_devices",
                        "button#nav_trusted_devices",
                        "text:button:Trusted Devices",
                        "text:button:Trusted devices",
                        "#nav_trusted_devices.active",
                        "[data-tour='nav-trusted-devices']",
                        "[data-tour='trusted-devices']",
                        "button[id='nav_trusted_devices']",
                        "text:button:trusted devices",
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
                    "title": "Trusted Devices live in Settings",
                    "body": "Users can manage trusted devices from Settings. This is where they can pair a mobile phone using the DNA-Nexus mobile app, scan a QR code, and later review or revoke devices that are allowed to help with secure login.",
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
                    "id": "settings-trusted-devices",
                    "target": [
                        "[data-tour='trusted-devices']",
                        "[data-tour='settings-trusted-devices']",
                        "[data-tour='admin-trusted-devices']",
                        "[data-tour='device-pairing']",
                        "[data-tour='pair-device']",
                        "#trustedDevices",
                        "#trusted_devices",
                        "#trustedDevicesPanel",
                        "#trustedDevicesSection",
                        "#devicePairing",
                        "#pairDevice",
                        "#pairMobile",
                        "#pairedDevices",
                        ".trusted-devices",
                        ".trustedDevices",
                        ".device-pairing",
                        ".paired-devices",
                        "button[id*='trusted']",
                        "button[id*='device']",
                        "button[id*='pair']",
                        "a[href*='devices']",
                        "a[href*='trusted']",
                        "text:h1:trusted devices",
                        "text:h2:trusted devices",
                        "text:h3:trusted devices",
                        "text:*:trusted devices",
                        "text:*:paired devices",
                        "text:*:pair device",
                        "text:*:pair mobile",
                        "text:*:mobile app",
                        "text:*:DNA Connect",
                        "text:*:DNA-Nexus mobile"
                    ],
                    "placement": "bottom",
                    "title": "Trusted devices",
                    "body": "Trusted Devices is where you can pair a phone or another approved device with DNA-Nexus. For example, a user can use the DNA-Nexus mobile app / DNA Connect style flow to scan a QR code, approve logins, and manage which personal devices are allowed to access the account."
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
        },
        {
            "id": "admin.first_run.v1",
            "scope": "admin",
            "title": "Admin Panel tour",
            "autoStart": true,
            "steps": [
                {
                    "id": "admin-overview",
                    "target": [
                        "[data-tour='admin-screen']",
                        "[data-view='admin']",
                        "#adminRoot",
                        "#adminPanel",
                        "#adminContent",
                        "#main",
                        ".admin-shell",
                        ".admin-main",
                        ".admin-content",
                        "text:h1:admin",
                        "text:h2:admin",
                        "main"
                    ],
                    "placement": "bottom",
                    "title": "Admin area",
                    "body": "This is the server-wide administration area. Admin pages control users, approvals, apps, workspaces, audit logs, statistics and global server settings."
                },
                {
                    "id": "admin-users",
                    "target": [
                        "[data-tour='admin-users']",
                        "#nav_admin_users",
                        "a[href*='admin_users']",
                        "a[href*='admin_users.html']",
                        "a[href*='admin_approvals']",
                        "a[href*='admin_approvals.html']",
                        "text:a:users",
                        "text:button:users",
                        "text:a:approvals",
                        "text:button:approvals"
                    ],
                    "placement": "right",
                    "title": "Users and approvals",
                    "body": "User administration is where new accounts can be approved, disabled or managed. This is one of the most important admin workflows."
                },
                {
                    "id": "admin-trusted-devices",
                    "target": [
                        "[data-tour='trusted-devices']",
                        "[data-tour='settings-trusted-devices']",
                        "[data-tour='admin-trusted-devices']",
                        "[data-tour='device-pairing']",
                        "[data-tour='pair-device']",
                        "#trustedDevices",
                        "#trusted_devices",
                        "#trustedDevicesPanel",
                        "#trustedDevicesSection",
                        "#devicePairing",
                        "#pairDevice",
                        "#pairMobile",
                        "#pairedDevices",
                        ".trusted-devices",
                        ".trustedDevices",
                        ".device-pairing",
                        ".paired-devices",
                        "button[id*='trusted']",
                        "button[id*='device']",
                        "button[id*='pair']",
                        "a[href*='devices']",
                        "a[href*='trusted']",
                        "text:h1:trusted devices",
                        "text:h2:trusted devices",
                        "text:h3:trusted devices",
                        "text:*:trusted devices",
                        "text:*:paired devices",
                        "text:*:pair device",
                        "text:*:pair mobile",
                        "text:*:mobile app",
                        "text:*:DNA Connect",
                        "text:*:DNA-Nexus mobile"
                    ],
                    "placement": "bottom",
                    "title": "Trusted devices and mobile pairing",
                    "body": "Trusted device management helps admins understand which phones or computers are paired with accounts. A paired phone using the DNA-Nexus mobile app can be used for QR-based identity flows, login approval, and safer account access. Admin views should make it clear when a device is trusted, revoked, or needs review."
                },
                {
                    "id": "admin-apps",
                    "target": [
                        "[data-tour='admin-apps']",
                        "#nav_admin_apps",
                        "a[href*='admin_apps']",
                        "a[href*='admin_apps.html']",
                        "text:a:apps",
                        "text:button:apps"
                    ],
                    "placement": "right",
                    "title": "Apps",
                    "body": "The Apps page controls installed DNA-Nexus apps. This becomes important as the server grows into a real app platform."
                },
                {
                    "id": "admin-workspaces",
                    "target": [
                        "[data-tour='admin-workspaces']",
                        "#nav_admin_workspaces",
                        "a[href*='admin_workspaces']",
                        "a[href*='admin_workspaces.html']",
                        "text:a:workspaces",
                        "text:button:workspaces"
                    ],
                    "placement": "right",
                    "title": "Workspaces",
                    "body": "Workspace administration helps admins review shared spaces, members, quotas and server-wide collaboration settings."
                },
                {
                    "id": "admin-audit",
                    "target": [
                        "[data-tour='admin-audit']",
                        "#nav_admin_audit",
                        "a[href*='admin_audit']",
                        "a[href*='admin_audit.html']",
                        "text:a:audit",
                        "text:button:audit"
                    ],
                    "placement": "right",
                    "title": "Audit and history",
                    "body": "Audit views help admins understand important server activity and investigate what happened."
                },
                {
                    "id": "admin-stats",
                    "target": [
                        "[data-tour='admin-stats']",
                        "#nav_admin_stats",
                        "a[href*='admin_stats']",
                        "a[href*='admin_stats.html']",
                        "text:a:stats",
                        "text:button:stats",
                        "text:a:statistics",
                        "text:button:statistics"
                    ],
                    "placement": "right",
                    "title": "Statistics",
                    "body": "Admin statistics give a quick overview of users, files, storage, workspaces and other server health information."
                },
                {
                    "id": "admin-guide-button",
                    "target": [
                        ".dnx-tour-help",
                        "button.dnx-tour-help"
                    ],
                    "placement": "top",
                    "title": "Admin help is available here too",
                    "body": "The question mark restarts Nexus Guide inside admin pages. This lets admins rediscover tools later after updates."
                }
            ]
        },
        {
            "id": "trusted_devices.first_run.v1",
            "scope": "trusted_devices",
            "title": "Trusted Devices tour",
            "autoStart": true,
            "steps": [
                {
                    "id": "trusted-devices-overview",
                    "target": [
                        "#pairNewDeviceBtn",
                        "text:h2:Trusted Devices",
                        "text:h2:Trusted devices"
                    ],
                    "placement": "bottom",
                    "title": "Trusted Devices",
                    "body": "Trusted Devices is where DNA-Nexus remembers approved phones, computers or other devices. A trusted phone can use the DNA-Nexus mobile app / DNA Connect style flow to scan QR codes, approve identity actions and help with safer login."
                },
                {
                    "id": "trusted-devices-pair-phone",
                    "target": [
                        "#pairNewDeviceBtn",
                        "#pairStatusLine",
                        "text:h3:Pair a new device",
                        "text:button:Pair New Device",
                        "text:button:Pair a new device",
                        "text:*:Open the DNA-Nexus mobile app"
                    ],
                    "placement": "bottom",
                    "title": "Pair your mobile phone",
                    "body": "To pair a phone, the user opens the DNA-Nexus mobile app and scans the QR code shown by the server. After approval, that phone can become a trusted device for identity and login workflows."
                },
                {
                    "id": "trusted-devices-review",
                    "target": [
                        "text:h3:Trusted devices",
                        "text:h3:Trusted Devices",
                        "text:h2:Trusted devices",
                        "text:h2:Trusted Devices"
                    ],
                    "placement": "right",
                    "title": "Review paired devices",
                    "body": "This section lists devices that can access your DNA-Nexus account through app pairing. If a phone is lost or replaced, remove trust from the old device."
                },
                {
                    "id": "trusted-devices-guide",
                    "target": [
                        ".dnx-tour-help",
                        "button.dnx-tour-help"
                    ],
                    "placement": "top",
                    "title": "Help is available here too",
                    "body": "The question mark restarts Nexus Guide on the Trusted Devices page."
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

        const forcedScope = String(window.DNANexusOnboardingScope || "").trim().toLowerCase();
        if (forcedScope) {
            return forcedScope;
        }

        if (path.includes("/filemgr/") ||
            path.includes("/apps/filemgr/") ||
            path.includes("filemgr")) {
            return "filemgr";
        }

        const fileManagerHints = [
            "#titleLine",
            "#gridWrap",
            "#grid",
            "#pathLine",
            "#status",
            "#scopeSelect",
            "#workspaceActions",
            "#trashBtn",
            "[data-tour='filemgr-screen']",
            "[data-tour='filemgr-location']"
        ];

        for (const selector of fileManagerHints) {
            if (visibleSelector(selector)) {
                return "filemgr";
            }
        }

        if (path.includes("/photogallery/") || path.includes("photogallery")) {
            return "photogallery";
        }

        if (path.includes("/filemgr/") ||
            path.includes("filemgr") ||
            path.includes("file_manager") ||
            path.includes("file-manager")) {
            return "filemgr";
        }

        const trustedDeviceHints = [
            "#nav_trusted_devices.active",
            "#pairNewDeviceBtn",
            "#pairStopBtn",
            "#pairStatusLine",
            "[data-tour='trusted-devices']",
            "[data-tour='nav-trusted-devices']"
        ];

        for (const selector of trustedDeviceHints) {
            if (visibleSelector(selector)) {
                return "trusted_devices";
            }
        }

        if ((bodyText.includes("trusted devices") &&
             bodyText.includes("pair a new device")) ||
            bodyText.includes("open the dna-nexus mobile app") ||
            bodyText.includes("no trusted devices yet")) {
            return "trusted_devices";
        }

        if (path.includes("trusted") ||
            path.includes("device") ||
            path.includes("devices") ||
            path.includes("pair") ||
            hash.includes("trusted") ||
            hash.includes("device") ||
            hash.includes("devices") ||
            hash.includes("pair") ||
            search.includes("trusted") ||
            search.includes("device") ||
            search.includes("devices") ||
            search.includes("pair")) {
            return "trusted_devices";
        }

        if (path.includes("admin") ||
            hash.includes("admin") ||
            search.includes("admin")) {
            return "admin";
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

    function ensureFileManagerTour() {
        if (!manifest || !Array.isArray(manifest.tours)) {
            return;
        }

        const exists = manifest.tours.some(tour => tour && tour.scope === "filemgr");
        if (exists) {
            return;
        }

        const tour = {
            id: "filemgr.first_run.v2",
            scope: "filemgr",
            title: "File Manager tour",
            autoStart: true,
            steps: [
                {
                    id: "filemgr-overview",
                    target: ["[data-tour='filemgr-screen']", "#titleLine", "#gridWrap", "#status"],
                    placement: "bottom",
                    title: "File Manager",
                    body: "File Manager is where users browse, upload, download, preview, share and organize their files."
                },
                {
                    id: "filemgr-storage-location",
                    target: ["[data-tour='filemgr-location']", "#status", "#quotaLine", "#scopeBar", "#scopeSelect", "#pathLine"],
                    placement: "bottom",
                    title: "Storage and location",
                    body: "If this account has no personal storage allocated yet, File Manager cannot show normal files until an admin allocates storage. When storage is available, the Location selector can switch between My files and shared workspaces."
                },
                {
                    id: "filemgr-main-grid",
                    target: ["[data-tour='filemgr-grid']", "#gridWrap", "#grid", "#emptyState"],
                    placement: "top",
                    title: "Files appear here",
                    body: "This main area shows folders and files. Users can open folders, select items, use context menus, and drag files here to upload.",
                    notice: "Browser tip: Brave gives the best DNA-Nexus UX. Chrome is also good. Firefox currently has known UI issues, so use Brave or Chrome for the smoothest experience."
                },
                {
                    id: "filemgr-toolbar",
                    target: ["[data-tour='filemgr-toolbar']", "#upBtn", "#viewToggleBtn", "#sortBtn", "#favoritesToggleBtn", "#refreshBtn"],
                    placement: "bottom",
                    title: "View and navigation tools",
                    body: "The toolbar lets users go up a folder, switch between list and grid views, sort folders first, filter favorites, and refresh the current view."
                },
                {
                    id: "filemgr-workspaces",
                    target: ["#scopeBar", "#scopeSelect", "#workspaceCreateSharedBtn", "#workspaceMembersBtn"],
                    placement: "bottom",
                    title: "Shared spaces",
                    body: "When workspace features are available, users can switch locations, create shared spaces, and review workspace members from here."
                },
                {
                    id: "filemgr-trash",
                    target: ["[data-tour='filemgr-trash']", "#trashBtn"],
                    placement: "bottom",
                    title: "Trash",
                    body: "Deleted files go to Trash first. From there they can be restored or permanently removed, depending on permissions."
                },
                {
                    id: "filemgr-guide-button",
                    target: [".dnx-tour-help", "button.dnx-tour-help"],
                    placement: "top",
                    title: "Restart help any time",
                    body: "The question mark opens Nexus Guide again, so users can replay this tour later."
                }
            ]
        };

        const insertAt = manifest.tours.length ? 1 : 0;
        manifest.tours.splice(insertAt, 0, tour);
    }


    function ensureFileManagerShareLinkTour() {
        if (!manifest || !Array.isArray(manifest.tours)) {
            return;
        }

        const id = "filemgr.share_link_first_open.v1";
        const exists = manifest.tours.some(tour => tour && tour.id === id);
        if (exists) {
            return;
        }

        const tour = {
            id: id,
            scope: "filemgr",
            title: "Share link dialog",
            autoStart: false,
            showInMenu: true,
            when: {
                any: [
                    "#shareModal.show[data-share-mode='standard'] [data-tour='filemgr-share-modal']",
                    "#shareModal[aria-hidden='false'][data-share-mode='standard'] [data-tour='filemgr-share-modal']"
                ]
            },
            steps: [
                {
                    id: "filemgr-share-overview",
                    target: [
                        "[data-tour='filemgr-share-modal']",
                        "#shareModal.show .modalCard"
                    ],
                    placement: "left",
                    title: "Public share link",
                    body: "This dialog creates a public link for the selected file or folder. Anyone who has the link can open the shared item while the link is valid."
                },
                {
                    id: "filemgr-share-expiry",
                    target: [
                        "[data-tour='filemgr-share-expiry']",
                        "#shareExpiry"
                    ],
                    placement: "left",
                    title: "Choose an expiry",
                    body: "Expiry controls how long the link works. Shorter expiry is safer for one-time sharing. Never expiring links should be used carefully."
                },
                {
                    id: "filemgr-share-create",
                    target: [
                        "[data-tour='filemgr-share-create']",
                        "#shareCreateBtn"
                    ],
                    placement: "left",
                    title: "Create the URL",
                    body: "Create link generates the public URL. After the link appears below, use Copy to place it on your clipboard."
                },
                {
                    id: "filemgr-share-copy",
                    target: [
                        "#shareOutWrap:not(.hidden) [data-tour='filemgr-share-copy']",
                        "#shareOutWrap:not(.hidden) #shareCopyBtn"
                    ],
                    placement: "left",
                    title: "Copy the link",
                    body: "When a link already exists or has just been created, Copy places the URL on your clipboard so you can send it."
                },
                {
                    id: "filemgr-share-safety",
                    target: [
                        "[data-tour='filemgr-share-modal']",
                        "#shareModal.show .modalCard"
                    ],
                    placement: "left",
                    title: "Share carefully",
                    body: "Only send share links to people you trust.",
                    notice: "Anyone with the link may access the shared item until the link expires or is revoked."
                }
            ]
        };

        const afterFileMgr = manifest.tours.findIndex(tour => tour && tour.id === "filemgr.first_run.v2");
        const insertAt = afterFileMgr >= 0 ? afterFileMgr + 1 : manifest.tours.length;
        manifest.tours.splice(insertAt, 0, tour);
    }


    function ensureFileManagerPqEnrolledShareTour() {
        if (!manifest || !Array.isArray(manifest.tours)) {
            return;
        }

        const id = "filemgr.pq_enrolled_share_first_open.v1";
        const exists = manifest.tours.some(tour => tour && tour.id === id);
        if (exists) {
            return;
        }

        const tour = {
            id: id,
            scope: "filemgr",
            title: "PQ enrolled share dialog",
            autoStart: false,
            showInMenu: true,
            when: {
                any: [
                    "#shareModal.show[data-share-mode='pq-enrolled'] [data-tour='filemgr-share-modal']",
                    "#shareModal[aria-hidden='false'][data-share-mode='pq-enrolled'] [data-tour='filemgr-share-modal']"
                ]
            },
            steps: [
                {
                    id: "filemgr-pq-share-overview",
                    target: [
                        "[data-tour='filemgr-share-modal']",
                        "#shareModal.show .modalCard"
                    ],
                    placement: "left",
                    title: "PQ recipient-enrolled share",
                    body: "This creates a recipient-enrolled share invite. It is different from a normal public share link: the recipient uses the invite to enroll with their DNA identity before access is granted."
                },
                {
                    id: "filemgr-pq-share-recipient",
                    target: [
                        "[data-tour='filemgr-share-status']",
                        "#shareStatus",
                        "[data-tour='filemgr-share-modal']"
                    ],
                    placement: "left",
                    title: "For a specific recipient",
                    body: "Use this when you want the recipient to be tied to their own identity instead of only relying on a normal public URL. The invite URL starts the recipient enrollment flow."
                },
                {
                    id: "filemgr-pq-share-expiry",
                    target: [
                        "[data-tour='filemgr-share-expiry']",
                        "#shareExpiry"
                    ],
                    placement: "left",
                    title: "Choose how long it should work",
                    body: "Expiry limits the share lifetime. Shorter is safer. The recipient invite/enrollment window may also be limited separately by the server."
                },
                {
                    id: "filemgr-pq-share-create",
                    target: [
                        "[data-tour='filemgr-share-create']",
                        "#shareCreateBtn"
                    ],
                    placement: "left",
                    title: "Create the PQ invite",
                    body: "Create PQ invite generates the invite URL. Send that URL to the intended recipient so they can complete enrollment."
                },
                {
                    id: "filemgr-pq-share-copy",
                    target: [
                        "#shareOutWrap:not(.hidden) [data-tour='filemgr-share-copy']",
                        "#shareOutWrap:not(.hidden) #shareCopyBtn"
                    ],
                    placement: "left",
                    title: "Copy the invite URL",
                    body: "After the invite is created, Copy places the invite URL on your clipboard. Send it only to the intended recipient."
                },
                {
                    id: "filemgr-pq-share-safety",
                    target: [
                        "[data-tour='filemgr-share-modal']",
                        "#shareModal.show .modalCard"
                    ],
                    placement: "left",
                    title: "Treat invites as sensitive",
                    body: "A PQ invite is safer than a plain public link because it supports recipient enrollment, but the invite URL should still be protected. Revoke it if you sent it to the wrong place.",
                    notice: "Only share PQ invite URLs with people you trust."
                },
                {
                    id: "filemgr-pq-share-manager",
                    target: [
                        "[data-tour='filemgr-share-modal']",
                        "#shareModal.show .modalCard"
                    ],
                    placement: "left",
                    title: "Manage shares later",
                    body: "After shares are created, they can be reviewed, copied, expired or revoked later from Shares Manager."
                }
            ]
        };

        const afterStandardShare = manifest.tours.findIndex(tour => tour && tour.id === "filemgr.share_link_first_open.v1");
        const afterFileMgr = manifest.tours.findIndex(tour => tour && tour.id === "filemgr.first_run.v2");
        const insertAt = afterStandardShare >= 0
            ? afterStandardShare + 1
            : (afterFileMgr >= 0 ? afterFileMgr + 1 : manifest.tours.length);
        manifest.tours.splice(insertAt, 0, tour);
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

    function conditionMatches(when) {
        if (!when) return true;

        if (Array.isArray(when.any) && when.any.length && !anySelectorVisible(when.any)) {
            return false;
        }

        if (Array.isArray(when.all) && when.all.length && !allSelectorsVisible(when.all)) {
            return false;
        }

        const blocked = Array.isArray(when.none)
            ? when.none
            : (Array.isArray(when.not) ? when.not : []);

        if (blocked.length && anySelectorVisible(blocked)) {
            return false;
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

    function isTourAvailableNow(tour) {
        if (!tour || !tour.id) return false;
        if (!conditionMatches(tour.when)) return false;
        return getShowableSteps(tour).length > 0;
    }

    function isFileManagerStorageUnallocatedActive() {
        try {
            const state = window.DNANexusFileManagerTourState;
            if (state && typeof state.isStorageUnallocated === "function") {
                return !!state.isStorageUnallocated();
            }
        } catch (_) {
            // ignore
        }

        return anySelectorVisible(["[data-tour-filemgr-storage-unallocated]"]);
    }

    function isTourAvailableNow(tour) {
        if (!tour || !tour.id) return false;
        if (!conditionMatches(tour.when)) return false;

        const scope = String(tour.scope || "");
        const id = String(tour.id || "");

        if (scope === "filemgr") {
            const unallocated = isFileManagerStorageUnallocatedActive();

            if (id === "filemgr.storage_unallocated.v1") {
                return unallocated && getShowableSteps(tour).length > 0;
            }

            if (unallocated) {
                return false;
            }
        }

        return getShowableSteps(tour).length > 0;
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

        if (step.notice) {
            const notice = createEl("div", "dnx-tour-notice");
            notice.appendChild(createEl("span", "dnx-tour-notice-icon", "!"));
            notice.appendChild(createEl("span", "dnx-tour-notice-text", String(step.notice || "")));
            bubble.appendChild(notice);
        }

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

        if (suppressParentGuideForEmbeddedApp()) {
            return false;
        }

        if (!conditionMatches(tour.when)) return false;

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

    function isTopLevelGuideWindow() {
        try {
            return window.self === window.top;
        } catch (_) {
            return true;
        }
    }

    function isAppShellPage() {
        const path = String(window.location.pathname || "").toLowerCase();
        return path === "/app" || path.endsWith("/app") || path.includes("/app/");
    }

    function visibleEmbeddedAppFrame() {
        if (!document.body) {
            return null;
        }

        // Only the real top-level /app shell should yield to embedded apps.
        // Iframe apps keep their own Nexus Guide.
        if (!isTopLevelGuideWindow() || !isAppShellPage()) {
            return null;
        }

        const frames = Array.from(document.querySelectorAll("iframe"));
        for (const frame of frames) {
            if (isVisible(frame)) {
                return frame;
            }
        }

        return null;
    }

    function parentShouldYieldToEmbeddedApp() {
        return !!visibleEmbeddedAppFrame();
    }

    function removeOwnHelpButton() {
        closeHelpMenu();

        const buttons = Array.from(document.querySelectorAll(".dnx-tour-help"));
        for (const btn of buttons) {
            btn.remove();
        }

        helpButton = null;
    }

    function suppressParentGuideForEmbeddedApp() {
        if (!parentShouldYieldToEmbeddedApp()) {
            return false;
        }

        if (activeTour) {
            stopTour();
        }

        removeOwnHelpButton();
        return true;
    }

    
function toggleHelpMenu() {
        if (helpMenu) {
            closeHelpMenu();
            return;
        }

        const tours = getToursForCurrentScope()
            .filter(tour => {
                if (!tour) return false;
                if (tour.showInMenu === false || tour.menuHidden === true || tour.hiddenInMenu === true) {
                    return false;
                }
                return conditionMatches(tour.when);
            });

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


    function hideParentGuideButtonForEmbeddedApp() {
        if (!window.parent || window.parent === window) {
            return;
        }

        let scope = "";
        try {
            scope = detectScope();
        } catch (_) {
            scope = "";
        }

        if (!scope || scope === "shell") {
            return;
        }

        try {
            const parentDoc = window.parent.document;
            if (!parentDoc || !parentDoc.documentElement) {
                return;
            }

            parentDoc.documentElement.classList.add("dnx-embedded-app-guide-active");

            let style = parentDoc.getElementById("dnxEmbeddedAppGuideHideStyle");
            if (!style) {
                style = parentDoc.createElement("style");
                style.id = "dnxEmbeddedAppGuideHideStyle";
                parentDoc.head.appendChild(style);
            }

            style.textContent =
                "html.dnx-embedded-app-guide-active .dnx-tour-help," +
                "html.dnx-embedded-app-guide-active .dnx-tour-menu{" +
                "display:none!important;" +
                "}";
        } catch (_) {
            // Cross-frame access may fail if the app is ever served from another origin.
        }
    }

    function restoreParentGuideButtonAfterEmbeddedApp() {
        if (!window.parent || window.parent === window) {
            return;
        }

        try {
            const parentDoc = window.parent.document;
            if (parentDoc && parentDoc.documentElement) {
                parentDoc.documentElement.classList.remove("dnx-embedded-app-guide-active");
            }
        } catch (_) {
            // ignore
        }
    }

    function ensureHelpButton() {
        hideParentGuideButtonForEmbeddedApp();

        if (!document.body) {
            return;
        }

        if (suppressParentGuideForEmbeddedApp()) {
            return;
        }

        const existingButtons = Array.from(document.querySelectorAll(".dnx-tour-help"));

        if (helpButton && document.body.contains(helpButton)) {
            for (const btn of existingButtons) {
                if (btn !== helpButton) {
                    btn.remove();
                }
            }
            return;
        }

        for (const btn of existingButtons) {
            btn.remove();
        }

        helpButton = createEl("button", "dnx-tour-help", "?");
        helpButton.id = "dnxTourHelpButton";
        helpButton.type = "button";
        helpButton.title = "Nexus Guide";
        helpButton.setAttribute("aria-label", "Nexus Guide");
        helpButton.addEventListener("click", toggleHelpMenu);
        document.body.appendChild(helpButton);
    }

    if (!window.__DNX_EMBEDDED_GUIDE_UNLOAD_HOOK__) {
        window.__DNX_EMBEDDED_GUIDE_UNLOAD_HOOK__ = true;
        window.addEventListener("pagehide", restoreParentGuideButtonAfterEmbeddedApp);
        window.addEventListener("beforeunload", restoreParentGuideButtonAfterEmbeddedApp);
    }

    function autoStartTours(force) {
        const scope = detectScope();

        if (suppressParentGuideForEmbeddedApp()) {
            lastScope = scope;
            return false;
        }

        if (scope === "filemgr" &&
            window.DNANexusFileManagerTourState &&
            typeof window.DNANexusFileManagerTourState.isReady === "function" &&
            !window.DNANexusFileManagerTourState.isReady()) {
            window.setTimeout(() => autoStartTours(!!force), 450);
            return false;
        }

        const tours = getToursForCurrentScope().filter(tour => tour.autoStart && conditionMatches(tour.when));

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

        if (suppressParentGuideForEmbeddedApp()) {
            lastScope = detectScope();
            return;
        }

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

        ensureFileManagerTour();
        ensureFileManagerShareLinkTour();
        ensureFileManagerPqEnrolledShareTour();
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


    function findTourById(id) {
        id = String(id || "").trim();
        if (!id || !manifest || !Array.isArray(manifest.tours)) {
            return null;
        }

        return manifest.tours.find(tour => tour && String(tour.id || "") === id) || null;
    }

    function startTourById(id, force) {
        const tour = findTourById(id);
        if (!tour) {
            return false;
        }

        return startTour(tour, !!force);
    }

    function startTourByIdOnce(id) {
        const tour = findTourById(id);
        if (!tour) {
            return false;
        }

        const status = getTourStatus(tour.id);
        if (status === "completed" || status === "dismissed") {
            return false;
        }

        return startTour(tour, false);
    }

    window.DNANexusGuidedTours = {
        restartCurrentScope: function () {
            autoStartTours(true);
        },
        startTourById: function (id, force) {
            return startTourById(id, !!force);
        },
        startTourByIdOnce: function (id) {
            return startTourByIdOnce(id);
        },
        resetAll: function () {
            writeState({});
        },
        debug: function () {
            return {
                scope: detectScope(),
                tours: getToursForCurrentScope().map(t => t.id),
                state: readState(),
                helpButton: !!document.querySelector(".dnx-tour-help"),
                isTopLevelGuideWindow: isTopLevelGuideWindow(),
                isAppShellPage: isAppShellPage(),
                embeddedAppFrame: !!visibleEmbeddedAppFrame(),
                parentShouldYieldToEmbeddedApp: parentShouldYieldToEmbeddedApp()
            };
        }
    };
})();
