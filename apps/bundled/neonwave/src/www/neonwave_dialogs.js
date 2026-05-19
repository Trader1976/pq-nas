(() => {
    "use strict";

    function t(key, params, fallback) {
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

    function ensureStyles() {
        if (document.getElementById("nwDialogStyles")) return;

        const style = document.createElement("style");
        style.id = "nwDialogStyles";
        style.textContent = `
.nwDialogBackdrop {
    position: fixed;
    inset: 0;
    z-index: 999999;
    display: grid;
    place-items: center;
    padding: 18px;
    background: rgba(0,0,0,.58);
    backdrop-filter: blur(8px);
}
.nwDialogCard {
    width: min(440px, 100%);
    border: 1px solid rgba(255,255,255,.16);
    border-radius: 22px;
    background: linear-gradient(135deg, rgba(20,30,45,.98), rgba(5,9,16,.98));
    box-shadow: 0 24px 80px rgba(0,0,0,.48);
    color: #f5f7ff;
    padding: 20px;
}
.nwDialogTitle {
    font-size: 18px;
    font-weight: 900;
    margin: 0 0 8px;
}
.nwDialogMessage {
    color: rgba(245,247,255,.74);
    line-height: 1.45;
    white-space: pre-wrap;
    margin-bottom: 14px;
}
.nwDialogInput {
    width: 100%;
    border: 1px solid rgba(255,255,255,.18);
    border-radius: 14px;
    padding: 11px 12px;
    background: rgba(0,0,0,.24);
    color: #f5f7ff;
    outline: none;
    margin: 4px 0 14px;
}
.nwDialogInput:focus {
    border-color: rgba(0,245,255,.65);
    box-shadow: 0 0 0 3px rgba(0,245,255,.14);
}
.nwDialogActions {
    display: flex;
    justify-content: flex-end;
    gap: 10px;
}
.nwDialogBtn {
    border: 0;
    border-radius: 13px;
    padding: 10px 14px;
    font-weight: 900;
    cursor: pointer;
}
.nwDialogBtnCancel {
    background: rgba(255,255,255,.10);
    color: #f5f7ff;
}
.nwDialogBtnOk {
    background: #00f5ff;
    color: #001317;
}
.nwDialogBtnDanger {
    background: #ff6b6b;
    color: #190000;
}`;
        document.head.appendChild(style);
    }

    function showDialog(opts) {
        ensureStyles();

        const options = opts || {};
        const wantsInput = options.input === true;

        return new Promise((resolve) => {
            const old = document.querySelector(".nwDialogBackdrop");
            if (old) old.remove();

            const backdrop = document.createElement("div");
            backdrop.className = "nwDialogBackdrop";

            const card = document.createElement("div");
            card.className = "nwDialogCard";
            card.setAttribute("role", "dialog");
            card.setAttribute("aria-modal", "true");

            const title = document.createElement("div");
            title.className = "nwDialogTitle";
            title.textContent = String(options.title || t("neonwave.dialog.title", null, "NeonWave"));

            const message = document.createElement("div");
            message.className = "nwDialogMessage";
            message.textContent = String(options.message || "");

            let input = null;
            if (wantsInput) {
                input = document.createElement("input");
                input.className = "nwDialogInput";
                input.type = "text";
                input.maxLength = Number(options.maxLength || 120);
                input.value = String(options.defaultValue || "");
                input.placeholder = String(options.placeholder || "");
            }

            const actions = document.createElement("div");
            actions.className = "nwDialogActions";

            const cancelText = options.cancelText;
            if (cancelText !== null) {
                const cancel = document.createElement("button");
                cancel.className = "nwDialogBtn nwDialogBtnCancel";
                cancel.type = "button";
                cancel.textContent = String(cancelText || t("neonwave.dialog.cancel", null, "Cancel"));
                cancel.addEventListener("click", () => close(wantsInput ? null : false));
                actions.appendChild(cancel);
            }

            const ok = document.createElement("button");
            ok.className = "nwDialogBtn nwDialogBtnOk";
            if (options.danger) ok.classList.add("nwDialogBtnDanger");
            ok.type = "button";
            ok.textContent = String(options.okText || t("neonwave.dialog.ok", null, "OK"));
            ok.addEventListener("click", () => close(wantsInput ? String(input.value || "").trim() : true));
            actions.appendChild(ok);

            card.appendChild(title);
            if (message.textContent) card.appendChild(message);
            if (input) card.appendChild(input);
            card.appendChild(actions);
            backdrop.appendChild(card);
            document.body.appendChild(backdrop);

            const previousFocus = document.activeElement;

            function onKey(ev) {
                if (ev.key === "Escape") {
                    ev.preventDefault();
                    close(wantsInput ? null : false);
                }
                if (ev.key === "Enter" && wantsInput && document.activeElement === input) {
                    ev.preventDefault();
                    close(String(input.value || "").trim());
                }
            }

            function close(value) {
                document.removeEventListener("keydown", onKey, true);
                backdrop.remove();
                try {
                    if (previousFocus && typeof previousFocus.focus === "function") previousFocus.focus();
                } catch (_) {}
                resolve(value);
            }

            document.addEventListener("keydown", onKey, true);

            setTimeout(() => {
                if (input) {
                    input.focus();
                    input.select();
                } else {
                    ok.focus();
                }
            }, 0);
        });
    }

    async function showMessage(opts) {
        await showDialog({
            title: opts && opts.title,
            message: opts && opts.message,
            okText: opts && opts.okText,
            cancelText: null
        });
    }

    async function showQuestion(opts) {
        return !!(await showDialog({
            title: opts && opts.title,
            message: opts && opts.message,
            okText: opts && opts.okText,
            cancelText: opts && opts.cancelText,
            danger: opts && opts.danger
        }));
    }

    async function showTextInput(opts) {
        return await showDialog({
            title: opts && opts.title,
            message: opts && opts.message,
            defaultValue: opts && opts.defaultValue,
            placeholder: opts && opts.placeholder,
            okText: opts && opts.okText,
            cancelText: opts && opts.cancelText,
            input: true,
            maxLength: opts && opts.maxLength
        });
    }

    window.NEONWAVE_UI = {
        t,
        alert: showMessage,
        confirm: showQuestion,
        prompt: showTextInput
    };
})();
