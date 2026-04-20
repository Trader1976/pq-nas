(() => {
    "use strict";

    const STYLE_ID = "pqshare-unlock-modal-style";

    function injectStyle() {
        if (document.getElementById(STYLE_ID)) return;

        const style = document.createElement("style");
        style.id = STYLE_ID;
        style.textContent = `
          .pqsu-backdrop{
            position:fixed;
            inset:0;
            background:rgba(3,8,20,0.72);
            backdrop-filter:blur(6px);
            display:flex;
            align-items:center;
            justify-content:center;
            z-index:100000;
            padding:20px;
          }
          .pqsu-modal{
            width:min(100%, 560px);
            background:rgba(18,26,43,0.96);
            border:1px solid rgba(255,255,255,0.10);
            border-radius:22px;
            box-shadow:0 30px 80px rgba(0,0,0,0.38);
            color:#eef3ff;
            font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
            overflow:hidden;
          }
          .pqsu-head{
            padding:20px 22px 8px;
          }
          .pqsu-eyebrow{
            font-size:12px;
            font-weight:800;
            letter-spacing:.12em;
            text-transform:uppercase;
            color:#7dd3fc;
            margin-bottom:8px;
          }
          .pqsu-title{
            margin:0;
            font-size:26px;
            line-height:1.1;
          }
          .pqsu-body{
            padding:0 22px 22px;
          }
          .pqsu-lead{
            color:#aab7d1;
            line-height:1.6;
            margin:10px 0 16px;
          }
          .pqsu-warn{
            margin:0 0 16px;
            padding:12px 14px;
            border-radius:14px;
            background:rgba(252,165,165,0.10);
            border:1px solid rgba(252,165,165,0.22);
            color:#ffe8e8;
            line-height:1.55;
            font-size:14px;
          }
          .pqsu-field{
            margin:14px 0;
          }
          .pqsu-label{
            display:block;
            font-size:14px;
            font-weight:700;
            margin-bottom:8px;
          }
          .pqsu-input{
            width:100%;
            box-sizing:border-box;
            border-radius:14px;
            border:1px solid rgba(255,255,255,0.10);
            background:rgba(255,255,255,0.04);
            color:#eef3ff;
            padding:14px 15px;
            font-size:16px;
            outline:none;
          }
          .pqsu-input:focus{
            border-color:rgba(125,211,252,0.6);
            box-shadow:0 0 0 3px rgba(125,211,252,0.14);
          }
          .pqsu-check{
            display:flex;
            gap:10px;
            align-items:flex-start;
            margin:16px 0 4px;
            color:#d9e8ff;
            font-size:14px;
            line-height:1.5;
          }
          .pqsu-check input{
            margin-top:3px;
          }
          .pqsu-error{
            min-height:22px;
            color:#fca5a5;
            font-size:14px;
            font-weight:700;
            margin-top:10px;
          }
          .pqsu-actions{
            display:flex;
            flex-wrap:wrap;
            gap:10px;
            margin-top:18px;
          }
          .pqsu-btn{
            appearance:none;
            border:0;
            border-radius:14px;
            padding:14px 18px;
            font-size:15px;
            font-weight:800;
            cursor:pointer;
          }
          .pqsu-btn-primary{
            background:linear-gradient(180deg, #8be1ff, #68c8f2);
            color:#082033;
            box-shadow:0 12px 30px rgba(104,200,242,0.25);
          }
          .pqsu-btn-secondary{
            background:rgba(255,255,255,0.06);
            color:#eef3ff;
            border:1px solid rgba(255,255,255,0.10);
          }
          .pqsu-btn-danger{
            background:rgba(252,165,165,0.12);
            color:#ffe5e5;
            border:1px solid rgba(252,165,165,0.22);
          }
        `;
        document.head.appendChild(style);
    }

    function escapeHtml(s) {
        return String(s || "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;");
    }

    function showUnlockModal({ mode, alg, purpose, errorMessage = "" }) {
        injectStyle();

        return new Promise((resolve) => {
            const backdrop = document.createElement("div");
            backdrop.className = "pqsu-backdrop";

            const isSetup = mode === "setup";
            const purposeText = purpose === "enroll"
                ? "This browser is about to create a local device key for post-quantum share enrollment."
                : "This browser needs to unlock its local device key before it can open this protected share.";

            backdrop.innerHTML = `
              <div class="pqsu-modal" role="dialog" aria-modal="true" aria-labelledby="pqsu-title">
                <div class="pqsu-head">
                  <div class="pqsu-eyebrow">DNA-Nexus Post-Quantum Share</div>
                  <h2 id="pqsu-title" class="pqsu-title">${isSetup ? "Create device key passphrase" : "Unlock device key"}</h2>
                </div>
                <div class="pqsu-body">
                  <div class="pqsu-lead">${escapeHtml(purposeText)}</div>

                  <div class="pqsu-warn">
                    This passphrase protects your local ${escapeHtml(alg)} device key stored in this browser.
                    It is never sent to the server and cannot be recovered.
                    If you forget it, this browser will no longer be able to open shares encrypted to this device key.
                    You can reset and re-enroll this browser for future shares, but older shares tied to the old key will remain inaccessible here.
                  </div>

                  <div class="pqsu-field">
                    <label class="pqsu-label" for="pqsu-secret">${isSetup ? "Create passphrase" : "Enter passphrase"}</label>
                    <input id="pqsu-secret" class="pqsu-input" type="password" autocomplete="new-password">
                  </div>

                  ${isSetup ? `
                    <div class="pqsu-field">
                      <label class="pqsu-label" for="pqsu-secret2">Confirm passphrase</label>
                      <input id="pqsu-secret2" class="pqsu-input" type="password" autocomplete="new-password">
                    </div>
                    <label class="pqsu-check">
                      <input id="pqsu-ack" type="checkbox">
                      <span>I understand this passphrase cannot be recovered.</span>
                    </label>
                  ` : ""}

                  <div id="pqsu-error" class="pqsu-error">${escapeHtml(errorMessage)}</div>

                  <div class="pqsu-actions">
                    <button id="pqsu-submit" class="pqsu-btn pqsu-btn-primary" type="button">
                      ${isSetup ? "Create and continue" : "Unlock"}
                    </button>
                    <button id="pqsu-cancel" class="pqsu-btn pqsu-btn-secondary" type="button">Cancel</button>
                    ${!isSetup ? `<button id="pqsu-reset" class="pqsu-btn pqsu-btn-danger" type="button">Reset this browser key</button>` : ""}
                  </div>
                </div>
              </div>
            `;

            document.body.appendChild(backdrop);

            const secretEl = backdrop.querySelector("#pqsu-secret");
            const secret2El = backdrop.querySelector("#pqsu-secret2");
            const ackEl = backdrop.querySelector("#pqsu-ack");
            const errorEl = backdrop.querySelector("#pqsu-error");
            const submitBtn = backdrop.querySelector("#pqsu-submit");
            const cancelBtn = backdrop.querySelector("#pqsu-cancel");
            const resetBtn = backdrop.querySelector("#pqsu-reset");

            function close(result) {
                backdrop.remove();
                resolve(result);
            }

            function submit() {
                const secret = String(secretEl?.value || "");
                if (!secret) {
                    errorEl.textContent = "Passphrase is required.";
                    return;
                }

                if (isSetup) {
                    const secret2 = String(secret2El?.value || "");
                    if (secret.length < 8) {
                        errorEl.textContent = "Use at least 8 characters.";
                        return;
                    }
                    if (secret !== secret2) {
                        errorEl.textContent = "Passphrases do not match.";
                        return;
                    }
                    if (!ackEl?.checked) {
                        errorEl.textContent = "Please confirm that you understand the recovery warning.";
                        return;
                    }
                }

                close({ action: "submit", secret });
            }

            submitBtn?.addEventListener("click", submit);
            cancelBtn?.addEventListener("click", () => close({ action: "cancel" }));
            resetBtn?.addEventListener("click", () => close({ action: "reset" }));

            backdrop.addEventListener("keydown", (e) => {
                if (e.key === "Escape") {
                    e.preventDefault();
                    close({ action: "cancel" });
                }
                if (e.key === "Enter") {
                    e.preventDefault();
                    submit();
                }
            });

            setTimeout(() => secretEl?.focus(), 0);
        });
    }

    async function ensureUnlocked({ preferredAlg = "ML-KEM-768", purpose = "open" } = {}) {
        if (!window.PqShareKeysV1) {
            throw new Error("PQ key helper not loaded");
        }

        const alg = window.PqShareKeysV1.normalizeKemAlg(preferredAlg);
        let errorMessage = "";

        for (;;) {
            const hasIdentity = !!window.PqShareKeysV1.hasStoredIdentity(alg);
            const mode = hasIdentity ? "unlock" : "setup";

            const result = await showUnlockModal({
                mode,
                alg,
                purpose,
                errorMessage
            });

            if (!result || result.action === "cancel") {
                throw new Error("Device key passphrase is required");
            }

            if (result.action === "reset") {
                const ok = window.confirm(
                    "Reset this browser's local device key?\n\n" +
                    "This will remove the existing local key for this browser. " +
                    "Older shares encrypted to the old key will no longer open here."
                );
                if (ok) {
                    window.PqShareKeysV1.resetLocalIdentity(alg);
                }
                errorMessage = "";
                continue;
            }

            try {
                window.PqShareKeysV1.setIdentityUnlockSecret(result.secret);

                if (mode === "unlock") {
                    await window.PqShareKeysV1.unlockStoredIdentity(alg, {
                        unlockSecret: result.secret
                    });
                }

                return result.secret;
            } catch (err) {
                window.PqShareKeysV1.clearIdentityUnlockSecret();
                errorMessage = String(err && err.message ? err.message : err) || "Unlock failed";
            }
        }
    }

    globalThis.PqShareUnlockV1 = {
        ensureUnlocked
    };
})();