(() => {
    const boot = globalThis.PQ_SHARE_OPEN_BOOT || null;

    function kemAlgFromMode(mode) {
        const s = String(mode || "").toLowerCase();
        if (s.startsWith("mlkem768")) return "ML-KEM-768";
        return "X25519";
    }

    async function ensureOpenUnlock(mode) {
        if (!window.PqShareUnlockV1) {
            throw new Error("PQ unlock helper not loaded");
        }
        await window.PqShareUnlockV1.ensureUnlocked({
            preferredAlg: kemAlgFromMode(mode),
            purpose: "open"
        });
    }
    function el(id) {
        return document.getElementById(id);
    }

    function ensureUi() {
        if (el("pqshare-root")) return;

        document.body.innerHTML = `
      <style>
        :root{
          --bg:#0b1220;
          --panel:#121a2b;
          --fg:#eef3ff;
          --muted:#aab7d1;
          --accent:#7dd3fc;
          --border:rgba(255,255,255,0.10);
          --ok:#6ee7b7;
          --err:#fca5a5;
        }
        html,body{
          margin:0;
          min-height:100%;
          background:
            radial-gradient(1200px 700px at 15% 10%, rgba(125,211,252,0.10), transparent 55%),
            linear-gradient(180deg, #08101d, #0b1220 60%, #0a1220);
          color:var(--fg);
          font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        }
        .wrap{
          max-width:760px;
          margin:0 auto;
          padding:28px 18px 56px;
        }
        .card{
          background:rgba(18,26,43,0.92);
          border:1px solid var(--border);
          border-radius:22px;
          padding:24px;
          box-shadow:0 30px 80px rgba(0,0,0,0.35);
          backdrop-filter:blur(8px);
        }
        .eyebrow{
          font-size:12px;
          font-weight:800;
          letter-spacing:.12em;
          text-transform:uppercase;
          color:var(--accent);
          margin-bottom:8px;
        }
        h1{
          margin:0 0 10px 0;
          font-size:30px;
          line-height:1.1;
        }
        .lead{
          color:var(--muted);
          line-height:1.6;
          margin:0 0 18px 0;
        }
        .info{
          margin:0 0 18px 0;
          padding:12px 14px;
          border-radius:14px;
          background:rgba(125,211,252,0.08);
          border:1px solid rgba(125,211,252,0.20);
          color:#e7f6ff;
          line-height:1.55;
        }
        .fileline{
          margin:0 0 10px 0;
          color:var(--fg);
          font-weight:700;
          word-break:break-word;
        }
        .status{
          min-height:24px;
          margin:0 0 16px 0;
          color:var(--muted);
          font-weight:700;
        }
        button{
          appearance:none;
          border:0;
          border-radius:14px;
          padding:14px 18px;
          font-size:15px;
          font-weight:800;
          cursor:pointer;
          background:linear-gradient(180deg, #8be1ff, #68c8f2);
          color:#082033;
          box-shadow:0 12px 30px rgba(104,200,242,0.25);
        }
        button[disabled]{
          cursor:default;
          opacity:0.70;
        }
        .hidden{
          display:none !important;
        }
      </style>

      <main class="wrap">
        <div id="pqshare-root" class="card">
          <div class="eyebrow">DNA-Nexus Post-Quantum Share</div>

          <h1>Open Post-Quantum protected share</h1>

          <div class="lead">
            This shared file is protected with <strong>ML-KEM-768</strong>. The file key is unwrapped in this browser and the file is decrypted locally before download.
          </div>

          <div class="info">
            <strong>Recipient KEM:</strong> ML-KEM-768<br>
            <strong>Payload encryption:</strong> AES-256-GCM<br>
            <strong>Open mode:</strong> Local browser decrypt
          </div>

          <div id="pqshare-file" class="fileline"></div>
          <div id="pqshare-status" class="status">Preparing Post-Quantum open…</div>
          <button id="pqshare-open-btn" type="button">Decrypt and download locally</button>
        </div>
      </main>
    `;
    }

    function setStatus(msg) {
        ensureUi();
        const n = el("pqshare-status");
        if (n) n.textContent = msg;
    }

    function setFileName(name) {
        ensureUi();
        const n = el("pqshare-file");
        if (n) n.textContent = name ? `File: ${name}` : "";
    }
    function setButtonState(text, disabled, hidden = false) {
        ensureUi();
        const btn = el("pqshare-open-btn");
        if (!btn) return;
        btn.textContent = text || "Decrypt and download locally";
        btn.disabled = !!disabled;
        btn.classList.toggle("hidden", !!hidden);
    }
    function downloadBytes(bytesOrParts, fileName, mimeType) {
        const parts = Array.isArray(bytesOrParts) ? bytesOrParts : [bytesOrParts];
        const blob = new Blob(parts, { type: mimeType || "application/octet-stream" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = fileName || "download.bin";
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 2000);
    }
    async function verifyWholeFileSnapshot(bytes, snapshot) {
        const wantSha = String(snapshot?.sha256_hex || "").toLowerCase();
        if (wantSha) {
            const gotSha = (await PqShareKeysV1.sha256Hex(bytes)).toLowerCase();
            if (gotSha !== wantSha) {
                throw new Error("Decrypted file digest mismatch");
            }
        }

        const wantSize = Number(snapshot?.size_bytes || 0);
        if (wantSize > 0 && bytes.byteLength !== wantSize) {
            throw new Error("Decrypted file size mismatch");
        }
    }
    function u32be(n) {
        return new Uint8Array([
            (n >>> 24) & 0xff,
            (n >>> 16) & 0xff,
            (n >>> 8) & 0xff,
            n & 0xff
        ]);
    }

    function concatBytes(...parts) {
        const total = parts.reduce((n, p) => n + (p ? p.length : 0), 0);
        const out = new Uint8Array(total);
        let off = 0;
        for (const p of parts) {
            if (!p || !p.length) continue;
            out.set(p, off);
            off += p.length;
        }
        return out;
    }

    function chunkIvFromPrefix(prefixBytes, chunkIndex) {
        return concatBytes(prefixBytes, u32be(chunkIndex));
    }

    function chunkAadFromBase(baseAadBytes, chunkIndex, plainChunkSize) {
        return concatBytes(baseAadBytes, u32be(chunkIndex), u32be(plainChunkSize));
    }
    async function fetchEnvelope() {
        const res = await fetch((boot && boot.open_api) || "/api/v4/shares/pq/open", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                share_token: boot.share_token
            })
        });

        const text = await res.text();
        let data = {};
        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            throw new Error(`Open API returned non-JSON response (${res.status})`);
        }

        if (!res.ok || data.ok === false) {
            throw new Error(data.message || data.error || `Open API failed (${res.status})`);
        }

        return data.envelope || data;
    }
    async function fetchOpenInit() {
        const res = await fetch((boot && boot.open_init_api) || "/api/v4/shares/pq/open/init", {
            method: "POST",
            credentials: "same-origin",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                share_token: boot.share_token
            })
        });

        const text = await res.text();
        let data = {};
        try {
            data = text ? JSON.parse(text) : {};
        } catch {
            throw new Error(`Open init API returned non-JSON response (${res.status})`);
        }

        if (!res.ok || data.ok === false) {
            throw new Error(data.message || data.error || `Open init API failed (${res.status})`);
        }

        return data.open || data;
    }

    async function fetchChunk(openId, index) {
        const url = new URL((boot && boot.open_chunk_api) || "/api/v4/shares/pq/open/chunk", window.location.origin);
        url.searchParams.set("open_id", openId);
        url.searchParams.set("i", String(index));

        const res = await fetch(url.toString(), {
            method: "GET",
            credentials: "same-origin",
            cache: "no-store"
        });

        if (!res.ok) {
            let msg = `Chunk fetch failed (${res.status})`;
            try {
                const j = await res.json();
                msg = j.message || j.error || msg;
            } catch {}
            throw new Error(msg);
        }

        return new Uint8Array(await res.arrayBuffer());
    }
    async function decryptEnvelope(env) {
        if (!window.PqShareKeysV1) {
            throw new Error("PQ key helper not loaded");
        }

        await ensureOpenUnlock(env.mode);

        const aad = PqShareKeysV1.b64ToBytes(env.aad_b64);
        const cekRaw = await PqShareKeysV1.unwrapCekFromEnvelope(env);

        const cek = await crypto.subtle.importKey(
            "raw",
            cekRaw,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const plaintext = new Uint8Array(await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: PqShareKeysV1.b64ToBytes(env.payload.iv_b64),
                additionalData: aad
            },
            cek,
            PqShareKeysV1.b64ToBytes(env.payload.ciphertext_b64)
        ));

        await verifyWholeFileSnapshot(plaintext, env.snapshot);
        return plaintext;
    }
    async function decryptChunkBytes(cekRaw, chunkCiphertext, ivBytes, aadBytes) {
        const cek = await crypto.subtle.importKey(
            "raw",
            cekRaw,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        const pt = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: ivBytes,
                additionalData: aadBytes
            },
            cek,
            chunkCiphertext
        );

        return new Uint8Array(pt);
    }

    async function openAndDownloadV2() {
        if (!boot?.share_token) {
            throw new Error("Missing PQ share bootstrap data");
        }

        setFileName(boot.file_name || "");
        setStatus("Requesting post-quantum open session…");

        const open = await fetchOpenInit();
        await ensureOpenUnlock(open.mode);
        const cekRaw = await PqShareKeysV1.unwrapCekFromEnvelope(open);

        const baseAad = PqShareKeysV1.b64ToBytes(open.aad_b64);
        const noncePrefix = PqShareKeysV1.b64ToBytes(open.stream.chunk_nonce_prefix_b64);

        const pieces = [];
        let totalPlain = 0;

        for (let i = 0; i < Number(open.stream.chunk_count || 0); ++i) {
            setStatus(`Downloading and decrypting chunk ${i + 1}/${open.stream.chunk_count}…`);

            const offset = i * Number(open.stream.chunk_size_bytes || 0);
            const remain = Math.max(0, Number(open.snapshot?.size_bytes || 0) - offset);
            const plainChunkSize = Math.min(Number(open.stream.chunk_size_bytes || 0), remain);

            const chunkCiphertext = await fetchChunk(open.stream.open_id, i);
            const iv = chunkIvFromPrefix(noncePrefix, i);
            const aad = chunkAadFromBase(baseAad, i, plainChunkSize);
            const plain = await decryptChunkBytes(cekRaw, chunkCiphertext, iv, aad);

            if (plain.byteLength !== plainChunkSize) {
                throw new Error(`Chunk ${i} plaintext size mismatch`);
            }

            pieces.push(plain);
            totalPlain += plain.byteLength;
        }

        if (Number(open.snapshot?.size_bytes || 0) > 0 && totalPlain !== Number(open.snapshot.size_bytes)) {
            throw new Error("Decrypted file size mismatch");
        }

        setStatus("Verifying final file integrity…");
        const plaintext = concatBytes(...pieces);
        await verifyWholeFileSnapshot(plaintext, open.snapshot);

        setStatus("Integrity verified. Download starting…");
        downloadBytes(plaintext, open.file_name || boot.file_name || "download.bin", open.mime_type);
        setStatus("Done. Integrity verified and download started.");
    }
    async function openAndDownload() {
        if ((boot && boot.open_init_api) || (boot && boot.open_chunk_api)) {
            return openAndDownloadV2();
        }

        if (!boot?.share_token) {
            throw new Error("Missing PQ share bootstrap data");
        }

        setFileName(boot.file_name || "");
        setStatus("Requesting encrypted envelope…");
        const env = await fetchEnvelope();

        setFileName(env.file_name || boot.file_name || "");
        setStatus("Decrypting locally in this browser…");
        const plaintext = await decryptEnvelope(env);

        setStatus("Integrity verified. Download starting…");
        downloadBytes(plaintext, env.file_name || boot.file_name || "download.bin", env.mime_type);
        setStatus("Done. Integrity verified and download started.");
    }

    async function start() {
        ensureUi();
        setFileName(boot?.file_name || "");

        const btn = el("pqshare-open-btn");

        const runOpen = async (manual) => {
            setButtonState(
                manual ? "Decrypting and downloading…" : "Opening automatically…",
                true,
                false
            );

            try {
                await openAndDownload();
                setButtonState("Download started", true, true);
            } catch (err) {
                setStatus(err?.message || String(err));
                setButtonState("Retry decrypt and download", false, false);
            }
        };

        if (btn) {
            btn.onclick = async () => {
                await runOpen(true);
            };
        }

        await runOpen(false);
    }
    
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", start, { once: true });
    } else {
        start();
    }
})();