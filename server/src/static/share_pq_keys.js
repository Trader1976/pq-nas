(() => {
    const IDENTITY_KEY_X25519 = "pqshare:identity:x25519:v1";
    const IDENTITY_KEY_MLKEM768 = "pqshare:identity:mlkem768:v1";
    const PENDING_PREFIX = "pqshare:pending:";
    const DEVICE_PREFIX = "pqshare:device:";

    // Decrypted identities live only in memory for the current page session.
    const unlockedIdentityCache = new Map(); // storageKey -> decrypted identity record
    let identityUnlockSecret = null;

    function normalizeB64(s) {
        return String(s || "").replace(/-/g, "+").replace(/_/g, "/");
    }

    function b64ToBytes(b64) {
        const bin = atob(normalizeB64(b64));
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
        return out;
    }

    function bytesToB64(bytes) {
        let s = "";
        const chunk = 0x8000;
        for (let i = 0; i < bytes.length; i += chunk) {
            s += String.fromCharCode(...bytes.subarray(i, i + chunk));
        }
        return btoa(s);
    }

    function utf8ToBytes(s) {
        return new TextEncoder().encode(String(s || ""));
    }

    function randomBytes(n) {
        const out = new Uint8Array(n);
        crypto.getRandomValues(out);
        return out;
    }

    function normalizeKemAlg(alg) {
        const s = String(alg || "").trim().toUpperCase();
        if (!s) return "X25519";
        if (s === "X25519") return "X25519";
        if (s === "ML-KEM-768" || s === "MLKEM768") return "ML-KEM-768";
        return s;
    }

    function identityStorageKeyForAlg(alg) {
        const norm = normalizeKemAlg(alg);
        if (norm === "ML-KEM-768") return IDENTITY_KEY_MLKEM768;
        return IDENTITY_KEY_X25519;
    }

    function identityIdForAlg(alg, publicKeyB64) {
        const norm = normalizeKemAlg(alg);
        if (norm === "ML-KEM-768") return "mlkem768:" + publicKeyB64;
        return "x25519:" + publicKeyB64;
    }

    async function supportsX25519() {
        if (!globalThis.crypto?.subtle) return false;
        try {
            const kp = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
            return !!kp?.publicKey && !!kp?.privateKey;
        } catch {
            return false;
        }
    }

    function supportsNativeMlKem() {
        try {
            return !!(
                globalThis.crypto?.subtle &&
                typeof crypto.subtle.supports === "function" &&
                crypto.subtle.supports("generateKey", "ML-KEM-768")
            );
        } catch {
            return false;
        }
    }

    function getUnlockSecret(opts = {}) {
        return opts.unlockSecret || identityUnlockSecret || null;
    }

    function metadataOnlyIdentity(rec) {
        if (!rec) return null;
        return {
            v: rec.v,
            identity_id: rec.identity_id,
            alg: rec.alg,
            created_at: rec.created_at,
            public_key_b64: rec.public_key_b64
        };
    }

    function readStoredIdentityRecord(alg) {
        const raw = localStorage.getItem(identityStorageKeyForAlg(alg));
        if (!raw) return null;
        try {
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    function isLegacyPlaintextIdentityRecord(rec) {
        return !!(
            rec &&
            (
                typeof rec.private_key_b64 === "string" ||
                typeof rec.private_key_pkcs8_b64 === "string"
            )
        );
    }

    function isWrappedIdentityRecord(rec, alg) {
        const norm = normalizeKemAlg(alg);
        return !!(
            rec &&
            rec.public_key_b64 &&
            rec.alg === norm &&
            rec.private_key_wrap &&
            rec.private_key_wrap.salt_b64 &&
            rec.private_key_wrap.iv_b64 &&
            rec.private_key_wrap.ciphertext_b64
        );
    }

    function getStoredIdentity(alg) {
        const rec = readStoredIdentityRecord(alg);
        if (!rec) return null;
        if (isLegacyPlaintextIdentityRecord(rec)) return null;
        return rec;
    }

    function setIdentityUnlockSecret(secret) {
        unlockedIdentityCache.clear();
        identityUnlockSecret = secret ? String(secret) : null;
    }

    function clearIdentityUnlockSecret() {
        identityUnlockSecret = null;
        unlockedIdentityCache.clear();
    }

    async function deriveWrapKeyFromSecret(secret, saltBytes) {
        const baseKey = await crypto.subtle.importKey(
            "raw",
            utf8ToBytes(secret),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                hash: "SHA-256",
                salt: saltBytes,
                iterations: 210000
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );
    }

    async function encryptPrivateField(secret, privateValueB64) {
        const salt = randomBytes(16);
        const iv = randomBytes(12);
        const key = await deriveWrapKeyFromSecret(secret, salt);

        const ct = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            utf8ToBytes(privateValueB64)
        );

        return {
            kdf: "PBKDF2-SHA256",
            iterations: 210000,
            salt_b64: bytesToB64(salt),
            iv_b64: bytesToB64(iv),
            ciphertext_b64: bytesToB64(new Uint8Array(ct))
        };
    }

    async function decryptPrivateField(secret, wrap) {
        if (!wrap?.salt_b64 || !wrap?.iv_b64 || !wrap?.ciphertext_b64) {
            throw new Error("wrapped private key metadata missing");
        }

        const key = await deriveWrapKeyFromSecret(secret, b64ToBytes(wrap.salt_b64));

        const pt = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: b64ToBytes(wrap.iv_b64)
            },
            key,
            b64ToBytes(wrap.ciphertext_b64)
        );

        return new TextDecoder().decode(pt);
    }

    async function storeWrappedIdentityRecord(alg, publicKeyB64, privateValueB64, secret, createdAt) {
        const norm = normalizeKemAlg(alg);
        const storageKey = identityStorageKeyForAlg(norm);
        const private_key_wrap = await encryptPrivateField(secret, privateValueB64);

        const rec = {
            v: 3,
            identity_id: identityIdForAlg(norm, publicKeyB64),
            alg: norm,
            created_at: createdAt || new Date().toISOString(),
            public_key_b64: publicKeyB64,
            private_key_wrap
        };

        localStorage.setItem(storageKey, JSON.stringify(rec));

        if (norm === "ML-KEM-768") {
            unlockedIdentityCache.set(storageKey, {
                ...rec,
                private_key_b64: privateValueB64
            });
        } else {
            unlockedIdentityCache.set(storageKey, {
                ...rec,
                private_key_pkcs8_b64: privateValueB64
            });
        }

        return rec;
    }

    async function migrateLegacyIdentityRecord(alg, opts = {}) {
        const norm = normalizeKemAlg(alg);
        const rec = readStoredIdentityRecord(norm);
        if (!rec) return null;
        if (!isLegacyPlaintextIdentityRecord(rec)) return rec;

        const secret = getUnlockSecret(opts);
        if (!secret) {
            throw new Error("identity unlock secret required to migrate legacy identity record");
        }

        if (!rec.public_key_b64) {
            throw new Error("legacy identity record missing public key");
        }

        if (norm === "ML-KEM-768") {
            if (!rec.private_key_b64) {
                throw new Error("legacy ML-KEM-768 private key missing");
            }
            return storeWrappedIdentityRecord(
                norm,
                rec.public_key_b64,
                rec.private_key_b64,
                secret,
                rec.created_at
            );
        }

        if (!rec.private_key_pkcs8_b64) {
            throw new Error("legacy X25519 private key missing");
        }

        return storeWrappedIdentityRecord(
            norm,
            rec.public_key_b64,
            rec.private_key_pkcs8_b64,
            secret,
            rec.created_at
        );
    }

    async function unlockStoredIdentity(alg, opts = {}) {
        const norm = normalizeKemAlg(alg);
        const storageKey = identityStorageKeyForAlg(norm);

        const cached = unlockedIdentityCache.get(storageKey);
        if (cached) return cached;

        let rec = readStoredIdentityRecord(norm);
        if (!rec) throw new Error("browser identity not found");

        if (isLegacyPlaintextIdentityRecord(rec)) {
            await migrateLegacyIdentityRecord(norm, opts);
            rec = readStoredIdentityRecord(norm);
        }

        if (!rec) throw new Error("browser identity not found");

        const secret = getUnlockSecret(opts);
        if (!secret) throw new Error("identity unlock secret required");

        if (rec.alg === "ML-KEM-768") {
            const private_key_b64 = await decryptPrivateField(secret, rec.private_key_wrap);
            const out = { ...rec, private_key_b64 };
            unlockedIdentityCache.set(storageKey, out);
            return out;
        }

        if (rec.alg === "X25519") {
            const private_key_pkcs8_b64 = await decryptPrivateField(secret, rec.private_key_wrap);
            const out = { ...rec, private_key_pkcs8_b64 };
            unlockedIdentityCache.set(storageKey, out);
            return out;
        }

        throw new Error(`Unsupported identity alg: ${rec.alg}`);
    }

    async function ensureBrowserIdentity(opts = {}) {
        const preferredAlg = normalizeKemAlg(opts.preferredAlg || "X25519");

        let rec = readStoredIdentityRecord(preferredAlg);
        if (rec && isLegacyPlaintextIdentityRecord(rec)) {
            await migrateLegacyIdentityRecord(preferredAlg, opts);
            rec = readStoredIdentityRecord(preferredAlg);
        }

        if (isWrappedIdentityRecord(rec, preferredAlg)) {
            return metadataOnlyIdentity(rec);
        }

        const secret = getUnlockSecret(opts);
        if (!secret) {
            throw new Error(`identity unlock secret required for ${preferredAlg}`);
        }

        if (preferredAlg === "ML-KEM-768") {
            if (!globalThis.PqShareMlKemV1) {
                throw new Error("ML-KEM-768 browser helper not loaded");
            }

            const mk = await globalThis.PqShareMlKemV1.keygen768();
            const wrapped = await storeWrappedIdentityRecord(
                "ML-KEM-768",
                mk.public_key_b64,
                mk.private_key_b64,
                secret
            );

            return metadataOnlyIdentity(wrapped);
        }

        if (!(await supportsX25519())) {
            throw new Error("This browser does not support X25519 WebCrypto");
        }

        const keyPair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
        const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
        const privatePkcs8B64 = bytesToB64(
            new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey))
        );

        const wrapped = await storeWrappedIdentityRecord(
            "X25519",
            bytesToB64(publicRaw),
            privatePkcs8B64,
            secret
        );

        return metadataOnlyIdentity(wrapped);
    }

    async function generatePendingEnrollment(inviteId, opts = {}) {
        if (!inviteId) throw new Error("missing inviteId");

        const preferredAlg = normalizeKemAlg(opts.preferredAlg || "X25519");
        const ident = await ensureBrowserIdentity({
            preferredAlg,
            unlockSecret: opts.unlockSecret
        });

        localStorage.setItem(PENDING_PREFIX + inviteId, JSON.stringify({
            v: 2,
            identity_id: ident.identity_id,
            alg: ident.alg,
            public_key_b64: ident.public_key_b64,
            created_at: new Date().toISOString()
        }));

        return {
            kem_alg: ident.alg,
            public_key_b64: ident.public_key_b64
        };
    }

    function getPendingEnrollment(inviteId) {
        const raw = localStorage.getItem(PENDING_PREFIX + inviteId);
        if (!raw) return null;
        try {
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    async function claimPendingEnrollment(inviteId, recipientDeviceId) {
        if (!inviteId) throw new Error("missing inviteId");
        if (!recipientDeviceId) throw new Error("missing recipientDeviceId");

        const pending = getPendingEnrollment(inviteId);
        if (!pending?.identity_id) throw new Error("pending enrollment key not found");

        const deviceRec = {
            v: 2,
            recipient_device_id: recipientDeviceId,
            identity_id: pending.identity_id,
            alg: normalizeKemAlg(pending.alg || "X25519"),
            claimed_at: new Date().toISOString()
        };

        localStorage.setItem(DEVICE_PREFIX + recipientDeviceId, JSON.stringify(deviceRec));
        localStorage.removeItem(PENDING_PREFIX + inviteId);
        return deviceRec;
    }

    function getDeviceRecord(recipientDeviceId) {
        const raw = localStorage.getItem(DEVICE_PREFIX + recipientDeviceId);
        if (!raw) return null;
        try {
            return JSON.parse(raw);
        } catch (_) {
            return null;
        }
    }

    async function loadDevicePrivateKey(recipientDeviceId, opts = {}) {
        const rec = getDeviceRecord(recipientDeviceId);
        if (!rec) {
            throw new Error("recipient private key not found for this browser");
        }

        const alg = normalizeKemAlg(rec.alg || "X25519");
        if (alg !== "X25519") {
            throw new Error(`Private key loader for ${alg} is not wired yet`);
        }

        if (rec.identity_id) {
            const ident = await unlockStoredIdentity("X25519", opts);
            if (!ident?.private_key_pkcs8_b64) {
                throw new Error("browser identity private key missing");
            }

            return crypto.subtle.importKey(
                "pkcs8",
                b64ToBytes(ident.private_key_pkcs8_b64),
                { name: "X25519" },
                false,
                ["deriveBits"]
            );
        }

        if (rec.private_key_pkcs8_b64) {
            throw new Error("legacy plaintext X25519 private key record detected; migrate or re-enroll");
        }

        throw new Error("recipient private key not found for this browser");
    }

    async function importSenderPublicKeyX25519(publicKeyB64) {
        return crypto.subtle.importKey(
            "raw",
            b64ToBytes(publicKeyB64),
            { name: "X25519" },
            false,
            []
        );
    }

    async function deriveWrapKeyFromEnvelope(privateKey, env) {
        const senderPub = await importSenderPublicKeyX25519(env.wrapped_key.sender_public_key_b64);
        const sharedBits = await crypto.subtle.deriveBits(
            { name: "X25519", public: senderPub },
            privateKey,
            256
        );

        const hkdfBaseKey = await crypto.subtle.importKey(
            "raw",
            sharedBits,
            "HKDF",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: b64ToBytes(env.wrapped_key.hkdf_salt_b64),
                info: b64ToBytes(env.wrapped_key.hkdf_info_b64)
            },
            hkdfBaseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
    }

    async function deriveWrapKeyFromSharedSecret(sharedSecretBytes, env) {
        const hkdfBaseKey = await crypto.subtle.importKey(
            "raw",
            sharedSecretBytes,
            "HKDF",
            false,
            ["deriveKey"]
        );

        return crypto.subtle.deriveKey(
            {
                name: "HKDF",
                hash: "SHA-256",
                salt: b64ToBytes(env.wrapped_key.hkdf_salt_b64),
                info: b64ToBytes(env.wrapped_key.hkdf_info_b64)
            },
            hkdfBaseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );
    }

    async function unwrapCekFromEnvelope(env, opts = {}) {
        if (env.mode === "x25519_aes256gcm_v1") {
            const privateKey = await loadDevicePrivateKey(env.recipient_device_id, opts);
            const wrapKey = await deriveWrapKeyFromEnvelope(privateKey, env);
            const aad = b64ToBytes(env.aad_b64);

            return new Uint8Array(await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: b64ToBytes(env.wrapped_key.wrap_iv_b64),
                    additionalData: aad
                },
                wrapKey,
                b64ToBytes(env.wrapped_key.wrapped_cek_b64)
            ));
        }

        if (env.mode === "mlkem768_aes256gcm_v1" || env.mode === "mlkem768_aes256gcm_chunks_v2") {
            if (!globalThis.PqShareMlKemV1) {
                throw new Error("ML-KEM-768 browser helper not loaded");
            }

            const dev = getDeviceRecord(env.recipient_device_id);
            if (!dev) {
                throw new Error("recipient device record not found for this browser");
            }

            const ident = await unlockStoredIdentity("ML-KEM-768", opts);
            if (!ident?.private_key_b64) {
                throw new Error("ML-KEM-768 browser identity private key missing");
            }

            const sharedSecret = await globalThis.PqShareMlKemV1.decapsulate768({
                privateKeyB64: ident.private_key_b64,
                ciphertextB64: env.wrapped_key.kem_ciphertext_b64
            });

            const wrapKey = await deriveWrapKeyFromSharedSecret(sharedSecret, env);
            const aad = b64ToBytes(env.aad_b64);

            return new Uint8Array(await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: b64ToBytes(env.wrapped_key.wrap_iv_b64),
                    additionalData: aad
                },
                wrapKey,
                b64ToBytes(env.wrapped_key.wrapped_cek_b64)
            ));
        }

        throw new Error(`Unsupported open mode: ${env.mode}`);
    }

    function hasStoredIdentity(alg) {
        const norm = normalizeKemAlg(alg);
        return !!readStoredIdentityRecord(norm);
    }

    function resetLocalIdentity(alg) {
        const norm = normalizeKemAlg(alg);
        const storageKey = identityStorageKeyForAlg(norm);
        const rec = readStoredIdentityRecord(norm);
        const identityId = rec?.identity_id || null;

        localStorage.removeItem(storageKey);
        unlockedIdentityCache.delete(storageKey);

        const toDelete = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (!key) continue;
            if (!key.startsWith(PENDING_PREFIX) && !key.startsWith(DEVICE_PREFIX)) continue;

            try {
                const obj = JSON.parse(localStorage.getItem(key) || "null");
                if (!obj) continue;

                if (identityId && obj.identity_id === identityId) {
                    toDelete.push(key);
                    continue;
                }

                if (normalizeKemAlg(obj.alg || "") === norm) {
                    toDelete.push(key);
                }
            } catch (_) {
            }
        }

        for (const key of toDelete) {
            localStorage.removeItem(key);
        }

        identityUnlockSecret = null;
        unlockedIdentityCache.clear();
    }

    async function sha256Hex(bytes) {
        const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
        let out = "";
        for (const b of digest) out += b.toString(16).padStart(2, "0");
        return out;
    }

    if (typeof globalThis.addEventListener === "function") {
        globalThis.addEventListener("pagehide", () => {
            unlockedIdentityCache.clear();
        });

        globalThis.addEventListener("beforeunload", () => {
            unlockedIdentityCache.clear();
        });
    }

    globalThis.PqShareKeysV1 = {
        supportsX25519,
        supportsNativeMlKem,
        normalizeKemAlg,
        hasStoredIdentity,
        resetLocalIdentity,
        setIdentityUnlockSecret,
        clearIdentityUnlockSecret,
        unlockStoredIdentity,
        ensureBrowserIdentity,
        generatePendingEnrollment,
        getPendingEnrollment,
        claimPendingEnrollment,
        getDeviceRecord,
        loadDevicePrivateKey,
        deriveWrapKeyFromEnvelope,
        unwrapCekFromEnvelope,
        b64ToBytes,
        bytesToB64,
        sha256Hex
    };
})();