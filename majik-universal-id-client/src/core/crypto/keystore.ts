/**
 * MajikKeyStore.ts
 *
 * IDB persistence + in-memory cache layer for MajikKey accounts.
 * Replaces MajikKeyStore as the account storage backend for MajikMessage.
 *
 */

import { MajikKey, MajikKeyJSON, SerializedIdentity } from "@majikah/majik-key";

import { KDF_VERSION } from "./constants";

// ─── IDB Config ───────────────────────────────────────────────────────────────

const STORE_NAME = "majik-keys";
const LEGACY_STORE_NAME = "identities"; // MajikKeyStore's old store — for migration reads
const DB_VERSION = 2; // bump from MajikKeyStore's v1 to trigger onupgradeneeded

// ─── Types ────────────────────────────────────────────────────────────────────

/**
 * The legacy SerializedIdentity shape from MajikKeyStore.
 * Used only for reading old IDB records during migration.
 */
interface LegacySerializedIdentity {
  id: string;
  publicKey: string; // base64
  fingerprint: string;
  encryptedPrivateKey?: string; // base64
  salt?: string; // base64
}

export class MajikKeyStoreError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikKeyStoreError";
    this.cause = cause;
  }
}

// ─── MajikKeyStore ────────────────────────────────────────────────────────────

export class MajikKeyStore {
  private static _deviceID: string = "default";
  private static _dbPromise: Promise<IDBDatabase> | null = null;

  /**
   * In-memory cache of all loaded MajikKey instances (locked or unlocked).
   * Keyed by account ID. Unlocked state lives inside each MajikKey instance.
   */
  private static _keys: Map<string, MajikKey> = new Map();

  /**
   * Optional callback invoked when UI needs to prompt for a passphrase.
   * Should return the passphrase string or Promise<string>.
   */
  static onUnlockRequested?: (id: string) => string | Promise<string>;

  // ── Init ───────────────────────────────────────────────────────────────────

  /**
   * Initialize the store with a device/user ID.
   * Must be called before any other method.
   */
  static init(deviceID: string): void {
    this._deviceID = deviceID;
    this._dbPromise = null; // reset DB connection on re-init
    this._keys.clear();
  }

  // ── IDB ───────────────────────────────────────────────────────────────────

  private static async _getDB(): Promise<IDBDatabase> {
    if (this._dbPromise) return this._dbPromise;

    this._dbPromise = new Promise((resolve, reject) => {
      const request = indexedDB.open(this._deviceID, DB_VERSION);

      request.onupgradeneeded = (event) => {
        const db = request.result;
        const oldVersion = event.oldVersion;

        // Create new store for MajikKeyJSON (v2+)
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "id" });
        }

        // Keep legacy "identities" store intact for migration reads
        // (do not delete it — old data may need to be migrated on demand)
        if (
          oldVersion < 1 &&
          !db.objectStoreNames.contains(LEGACY_STORE_NAME)
        ) {
          db.createObjectStore(LEGACY_STORE_NAME, { keyPath: "id" });
        }
      };

      request.onsuccess = () => resolve(request.result);
      request.onerror = () =>
        reject(new MajikKeyStoreError("IDB open failed", request.error));
    });

    return this._dbPromise;
  }

  private static async _put(json: MajikKeyJSON): Promise<void> {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.put(json);
      req.onsuccess = () => resolve();
      req.onerror = () =>
        reject(new MajikKeyStoreError("Failed to store MajikKey", req.error));
    });
  }

  private static async _get(id: string): Promise<MajikKeyJSON | null> {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () =>
        reject(new MajikKeyStoreError("Failed to read MajikKey", req.error));
    });
  }

  private static async _getAll(): Promise<MajikKeyJSON[]> {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => resolve(req.result || []);
      req.onerror = () =>
        reject(new MajikKeyStoreError("Failed to list MajikKeys", req.error));
    });
  }

  private static async _delete(id: string): Promise<void> {
    const db = await this._getDB();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () =>
        reject(new MajikKeyStoreError("Failed to delete MajikKey", req.error));
    });
  }

  // ── Legacy IDB (migration reads only) ─────────────────────────────────────

  private static async _getLegacy(
    id: string,
  ): Promise<LegacySerializedIdentity | null> {
    try {
      const db = await this._getDB();
      if (!db.objectStoreNames.contains(LEGACY_STORE_NAME)) return null;
      return new Promise((resolve) => {
        const tx = db.transaction(LEGACY_STORE_NAME, "readonly");
        const store = tx.objectStore(LEGACY_STORE_NAME);
        const req = store.get(id);
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      });
    } catch {
      return null;
    }
  }

  private static async _getAllLegacy(): Promise<LegacySerializedIdentity[]> {
    try {
      const db = await this._getDB();
      if (!db.objectStoreNames.contains(LEGACY_STORE_NAME)) return [];
      return new Promise((resolve) => {
        const tx = db.transaction(LEGACY_STORE_NAME, "readonly");
        const store = tx.objectStore(LEGACY_STORE_NAME);
        const req = store.getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => resolve([]);
      });
    } catch {
      return [];
    }
  }

  // ── Core API ──────────────────────────────────────────────────────────────

  /**
   * Store a MajikKey in IDB and cache it in memory.
   * The key must be unlocked (toKeyIdentity() is called to warm the memory cache).
   * The full MajikKeyJSON is persisted — including ML-KEM keys and kdfVersion.
   */
  static async save(key: MajikKey): Promise<void> {
    await this._put(key.toJSON());
    this._keys.set(key.id, key);
  }

  /**
   * Load a MajikKey by ID. Checks memory cache first, then IDB, then legacy IDB.
   * Returns null if not found anywhere.
   *
   * Loaded keys are LOCKED. Call unlock(id, passphrase) to unlock.
   */
  static async load(id: string): Promise<MajikKey | null> {
    // 1. Memory cache
    const cached = this._keys.get(id);
    if (cached) return cached;

    // 2. New IDB store (MajikKeyJSON)
    const json = await this._get(id);
    if (json) {
      const key = MajikKey.fromJSON(json);
      this._keys.set(id, key);
      return key;
    }

    // 3. Legacy IDB store (MajikKeyStore format) — migrate on read
    const legacy = await this._getLegacy(id);
    if (legacy) {
      const key = MajikKeyStore.fromLegacySerializedIdentity(legacy);
      // Don't save yet — wait until the user unlocks and we can verify
      this._keys.set(id, key);
      return key;
    }

    return null;
  }

  /**
   * Load all MajikKeys from IDB (new store + legacy store merged).
   * Legacy accounts are included but NOT migrated until explicitly unlocked.
   */
  static async loadAll(): Promise<MajikKey[]> {
    const results = new Map<string, MajikKey>();

    // New store first
    const allNew = await this._getAll();
    for (const json of allNew) {
      const key = MajikKey.fromJSON(json);
      results.set(key.id, key);
      this._keys.set(key.id, key);
    }

    // Legacy store — add any not already in new store
    const allLegacy = await this._getAllLegacy();
    for (const legacy of allLegacy) {
      if (!results.has(legacy.id)) {
        const key = MajikKeyStore.fromLegacySerializedIdentity(legacy);
        results.set(key.id, key);
        this._keys.set(key.id, key);
      }
    }

    return [...results.values()];
  }

  static async getAccount(id: string): Promise<MajikKey> {
    const key = await this.load(id);
    if (!key) throw new MajikKeyStoreError(`Account not found: ${id}`);
    return key;
  }

  /**
   * Unlock a stored MajikKey with the given passphrase.
   * Automatically dispatches to the correct KDF (PBKDF2 for old accounts, Argon2id for new).
   * Updates the in-memory cache with the unlocked instance.
   */
  static async unlock(id: string, passphrase: string): Promise<MajikKey> {
    const key = await this.load(id);
    if (!key) throw new MajikKeyStoreError(`Account not found: ${id}`);

    if (key.isUnlocked) return key;

    await key.unlock(passphrase);
    this._keys.set(id, key);
    return key;
  }

  /**
   * Lock a MajikKey — clears private keys from memory.
   */
  static lock(id: string): void {
    const key = this._keys.get(id);
    if (key) key.lock();
  }

  /**
   * Lock all loaded accounts.
   */
  static lockAll(): void {
    for (const key of this._keys.values()) {
      key.lock();
    }
  }

  /**
   * Get the private key of an unlocked account.
   * Throws if not found or not unlocked — caller must call unlock() first.
   */
  static getPrivateKey(
    idOrFingerprint: string,
  ): CryptoKey | { raw: Uint8Array } {
    // Check by ID
    const byId = this._keys.get(idOrFingerprint);
    if (byId?.isUnlocked) return byId.getPrivateKey();

    // Check by fingerprint
    for (const key of this._keys.values()) {
      if (key.fingerprint === idOrFingerprint && key.isUnlocked) {
        return key.getPrivateKey();
      }
    }

    throw new MajikKeyStoreError(
      `Account "${idOrFingerprint}" must be unlocked first via unlock()`,
    );
  }

  /**
   * Get the ML-KEM secret key of an unlocked account.
   * Returns undefined if the account has no ML-KEM keys (pre-migration).
   */
  static getMlKemSecretKey(idOrFingerprint: string): Uint8Array | undefined {
    const key = this._findKey(idOrFingerprint);
    if (!key?.isUnlocked) return undefined;
    try {
      return key.getMlKemSecretKey();
    } catch {
      return undefined; // account exists but has no ML-KEM keys yet
    }
  }

  /**
   * Get a loaded MajikKey by ID or fingerprint.
   */
  static get(idOrFingerprint: string): MajikKey | undefined {
    return this._findKey(idOrFingerprint);
  }

  /**
   * List all currently loaded MajikKey instances (locked + unlocked).
   */
  static list(): MajikKey[] {
    return [...this._keys.values()];
  }

  /**
   * Check whether an account exists by ID or fingerprint.
   * Checks memory cache first, then IDB.
   */
  static async has(idOrFingerprint: string): Promise<boolean> {
    // Memory cache
    if (this._findKey(idOrFingerprint)) return true;

    // IDB (new store)
    const allNew = await this._getAll();
    if (
      allNew.some(
        (j) => j.id === idOrFingerprint || j.fingerprint === idOrFingerprint,
      )
    ) {
      return true;
    }

    // Legacy IDB
    const allLegacy = await this._getAllLegacy();
    return allLegacy.some(
      (l) => l.id === idOrFingerprint || l.fingerprint === idOrFingerprint,
    );
  }

  /**
   * Validate whether a passphrase can decrypt the stored account.
   * Does NOT unlock or mutate any state.
   */
  static async isPassphraseValid(
    id: string,
    passphrase: string,
  ): Promise<boolean> {
    const key = await this.load(id);
    if (!key) return false;
    return key.verify(passphrase);
  }

  /**
   * Delete an account from IDB and memory cache.
   */
  static async delete(id: string): Promise<void> {
    await this._delete(id);
    this._keys.delete(id);
  }

  /**
   * Ensure an account is unlocked, prompting for passphrase if needed.
   * Drop-in replacement for MajikMessage.ensureIdentityUnlocked().
   *
   * @param id - Account ID
   * @param promptFn - Optional passphrase prompt function
   * @returns The unlocked account's X25519 private key
   */
  static async ensureUnlocked(
    id: string,
    promptFn?: (id: string) => string | Promise<string>,
  ): Promise<CryptoKey | { raw: Uint8Array }> {
    // Try from memory first (already unlocked)
    try {
      return this.getPrivateKey(id);
    } catch {
      /* not unlocked */
    }

    // Ask for passphrase
    let passphrase: string | null = null;
    if (promptFn) {
      const res = promptFn(id);
      passphrase = typeof res === "string" ? res : await res;
    } else if (this.onUnlockRequested) {
      const res = this.onUnlockRequested(id);
      passphrase = typeof res === "string" ? res : await res;
    } else if (typeof window !== "undefined" && window.prompt) {
      passphrase = window.prompt("Enter passphrase to unlock account:", "");
    }

    if (!passphrase) throw new MajikKeyStoreError("Unlock cancelled");

    await this.unlock(id, passphrase);
    return this.getPrivateKey(id);
  }

  // ── Migration: fromLegacySerializedIdentity ────────────────────────────────

  /**
   * Reconstruct a locked MajikKey from a MajikKeyStore SerializedIdentity.
   *
   * The legacy format has:
   *   - id, publicKey (base64), fingerprint
   *   - encryptedPrivateKey (base64, PBKDF2-encrypted)
   *   - salt (base64, 16 bytes)
   *   - NO: kdfVersion (implied PBKDF2), NO: ML-KEM keys, NO: label, NO: backup
   *
   * The resulting MajikKey will:
   *   - Have kdfVersion: PBKDF2 (so unlock() uses the correct KDF)
   *   - Have hasMlKem: false (until importFromMnemonicBackup() is called)
   *   - Be locked (private key not in memory)
   *
   * After unlock(), MajikMessage can call key.migrate(passphrase) to upgrade
   * the KDF to Argon2id. For full ML-KEM upgrade, importFromMnemonicBackup()
   * is required (mnemonic needed).
   *
   * This method is also the answer to your question: it's how MajikKey
   * accepts a SerializedIdentity from the existing MajikKeyStore IDB.
   */
  static fromLegacySerializedIdentity(si: LegacySerializedIdentity): MajikKey {
    if (!si.id || !si.publicKey || !si.fingerprint) {
      throw new MajikKeyStoreError(
        "Invalid legacy SerializedIdentity: missing required fields",
      );
    }

    // // SerializedIdentity may or may not have encryptedPrivateKey
    // // (some records were stored without it — public-key-only contacts)
    // const encryptedPrivateKey = si.encryptedPrivateKey
    //   ? base64ToArrayBuffer(si.encryptedPrivateKey)
    //   : new ArrayBuffer(0);

    // Reconstruct as a minimal MajikKeyJSON (v1 PBKDF2, no ML-KEM)
    const json: MajikKeyJSON = {
      id: si.id,
      label: "",
      publicKey: si.publicKey,
      fingerprint: si.fingerprint,
      encryptedPrivateKey: si.encryptedPrivateKey || "",
      salt: si.salt || "",
      backup: "_LEGACY", // no backup available from legacy format
      timestamp: new Date().toISOString(),
      kdfVersion: KDF_VERSION.PBKDF2, // legacy MajikKeyStore always used PBKDF2
      // mlKemPublicKey: absent — hasMlKem will be false
      // encryptedMlKemSecretKey: absent
    };

    return MajikKey.fromJSON(json);
  }

  /**
   * Migrate all legacy MajikKeyStore accounts to the new MajikKeyJSON format.
   *
   * Reads all records from the old "identities" IDB store, reconstructs
   * them as MajikKey instances, and writes them to the new "majik-keys" store.
   * Does NOT upgrade KDF or add ML-KEM keys — that requires the passphrase/mnemonic.
   *
   * Call this once on app startup after MajikKeyStore → MajikKeyStore transition.
   * Safe to call multiple times (already-migrated accounts are skipped).
   */
  static async migrateAllLegacy(): Promise<{
    migrated: number;
    skipped: number;
  }> {
    const legacyAll = await this._getAllLegacy();
    let migrated = 0;
    let skipped = 0;

    for (const legacy of legacyAll) {
      // Skip if already in new store
      const existing = await this._get(legacy.id);
      if (existing) {
        skipped++;
        continue;
      }

      try {
        const key = MajikKeyStore.fromLegacySerializedIdentity(legacy);
        await this._put(key.toJSON());
        this._keys.set(key.id, key);
        migrated++;
      } catch (err) {
        console.warn(`Failed to migrate legacy account ${legacy.id}:`, err);
        skipped++;
      }
    }

    return { migrated, skipped };
  }

  /**
   * Migrate a legacy MajikKeyStore account to the new MajikKeyJSON format.
   *
   * Reconstructs them as MajikKey instances, and writes them to the new "majik-keys" store.
   * Does NOT upgrade KDF or add ML-KEM keys — that requires the passphrase/mnemonic.
   *
   * Call this once on app startup after MajikKeyStore → MajikKeyStore transition.
   * Safe to call multiple times (already-migrated accounts are skipped).
   */
  static async migrate(identity: SerializedIdentity): Promise<{
    success: boolean;
    message: string;
  }> {
    try {
      const key = MajikKeyStore.fromLegacySerializedIdentity(identity);
      await this._put(key.toJSON());
      this._keys.set(key.id, key);
      return {
        success: true,
        message: `Successfully migrated ${identity.id}`,
      };
    } catch (err) {
      console.warn(`Failed to migrate legacy account ${identity.id}:`, err);
      return {
        success: false,
        message: `Failed to migrate legacy account ${identity.id}: ${err}`,
      };
    }
  }

  // ── Drop-in replacements for MajikKeyStore methods used by MajikMessage ─────────

  /**
   * Drop-in for MajikKeyStore.addMajikKey().
   * Saves the FULL MajikKeyJSON to IDB (not just 5 fields).
   */
  static async addMajikKey(key: MajikKey): Promise<void> {
    return this.save(key);
  }

  /**
   * Drop-in for MajikKeyStore.unlockIdentity().
   */
  static async unlockIdentity(
    id: string,
    passphrase: string,
  ): Promise<MajikKey> {
    return this.unlock(id, passphrase);
  }

  /**
   * Drop-in for MajikKeyStore.lockIdentity().
   */
  static lockIdentity(id: string): void {
    return this.lock(id);
  }

  /**
   * Drop-in for MajikKeyStore.hasIdentity().
   */
  static async hasIdentity(fingerprint: string): Promise<boolean> {
    return this.has(fingerprint);
  }

  /**
   * Drop-in for MajikKeyStore.isPassphraseValid().
   */
  static async isPassphraseValidFor(
    id: string,
    passphrase: string,
  ): Promise<boolean> {
    return this.isPassphraseValid(id, passphrase);
  }

  /**
   * Drop-in for MajikKeyStore.updatePassphrase().
   * Correctly upgrades KDF to Argon2id on re-encryption (MajikKeyStore never did this).
   */
  static async updatePassphrase(
    id: string,
    currentPassphrase: string,
    newPassphrase: string,
  ): Promise<void> {
    const key = await this.load(id);
    if (!key) throw new MajikKeyStoreError(`Account not found: ${id}`);
    await key.updatePassphrase(currentPassphrase, newPassphrase);
    await this._put(key.toJSON()); // persist updated encrypted state
  }

  /**
   * Drop-in for MajikKeyStore.listStoredIdentities().
   * Returns all stored MajikKey instances (loaded from IDB if needed).
   */
  static async listStoredKeys(): Promise<MajikKey[]> {
    return this.loadAll();
  }

  /**
   * Drop-in for MajikKeyStore.deleteIdentity().
   */
  static async deleteIdentity(id: string): Promise<void> {
    return this.delete(id);
  }

  static async deleteAll(): Promise<void> {
    const db = await this._getDB();

    const clearStore = (storeName: string) =>
      new Promise<void>((resolve, reject) => {
        if (!db.objectStoreNames.contains(storeName)) return resolve();
        const tx = db.transaction(storeName, "readwrite");
        const req = tx.objectStore(storeName).clear();
        req.onsuccess = () => resolve();
        req.onerror = () =>
          reject(
            new MajikKeyStoreError(
              `Failed to clear store: ${storeName}`,
              req.error,
            ),
          );
      });

    await clearStore(STORE_NAME);
    await clearStore(LEGACY_STORE_NAME);
    this._keys.clear();
  }

  /**
   * Drop-in for MajikKeyStore.generateMnemonic().
   */
  static generateMnemonic(strength: 128 | 256 = 128): string {
    return MajikKey.generateMnemonic(strength);
  }

  /**
   * Drop-in for MajikKeyStore.exportIdentityMnemonicBackup().
   * The account must be unlocked.
   */
  static async exportMnemonicBackup(
    id: string,
    mnemonic: string,
  ): Promise<string> {
    const key = this._keys.get(id);
    if (!key) throw new MajikKeyStoreError(`Account not found: ${id}`);
    if (key.isLocked)
      throw new MajikKeyStoreError("Account must be unlocked to export backup");
    return key.exportMnemonicBackup(mnemonic);
  }

  /**
   * Drop-in for MajikKeyStore.importIdentityFromMnemonicBackup().
   * Fully upgrades the account: Argon2id KDF + ML-KEM keys in one step.
   */
  static async importFromMnemonicBackup(
    backupBase64: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<MajikKey> {
    const key = await MajikKey.importFromMnemonicBackup(
      backupBase64,
      mnemonic,
      passphrase,
      label,
    );
    await this.save(key);
    return key;
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private static _findKey(idOrFingerprint: string): MajikKey | undefined {
    // By ID
    const byId = this._keys.get(idOrFingerprint);
    if (byId) return byId;
    // By fingerprint
    for (const key of this._keys.values()) {
      if (key.fingerprint === idOrFingerprint) return key;
    }
    return undefined;
  }
}
