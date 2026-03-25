/**
 * MajikUniversalIdClient.ts
 *
 */

import { MajikKey } from "@majikah/majik-key";
import { MajikKeyStore } from "./core/crypto/keystore";
import {
  MajikContact,
  MajikContactCard,
  type MajikContactMeta,
  type SerializedMajikContact,
} from "./core/contacts/majik-contact";

import { MajikSignature } from "@majikah/majik-signature";
import type {
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  SignOptions,
  VerificationResult,
} from "@majikah/majik-signature";
import { KEY_ALGO } from "./core/crypto/constants";
import {
  arrayBufferToBase64,
  arrayToBase64,
  base64ToArrayBuffer,
  base64ToUint8Array,
} from "./core/utils/utilities";
import {
  MajikContactDirectory,
  MajikContactDirectoryData,
} from "./core/contacts/majik-contact-directory";
import {
  clearAllBlobs,
  idbLoadBlob,
  idbSaveBlob,
} from "./core/utils/idb-majik-system";
import {
  autoSaveMajikFileData,
  loadSavedMajikFileData,
} from "./core/utils/majik-file-utils";
import { gunzipSync, gzipSync } from "fflate";
import { MAJIK_API_RESPONSE } from "./core/types";
import {
  ImageSignatureStub,
  ImageSignOptions,
  ImageVerificationResult,
} from "@majikah/majik-signature/dist/core/stamp";

import {
  CreateUniversalIDOptions,
  MajikUniversalID,
} from "@majikah/majik-universal-id";
import { MajikUser } from "@thezelijah/majik-user";

// ─── Types ────────────────────────────────────────────────────────────────────

type MajikUniversalIdClientEvents =
  | "create-id"
  | "sign"
  | "verify"
  | "unlock"
  | "lock"
  | "new-account"
  | "new-contact"
  | "removed-account"
  | "removed-contact"
  | "active-account-change"
  | "error";

interface MajikUniversalIdClientStatic<T extends MajikUniversalIdClient> {
  new (config: MajikUniversalIdClientConfig, id?: string): T;
  fromJSON(json: MajikUniversalIdClientJSON): Promise<T>;
}

type EventCallback = (...args: any[]) => void;

export interface MajikUniversalIdClientConfig {
  /**
   * Shared contact directory. Pass the same instance used by MajikMessage
   * so that contacts stay in sync between both clients automatically.
   */
  contactDirectory?: MajikContactDirectory;

  user?: MajikUser;
}

export interface SignResult {
  signature: MajikSignature;
  signerId: string;
  contentHash: string;
  timestamp: string;
  contentType?: string;
}

export interface VerifyResult extends VerificationResult {
  signerLabel?: string; // resolved from contact directory if available
}

export interface MajikUniversalIdClientJSON {
  id: string;
  contacts: MajikContactDirectoryData;
  ownAccounts?: {
    accounts: SerializedMajikContact[];
    order: string[];
  };
}

// ─── MajikUniversalIdClient ─────────────────────────────────────────────────────

export class MajikUniversalIdClient {
  private userProfile: string = "default";
  private readonly _id: string;
  private _contactDirectory: MajikContactDirectory;
  private _ownAccounts: Map<string, MajikContact> = new Map();
  private _ownAccountsOrder: string[] = [];
  private _listeners: Map<MajikUniversalIdClientEvents, EventCallback[]> =
    new Map();

  private autosaveTimer: number | null = null;
  private autosaveIntervalId: number | null = null;
  private readonly autosaveIntervalMs = 15_000;
  private readonly autosaveDebounceMs = 500;

  private user_data: MajikUser | null = null;

  constructor(config: MajikUniversalIdClientConfig) {
    this._id = crypto.randomUUID();
    this._contactDirectory =
      config.contactDirectory ?? new MajikContactDirectory();

    this.user_data = config.user || null;

    const events: MajikUniversalIdClientEvents[] = [
      "create-id",
      "sign",
      "verify",
      "unlock",
      "lock",
      "new-account",
      "new-contact",
      "removed-account",
      "removed-contact",
      "error",
      "active-account-change",
    ];
    events.forEach((e) => this._listeners.set(e, []));
  }

  get user(): MajikUser | null {
    return this.user_data;
  }

  set user(user: MajikUser) {
    if (!user) {
      throw new Error("User cannot be null or undefined");
    }

    const userValidation = user.validate();

    if (!userValidation.isValid) {
      throw new Error(userValidation.errors.join(", "));
    }
    this.user_data = user;
  }

  clearUser(): void {
    this.user_data = null;
  }

  // ── Getters ──────────────────────────────────────────────────────────────

  get id(): string {
    return this._id;
  }

  // ── Account Management ────────────────────────────────────────────────────

  /**
   * Generate a new BIP-39 mnemonic phrase.
   */
  generateMnemonic(strength: 128 | 256 = 128): string {
    return MajikKey.generateMnemonic(strength);
  }

  /**
   * Create a new account from a mnemonic and register it.
   * The account is immediately unlocked after creation.
   */
  async createAccount(
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<{ id: string; fingerprint: string; backup: string }> {
    try {
      const key = await MajikKey.create(mnemonic, passphrase, label);
      await MajikKeyStore.addMajikKey(key);

      const contact = MajikContact.fromJSON(await key.toContact().toJSON());
      this._registerOwnAccount(contact);

      this._emit("new-account", contact);
      return { id: key.id, fingerprint: key.fingerprint, backup: key.backup };
    } catch (err) {
      this._emit("error", err, { context: "createAccount" });
      throw err;
    }
  }

  /**
   * Import an account from a mnemonic-encrypted backup.
   * Fully upgrades to Argon2id + ML-KEM + signing keys in one step.
   */
  async importAccountFromMnemonicBackup(
    backupBase64: string,
    mnemonic: string,
    passphrase: string,
    label?: string,
  ): Promise<{ id: string; fingerprint: string }> {
    try {
      const key = await MajikKeyStore.importFromMnemonicBackup(
        backupBase64,
        mnemonic,
        passphrase,
        label,
      );

      if (this.getOwnAccountById(key.id)) {
        throw new Error("Account with the same ID already exists");
      }

      const contact = MajikContact.fromJSON(await key.toContact().toJSON());
      this._registerOwnAccount(contact);

      this._emit("new-account", contact);
      return { id: key.id, fingerprint: key.fingerprint };
    } catch (err) {
      this._emit("error", err, { context: "importAccountFromMnemonicBackup" });
      throw err;
    }
  }

  /**
   * Export a mnemonic-encrypted backup for an account.
   * The account must be unlocked.
   */
  async exportAccountMnemonicBackup(
    id: string,
    mnemonic: string,
  ): Promise<string> {
    return MajikKeyStore.exportMnemonicBackup(id, mnemonic);
  }

  /**
   * Register an already-existing MajikContact as one of this client's own
   * accounts. Useful when bootstrapping from a persisted MajikMessage state.
   */
  addOwnAccount(account: MajikContact): void {
    this._registerOwnAccount(account);
    this._emit("new-account", account);
  }

  /**
   * Remove an own account from the instance.
   * Does NOT delete it from MajikKeyStore — call MajikKeyStore.deleteIdentity()
   * separately if permanent deletion is needed.
   */
  removeOwnAccount(id: string): boolean {
    if (!this._ownAccounts.has(id)) return false;
    this._ownAccounts.delete(id);
    const idx = this._ownAccountsOrder.indexOf(id);
    if (idx > -1) this._ownAccountsOrder.splice(idx, 1);

    this._contactDirectory.removeContact(id);

    this._emit("removed-account", id);
    return true;
  }

  getOwnAccountById(id: string): MajikContact | undefined {
    return this._ownAccounts.get(id);
  }

  getActiveAccount(): MajikContact | null {
    if (!this._ownAccountsOrder.length) return null;
    return this._ownAccounts.get(this._ownAccountsOrder[0]) ?? null;
  }

  isAccountActive(id: string): boolean {
    return !!this._ownAccounts.has(id) && this._ownAccountsOrder[0] === id;
  }

  setActiveAccount(id: string): boolean {
    if (!this._ownAccounts.has(id)) return false;
    const idx = this._ownAccountsOrder.indexOf(id);
    if (idx > -1) this._ownAccountsOrder.splice(idx, 1);
    this._ownAccountsOrder.unshift(id);
    return true;
  }

  listOwnAccounts(): MajikContact[] {
    return this._ownAccountsOrder
      .map((id) => this._ownAccounts.get(id))
      .filter((c): c is MajikContact => !!c);
  }

  /**
   * Unlock an account with its passphrase.
   * Required before signing. Not required for verification.
   */
  async unlockAccount(id: string, passphrase: string): Promise<void> {
    try {
      await MajikKeyStore.unlock(id, passphrase);
      this._emit("unlock", id);
    } catch (err) {
      this._emit("error", err, { context: "unlockAccount", id });
      throw err;
    }
  }

  /**
   * Lock an account — clears signing keys from memory.
   */
  lockAccount(id: string): void {
    MajikKeyStore.lock(id);
    this._emit("lock", id);
  }

  /**
   * Lock all loaded accounts.
   */
  lockAllAccounts(): void {
    MajikKeyStore.lockAll();
    for (const id of this._ownAccountsOrder) {
      this._emit("lock", id);
    }
  }

  /**
   * Check whether an account's passphrase is correct without unlocking it.
   */
  async verifyPassphrase(id: string, passphrase: string): Promise<boolean> {
    return MajikKeyStore.isPassphraseValid(id, passphrase);
  }

  /**
   * Update the passphrase for an account. Re-encrypts all keys.
   */
  async updatePassphrase(
    id: string,
    currentPassphrase: string,
    newPassphrase: string,
  ): Promise<void> {
    try {
      await MajikKeyStore.updatePassphrase(
        id,
        currentPassphrase,
        newPassphrase,
      );
    } catch (err) {
      this._emit("error", err, { context: "updatePassphrase", id });
      throw err;
    }
  }

  /**
   * Check whether an account has signing keys (Ed25519 + ML-DSA-87).
   * Accounts created before the signing key upgrade need to be re-imported
   * via importAccountFromMnemonicBackup() to gain signing capability.
   */
  accountHasSigningKeys(id: string): boolean {
    const key = MajikKeyStore.get(id);
    return key?.hasSigningKeys ?? false;
  }

  /**
   * Load all accounts persisted in MajikKeyStore into this instance.
   * Call this on startup to hydrate from IDB.
   */
  async loadAccountsFromStore(): Promise<void> {
    try {
      const keys = await MajikKeyStore.loadAll();
      for (const key of keys) {
        if (!this._ownAccounts.has(key.id)) {
          const contact = MajikContact.fromJSON(await key.toContact().toJSON());
          this._registerOwnAccount(contact);
        }
      }
    } catch (err) {
      this._emit("error", err, { context: "loadAccountsFromStore" });
      throw err;
    }
  }

  // ── Contact Management ────────────────────────────────────────────────────

  // ── Contact Management ────────────────────────────────────────────────────

  getContactByID(id: string): MajikContact | null {
    if (!id?.trim()) throw new Error("Invalid contact ID");
    return this._contactDirectory.getContact(id) ?? null;
  }

  async getContactByPublicKey(
    publicKeyBase64: string,
  ): Promise<MajikContact | null> {
    if (!publicKeyBase64?.trim()) throw new Error("Invalid public key");
    return (
      (await this._contactDirectory.getContactByPublicKeyBase64(
        publicKeyBase64,
      )) ?? null
    );
  }

  async exportContactAsJSON(contactId: string): Promise<string | null> {
    const contact = this._contactDirectory.getContact(contactId);
    if (!contact) return null;

    let publicKeyBase64: string;
    const anyPub: any = contact.publicKey;
    if (anyPub?.raw instanceof Uint8Array) {
      publicKeyBase64 = arrayBufferToBase64(anyPub.raw.buffer);
    } else {
      const raw = await crypto.subtle.exportKey(
        "raw",
        contact.publicKey as CryptoKey,
      );
      publicKeyBase64 = arrayBufferToBase64(raw);
    }

    return JSON.stringify(
      {
        id: contact.id,
        label: contact.meta?.label || "",
        publicKey: publicKeyBase64,
        fingerprint: contact.fingerprint,
        mlKey: contact.mlKey,
      } satisfies MajikContactCard,
      null,
      2,
    );
  }

  async exportContactAsString(contactId: string): Promise<string | null> {
    const contact = this._contactDirectory.getContact(contactId);
    if (!contact) return null;

    const compressedString = this.exportContactCompressed(contact);
    return compressedString;
  }

  async importContactFromJSON(jsonStr: string): Promise<MAJIK_API_RESPONSE> {
    try {
      const data: MajikContactCard = JSON.parse(jsonStr);
      if (!data.id || !data.publicKey || !data.fingerprint) {
        return { success: false, message: "Invalid contact JSON" };
      }

      const rawBuffer = base64ToArrayBuffer(data.publicKey as string);
      let publicKey: CryptoKey | { raw: Uint8Array };
      try {
        publicKey = await crypto.subtle.importKey(
          "raw",
          rawBuffer,
          KEY_ALGO,
          true,
          [],
        );
      } catch {
        publicKey = { raw: new Uint8Array(rawBuffer) };
      }

      this.addContact(
        new MajikContact({
          id: data.id,
          publicKey,
          fingerprint: data.fingerprint,
          meta: { label: data.label },
          mlKey: data.mlKey,
        }),
      );

      return { success: true, message: "Contact imported successfully" };
    } catch (err) {
      return {
        success: false,
        message: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  async importContactFromString(
    base64Str: string,
  ): Promise<MAJIK_API_RESPONSE> {
    try {
      const parsedContact = await this.importContactCompressed(base64Str);

      this.addContact(parsedContact);
      return { success: true, message: "Contact imported successfully" };
    } catch (err) {
      return {
        success: false,
        message: err instanceof Error ? err.message : "Unknown error",
      };
    }
  }

  async exportContactCompressed(contact: MajikContact): Promise<string> {
    // Prepare JSON with raw keys
    let publicKeyBase64: string;
    const anyPub: any = contact.publicKey;
    if (anyPub?.raw instanceof Uint8Array) {
      publicKeyBase64 = arrayBufferToBase64(anyPub.raw.buffer);
    } else {
      const raw = await crypto.subtle.exportKey(
        "raw",
        contact.publicKey as CryptoKey,
      );
      publicKeyBase64 = arrayBufferToBase64(raw);
    }

    const jsonObj: MajikContactCard = {
      id: contact.id,
      label: contact.meta?.label || "",
      publicKey: publicKeyBase64,
      fingerprint: contact.fingerprint,
      mlKey: contact.mlKey,
    };

    const jsonStr = JSON.stringify(jsonObj);

    const utf8 = new TextEncoder().encode(jsonStr);

    // Compress with gzip or Brotli
    const compressed = gzipSync(utf8);

    // Encode for string export
    return arrayToBase64(compressed);
  }

  async importContactCompressed(base64Str: string): Promise<MajikContact> {
    const compressed = base64ToArrayBuffer(base64Str);
    const decompressed = gunzipSync(new Uint8Array(compressed));
    const jsonStr = new TextDecoder().decode(decompressed);

    const data: any = JSON.parse(jsonStr);

    const rawBuffer = base64ToArrayBuffer(data.publicKey as string);
    let publicKey: CryptoKey | { raw: Uint8Array };
    try {
      publicKey = await crypto.subtle.importKey(
        "raw",
        rawBuffer,
        KEY_ALGO,
        true,
        [],
      );
    } catch {
      publicKey = { raw: new Uint8Array(rawBuffer) };
    }

    return new MajikContact({
      id: data.id,
      publicKey,
      fingerprint: data.fingerprint,
      meta: { label: data.label },
      mlKey: data.mlKey,
    });
  }

  addContact(contact: MajikContact): void {
    this._contactDirectory.addContact(contact);
    this._emit("new-contact", contact);
    this.scheduleAutosave();
  }

  removeContact(id: string): void {
    const result = this._contactDirectory.removeContact(id);
    if (!result.success) throw new Error(result.message);
    this._emit("removed-contact", id);
    this.scheduleAutosave();
  }

  getContactById(id: string): MajikContact | null {
    return this._contactDirectory.getContact(id) ?? null;
  }

  listContacts(includeOwnAccounts = false): MajikContact[] {
    const contacts = this._contactDirectory.listContacts(true);
    if (includeOwnAccounts) return contacts;
    const ownIds = new Set(this.listOwnAccounts().map((a) => a.id));
    return contacts.filter((c) => !ownIds.has(c.id));
  }

  updateContactMeta(id: string, meta: Partial<MajikContactMeta>): void {
    this._contactDirectory.updateContactMeta(id, meta);
  }

  /**
   * Resolve a human-readable label for a signer ID.
   * Checks own accounts first, then the contact directory.
   * Returns the fingerprint truncated to 16 chars if no label is found.
   */
  resolveSignerLabel(signerId: string): string {
    // Check own accounts
    const ownAccount = this._ownAccounts.get(signerId);
    if (ownAccount?.meta?.label) return ownAccount.meta.label;

    // Check contact directory
    const contact = this._contactDirectory.getContact(signerId);
    if (contact?.meta?.label) return contact.meta.label;

    // Fallback to truncated fingerprint
    return `${signerId.slice(0, 16)}…`;
  }

  // ── Signing ───────────────────────────────────────────────────────────────

  /**
   * Sign content with the active account.
   *
   * The active account must be unlocked and have signing keys.
   * Use unlockAccount() first if needed.
   *
   * @param content     - Raw bytes or UTF-8 string to sign
   * @param options     - Optional content type and timestamp override
   * @param accountId   - Override which account signs. Defaults to active account.
   */
  async sign(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<SignResult> {
    try {
      const id = accountId ?? this.getActiveAccount()?.id;
      if (!id)
        throw new Error("No active account — call setActiveAccount() first");

      const key = MajikKeyStore.get(id);
      if (!key) throw new Error(`Account not found in keystore: "${id}"`);

      if (key.isLocked) {
        throw new Error(
          `Account "${id}" is locked. Call unlockAccount() before signing.`,
        );
      }

      if (!key.hasSigningKeys) {
        throw new Error(
          `Account "${id}" has no signing keys. ` +
            `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
        );
      }

      const signature = await MajikSignature.sign(content, key, options);

      const result: SignResult = {
        signature,
        signerId: signature.signerId,
        contentHash: signature.contentHash,
        timestamp: signature.timestamp,
        contentType: signature.contentType,
      };

      this._emit("sign", result);
      return result;
    } catch (err) {
      this._emit("error", err, { context: "sign" });
      throw err;
    }
  }

  /**
   * Sign content and immediately serialize to a base64 string.
   * Convenience wrapper around sign() + serialize().
   */
  async signAndSerialize(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<string> {
    const { signature } = await this.sign(content, options, accountId);
    return signature.serialize();
  }

  /**
   * Sign content and return the full JSON envelope.
   * Convenience wrapper around sign() + toJSON().
   */
  async signToJSON(
    content: Uint8Array | string,
    options?: SignOptions,
    accountId?: string,
  ): Promise<MajikSignatureJSON> {
    const { signature } = await this.sign(content, options, accountId);
    return signature.toJSON();
  }

  // ── Verification ──────────────────────────────────────────────────────────

  /**
   * Verify a signature against content.
   *
   * Public keys can be supplied directly, extracted from the envelope itself,
   * or resolved from a known MajikKey account or contact in the directory.
   *
   * No private key is needed. Safe to call on locked accounts.
   *
   * @param content     - The original content that was signed
   * @param signature   - MajikSignature instance, JSON object, or base64 string
   * @param publicKeys  - Optional. If omitted, public keys are extracted from
   *                      the envelope (self-reported — cross-check signerId
   *                      against a trusted source for full security).
   */
  verify(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    publicKeys?: MajikSignerPublicKeys,
  ): VerifyResult {
    try {
      // Deserialize if base64 string
      const sig =
        typeof signature === "string"
          ? MajikSignature.deserialize(signature)
          : signature instanceof MajikSignature
            ? signature
            : MajikSignature.fromJSON(signature);

      // Resolve public keys
      const keys: MajikSignerPublicKeys =
        publicKeys ??
        (sig instanceof MajikSignature
          ? sig.extractPublicKeys()
          : MajikSignature.fromJSON(
              sig as MajikSignatureJSON,
            ).extractPublicKeys());

      const result = MajikSignature.verify(content, sig, keys);

      const verifyResult: VerifyResult = {
        ...result,
        signerLabel: result.signerId?.trim()
          ? this.resolveSignerLabel(result.signerId)
          : undefined,
      };

      this._emit("verify", verifyResult);
      return verifyResult;
    } catch (err) {
      this._emit("error", err, { context: "verify" });
      throw err;
    }
  }

  /**
   * Verify against a specific known MajikKey account.
   * Automatically extracts public keys from the key client.
   * Works on locked accounts — only public key fields are used.
   */
  verifyWithAccount(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    accountId: string,
  ): VerifyResult {
    const key = MajikKeyStore.get(accountId);
    if (!key) throw new Error(`Account not found: "${accountId}"`);

    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${accountId}" has no signing public keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable verification.`,
      );
    }

    const publicKeys = MajikSignature.publicKeysFromMajikKey(key);
    return this.verify(content, signature, publicKeys);
  }

  /**
   * Verify against a contact from the directory by their ID.
   * Useful when you have the signer's contact card stored locally.
   */
  async verifyWithContact(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    contactId: string,
  ): Promise<VerifyResult> {
    const contact = this._contactDirectory.getContact(contactId);
    if (!contact) throw new Error(`Contact not found: "${contactId}"`);

    const sig =
      typeof signature === "string"
        ? MajikSignature.deserialize(signature)
        : signature instanceof MajikSignature
          ? signature
          : MajikSignature.fromJSON(signature as MajikSignatureJSON);

    // Cross-check: the envelope's signerId must match the contact's fingerprint
    const envelopeSignerId =
      sig instanceof MajikSignature
        ? sig.signerId
        : (sig as MajikSignatureJSON).signerId;

    if (envelopeSignerId !== contact.fingerprint) {
      const result: VerifyResult = {
        valid: false,
        signerId: envelopeSignerId,
        contentHash:
          sig instanceof MajikSignature
            ? sig.contentHash
            : (sig as MajikSignatureJSON).contentHash,
        timestamp:
          sig instanceof MajikSignature
            ? sig.timestamp
            : (sig as MajikSignatureJSON).timestamp,
        signerLabel: this.resolveSignerLabel(envelopeSignerId),
      };
      this._emit("verify", result);
      return result;
    }

    const edPublicKeyBase64 =
      sig instanceof MajikSignature
        ? sig.signerEdPublicKey
        : (sig as MajikSignatureJSON).signerEdPublicKey;

    const mlDsaPublicKeyBase64 =
      sig instanceof MajikSignature
        ? sig.signerMlDsaPublicKey
        : (sig as MajikSignatureJSON).signerMlDsaPublicKey;

    const publicKeys: MajikSignerPublicKeys = {
      signerId: contact.fingerprint,
      edPublicKey: base64ToUint8Array(edPublicKeyBase64),
      mlDsaPublicKey: base64ToUint8Array(mlDsaPublicKeyBase64),
    };

    return this.verify(content, sig, publicKeys);
  }

  /**
   * Batch verify multiple signatures against the same content.
   * Returns one VerifyResult per signature in the same order.
   */
  verifyBatch(
    content: Uint8Array | string,
    signatures: Array<MajikSignature | MajikSignatureJSON | string>,
    publicKeys?: MajikSignerPublicKeys,
  ): VerifyResult[] {
    return signatures.map((sig) => {
      try {
        return this.verify(content, sig, publicKeys);
      } catch (err) {
        this._emit("error", err, { context: "verifyBatch" });
        return {
          valid: false,
          signerId: "",
          contentHash: "",
          timestamp: "",
          signerLabel: undefined,
        };
      }
    });
  }

  // ── Text / Detached Signing ───────────────────────────────────────────────────

  /**
   * Convenience alias for signing a plain string.
   *
   * Identical to signContent() but accepts only strings — makes call-sites
   * that deal exclusively with text cleaner (no Uint8Array overload noise).
   *
   * @example
   *   const sig = await majik.signText("Hello world", { contentType: "text/plain" });
   *   const b64 = sig.serialize(); // store alongside the text
   */
  async signText(
    text: string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
    },
  ): Promise<MajikSignature> {
    if (!text?.trim())
      throw new Error("signText: text must be a non-empty string");
    return this.signContent(text, options);
  }

  /**
   * Sign content and return both the MajikSignature instance and a portable
   * base64-serialized string in one call.
   *
   * The serialized string is safe to store in a database column, embed in a
   * JSON field, pass in an HTTP header, or encode in a QR code alongside the
   * original content. Pass it back to verifyDetached() to verify.
   *
   * @example — sign a document and store the detached signature
   *   const { serialized } = await majik.signAndDetach(docBytes, {
   *     contentType: "application/pdf",
   *   });
   *   await db.insert({ doc_id, signature: serialized });
   *
   * @example — sign a text message
   *   const { signature, serialized } = await majik.signAndDetach("Hello!", {
   *     contentType: "text/plain",
   *   });
   */
  async signAndDetach(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
    },
  ): Promise<{ signature: MajikSignature; serialized: string }> {
    const signature = await this.signContent(content, options);
    return { signature, serialized: signature.serialize() };
  }

  // ── Text / Detached Verification ──────────────────────────────────────────────

  /**
   * Verify a plain string against a MajikSignature.
   *
   * Accepts the signature as a MajikSignature instance, a MajikSignatureJSON
   * object, or a base64-serialized string — whichever form is easiest at the
   * call-site.
   *
   * The signer can be identified by contact ID, raw public key base64, or a
   * MajikKey client. If none is provided the public keys embedded in the
   * signature envelope are used (self-reported — cross-check result.signerId
   * against a known contact fingerprint before trusting).
   *
   * @example
   *   const result = await majik.verifyText("Hello world", sig, {
   *     contactId: "contact_abc",
   *   });
   *   if (result.valid) console.log("Authentic");
   */
  async verifyText(
    text: string,
    signature: MajikSignature | MajikSignatureJSON | string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
  ): Promise<VerificationResult> {
    if (!text?.trim())
      throw new Error("verifyText: text must be a non-empty string");

    const sig =
      typeof signature === "string"
        ? MajikSignature.deserialize(signature)
        : signature;

    return this.verifyContent(text, sig, options);
  }

  /**
   * Verify content against a base64-serialized detached signature string.
   *
   * This is the pair to signAndDetach() — designed for call-sites that retrieve
   * a stored base64 signature from a database or API and want to verify without
   * importing MajikSignature themselves.
   *
   * The signer can be identified by contact ID, raw public key base64, or a
   * MajikKey. If none is provided, self-reported keys from the envelope are used
   * (see security note on verifyContent).
   *
   * @example
   *   const row = await db.findOne({ doc_id });
   *   const result = await majik.verifyDetached(docBytes, row.signature, {
   *     contactId: row.signer_contact_id,
   *   });
   *   if (result.valid) console.log("Signed by", result.signerId);
   */
  async verifyDetached(
    content: Uint8Array | string,
    serializedSignature: string,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
  ): Promise<VerificationResult> {
    if (!serializedSignature?.trim()) {
      throw new Error(
        "verifyDetached: serializedSignature must be a non-empty string",
      );
    }

    let sig: MajikSignature;
    try {
      sig = MajikSignature.deserialize(serializedSignature);
    } catch {
      // Fallback: maybe caller passed raw JSON rather than base64
      try {
        sig = MajikSignature.fromJSON(serializedSignature);
      } catch {
        throw new Error(
          "verifyDetached: could not parse signature — expected a base64 " +
            "string from sig.serialize() or a JSON string from sig.toJSON()",
        );
      }
    }

    return this.verifyContent(content, sig, options);
  }

  // ── Signature Serialization Helpers ──────────────────────────────────────────

  /**
   * Deserialize a base64 signature string into a MajikSignature client.
   *
   * Round-trip partner for MajikSignature.serialize() / sig.toString().
   * Use when you have a stored base64 string and need to inspect or pass
   * the instance to another method.
   *
   * Throws MajikSignatureSerializationError on malformed input.
   *
   * @example
   *   const sig = majik.deserializeSignature(storedBase64);
   *   console.log(sig.signerId, sig.timestamp);
   */
  deserializeSignature(serialized: string): MajikSignature {
    if (!serialized?.trim()) {
      throw new Error("deserializeSignature: input must be a non-empty string");
    }
    return MajikSignature.deserialize(serialized);
  }

  /**
   * Extract lightweight metadata from a base64 or JSON signature string
   * without performing cryptographic verification.
   *
   * Useful for displaying "Signed by X at Y" in a UI before the user
   * explicitly triggers a verification step.
   *
   * Returns null if the string cannot be parsed as a MajikSignature.
   *
   * @example
   *   const meta = majik.getSignatureMetadata(storedSig);
   *   if (meta) {
   *     const contact = majik.getContactByID(meta.signerId);
   *     console.log(`Signed by ${contact?.meta?.label ?? meta.signerId} at ${meta.timestamp}`);
   *   }
   */
  getSignatureMetadata(serialized: string): {
    signerId: string;
    timestamp: string;
    contentType: string | undefined;
    contentHash: string;
    version: number;
  } | null {
    if (!serialized?.trim()) return null;

    try {
      let sig: MajikSignature;
      try {
        sig = MajikSignature.deserialize(serialized);
      } catch {
        sig = MajikSignature.fromJSON(serialized);
      }

      return {
        signerId: sig.signerId,
        timestamp: sig.timestamp,
        contentType: sig.contentType,
        contentHash: sig.contentHash,
        version: sig.version,
      };
    } catch {
      return null;
    }
  }

  // ── Signing Capability Guard ──────────────────────────────────────────────────

  /**
   * Check whether an account has signing keys without throwing.
   *
   * Use this as a fast boolean guard before showing signing UI or before
   * calling any sign* method — those methods throw if signing keys are absent,
   * so checking first lets you degrade gracefully (e.g. hide a "Sign" button).
   *
   * Checks the in-memory keystore cache only — the account must be loaded.
   * Returns false for unknown accounts rather than throwing.
   *
   * @example
   *   if (!majik.hasSigningCapability()) {
   *     showUpgradePrompt("Re-import your account to enable signing");
   *     return;
   *   }
   *   const sig = await majik.signText(message);
   */
  hasSigningCapability(accountId?: string): boolean {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id) return false;
    const key = MajikKeyStore.get(id);
    return key?.hasSigningKeys === true;
  }

  // ── Content & File Signing ────────────────────────────────────────────────

  /**
   * Sign raw bytes or a string using the active account.
   *
   * The active account is unlocked automatically if needed.
   * This is the MajikMessage equivalent of MajikSignature.sign() — it resolves
   * the signing key from the keystore so you don't have to manage it yourself.
   *
   * @example
   *   const sig = await majik.signContent(documentBytes, { contentType: "application/pdf" });
   *   const b64 = sig.serialize(); // store alongside the document
   */
  async signContent(
    content: Uint8Array | string,
    options?: {
      contentType?: string;
      timestamp?: string;
      accountId?: string;
    },
  ): Promise<MajikSignature> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    try {
      await MajikKeyStore.ensureUnlocked(id);
      const key = MajikKeyStore.get(id);
      if (!key) throw new Error(`Account not found in keystore: "${id}"`);
      if (!key.hasSigningKeys) {
        throw new Error(
          `Account "${id}" has no signing keys. ` +
            `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
        );
      }

      return MajikSignature.sign(content, key, {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
      });
    } catch (err) {
      this._emit("error", err, { context: "signContent" });
      throw err;
    }
  }

  /**
   * Sign a file and embed the signature directly into it using the active account.
   *
   * Format is auto-detected from magic bytes — PDF stays PDF, WAV stays WAV, etc.
   * Strips any existing signature before signing (idempotent re-signing).
   * The active account is unlocked automatically if needed.
   *
   * @example
   *   const { blob: signedPdf } = await majik.signFile(pdfBlob);
   *   // signedPdf is a valid PDF with the signature embedded in its metadata
   *
   * @example — non-active account
   *   const { blob } = await majik.signFile(wavBlob, { accountId: "acc_xyz" });
   */
  async signFile(
    file: Blob,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
    },
  ): Promise<{
    blob: Blob;
    signature: MajikSignature;
    handler: string;
    mimeType: string;
  }> {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    try {
      await MajikKeyStore.ensureUnlocked(id);
      const key = MajikKeyStore.get(id);
      if (!key) throw new Error(`Account not found in keystore: "${id}"`);
      if (!key.hasSigningKeys) {
        throw new Error(
          `Account "${id}" has no signing keys. ` +
            `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
        );
      }

      return MajikSignature.signFile(file, key, {
        contentType: options?.contentType,
        timestamp: options?.timestamp,
        mimeType: options?.mimeType,
      });
    } catch (err) {
      this._emit("error", err, { context: "signFile" });
      throw err;
    }
  }

  /**
   * Sign multiple file blobs with the active (or specified) account in one call.
   *
   * Each file is signed independently — a failure on one does not abort the
   * others. Check result.error on each item to handle partial failures.
   *
   * The hasSigningKeys check is done once upfront before any signing begins,
   * so the whole batch fails fast if the account can't sign rather than
   * discovering it mid-batch.
   *
   * @example
   *   const results = await majik.batchSignFiles([
   *     { file: pdfBlob, contentType: "application/pdf" },
   *     { file: wavBlob, contentType: "audio/wav" },
   *     { file: mp4Blob, contentType: "video/mp4" },
   *   ]);
   *   for (const r of results) {
   *     if (r.error) console.error("Failed:", r.error.message);
   *     else await r2.put(key, await r.blob!.arrayBuffer());
   *   }
   */
  async batchSignFiles(
    files: Array<{
      file: Blob;
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
    }>,
    options?: { accountId?: string },
  ): Promise<
    Array<{
      blob: Blob | null;
      signature: MajikSignature | null;
      serialized: string | null;
      handler: string | null;
      mimeType: string | null;
      error: Error | null;
    }>
  > {
    const id = options?.accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    await MajikKeyStore.ensureUnlocked(id);
    const key = MajikKeyStore.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${id}" has no signing keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
      );
    }

    return Promise.all(
      files.map(async ({ file, contentType, timestamp, mimeType }) => {
        try {
          const result = await MajikSignature.signFile(file, key, {
            contentType,
            timestamp,
            mimeType,
          });
          return {
            blob: result.blob,
            signature: result.signature,
            serialized: result.signature.serialize(),
            handler: result.handler,
            mimeType: result.mimeType,
            error: null,
          };
        } catch (err) {
          this._emit("error", err, { context: "batchSignFiles" });
          return {
            blob: null,
            signature: null,
            serialized: null,
            handler: null,
            mimeType: null,
            error: err instanceof Error ? err : new Error(String(err)),
          };
        }
      }),
    );
  }

  // ── Verification ──────────────────────────────────────────────────────────

  /**
   * Verify raw bytes or a string against a MajikSignature.
   *
   * The signer can be identified by:
   *   - A contact ID from the contact directory
   *   - A raw base64 public key string (same format used in contacts)
   *   - A MajikKey instance directly
   *
   * If no signer is provided, the public keys embedded in the signature
   * envelope are used (self-reported — see security note below).
   *
   * > ⚠️ When no signer is provided, the extracted public keys are self-reported
   * > by whoever created the signature. Always cross-check `result.signerId`
   * > against a known contact fingerprint before trusting the result.
   *
   * @example — verify against a known contact
   *   const result = await majik.verifyContent(docBytes, sig, { contactId: "contact_abc" });
   *   if (result.valid) console.log("Authentic, signed by:", result.signerId);
   *
   * @example — verify using embedded keys (self-reported)
   *   const result = await majik.verifyContent(docBytes, sig);
   *   // always check result.signerId matches a known fingerprint
   */
  async verifyContent(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
  ): Promise<VerificationResult> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);

      if (publicKeys) {
        return MajikSignature.verify(content, signature, publicKeys);
      }

      // No signer provided — extract keys from envelope (self-reported)
      const sig =
        signature instanceof MajikSignature
          ? signature
          : MajikSignature.fromJSON(signature);

      return MajikSignature.verify(content, sig, sig.extractPublicKeys());
    } catch (err) {
      this._emit("error", err, { context: "verifyContent" });
      throw err;
    }
  }

  /**
   * Verify a file's embedded signature.
   *
   * The signer can be identified by:
   *   - A contact ID from the contact directory
   *   - A raw base64 public key string
   *   - A MajikKey instance directly
   *
   * If no signer is provided, the public keys embedded in the signature
   * envelope are used (self-reported — see security note on verifyContent).
   *
   * @example — verify a signed PDF against a known contact
   *   const result = await majik.verifyFile(signedPdf, { contactId: "contact_abc" });
   *   if (result.valid) console.log("Verified:", result.signerId, result.timestamp);
   *
   * @example — check own signed file using active account
   *   const result = await majik.verifyFile(signedWav, {
   *     contactId: majik.getActiveAccount()?.id,
   *   });
   */
  async verifyFile(
    file: Blob,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
      mimeType?: string;
    },
  ): Promise<VerificationResult & { handler?: string; reason?: string }> {
    try {
      const publicKeys = await this._resolveSignerPublicKeys(options);

      if (publicKeys) {
        const results = await MajikSignature.verifyFile(
          file,
          publicKeys,
          {
            expectedSignerId: options?.expectedSignerId,
            mimeType: options?.mimeType,
          },
          true,
        );
        return results[0];
      }

      // No signer provided — extract and use self-reported keys from first signature.
      // For full multi-sig verification, pass a contactId or publicKeyBase64.
      const extracted = await MajikSignature.extractFrom(file, {
        mimeType: options?.mimeType,
      });
      if (!extracted.length) {
        return {
          valid: false,
          signerId: "",
          contentHash: "",
          timestamp: new Date().toISOString(),
          reason: "No embedded signature found",
        };
      }

      const firstSig = extracted[0];
      const results = await MajikSignature.verifyFile(
        file,
        firstSig.extractPublicKeys(),
        {
          expectedSignerId: firstSig.signerId,
          mimeType: options?.mimeType,
        },
        true,
      );
      return results[0];
    } catch (err) {
      this._emit("error", err, { context: "verifyFile" });
      throw err;
    }
  }

  /**
   * Verify multiple files' embedded signatures against the same signer in
   * one call.
   *
   * Each file is verified independently — a failed verification sets
   * result.valid = false and populates result.error, it does not throw.
   *
   * @example
   *   const results = await majik.batchVerifyFiles(
   *     [pdfBlob, wavBlob, mp4Blob],
   *     { contactId: "contact_abc" },
   *   );
   *   const allValid = results.every(r => r.valid);
   */
  async batchVerifyFiles(
    files: Array<
      Blob | { file: Blob; mimeType?: string; expectedSignerId?: string }
    >,
    options?: {
      contactId?: string;
      publicKeyBase64?: string;
      key?: MajikKey;
      expectedSignerId?: string;
    },
  ): Promise<
    Array<
      VerificationResult & {
        handler: string | undefined; // aligned with VerificationResult.handler
        mimeType: string | undefined;
        error: Error | null;
      }
    >
  > {
    // Resolve public keys once — reused across all files in the batch
    const publicKeys = await this._resolveSignerPublicKeys(options).catch(
      () => null,
    );

    return Promise.all(
      files.map(async (entry) => {
        const { file, mimeType, expectedSignerId } =
          entry instanceof Blob
            ? {
                file: entry,
                mimeType: undefined,
                expectedSignerId: options?.expectedSignerId,
              }
            : {
                ...entry,
                expectedSignerId:
                  entry.expectedSignerId ?? options?.expectedSignerId,
              };

        try {
          let result: VerificationResult;

          if (publicKeys) {
            const results = await MajikSignature.verifyFile(file, publicKeys, {
              mimeType,
              expectedSignerId,
            });
            result = results[0];
          } else {
            const extracted = await MajikSignature.extractFrom(file, {
              mimeType,
            });
            if (!extracted.length) {
              return {
                valid: false,
                signerId: undefined,
                contentHash: undefined,
                timestamp: new Date().toISOString(),
                reason: "No embedded signature found",
                handler: undefined,
                mimeType,
                error: null,
              };
            }

            const firstSig = extracted[0];
            const results = await MajikSignature.verifyFile(
              file,
              firstSig.extractPublicKeys(),
              { mimeType, expectedSignerId: firstSig.signerId },
            );
            result = results[0];
          }

          return {
            ...result,
            handler: result.handler,
            mimeType,
            error: null,
          };
        } catch (err) {
          this._emit("error", err, { context: "batchVerifyFiles" });
          return {
            valid: false,
            signerId: undefined,
            contentHash: undefined,
            timestamp: new Date().toISOString(),
            handler: undefined,
            mimeType,
            error: err instanceof Error ? err : new Error(String(err)),
          };
        }
      }),
    );
  }

  // ── Signature Utilities ───────────────────────────────────────────────────

  /**
   * Extract the embedded MajikSignature from a file.
   * Returns an array of typed MajikSignature instance, or empty if not found.
   *
   * Does not verify — use verifyFile() to verify.
   *
   * @example
   *   const sig = await majik.extractSignature(file);
   *   if (sig) console.log("Signed by:", sig.signerId, "at", sig.timestamp);
   */
  async extractSignature(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<MajikSignature[] | null> {
    try {
      return MajikSignature.extractFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "extractSignature" });
      throw err;
    }
  }

  /**
   * Return a clean copy of the file with any embedded signature removed.
   * The returned bytes are exactly what was originally signed.
   *
   * Useful before re-processing or re-encrypting a signed file.
   *
   * @example
   *   const originalBlob = await majik.stripSignature(signedMp4);
   */
  async stripSignature(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<Blob> {
    try {
      return MajikSignature.stripFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "stripSignature" });
      throw err;
    }
  }

  /**
   * Check whether a file contains an embedded MajikSignature.
   * Does not verify — purely a structural presence check.
   *
   * @example
   *   if (await majik.isFileSigned(file)) {
   *     const result = await majik.verifyFile(file, { contactId });
   *   }
   */
  async isFileSigned(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<boolean> {
    try {
      return MajikSignature.isSigned(file, options);
    } catch (err) {
      this._emit("error", err, { context: "isFileSigned" });
      throw err;
    }
  }

  /**
   * Get the public keys for the active account, ready for use with
   * MajikSignature.verify() or for sharing with another party.
   *
   * Works on locked keys — only reads public fields.
   *
   * @example
   *   const myKeys = await majik.getSigningPublicKeys();
   *   // share myKeys with someone so they can verify your signatures
   */
  async getSigningPublicKeys(
    accountId?: string,
  ): Promise<MajikSignerPublicKeys> {
    const id = accountId ?? this.getActiveAccount()?.id;
    if (!id)
      throw new Error("No active account — call setActiveAccount() first");

    const key = MajikKeyStore.get(id);
    if (!key) throw new Error(`Account not found in keystore: "${id}"`);
    if (!key.hasSigningKeys) {
      throw new Error(
        `Account "${id}" has no signing keys. ` +
          `Re-import via importAccountFromMnemonicBackup() to enable signing.`,
      );
    }

    return MajikSignature.publicKeysFromMajikKey(key);
  }

  /**
   * Re-sign a file blob — strips any existing embedded signature, signs
   * with the active (or specified) account, and returns the newly signed blob.
   *
   * Use after key rotation or when the signing account changes. The returned
   * blob is the same format as the input — PDF stays PDF, WAV stays WAV.
   *
   * Distinct from resignMajikFile() which operates on a MajikFile instance
   * (the encrypted .mjkb container). This operates on a plain file Blob.
   *
   * @example
   *   const { blob } = await majik.resignFile(oldSignedPdf);
   *   await r2.put(key, await blob.arrayBuffer());
   */
  async resignFile(
    file: Blob,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      accountId?: string;
    },
  ): Promise<{
    blob: Blob;
    signature: MajikSignature;
    handler: string;
    mimeType: string;
  }> {
    // signFile already strips before signing — resignFile is a named alias
    // that makes the caller's intent explicit at the call-site.
    return this.signFile(file, options);
  }

  /**
   * Extract metadata from a file's embedded signature without verifying it.
   *
   * Useful for rendering "Signed by X at Y" in a UI before the user
   * explicitly triggers a verify step, or for routing to the correct
   * contact record before calling verifyFile().
   *
   * Returns null if the file has no embedded signature or the JSON is
   * structurally malformed.
   *
   * @example
   *   const info = await majik.getFileSignatureInfo(pdfBlob);
   *   if (info) {
   *     const contact = majik.getContactByID(info.signerId);
   *     console.log(`Signed by ${contact?.meta?.label ?? info.signerId}`);
   *     console.log(`Format handled by: ${info.handler}`);
   *   }
   */
  async getFileSignatureInfo(
    file: Blob,
    options?: { mimeType?: string },
  ): Promise<MajikSignature[] | null> {
    try {
      return MajikSignature.extractFrom(file, options);
    } catch (err) {
      this._emit("error", err, { context: "getFileSignatureInfo" });
      throw err;
    }
  }

  // ── STAMP (compression-resistant image signing) ───────────────────────────
  //
  // These methods delegate to MajikImageSignature, passing `MajikSignature`
  // itself as the adapter — the same pattern used by signFile → MajikSignatureEmbed.
  //
  // The adapter is typed as MajikSignatureStaticAdapter (an interface defined
  // in core/stamp/image-signature.ts) so no circular import is introduced:
  //
  //   majik-signature → core/stamp/image-signature → (adapter interface only)
  //
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * Sign an image with dual-layer embedding.
   *
   * Every signed image carries two independent proofs:
   *
   *   Layer 1 — Pixel rows appended at the bottom (+~6px height)
   *     Full MajikSignature: Ed25519 + ML-DSA-87 (post-quantum)
   *     Survives: direct sharing, email attachments, Slack, internal tools
   *     Stripped by: platforms that crop/resize (Gmail, LinkedIn, Facebook)
   *
   *   Layer 2 — DCT coefficient steganography (invisible, no size change)
   *     Ed25519-only stub + Reed-Solomon ECC (205 bytes)
   *     Survives: Q70+ JPEG recompression, WebP conversion, platform uploads
   *     Does not survive: screenshots, heavy crop, below-Q70 recompression
   *
   * Output is PNG by default. When uploaded to a platform, Layer 1 may be
   * stripped but Layer 2 survives — verifyStamp() handles both automatically.
   *
   * Minimum image size: 600×600px (smaller images are padded with white).
   *
   * @param image    Any image format the browser supports (JPEG, PNG, WebP…)
   * @param key      Unlocked MajikKey with signing keys
   * @param options  Output MIME type, JPEG quality, timestamp override
   * @returns        blob (signed image), stub (DCT layer metadata),
   *                 fullEnvelope (complete MajikSignatureJSON for Layer 1)
   *
   * @example
   *   const { blob, stub } = await MajikSignature.stampImage(imageBlob, key);
   *   // blob  → upload or attach; visually identical to the original
   *   // stub  → signerId, timestamp, pHash for display
   */
  static async stampImage(
    image: Blob,
    key: MajikKey,
    options?: ImageSignOptions,
  ): Promise<{
    blob: Blob;
    stub: ImageSignatureStub;
    fullEnvelope: MajikSignatureJSON;
  }> {
    return MajikSignature.stampImage(image, key, options);
  }

  /**
   * Verify a stamped image's embedded MajikImageSignature.
   *
   * Tries both layers automatically:
   *   - Both present → both must pass (maximum integrity, post-quantum proof)
   *   - Pixel row only → pixel row must pass (full Ed25519 + ML-DSA-87)
   *   - DCT only → DCT must pass (Ed25519 fallback, typical after platform upload)
   *   - Neither → invalid
   *
   * The `layer` field in the result communicates the trust level so callers
   * can surface it in UI: 'both' > 'pixel-row' > 'dct-only'.
   *
   * @param image    The image to verify — may be platform-compressed
   * @param options  hammingThreshold override (default 8 — strict)
   *
   * @example
   *   const result = await MajikSignature.verifyStamp(imageBlob);
   *   if (result.valid) {
   *     console.log(`✓ Signed by ${result.signerId}`);
   *     console.log(`  Verified via: ${result.layer}`);
   *     // result.layer: 'both' | 'pixel-row' | 'dct-only'
   *   }
   */
  static async verifyStamp(
    image: Blob,
    options?: { hammingThreshold?: number },
  ): Promise<ImageVerificationResult> {
    return MajikSignature.verifyStamp(image, options);
  }

  /**
   * Inspect which stamp layers are present without verifying.
   *
   * Fast — useful for rendering a "Signed by X on Y" badge in a UI before
   * committing to a full cryptographic verify call.
   *
   * Does NOT confirm the signatures are valid — call verifyStamp() for that.
   *
   * @example
   *   const info = await MajikSignature.inspectStamp(imageBlob);
   *   if (info.hasPixelRow) console.log('Full post-quantum proof present');
   *   if (info.hasDct)      console.log('Compression-resistant stub present');
   *   info.dctMeta?.signerId        // signer ID (unverified — display only)
   *   info.pixelRowMeta?.timestamp  // timestamp (unverified — display only)
   */
  static async inspectStamp(image: Blob): Promise<{
    hasPixelRow: boolean;
    hasDct: boolean;
    pixelRowMeta?: { signerId: string; timestamp: string };
    dctMeta?: { signerId: string; timestamp: string; pHash: string };
  }> {
    return MajikSignature.inspectStamp(image);
  }

  /**
   * Returns true if the image contains any MajikImageSignature layer.
   *
   * Does not verify — structural presence check only.
   * Use verifyStamp() to confirm the signature is cryptographically valid.
   *
   * @example
   *   if (await MajikSignature.isStamped(imageBlob)) { ... }
   */
  static async isStamped(image: Blob): Promise<boolean> {
    return MajikSignature.isStamped(image);
  }

  // ── Identity / Passphrase ─────────────────────────────────────────────────

  /**
   * Ensure an identity is unlocked.
   * Delegates entirely to MajikKeyStore.ensureUnlocked() — passphrase prompting
   * is handled there via onUnlockRequested or the optional promptFn.
   */
  async ensureIdentityUnlocked(
    id: string,
    promptFn?: (id: string) => string | Promise<string>,
  ): Promise<CryptoKey | { raw: Uint8Array }> {
    return MajikKeyStore.ensureUnlocked(id, promptFn);
  }

  async isPassphraseValid(passphrase: string, id?: string): Promise<boolean> {
    const target = id ? this.getOwnAccountById(id) : this.getActiveAccount();
    if (!target) return false;
    return MajikKeyStore.isPassphraseValid(target.id, passphrase);
  }

  // ── Private: Signer resolution ────────────────────────────────────────────

  /**
   * Resolve MajikSignerPublicKeys from whichever signer hint was provided.
   * Returns null if no hint was given (caller should fall back to self-reported keys).
   *
   * Mirrors the _resolveRecipients / _resolveFileIdentity pattern used
   * throughout MajikMessage — consistent account/contact resolution in one place.
   */
  private async _resolveSignerPublicKeys(options?: {
    contactId?: string;
    publicKeyBase64?: string;
    key?: MajikKey;
    expectedSignerId?: string;
  }): Promise<MajikSignerPublicKeys | null> {
    if (!options) return null;

    // Option A: caller passed a MajikKey instance directly
    if (options.key) {
      return MajikSignature.publicKeysFromMajikKey(options.key);
    }

    // Option B: contact ID looked up from the contact directory
    if (options.contactId) {
      const contact = this._contactDirectory.getContact(options.contactId);
      if (!contact) {
        throw new Error(`No contact found for id "${options.contactId}"`);
      }

      // Own accounts are in the keystore — get their signing keys directly
      const ownAccount = this.getOwnAccountById(options.contactId);
      if (ownAccount) {
        const key = MajikKeyStore.get(options.contactId);
        if (key?.hasSigningKeys) {
          return MajikSignature.publicKeysFromMajikKey(key);
        }
      }

      // External contact — resolve from their contact card fields
      if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
        throw new Error(
          `Contact "${options.contactId}" has no signing public keys. ` +
            `They may need to share an updated contact card.`,
        );
      }

      return {
        signerId: contact.fingerprint,
        edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
        mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
      };
    }

    // Option C: raw base64 public key — look up via contact directory
    if (options.publicKeyBase64) {
      const contact = await this._contactDirectory.getContactByPublicKeyBase64(
        options.publicKeyBase64,
      );
      if (!contact) {
        throw new Error(
          `No contact found for public key "${options.publicKeyBase64}"`,
        );
      }

      if (!contact.edPublicKeyBase64 || !contact.mlDsaPublicKeyBase64) {
        throw new Error(
          `Contact for key "${options.publicKeyBase64}" has no signing public keys.`,
        );
      }

      return {
        signerId: contact.fingerprint,
        edPublicKey: base64ToUint8Array(contact.edPublicKeyBase64),
        mlDsaPublicKey: base64ToUint8Array(contact.mlDsaPublicKeyBase64),
      };
    }

    return null;
  }

  // ── Serialization ─────────────────────────────────────────────────────────

  async toJSON(): Promise<MajikUniversalIdClientJSON> {
    const accounts: SerializedMajikContact[] = [];
    for (const id of this._ownAccountsOrder) {
      const acct = this._ownAccounts.get(id);
      if (acct) accounts.push(await acct.toJSON());
    }

    return {
      id: this._id,
      contacts: await this._contactDirectory.toJSON(),
      ownAccounts: {
        accounts,
        order: [...this._ownAccountsOrder],
      },
    };
  }

  static async fromJSON<T extends MajikUniversalIdClient>(
    this: new (config: MajikUniversalIdClientConfig, id?: string) => T,
    json: MajikUniversalIdClientJSON,
    config: MajikUniversalIdClientConfig = {},
  ): Promise<T> {
    const directory = config.contactDirectory ?? new MajikContactDirectory();

    if (!config.contactDirectory) {
      await directory.fromJSON(json.contacts);
    }

    const client = new this({ contactDirectory: directory });

    try {
      if (json.ownAccounts && Array.isArray(json.ownAccounts.accounts)) {
        for (const acct of json.ownAccounts.accounts) {
          try {
            const raw = base64ToArrayBuffer((acct as any).publicKeyBase64);
            const publicKey = await crypto.subtle.importKey(
              "raw",
              raw,
              KEY_ALGO,
              true,
              [],
            );
            const contact = MajikContact.create(
              (acct as any).id,
              publicKey,
              (acct as any).fingerprint,
              (acct as any).meta,
            );
            client._ownAccounts.set(contact.id, contact);
          } catch (e) {
            console.info(
              "Fallback restoring own account (raw-key wrapper)",
              (acct as any).id,
              e,
            );
          }
        }

        if (Array.isArray(json.ownAccounts.order)) {
          client._ownAccountsOrder = [...json.ownAccounts.order];
        }

        // Fallback: populate from contactDirectory if accounts array failed
        if (client._ownAccounts.size === 0) {
          for (const id of client._ownAccountsOrder) {
            const c = client._contactDirectory.getContact(id);
            if (c) client._ownAccounts.set(id, c);
          }
        }

        // Ensure own accounts are in contactDirectory
        client._ownAccountsOrder.forEach((id) => {
          const c = client._ownAccounts.get(id);
          if (c && !client._contactDirectory.hasContact(c.id)) {
            client._contactDirectory.addContact(c);
          }
        });
      }
    } catch (e) {
      console.warn("Error restoring ownAccounts:", e);
    }

    return client;
  }

  // ── Events ────────────────────────────────────────────────────────────────

  on(event: MajikUniversalIdClientEvents, callback: EventCallback): void {
    this._listeners.get(event)?.push(callback);
  }

  off(event: MajikUniversalIdClientEvents, callback?: EventCallback): void {
    const cbs = this._listeners.get(event);
    if (!cbs?.length) return;
    if (callback) {
      const i = cbs.indexOf(callback);
      if (i !== -1) cbs.splice(i, 1);
    } else {
      this._listeners.set(event, []);
    }
  }

  // ── Private ───────────────────────────────────────────────────────────────

  private _registerOwnAccount(contact: MajikContact): void {
    if (!this._ownAccounts.has(contact.id)) {
      this._ownAccounts.set(contact.id, contact);
      this._ownAccountsOrder.push(contact.id);
    }
    if (!this._contactDirectory.hasContact(contact.id)) {
      this._contactDirectory.addContact(contact);
    }
    if (!this.getActiveAccount()) {
      this.setActiveAccount(contact.id);
    }
  }

  private _emit(event: MajikUniversalIdClientEvents, ...args: any[]): void {
    this._listeners.get(event)?.forEach((cb) => {
      try {
        cb(...args);
      } catch (err) {
        console.warn(
          `MajikUniversalIdClient event handler error (${event}):`,
          err,
        );
      }
    });
  }

  // ── Persistence ───────────────────────────────────────────────────────────

  private attachAutosaveHandlers(): void {
    if (typeof window === "undefined") return;
    try {
      window.addEventListener("beforeunload", () => void this.saveState());
    } catch {
      /* ignore */
    }
    this.startAutosave();
  }

  startAutosave(): void {
    if (this.autosaveIntervalId || typeof window === "undefined") return;
    this.autosaveIntervalId = window.setInterval(
      () => void this.saveState(),
      this.autosaveIntervalMs,
    ) as unknown as number;
  }

  stopAutosave(): void {
    if (!this.autosaveIntervalId || typeof window === "undefined") return;
    window.clearInterval(this.autosaveIntervalId);
    this.autosaveIntervalId = null;
  }

  private scheduleAutosave(): void {
    if (typeof window === "undefined") return;
    if (this.autosaveTimer) window.clearTimeout(this.autosaveTimer);
    this.autosaveTimer = window.setTimeout(() => {
      void this.saveState();
      this.autosaveTimer = null;
    }, this.autosaveDebounceMs) as unknown as number;
  }

  async saveState(): Promise<void> {
    try {
      const json = await this.toJSON();
      await idbSaveBlob(
        "majik-signature-state",
        autoSaveMajikFileData(json),
        this.userProfile,
      );
    } catch (err) {
      console.error("Failed to save MajikUniversalIdClient state:", err);
    }
  }

  async loadState(): Promise<void> {
    try {
      const saved = await idbLoadBlob(
        "majik-signature-state",
        this.userProfile,
      );
      if (!saved?.data) return;
      const loaded = await loadSavedMajikFileData(saved.data);
      const restored = await MajikUniversalIdClient.fromJSON(
        loaded.j as MajikUniversalIdClientJSON,
      );
      this._contactDirectory = restored._contactDirectory;
      this._ownAccounts = restored._ownAccounts;
      this._ownAccountsOrder = [...restored._ownAccountsOrder];
    } catch (err) {
      console.error("Failed to load MajikUniversalIdClient state:", err);
    }
  }

  static async loadOrCreate<T extends MajikUniversalIdClient>(
    this: MajikUniversalIdClientStatic<T>,
    config: MajikUniversalIdClientConfig,
    userProfile = "default",
  ): Promise<T> {
    try {
      const saved = await idbLoadBlob("majik-signature-state", userProfile);
      if (saved?.data) {
        const loaded = await loadSavedMajikFileData(saved.data);
        const instance = (await this.fromJSON(
          loaded.j as MajikUniversalIdClientJSON,
        )) as T;
        instance.attachAutosaveHandlers();
        return instance;
      }
    } catch (err) {
      console.warn("Error loading saved MajikUniversalIdClient state:", err);
    }

    const created = new this(config);
    await created.saveState();
    created.attachAutosaveHandlers();
    return created;
  }

  async resetData(userProfile = "default"): Promise<void> {
    try {
      for (const id of [...this._ownAccountsOrder]) {
        await MajikKeyStore.deleteIdentity(id).catch(() => {});
      }

      this._ownAccounts.clear();
      this._ownAccountsOrder = [];

      try {
        this._contactDirectory.clear();
      } catch {
        /* ignore */
      }

      try {
        await MajikKeyStore.deleteAll();
      } catch {
        /* ignore */
      }

      try {
        await clearAllBlobs(userProfile);
      } catch {
        /* ignore */
      }

      this.stopAutosave();
      this.startAutosave();

      this._emit("active-account-change", null);
    } catch (err) {
      throw new Error(
        `Failed to reset data: ${err instanceof Error ? err.message : err}`,
      );
    }
  }

  /**
   * Create a new MajikUniversalID from a MajikUser and an unlocked MajikKey.
   *
   * The key must be unlocked and have all key fields: edPublicKey, mlDsaPublicKey,
   * mlKemPublicKey (for encryption), and mlKemSecretKey is not needed here —
   * only the public key is used during creation.
   *
   * Private personal info is immediately encrypted with the bound key's
   * ML-KEM-768 public key. The rehydrated value is kept in-memory so
   * privateInfo is accessible right after create() without a separate call.
   *
   * The identity starts at IDTier.UNVERIFIED.
   */
  async createUniversalID(
    user: MajikUser,
    key: MajikKey,
    options: CreateUniversalIDOptions,
  ): Promise<MajikUniversalID> {
    const createdID = MajikUniversalID.create(user, key, options);

    this._emit("create-id", createdID);
    return createdID;
  }
}
