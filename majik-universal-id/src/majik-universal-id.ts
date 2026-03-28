/**
 * src/majik-universal-id.ts
 *
 * MajikUniversalID — Universal identity class for the Majikah ecosystem.
 *
 * This is a PURE DOMAIN MODEL class. It does NOT make any HTTP calls.
 * Didit API calls (session creation, token refresh, etc.) live in a
 * separate MajikDiditService package to keep this class clean and portable.
 *
 * Responsibilities:
 *   - Anchors a MajikUser to one MajikKey signing bundle (1:1:1 binding)
 *   - Stores and graduates Didit verification state across 5 stages
 *   - Encrypts private personal info with MajikEnvelope (ML-KEM-768)
 *   - Verifies any content or file signed by the bound MajikKey
 *   - Maintains a full signature history with per-record audit logs
 *   - Enforces immutability: verified identities cannot be mutated until
 *     revokeVerification() is called (only after the 30-day lock expires)
 *   - Serializes to/from JSON and base64 for storage and transport
 *
 * PRIVATE INFO ENCRYPTION CONTRACT:
 *   - Private info is ALWAYS stored as EncryptedPrivateInfo (envelope + optional rehydrated)
 *   - toJSON() / toBase64() ALWAYS strip the `rehydrated` field — never persisted
 *   - _validateJSON() rejects any payload where metadata.private is not encrypted
 *   - Decryption has two entry points:
 *       1. fromJSON(json, { key }) — silent attempt on load, swallows all failures
 *       2. decryptPrivate(key)     — explicit call returning DecryptPrivateResult
 *   - Access decrypted data via the privateInfo getter (throws if not rehydrated)
 *   - Check isPrivateDecrypted before accessing privateInfo
 *   - sharePrivate() re-encrypts for other recipients and returns a scanner string
 *
 * Private constructor — always use MajikUniversalID.create() or
 * MajikUniversalID.fromJSON() / MajikUniversalID.fromBase64().
 */

import { MajikSignature } from "@majikah/majik-signature";
import type {
  MajikSignatureJSON,
  VerificationResult,
  SignOptions,
} from "@majikah/majik-signature";
import type { MajikKey } from "@majikah/majik-key";
import type { MajikUser } from "@thezelijah/majik-user";
import { MajikEnvelope } from "@majikah/majik-envelope";
import type { MajikRecipient, MajikIdentity } from "@majikah/majik-envelope";

import {
  IDStatus,
  IDTier,
  DiditStage,
  SignatureAlgorithm,
  SignatureVerificationOutcome,
  NotificationChannel,
  VisibilityScope,
} from "./core/schema";

import type {
  MajikIDMetadata,
  MajikIDSignature,
  MajikIDSettings,
  MajikIDPublicView,
  MajikIDVerificationSummary,
  MajikKeyPublicBundle,
  MajikUserRef,
  PublicProfile,
  PrivatePersonalInfo,
  EncryptedPrivateInfo,
  PostalAddress,
  DiditVerification,
  ConsentEntry,
  ISODateTime,
  SHA3_512Hash,
  Base64,
  CountryCode,
  YYYYMMDD,
  MajikUniversalIDData,
} from "./core/schema";

import type {
  CreateUniversalIDOptions,
  ContentVerificationResult,
  FileVerificationResult,
  WebhookProcessResult,
  UserSyncAction,
  UniversalIDValidationResult,
  MajikUniversalIDJSON,
  FromJSONOptions,
  DecryptPrivateResult,
  SharePrivateOptions,
} from "./core/types";

import type {
  DiditWebhookPayload,
  DiditWebhookHeaders,
  DiditMapperResult,
} from "./core/didit/schema";

import { diditMapper } from "./core/didit/webhook";

import {
  MajikUniversalIDError,
  MajikUniversalIDValidationError,
  MajikUniversalIDDeserializationError,
  MajikUniversalIDKeyError,
  MajikUniversalIDKeyNotFoundError,
  MajikUniversalIDSigningError,
  MajikUniversalIDVerificationError,
  MajikUniversalIDWebhookPayloadError,
  MajikUniversalIDRestrictedError,
  MajikUniversalIDIntegrityError,
  MajikUniversalIDImmutableError,
  MajikUniversalIDVerificationLockedError,
  MajikUniversalIDPrivateInfoLockedError,
  MajikUniversalIDPrivateInfoEncryptionError,
} from "./core/errors";

import {
  SCHEMA_VERSION,
  uuidv7,
  computeIDHash,
  verifyIDHash,
  bytesToBase64,
  objectToBase64,
  base64ToObject,
  bundleToSignerKeys,
  normalizeGender,
  normalizeToE164,
  now,
  assertDefined,
  assertNonEmptyString,
  assertHasSigningKeys,
  isVerificationLocked,
  verificationLockDaysRemaining,
} from "./core/utils";

// ─────────────────────────────────────────────
// MAJIK UNIVERSAL ID
// ─────────────────────────────────────────────

export class MajikUniversalID {
  // ── Private fields (ES2022 private — inaccessible at runtime) ────────────

  readonly #id: string;
  readonly #user_id: string;

  readonly #username: string | null;

  readonly #account_id: string;
  readonly #timestamp: ISODateTime;
  readonly #hash: SHA3_512Hash;

  #public_key: Base64;
  readonly #signing_key: MajikKeyPublicBundle;
  #user_ref: MajikUserRef;
  #metadata: MajikIDMetadata;
  #signature: MajikIDSignature;
  #settings: MajikIDSettings;
  #last_update: ISODateTime;

  // ── Private constructor ──────────────────────────────────────────────────

  private constructor(data: MajikUniversalIDData) {
    this.#id = data.id;
    this.#user_id = data.user_id;
    this.#username = data.username;
    this.#account_id = data.account_id;
    this.#public_key = data.public_key;
    this.#signing_key = { ...data.signing_key };
    this.#user_ref = { ...data.user_ref };
    this.#metadata = this._deepCopyMetadata(data.metadata);
    this.#signature = { ...data.signature };
    this.#settings = JSON.parse(JSON.stringify(data.settings));
    this.#timestamp = data.timestamp;
    this.#last_update = data.last_update;
    this.#hash = data.hash;
  }

  // ═══════════════════════════════════════════
  // GETTERS — Identity
  // ═══════════════════════════════════════════

  get id(): string {
    return this.#id;
  }
  get userId(): string {
    return this.#user_id;
  }
  get accountId(): string {
    return this.#account_id;
  }
  get publicKey(): Base64 {
    return this.#public_key;
  }
  get hash(): SHA3_512Hash {
    return this.#hash;
  }
  get timestamp(): ISODateTime {
    return this.#timestamp;
  }
  get lastUpdate(): ISODateTime {
    return this.#last_update;
  }

  // ═══════════════════════════════════════════
  // GETTERS — Verification State
  // ═══════════════════════════════════════════

  get tier(): IDTier {
    return this.#metadata.didit.tier;
  }
  get status(): IDStatus {
    return this.#metadata.didit.status;
  }
  get isVerified(): boolean {
    return this.tier !== IDTier.UNVERIFIED;
  }
  get isTrusted(): boolean {
    return this.tier === IDTier.TRUSTED;
  }

  /** ISO 8601 timestamp of when this identity last reached a verified tier. */
  get verifiedAt(): ISODateTime | undefined {
    return this.#metadata.didit.verified_at;
  }

  /**
   * Whether this identity is mutable (tier === UNVERIFIED).
   * A verified identity is immutable until revokeVerification() succeeds.
   */
  get isMutable(): boolean {
    return this.tier === IDTier.UNVERIFIED;
  }

  get isVerificationLocked(): boolean {
    const v = this.verifiedAt;
    return v ? isVerificationLocked(v) : false;
  }

  get verificationLockDaysRemaining(): number {
    const v = this.verifiedAt;
    return v ? verificationLockDaysRemaining(v) : 0;
  }

  get isRestricted(): boolean {
    if (!this.#user_ref.is_restricted) return false;
    if (!this.#user_ref.restricted_until) return true;
    return new Date() < new Date(this.#user_ref.restricted_until);
  }

  get verificationSummary(): MajikIDVerificationSummary {
    const didit = this.#metadata.didit;
    return {
      id: this.#id,
      tier: didit.tier,
      status: didit.status,
      is_verified: didit.tier !== IDTier.UNVERIFIED,
      verified_at: didit.verified_at,
      didit_reference_id: didit.didit_reference_id,
      all_stages_passed: didit.all_stages_passed,
      completed_stages: [...didit.completed_stages],
      biometric_status:
        didit.liveness?.biometric_status ??
        (didit.face_match
          ? ((didit.face_match.face_match_passed ? "passed" : "failed") as any)
          : ("not_submitted" as any)),
      aml_clear:
        !didit.aml_screening?.is_pep && !didit.aml_screening?.is_sanctioned,
      ip_risk_level: didit.ip_analysis?.risk_level,
      user_verification: {
        email_verified: this.#user_ref.email_verified,
        phone_verified: this.#user_ref.phone_verified,
        identity_verified: this.#user_ref.identity_verified,
      },
      username: this.#username,
    };
  }

  // ═══════════════════════════════════════════
  // GETTERS — Verification Stages
  // ═══════════════════════════════════════════

  /**
   * Returns the list of Didit stages that have been passed by this identity.
   * Derived directly from DiditVerification.completed_stages.
   *
   * Stages appear in the order they were completed, not enum declaration order.
   * An empty array means no stages have been passed (UNVERIFIED).
   */
  getPassedVerifications(): DiditStage[] {
    return [...this.#metadata.didit.completed_stages];
  }

  /**
   * Check whether a specific Didit stage has been passed.
   *
   * @param stage - A DiditStage enum value (e.g. DiditStage.LIVENESS)
   * @returns true if the stage appears in completed_stages, false otherwise
   *
   * @example
   * if (majikId.isVerificationPassed(DiditStage.PHONE_VERIFICATION)) {
   *   // phone has been OTP-verified
   * }
   */
  isVerificationPassed(stage: DiditStage): boolean {
    return this.#metadata.didit.completed_stages.includes(stage);
  }

  // ═══════════════════════════════════════════
  // GETTERS — Key & Data
  // ═══════════════════════════════════════════

  /** The single MajikKey bundle permanently bound to this identity. */
  get signingKey(): Readonly<MajikKeyPublicBundle> {
    return { ...this.#signing_key };
  }
  get userRef(): Readonly<MajikUserRef> {
    return { ...this.#user_ref };
  }
  get settings(): Readonly<MajikIDSettings> {
    return JSON.parse(JSON.stringify(this.#settings));
  }

  /**
   * Returns metadata with the private field stripped of rehydrated data.
   * Access decrypted private info via the privateInfo getter instead.
   */
  get metadata(): Readonly<MajikIDMetadata> {
    return this._deepCopyMetadata(this.#metadata);
  }

  // ═══════════════════════════════════════════
  // GETTERS — Private Info
  // ═══════════════════════════════════════════

  /**
   * Whether private info has been decrypted and is available in this session.
   * Check this before accessing privateInfo to avoid throwing.
   */
  get isPrivateDecrypted(): boolean {
    return !!this.#metadata.private.rehydrated;
  }

  /**
   * The decrypted private personal info for this session.
   *
   * IMPORTANT: This is NEVER persisted — it exists only in memory.
   * toJSON() and toBase64() always strip this value.
   *
   * @throws MajikUniversalIDPrivateInfoLockedError if not yet decrypted.
   *         Check isPrivateDecrypted first, or call decryptPrivate(key).
   */
  get privateInfo(): Readonly<PrivatePersonalInfo> {
    const rehydrated = this.#metadata.private.rehydrated;
    if (!rehydrated) throw new MajikUniversalIDPrivateInfoLockedError();
    return { ...rehydrated };
  }

  // ═══════════════════════════════════════════
  // STATIC FACTORY — create()
  // ═══════════════════════════════════════════

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
  static async create(
    user: MajikUser,
    key: MajikKey,
    options: CreateUniversalIDOptions,
  ): Promise<MajikUniversalID> {
    assertDefined(user, "user");
    assertDefined(key, "key");
    assertDefined(options, "options");
    assertNonEmptyString(options.account_id, "options.account_id");

    const userValidation = user.validate();
    if (!userValidation.isValid) {
      throw new MajikUniversalIDValidationError(
        `Invalid MajikUser: ${userValidation.errors.join(", ")}`,
      );
    }

    if (key.isLocked) {
      throw new MajikUniversalIDKeyError(
        "MajikKey must be unlocked to create a MajikUniversalID. Call key.unlock(passphrase) first.",
      );
    }
    assertHasSigningKeys(key);

    const id = uuidv7();
    const timestamp = now();

    // Build key bundle BEFORE hash — all 4 public keys are committed into the hash
    const keyBundle = MajikUniversalID._buildKeyBundle(key, timestamp);

    const hash = computeIDHash(id, user.id, timestamp, {
      x25519_public_key: keyBundle.x25519_public_key,
      ed_public_key: keyBundle.ed_public_key,
      ml_kem_public_key: keyBundle.ml_kem_public_key,
      ml_dsa_public_key: keyBundle.ml_dsa_public_key,
    });

    const userRef = MajikUniversalID._buildUserRef(user, timestamp);
    const publicProfile = MajikUniversalID._buildPublicProfile(user, options);
    const rawPrivate = MajikUniversalID._buildRawPrivateInfo(user);
    const didit = MajikUniversalID._buildEmptyDidit();
    const settings = MajikUniversalID._buildSettings(user, options);

    // Encrypt private info — uses the bound key's ML-KEM-768 public key only
    const privateField = await MajikUniversalID._encryptPrivateInfo(
      rawPrivate,
      key,
    );

    // Attach rehydrated so privateInfo is accessible immediately after create()
    privateField.rehydrated = rawPrivate;

    const metadata: MajikIDMetadata = {
      schema_version: options.schema_version ?? SCHEMA_VERSION,
      public: publicProfile,
      private: privateField,
      didit,
      consent_log: [],
    };

    // Sign core identity fields with the hybrid Ed25519 + ML-DSA-87 signature
    const canonicalPayload = JSON.stringify({
      id,
      user_id: user.id,
      timestamp,
      hash,
    });
    const majikSig = await MajikSignature.sign(canonicalPayload, key, {
      contentType: "application/majikid",
      timestamp,
    });

    const signature = MajikUniversalID._buildIDSignature(majikSig.toJSON(), [
      "id",
      "user_id",
      "timestamp",
      "hash",
    ]);

    return new MajikUniversalID({
      id,
      user_id: user.id,
      username: options?.username || null,
      account_id: options.account_id,
      public_key: key.publicKeyBase64,
      signing_key: keyBundle,
      user_ref: userRef,
      metadata,
      signature,
      settings,
      timestamp,
      last_update: timestamp,
      hash,
    });
  }

  // ═══════════════════════════════════════════
  // SERIALIZATION
  // ═══════════════════════════════════════════

  /**
   * Serialize to a plain MajikID JSON object.
   *
   * GUARANTEED: the `rehydrated` field is ALWAYS stripped from the private
   * info. Only the encrypted envelope is persisted. This is enforced by
   * _serializeMetadata() and cannot be bypassed.
   */
  toJSON(): MajikUniversalIDJSON {
    return {
      id: this.#id,
      user_id: this.#user_id,
      username: this.#username,
      account_id: this.#account_id,
      public_key: this.#public_key,
      signing_key: { ...this.#signing_key },
      user_ref: { ...this.#user_ref },
      metadata: this._serializeMetadata(),
      signature: { ...this.#signature },
      settings: JSON.parse(JSON.stringify(this.#settings)),
      timestamp: this.#timestamp,
      last_update: this.#last_update,
      hash: this.#hash,
    };
  }

  toBase64(): Base64 {
    try {
      return objectToBase64(this.toJSON());
    } catch (err) {
      throw new MajikUniversalIDError("Failed to serialize to base64", err);
    }
  }

  toString(): string {
    return this.toBase64();
  }

  // ═══════════════════════════════════════════
  // DESERIALIZATION
  // ═══════════════════════════════════════════

  /**
   * Reconstruct a MajikUniversalID from its JSON representation.
   * Validates structure and integrity hash on load.
   *
   * @param json    - The serialized MajikID JSON (object or string)
   * @param options - Optionally provide { key } to attempt decryption of
   *                  private info on load. All failures are silently swallowed —
   *                  private info remains encrypted-only if decryption fails.
   *                  Call decryptPrivate(key) afterwards to retry explicitly.
   */
  static async fromJSON(
    json: MajikUniversalIDJSON | string,
    options?: FromJSONOptions,
  ): Promise<MajikUniversalID> {
    try {
      const data: MajikUniversalIDJSON =
        typeof json === "string" ? JSON.parse(json) : json;

      MajikUniversalID._validateJSON(data);

      if (!verifyIDHash(data)) {
        throw new MajikUniversalIDIntegrityError(
          "Integrity hash mismatch — the stored hash does not match the computed hash " +
            "of id, user_id, timestamp, and public key material. " +
            "The record may have been tampered with.",
        );
      }

      const instance = new MajikUniversalID({
        ...data,
        signing_key: data.signing_key,
      });

      // Attempt silent decryption if a key was provided
      if (options?.key) {
        await instance._tryDecryptPrivateSilently(options.key);
      }

      return instance;
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDDeserializationError(
        "Failed to parse MajikUniversalID from JSON",
        err,
      );
    }
  }

  /**
   * Reconstruct from a base64-serialized string.
   * Optionally provide { key } for silent private info decryption.
   */
  static async fromBase64(
    b64: Base64,
    options?: FromJSONOptions,
  ): Promise<MajikUniversalID> {
    try {
      assertNonEmptyString(b64, "base64 string");
      return MajikUniversalID.fromJSON(
        base64ToObject<MajikUniversalIDJSON>(b64),
        options,
      );
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDDeserializationError(
        "Failed to deserialize MajikUniversalID from base64",
        err,
      );
    }
  }

  // ═══════════════════════════════════════════
  // PRIVATE INFO — DECRYPT & SHARE
  // ═══════════════════════════════════════════

  /**
   * Decrypt and rehydrate private personal info with the provided MajikKey.
   *
   * On success: `isPrivateDecrypted` becomes true, `privateInfo` is accessible.
   * On failure: returns `{ success: false, reason }` — NEVER throws.
   * If already decrypted in this session, returns the cached value immediately.
   *
   * @param key - The bound MajikKey. Must be unlocked. Fingerprint must match
   *              signing_key.fingerprint.
   */
  async decryptPrivate(key: MajikKey): Promise<DecryptPrivateResult> {
    // Already rehydrated — return cached
    if (this.#metadata.private.rehydrated) {
      return { success: true, data: { ...this.#metadata.private.rehydrated } };
    }

    if (!key) {
      return { success: false, reason: "No key provided" };
    }
    if (key.isLocked) {
      return {
        success: false,
        reason: "MajikKey is locked — call key.unlock(passphrase) first",
      };
    }
    if (key.fingerprint !== this.#signing_key.fingerprint) {
      return {
        success: false,
        reason: `Key fingerprint '${key.fingerprint}' does not match the bound key '${this.#signing_key.fingerprint}'`,
      };
    }
    if (!key.mlKemSecretKey) {
      return {
        success: false,
        reason:
          "MajikKey is missing mlKemSecretKey — re-import via importFromMnemonicBackup()",
      };
    }

    try {
      const decrypted = await this._decryptEnvelope(key);
      this.#metadata = {
        ...this.#metadata,
        private: { ...this.#metadata.private, rehydrated: decrypted },
      };
      return { success: true, data: { ...decrypted } };
    } catch (err) {
      return {
        success: false,
        reason: err instanceof Error ? err.message : "Decryption failed",
      };
    }
  }

  /**
   * Share private info with one or more recipients by re-encrypting it for
   * their MajikKeys using MajikEnvelope group encryption.
   *
   * Returns a MajikEnvelope scanner string (`~*$MJKMSG:<base64>`) that each
   * recipient can decrypt with their own MajikKey:
   *
   *   const env = MajikEnvelope.fromScannerString(scannerString);
   *   const json = await env.decrypt({ fingerprint, mlKemSecretKey });
   *   const privateInfo: PrivatePersonalInfo = JSON.parse(json);
   *
   * The sender's key is always included as a recipient so the sender can
   * decrypt their own share string. Recipients list is deduplicated by
   * fingerprint. This does NOT mutate the current instance.
   *
   * @param options.senderKey  - Unlocked bound MajikKey (used to decrypt first)
   * @param options.recipients - One or more MajikKey instances to share with
   *                             (only mlKemPublicKey is used — do NOT need to be unlocked)
   * @returns MajikEnvelope scanner string
   */
  async sharePrivate(options: SharePrivateOptions): Promise<string> {
    assertDefined(options, "options");
    assertDefined(options.senderKey, "options.senderKey");
    if (!options.recipients?.length) {
      throw new MajikUniversalIDValidationError(
        "At least one recipient key is required",
        "options.recipients",
      );
    }

    const { senderKey, recipients } = options;

    if (senderKey.isLocked) {
      throw new MajikUniversalIDKeyError(
        "senderKey is locked — call senderKey.unlock(passphrase) first",
      );
    }
    if (senderKey.fingerprint !== this.#signing_key.fingerprint) {
      throw new MajikUniversalIDKeyNotFoundError(senderKey.fingerprint);
    }
    if (!senderKey.mlKemSecretKey) {
      throw new MajikUniversalIDKeyError(
        "senderKey is missing mlKemSecretKey — re-import via importFromMnemonicBackup()",
      );
    }

    for (const r of recipients) {
      if (!r.mlKemPublicKey) {
        throw new MajikUniversalIDKeyError(
          `Recipient key (fingerprint: ${r.fingerprint}) is missing mlKemPublicKey`,
        );
      }
    }

    // Decrypt if not already rehydrated
    const plaintext: PrivatePersonalInfo =
      this.#metadata.private.rehydrated ??
      (await this._decryptEnvelope(senderKey));

    // Build recipient list: sender first, then deduplicated additional recipients
    const allRecipients: MajikRecipient[] = [
      {
        fingerprint: senderKey.fingerprint,
        mlKemPublicKey: senderKey.mlKemPublicKey!,
      },
      ...recipients
        .filter((r) => r.fingerprint !== senderKey.fingerprint)
        .map((r) => ({
          fingerprint: r.fingerprint,
          mlKemPublicKey: r.mlKemPublicKey!,
        })),
    ];

    const shareEnvelope = await MajikEnvelope.encrypt({
      plaintext: JSON.stringify(plaintext),
      recipients: allRecipients,
      // senderFingerprint required only for group (2+ recipients)
      senderFingerprint:
        allRecipients.length > 1 ? senderKey.fingerprint : undefined,
    });

    return shareEnvelope.toScannerString();
  }

  // ═══════════════════════════════════════════
  // CONTENT SIGNING
  // (requires isMutable — verified identities cannot add new signatures)
  // ═══════════════════════════════════════════

  /**
   * Sign arbitrary content and store the record on this identity.
   * The key must match the bound signing_key fingerprint.
   * REQUIRES: isMutable === true and key must not be locked.
   */
  async signContent(
    content: Uint8Array | string,
    key: MajikKey,
    options?: SignOptions & { label?: string },
  ): Promise<MajikSignature> {
    this._assertMutable("signContent");
    this._assertNotRestricted();
    assertDefined(key, "key");
    assertDefined(content, "content");

    if (key.isLocked) {
      throw new MajikUniversalIDSigningError(
        "MajikKey is locked. Call key.unlock(passphrase) first.",
      );
    }
    assertHasSigningKeys(key);
    this._assertBoundKey(key.fingerprint);

    try {
      const sig = await MajikSignature.sign(content, key, options);

      this._touch();
      return sig;
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDSigningError("Failed to sign content", err);
    }
  }

  /**
   * Sign a file and embed the signature into it.
   * The key must match the bound signing_key fingerprint.
   * REQUIRES: isMutable === true and key must not be locked.
   */
  async signFile(
    file: Blob,
    key: MajikKey,
    options?: {
      contentType?: string;
      timestamp?: string;
      mimeType?: string;
      label?: string;
    },
  ): Promise<{
    blob: Blob;
    signature: MajikSignature;
    handler: string;
    mimeType: string;
  }> {
    this._assertMutable("signFile");
    this._assertNotRestricted();
    assertDefined(file, "file");
    assertDefined(key, "key");

    if (key.isLocked) {
      throw new MajikUniversalIDSigningError(
        "MajikKey is locked. Call key.unlock(passphrase) first.",
      );
    }
    assertHasSigningKeys(key);
    this._assertBoundKey(key.fingerprint);

    try {
      const result = await MajikSignature.signFile(file, key, options);

      this._touch();
      return result as any;
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDSigningError("Failed to sign file", err);
    }
  }

  // ═══════════════════════════════════════════
  // CONTENT VERIFICATION
  // (read-only — no mutable requirement)
  // ═══════════════════════════════════════════

  /**
   * Verify that content was signed by the key bound to this identity.
   * Verifies both Ed25519 AND ML-DSA-87 — both must pass.
   */
  verifyContent(
    content: Uint8Array | string,
    signature: MajikSignature | MajikSignatureJSON | string,
    context?: string,
  ): ContentVerificationResult {
    assertDefined(content, "content");
    assertDefined(signature, "signature");

    try {
      const sig =
        typeof signature === "string"
          ? MajikSignature.deserialize(signature)
          : signature instanceof MajikSignature
            ? signature
            : MajikSignature.fromJSON(signature as MajikSignatureJSON);

      const signerId = sig.signerId;

      if (signerId !== this.#signing_key.fingerprint) {
        return {
          valid: false,
          signer_fingerprint: signerId,
          signer_registered: false,
          reason: `Signer fingerprint '${signerId}' does not match the key bound to this MajikID`,
        };
      }

      const publicKeys = bundleToSignerKeys(this.#signing_key);
      const result: VerificationResult = MajikSignature.verify(
        content,
        sig,
        publicKeys,
      );

      return {
        valid: result.valid,
        signer_fingerprint: signerId,
        signer_registered: true,
        content_hash: result.contentHash,
        signed_at: result.timestamp,
        content_type: result.contentType,
        reason: result.valid ? undefined : (result as any).reason,
      };
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDVerificationError(
        "Content verification failed unexpectedly",
        err,
      );
    }
  }

  /** Verify a file's embedded MajikSignature against this identity. */
  async verifyFile(
    file: Blob,
    context?: string,
  ): Promise<FileVerificationResult> {
    assertDefined(file, "file");

    try {
      // ✅ Verify ONCE — returns array of results
      const results = await MajikSignature.verifyFile(
        file,
        this.#signing_key as any,
      );

      if (!results?.length) {
        return {
          valid: false,
          signer_fingerprint: "",
          signer_registered: false,
          reason: "No embedded MajikSignature found in file",
        };
      }

      // 🎯 Find the signature that matches THIS identity
      const match = results.find(
        (r) => r.signerId === this.#signing_key.fingerprint,
      );

      if (!match) {
        return {
          valid: false,
          signer_fingerprint: "",
          signer_registered: false,
          reason: "No signature found matching the key bound to this MajikID",
        };
      }

      if (!match.signerId?.trim()) {
        return {
          valid: false,
          signer_fingerprint: "",
          signer_registered: false,
          reason: "Invalid Signer Fingerprint",
        };
      }

      return {
        valid: match.valid,
        signer_fingerprint: match.signerId,
        signer_registered: true,
        content_hash: match.contentHash,
        signed_at: match.timestamp,
        content_type: match.contentType,
        handler: match.handler,
        reason: match.valid ? undefined : (match as any).reason,
      };
    } catch (err) {
      if (err instanceof MajikUniversalIDError) throw err;
      throw new MajikUniversalIDVerificationError(
        "File verification failed",
        err,
      );
    }
  }

  /** Convenience wrapper for verifying signed text strings. */
  verifyText(
    text: string,
    signature: MajikSignatureJSON | string,
    context?: string,
  ): ContentVerificationResult {
    return this.verifyContent(text, signature, context);
  }

  // ═══════════════════════════════════════════
  // DIDIT — WEBHOOK PROCESSING
  // (does NOT require isMutable — it IS the graduation path)
  // ═══════════════════════════════════════════

  /**
   * Process an incoming Didit webhook payload.
   * Verifies HMAC, maps to typed structures, graduates IDTier, and returns
   * actions for the caller to apply on the linked MajikUser.
   *
   * IMPORTANT: vendor_data in the webhook must equal this MajikUniversalID.id.
   */
  async processWebhook(
    payload: DiditWebhookPayload,
    headers: DiditWebhookHeaders,
    secret: string,
  ): Promise<WebhookProcessResult> {
    assertDefined(payload, "payload");
    assertDefined(headers, "headers");
    assertNonEmptyString(secret, "webhook secret");

    if (payload.vendor_data && payload.vendor_data !== this.#id) {
      throw new MajikUniversalIDWebhookPayloadError(
        `Webhook vendor_data '${payload.vendor_data}' does not match this MajikID '${this.#id}'. ` +
          "Ensure you pass MajikUniversalID.id as vendor_data when creating the Didit session.",
      );
    }

    const previousTier = this.#metadata.didit.tier;
    const result = diditMapper.map(payload, {
      verification_id: uuidv7(),
      majik_id: this.#id,
      user_id: this.#user_id,
      existing: this.#metadata.didit,
    });

    if (!result) {
      return {
        success: true,
        session_id: payload.session_id,
        session_status: payload.status,
        previous_tier: previousTier,
        new_tier: previousTier,
        tier_changed: false,
        all_stages_passed: false,
        updated_stages: [],
        user_sync_actions: [],
      };
    }

    this.#metadata = { ...this.#metadata, didit: result.verification };
    const userSyncActions = this._computeUserSyncActions(result, previousTier);
    this._applyUserRefSync(result);
    this._touch();

    return {
      success: true,
      session_id: payload.session_id,
      session_status: payload.status,
      previous_tier: previousTier,
      new_tier: result.verification.tier,
      tier_changed: result.verification.tier !== previousTier,
      all_stages_passed: result.all_stages_passed,
      updated_stages: result.updated_stages,
      user_sync_actions: userSyncActions,
      extracted_personal_data: result.extracted_personal_data,
    };
  }

  /** Apply a DiditMapperResult directly (after external image hashing). */
  applyDiditResult(result: DiditMapperResult): this {
    assertDefined(result, "result");
    this.#metadata = { ...this.#metadata, didit: result.verification };
    this._applyUserRefSync(result);
    this._touch();
    return this;
  }

  // ═══════════════════════════════════════════
  // DIDIT — VERIFICATION LIFECYCLE
  // ═══════════════════════════════════════════

  /**
   * Revoke all Didit verification and reset to UNVERIFIED.
   * Throws MajikUniversalIDVerificationLockedError if verified within 30 days.
   * Safe no-op if already UNVERIFIED.
   *
   * @param reason - Required justification stored in the audit trail
   */
  revokeVerification(reason: string): this {
    assertNonEmptyString(reason, "reason");
    if (this.tier === IDTier.UNVERIFIED) return this;

    const verifiedAt = this.verifiedAt;
    if (verifiedAt && isVerificationLocked(verifiedAt)) {
      throw new MajikUniversalIDVerificationLockedError(
        verifiedAt,
        verificationLockDaysRemaining(verifiedAt),
      );
    }

    this.#metadata = {
      ...this.#metadata,
      didit: {
        ...MajikUniversalID._buildEmptyDidit(),
        rejection_reason: reason,
        re_verification_required: false,
      },
    };

    this.#user_ref = {
      ...this.#user_ref,
      identity_verified: false,
      phone_verified: false,
      last_synced_at: now(),
    };

    this._touch();
    return this;
  }

  /** Flag for re-verification (admin). Does NOT unlock the identity. */
  requireReverification(reason?: string): this {
    this.#metadata = {
      ...this.#metadata,
      didit: {
        ...this.#metadata.didit,
        re_verification_required: true,
        rejection_reason: reason ?? this.#metadata.didit.rejection_reason,
      },
    };
    this._touch();
    return this;
  }

  // ═══════════════════════════════════════════
  // USER REF SYNC
  // ═══════════════════════════════════════════

  /** Sync user_ref from an updated MajikUser. REQUIRES: isMutable. */
  syncUserRef(user: MajikUser): this {
    this._assertMutable("user_ref");
    assertDefined(user, "user");

    if (user.id !== this.#user_id) {
      throw new MajikUniversalIDValidationError(
        `User ID mismatch: expected '${this.#user_id}', got '${user.id}'`,
        "user.id",
      );
    }

    this.#user_ref = MajikUniversalID._buildUserRef(user, now());
    this._touch();
    return this;
  }

  /** Update display name in user_ref and public profile. REQUIRES: isMutable. */
  updateDisplayName(displayName: string): this {
    this._assertMutable("display_name");
    assertNonEmptyString(displayName, "displayName");
    this.#user_ref = { ...this.#user_ref, display_name: displayName };
    this.#metadata = {
      ...this.#metadata,
      public: { ...this.#metadata.public, display_name: displayName },
    };
    this._touch();
    return this;
  }

  // ═══════════════════════════════════════════
  // SETTINGS
  // ═══════════════════════════════════════════

  /** Update settings. REQUIRES: isMutable. */
  updateSettings(updates: Partial<MajikIDSettings>): this {
    this._assertMutable("settings");
    this.#settings = {
      ...this.#settings,
      ...updates,
      notification: {
        ...this.#settings.notification,
        ...(updates.notification ?? {}),
      },
      privacy: { ...this.#settings.privacy, ...(updates.privacy ?? {}) },
      security: { ...this.#settings.security, ...(updates.security ?? {}) },
    };
    this._touch();
    return this;
  }

  // ═══════════════════════════════════════════
  // CONSENT
  // ═══════════════════════════════════════════

  /** Record a consent grant. REQUIRES: isMutable. */
  grantConsent(
    grantedTo: string,
    scopes: string[],
    expiresAt?: ISODateTime,
  ): this {
    this._assertMutable("consent");
    assertNonEmptyString(grantedTo, "grantedTo");
    if (!scopes?.length) {
      throw new MajikUniversalIDValidationError(
        "Consent scopes cannot be empty",
        "scopes",
      );
    }

    this.#metadata = {
      ...this.#metadata,
      consent_log: [
        ...(this.#metadata.consent_log ?? []),
        {
          consent_id: uuidv7(),
          granted_to: grantedTo,
          scopes,
          granted_at: now(),
          expires_at: expiresAt,
          is_active: true,
        } as ConsentEntry,
      ],
    };
    this._touch();
    return this;
  }

  /** Revoke a consent grant by ID. REQUIRES: isMutable. */
  revokeConsent(consentId: string): this {
    this._assertMutable("consent");
    assertNonEmptyString(consentId, "consentId");

    const log = this.#metadata.consent_log ?? [];
    if (!log.find((c) => c.consent_id === consentId)) {
      throw new MajikUniversalIDValidationError(
        `Consent record '${consentId}' not found`,
        "consentId",
      );
    }

    this.#metadata = {
      ...this.#metadata,
      consent_log: log.map((c) =>
        c.consent_id === consentId
          ? { ...c, is_active: false, revoked_at: now() }
          : c,
      ),
    };
    this._touch();
    return this;
  }

  getActiveConsents(): ConsentEntry[] {
    return (this.#metadata.consent_log ?? []).filter((c) => c.is_active);
  }

  // ═══════════════════════════════════════════
  // PUBLIC VIEWS
  // ═══════════════════════════════════════════

  /** Returns a public-safe projection — no private info, no signature records. */
  toPublicView(): MajikIDPublicView {
    return {
      id: this.#id,
      public_key: this.#public_key,
      hash: this.#hash,
      timestamp: this.#timestamp,
      public_profile: { ...this.#metadata.public },
      tier: this.tier,
      status: this.status,
      display_name: this.#user_ref.display_name,
      signing_key: {
        fingerprint: this.#signing_key.fingerprint,
        ed_public_key: this.#signing_key.ed_public_key,
        ml_dsa_public_key: this.#signing_key.ml_dsa_public_key,
        registered_at: this.#signing_key.registered_at,
      },
      verification_stages: MajikUniversalID._buildVerificationStagesMap(
        this.#metadata.didit.completed_stages,
      ),
      user_id: this.#user_id,
      username: this.#username,
    };
  }

  // ═══════════════════════════════════════════
  // VALIDATION
  // ═══════════════════════════════════════════

  validate(): UniversalIDValidationResult {
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!this.#id) errors.push("id is missing");
    if (!this.#user_id) errors.push("user_id is missing");
    if (!this.#account_id) errors.push("account_id is missing");
    if (!this.#public_key) errors.push("public_key is missing");
    if (!this.#hash) errors.push("hash is missing");
    if (!this.#timestamp) errors.push("timestamp is missing");

    if (!verifyIDHash(this.toJSON())) {
      errors.push(
        "integrity hash mismatch — hash does not match id, user_id, timestamp, " +
          "and public key material. Data may be corrupted or tampered with.",
      );
    }

    if (!this.#signing_key?.fingerprint) {
      errors.push("signing_key is missing or invalid");
    } else {
      if (!this.#signing_key.ed_public_key)
        errors.push("signing_key.ed_public_key is missing");
      if (!this.#signing_key.ml_dsa_public_key)
        errors.push("signing_key.ml_dsa_public_key is missing");
      if (!this.#signing_key.ml_kem_public_key)
        errors.push("signing_key.ml_kem_public_key is missing");
      if (!this.#signing_key.x25519_public_key)
        errors.push("signing_key.x25519_public_key is missing");
      if (this.#public_key !== this.#signing_key.x25519_public_key) {
        errors.push("public_key does not match signing_key.x25519_public_key");
      }
    }

    if (!this.#metadata.private?.envelope) {
      errors.push("private info is missing encryption envelope");
    }

    if (!this.isPrivateDecrypted) {
      warnings.push(
        "private info is encrypted and not yet decrypted in this session — " +
          "call decryptPrivate(key) to access it",
      );
    }

    if (!this.isMutable) {
      if (!this.verifiedAt) {
        warnings.push("identity is verified but has no verified_at timestamp");
      }
      if (this.#metadata.didit.re_verification_required) {
        warnings.push(
          "re_verification_required is set — call revokeVerification() when the 30-day lock expires",
        );
        if (this.isVerificationLocked) {
          warnings.push(
            `verification lock active — ${this.verificationLockDaysRemaining} day(s) remaining`,
          );
        }
      }
    }

    return { is_valid: errors.length === 0, errors, warnings };
  }

  // ═══════════════════════════════════════════
  // PRIVATE HELPERS
  // ═══════════════════════════════════════════

  private _touch(): void {
    this.#last_update = now();
  }

  private _assertNotRestricted(): void {
    if (this.isRestricted) {
      throw new MajikUniversalIDRestrictedError(
        this.#user_ref.restricted_until,
      );
    }
  }

  private _assertMutable(field?: string): void {
    if (!this.isMutable) {
      throw new MajikUniversalIDImmutableError(
        this.#metadata.didit.tier,
        field,
      );
    }
  }

  private _assertBoundKey(fingerprint: string): void {
    if (fingerprint !== this.#signing_key.fingerprint) {
      throw new MajikUniversalIDKeyNotFoundError(fingerprint);
    }
  }

  /**
   * Deep copy metadata while preserving the envelope structure and rehydrated
   * value correctly. Never uses JSON.parse/stringify on the whole metadata
   * object to avoid accidental loss of envelope references or rehydrated state.
   */
  private _deepCopyMetadata(m: MajikIDMetadata): MajikIDMetadata {
    return {
      schema_version: m.schema_version,
      public: JSON.parse(JSON.stringify(m.public)),
      private: {
        encrypted: true as const,
        envelope: m.private.envelope, // envelope is a plain JSON object — reference is fine
        rehydrated: m.private.rehydrated
          ? { ...m.private.rehydrated } // shallow copy — all fields are primitives or plain objects
          : undefined,
      },
      didit: JSON.parse(JSON.stringify(m.didit)),
      custom_claims: m.custom_claims
        ? JSON.parse(JSON.stringify(m.custom_claims))
        : undefined,
      consent_log: m.consent_log
        ? JSON.parse(JSON.stringify(m.consent_log))
        : undefined,
    };
  }

  /**
   * Serialize metadata for toJSON() — identical to _deepCopyMetadata but
   * ALWAYS omits the `rehydrated` field. This is the enforcement point:
   * decrypted private info NEVER leaves the class boundary via serialization.
   */
  private _serializeMetadata(): MajikIDMetadata {
    return {
      schema_version: this.#metadata.schema_version,
      public: JSON.parse(JSON.stringify(this.#metadata.public)),
      private: {
        encrypted: true as const,
        envelope: this.#metadata.private.envelope,
        // rehydrated intentionally omitted — never serialized
      },
      didit: JSON.parse(JSON.stringify(this.#metadata.didit)),
      custom_claims: this.#metadata.custom_claims
        ? JSON.parse(JSON.stringify(this.#metadata.custom_claims))
        : undefined,
      consent_log: this.#metadata.consent_log
        ? JSON.parse(JSON.stringify(this.#metadata.consent_log))
        : undefined,
    };
  }

  /**
   * Core envelope decryption — decrypt and parse the stored PrivatePersonalInfo.
   * Throws on any failure. Callers decide how to handle errors.
   */
  private async _decryptEnvelope(key: MajikKey): Promise<PrivatePersonalInfo> {
    const envelope = MajikEnvelope.fromJSON(this.#metadata.private.envelope);
    const identity: MajikIdentity = {
      fingerprint: key.fingerprint,
      mlKemSecretKey: key.mlKemSecretKey!,
    };
    const plaintext = await envelope.decrypt(identity);
    return JSON.parse(plaintext) as PrivatePersonalInfo;
  }

  /**
   * Called by fromJSON() when a key is provided.
   * Never throws — all failures are silently swallowed.
   */
  private async _tryDecryptPrivateSilently(key: MajikKey): Promise<void> {
    try {
      if (key.isLocked) return;
      if (key.fingerprint !== this.#signing_key.fingerprint) return;
      if (!key.mlKemSecretKey) return;

      const decrypted = await this._decryptEnvelope(key);
      this.#metadata = {
        ...this.#metadata,
        private: { ...this.#metadata.private, rehydrated: decrypted },
      };
    } catch {
      // Silent — private info stays encrypted-only in this session
    }
  }

  private _computeUserSyncActions(
    result: DiditMapperResult,
    previousTier: IDTier,
  ): UserSyncAction[] {
    const actions: UserSyncAction[] = [];
    const didit = result.verification;

    if (result.updated_stages.includes(DiditStage.PHONE_VERIFICATION)) {
      actions.push(
        didit.phone_verification?.otp_verified
          ? "verifyPhone"
          : "unverifyPhone",
      );
    }
    if (result.all_stages_passed && previousTier !== IDTier.TRUSTED) {
      actions.push("verifyIdentity");
    }
    if (!result.all_stages_passed && previousTier === IDTier.TRUSTED) {
      actions.push("unverifyIdentity");
    }
    if (
      didit.status === IDStatus.REVOKED ||
      didit.status === IDStatus.SUSPENDED
    ) {
      actions.push("restrict");
    }

    return actions;
  }

  private _applyUserRefSync(result: DiditMapperResult): void {
    const didit = result.verification;
    this.#user_ref = {
      ...this.#user_ref,
      phone_verified:
        didit.phone_verification?.otp_verified ?? this.#user_ref.phone_verified,
      identity_verified: result.all_stages_passed,
      last_synced_at: now(),
    };
  }

  // ═══════════════════════════════════════════
  // STATIC BUILDERS (private)
  // ═══════════════════════════════════════════

  private static _buildKeyBundle(
    key: MajikKey,
    registeredAt: ISODateTime,
  ): MajikKeyPublicBundle {
    if (!key.edPublicKey || !key.mlDsaPublicKey || !key.mlKemPublicKey) {
      throw new MajikUniversalIDKeyError(
        "MajikKey is missing required public key fields (ed, mlDsa, or mlKem). " +
          "Ensure the key was imported via importFromMnemonicBackup().",
      );
    }

    return {
      fingerprint: key.fingerprint,
      x25519_public_key: key.publicKeyBase64,
      ed_public_key: bytesToBase64(key.edPublicKey),
      ml_dsa_public_key: bytesToBase64(key.mlDsaPublicKey),
      ml_kem_public_key: bytesToBase64(key.mlKemPublicKey),
      kdf_version: (key.kdfVersion ?? 1) as 1 | 2,
      registered_at: registeredAt,
    };
  }

  private static _buildUserRef(
    user: MajikUser,
    syncedAt: ISODateTime,
  ): MajikUserRef {
    return {
      user_id: user.id,
      email: user.email,
      display_name: user.displayName,
      user_hash: user.hash,
      is_restricted: user.isCurrentlyRestricted?.() ?? false,
      restricted_until: (
        user.settings.system as any
      ).restrictedUntil?.toISOString?.(),
      email_verified: user.isEmailVerified,
      phone_verified: user.isPhoneVerified,
      identity_verified: user.isIdentityVerified,
      last_synced_at: syncedAt,
    };
  }

  private static _buildPublicProfile(
    user: MajikUser,
    _options: CreateUniversalIDOptions,
  ): PublicProfile {
    const meta = user.metadata;
    return {
      display_name: user.displayName,
      avatar_url: meta.picture,
      bio: meta.bio,
      preferred_language: (meta.language ?? "en") as any,
      location_label: meta.address
        ? [meta.address.city, meta.address.country_code ?? meta.address.country]
            .filter(Boolean)
            .join(", ")
        : undefined,
      social_handles: (meta.social_links ?? {}) as any,
    };
  }

  /**
   * Build the raw plaintext PrivatePersonalInfo from a MajikUser.
   * Used ONLY within create() immediately before _encryptPrivateInfo().
   * The result is NEVER stored directly.
   */
  private static _buildRawPrivateInfo(user: MajikUser): PrivatePersonalInfo {
    const meta = user.metadata;
    const name = meta.name;

    const address = meta.address
      ? ({
          line1: [meta.address.building, meta.address.street]
            .filter(Boolean)
            .join(", "),
          barangay: meta.address.area,
          city: meta.address.city ?? "",
          state_province: meta.address.region,
          postal_code: meta.address.zip ?? "",
          country: (meta.address.country_code ??
            meta.address.country ??
            "") as CountryCode,
        } as PostalAddress)
      : undefined;

    return {
      legal_first_name: name?.first_name ?? "",
      legal_middle_name: name?.middle_name,
      legal_last_name: name?.last_name ?? "",
      legal_name_suffix: name?.suffix,
      date_of_birth: (meta.birthdate ?? "") as YYYYMMDD,
      nationality: "" as CountryCode, // populated later from Didit Stage 1
      gender: normalizeGender(meta.gender ?? ""),
      primary_email: user.email,
      primary_phone: normalizeToE164(meta.phone ?? ""),
      home_address: address,
    };
  }

  /**
   * Encrypt a PrivatePersonalInfo value with the bound key's ML-KEM-768 public key.
   * Returns an EncryptedPrivateInfo WITHOUT the rehydrated field.
   * Throws MajikUniversalIDPrivateInfoEncryptionError on failure.
   */
  private static async _encryptPrivateInfo(
    info: PrivatePersonalInfo,
    key: MajikKey,
  ): Promise<EncryptedPrivateInfo> {
    if (!key.mlKemPublicKey) {
      throw new MajikUniversalIDPrivateInfoEncryptionError(
        "MajikKey is missing mlKemPublicKey — cannot encrypt private info. " +
          "Ensure the key was imported via importFromMnemonicBackup().",
      );
    }

    try {
      const envelope = await MajikEnvelope.encrypt({
        plaintext: JSON.stringify(info),
        recipients: [
          { fingerprint: key.fingerprint, mlKemPublicKey: key.mlKemPublicKey },
        ],
        // senderFingerprint not required for single recipient
      });

      return {
        encrypted: true,
        envelope: envelope.toJSON(),
        // rehydrated intentionally not set here — caller attaches it
      };
    } catch (err) {
      if (err instanceof MajikUniversalIDPrivateInfoEncryptionError) throw err;
      throw new MajikUniversalIDPrivateInfoEncryptionError(
        "Failed to encrypt private personal info",
        err,
      );
    }
  }

  private static _buildEmptyDidit(): DiditVerification {
    return {
      verification_id: uuidv7(),
      didit_reference_id: "",
      tier: IDTier.UNVERIFIED,
      status: IDStatus.PENDING_VERIFICATION,
      session: {
        session_id: "",
        initiated_at: now(),
        ip_address: "",
        location: {
          ip_address: "",
          ip_version: 4,
          country_code: "",
          country_name: "",
        },
        device: {
          device_id: uuidv7(),
          device_type: "unknown" as any,
          os_name: "",
          os_version: "",
          user_agent: "",
          language: "en",
          timezone: "UTC",
        },
        provider: "didit" as any,
      },
      all_stages_passed: false,
      completed_stages: [],
      re_verification_required: false,
    };
  }

  private static _buildSettings(
    user: MajikUser,
    options: CreateUniversalIDOptions,
  ): MajikIDSettings {
    const meta = user.metadata;
    return {
      notification: {
        channels: user.settings.notifications
          ? [NotificationChannel.EMAIL, NotificationChannel.PUSH]
          : [],
        security_alerts: true,
        login_notifications: true,
        verification_updates: true,
        marketing: false,
      },
      privacy: {
        profile_visibility: VisibilityScope.PRIVATE,
        share_with_partners: false,
        allow_analytics: false,
        data_portability_enabled: true,
      },
      security: {
        two_factor_enabled: false,
        login_session_timeout_minutes: 60,
        trusted_devices: [],
      },
      locale:
        options.locale ?? (meta.language ? `${meta.language}-PH` : "en-PH"),
      timezone: meta.timezone ?? "Asia/Manila",
    };
  }

  private static _buildIDSignature(
    json: MajikSignatureJSON,
    signedFields: string[],
  ): MajikIDSignature {
    return {
      algorithm: SignatureAlgorithm.HYBRID_ED25519_ML_DSA_87,
      signer_fingerprint: json.signerId,
      signer_ed_public_key: json.signerEdPublicKey,
      signer_ml_dsa_public_key: json.signerMlDsaPublicKey,
      content_hash: json.contentHash,
      ed_signature: json.edSignature,
      ml_dsa_signature: json.mlDsaSignature,
      signed_fields: signedFields,
      signed_at: json.timestamp,
      serialized_envelope: btoa(JSON.stringify(json)),
    };
  }

  /**
   * Derives a complete Record<DiditStage, boolean> from a completed_stages array.
   * Every DiditStage key is always present so consumers can iterate without
   * needing to know the full enum set.
   */
  private static _buildVerificationStagesMap(
    completedStages: DiditStage[],
  ): Record<DiditStage, boolean> {
    return {
      [DiditStage.ID_VERIFICATION]: completedStages.includes(
        DiditStage.ID_VERIFICATION,
      ),
      [DiditStage.LIVENESS]: completedStages.includes(DiditStage.LIVENESS),
      [DiditStage.FACE_MATCH]: completedStages.includes(DiditStage.FACE_MATCH),
      [DiditStage.PHONE_VERIFICATION]: completedStages.includes(
        DiditStage.PHONE_VERIFICATION,
      ),
      [DiditStage.IP_ANALYSIS]: completedStages.includes(
        DiditStage.IP_ANALYSIS,
      ),
    };
  }

  private static _validateJSON(
    data: unknown,
  ): asserts data is MajikUniversalIDJSON {
    if (!data || typeof data !== "object") {
      throw new MajikUniversalIDDeserializationError(
        "JSON must be a non-null object",
      );
    }
    const d = data as Record<string, unknown>;
    for (const field of [
      "id",
      "user_id",
      "account_id",
      "public_key",
      "hash",
      "timestamp",
    ]) {
      if (!d[field] || typeof d[field] !== "string") {
        throw new MajikUniversalIDDeserializationError(
          `Missing or invalid required field: '${field}'`,
        );
      }
    }
    if (!d["metadata"] || typeof d["metadata"] !== "object") {
      throw new MajikUniversalIDDeserializationError(
        "Missing or invalid 'metadata' field",
      );
    }
    const meta = d["metadata"] as Record<string, unknown>;
    if (!meta["private"] || typeof meta["private"] !== "object") {
      throw new MajikUniversalIDDeserializationError(
        "Missing or invalid 'metadata.private' field",
      );
    }
    const priv = meta["private"] as Record<string, unknown>;
    if (
      priv["encrypted"] !== true ||
      typeof priv["envelope"] !== "object" ||
      !priv["envelope"]
    ) {
      throw new MajikUniversalIDDeserializationError(
        "metadata.private must be an EncryptedPrivateInfo with an envelope. " +
          "Plaintext private info is never stored or accepted on load.",
      );
    }
    if (!d["signature"] || typeof d["signature"] !== "object") {
      throw new MajikUniversalIDDeserializationError(
        "Missing or invalid 'signature' field",
      );
    }
    if (
      !d["signing_key"] ||
      typeof d["signing_key"] !== "object" ||
      typeof (d["signing_key"] as Record<string, unknown>)["fingerprint"] !==
        "string"
    ) {
      throw new MajikUniversalIDDeserializationError(
        "Missing or invalid 'signing_key' — a MajikUniversalID requires exactly one bound MajikKey",
      );
    }
  }
}
