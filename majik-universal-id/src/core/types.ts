/**
 * src/core/types.ts
 *
 * Class-layer-only types for MajikUniversalID.
 * All schema/domain types live in ./schema and ./didit/schema.
 * External package types are imported directly from their packages.
 */

import type { DiditMapperResult } from "./didit/schema";
import type {
  IDTier,
  DiditStage,
  Base64,
  MajikKeyPublicBundle,
  ISODateTime,
  MajikIDSignature,
  MajikIDMetadata,
  MajikUserRef,
  MajikIDSettings,
  SHA3_512Hash,
} from "./schema";

// ── External package surface (no re-declaration) ──────────────────────────────
export type { MajikKey } from "@majikah/majik-key";
export type {
  MajikSignatureJSON,
  MajikSignerPublicKeys,
  VerificationResult,
  SignOptions,
} from "@majikah/majik-signature";
export type { MajikUser } from "@thezelijah/majik-user";
export type {
  MajikEnvelopeJSON,
  MajikRecipient,
  MajikIdentity,
} from "@majikah/majik-envelope";

// ── Re-export DiditMapperResult for use in WebhookProcessResult ───────────────
export type { DiditMapperResult } from "./didit/schema";

// ─────────────────────────────────────────────
// FACTORY OPTIONS
// ─────────────────────────────────────────────

export interface CreateUniversalIDOptions {
  /** account_id of the Majikah tenant. Required. */
  account_id: string;
  /** Preferred locale e.g. "en-PH". Defaults to "en-PH". */
  locale?: string;
  /** Schema version override. Defaults to SCHEMA_VERSION constant. */
  schema_version?: string;

  username?: string;
}

// ─────────────────────────────────────────────
// VERIFICATION RESULTS
// ─────────────────────────────────────────────

export interface ContentVerificationResult {
  valid: boolean;
  signer_fingerprint: string;
  /** Whether the signer fingerprint matches the bound MajikKey */
  signer_registered: boolean;
  content_hash?: string;
  signed_at?: string;
  content_type?: string;
  reason?: string;
}

export interface FileVerificationResult extends ContentVerificationResult {
  /** Which embed handler processed the file (e.g. "PDF", "WAV") */
  handler?: string;
}

// ─────────────────────────────────────────────
// WEBHOOK PROCESSING
// ─────────────────────────────────────────────

export interface WebhookProcessResult {
  success: boolean;
  session_id: string;
  session_status: string;
  previous_tier: IDTier;
  new_tier: IDTier;
  tier_changed: boolean;
  all_stages_passed: boolean;
  updated_stages: DiditStage[];
  /**
   * Actions the caller should perform on the linked MajikUser.
   * e.g. ["verifyPhone", "verifyIdentity"]
   */
  user_sync_actions: UserSyncAction[];
  /** Extracted personal data ready to merge into PrivatePersonalInfo */
  extracted_personal_data?: DiditMapperResult["extracted_personal_data"];
}

/** Actions the caller should perform on the linked MajikUser after a webhook */
export type UserSyncAction =
  | "verifyEmail"
  | "unverifyEmail"
  | "verifyPhone"
  | "unverifyPhone"
  | "verifyIdentity"
  | "unverifyIdentity"
  | "restrict";

// ─────────────────────────────────────────────
// AUDIT / VALIDATION
// ─────────────────────────────────────────────

export interface SignatureAuditEntry {
  verification_id: string;
  signature_record_id: string;
  verified_with_fingerprint: string;
  outcome: import("./schema").SignatureVerificationOutcome;
  both_algorithms_passed: boolean;
  ed25519_passed: boolean;
  ml_dsa_passed: boolean;
  content_hash_matched: boolean;
  verified_at: string;
  verifier_ip?: string;
  context?: string;
}

export interface UniversalIDValidationResult {
  is_valid: boolean;
  errors: string[];
  warnings: string[];
}

// ─────────────────────────────────────────────
// SERIALIZATION
// ─────────────────────────────────────────────

/**
 * Serialized form of MajikUniversalID.
 * Alias of MajikID for clarity at the class boundary.
 */
export interface MajikUniversalIDJSON {
  id: string;
  user_id: string;
  account_id: string;
  /**
   * Primary X25519 public key, base64 — 32 bytes.
   * Fingerprint (SHA-256 of this key) = signerId in MajikSignature envelopes.
   */
  public_key: Base64;
  /**
   * The single MajikKey bundle bound to this identity.
   * A MajikUniversalID is permanently bound to exactly one MajikKey.
   * To use a different key, create a new MajikUniversalID.
   */
  signing_key: MajikKeyPublicBundle;
  user_ref: MajikUserRef;
  metadata: MajikIDMetadata;
  signature: MajikIDSignature;
  settings: MajikIDSettings;
  timestamp: ISODateTime;
  last_update: ISODateTime;
  hash: SHA3_512Hash;
  username: string | null;
}

// ─────────────────────────────────────────────
// PRIVATE INFO ENCRYPTION
// ─────────────────────────────────────────────

/**
 * Options for fromJSON() when a decryption key is provided.
 */
export interface FromJSONOptions {
  /**
   * An unlocked MajikKey to attempt decryption of private info.
   * If the key is locked, wrong, or decryption fails for any reason,
   * the error is silently swallowed — private info remains encrypted-only.
   * No exception is thrown.
   */
  key?: import("@majikah/majik-key").MajikKey;
}

/**
 * Result of a decryptPrivate() call.
 */
export interface DecryptPrivateResult {
  success: boolean;
  /**
   * The decrypted private info — only present when success === true.
   */
  data?: import("./schema").PrivatePersonalInfo;
  /**
   * Reason for failure — only present when success === false.
   * Errors are returned, not thrown, to allow graceful handling.
   */
  reason?: string;
}

/**
 * Options for sharePrivate().
 */
export interface SharePrivateOptions {
  /**
   * The MajikKey instances of the recipients who should be able to decrypt.
   * Each key must have mlKemPublicKey present (does NOT need to be unlocked).
   * At least one recipient is required.
   */
  recipients: import("@majikah/majik-key").MajikKey[];
  /**
   * The currently unlocked bound MajikKey — needed to first decrypt the
   * private info so it can be re-encrypted for the recipients.
   */
  senderKey: import("@majikah/majik-key").MajikKey;
}
