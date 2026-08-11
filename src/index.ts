// ── Errors ──────────────────────────────────────────────────────────────────
export * from "./core/errors";

// ── Schema enums ──────────────────────────────────────────────────────────────
export type * from "./core/schema";

// ── Schema types ──────────────────────────────────────────────────────────────
export type * from "./core/schema";

// ── Didit webhook types ─────────────────────────────────────────────────────
// (unchanged)

// ── Class-layer types ────────────────────────────────────────────────────────
export type {
  CreateUniversalIDOptions,
  ContentVerificationResult, // now includes trust_level?: SignatureTrustLevel
  FileVerificationResult,
  WebhookProcessResult,
  UserSyncAction,
  SignatureAuditEntry,
  UniversalIDValidationResult,
  MajikUniversalIDJSON,
  FromJSONOptions,
  DecryptPrivateResult,
  SharePrivateOptions,
} from "./core/types";

// ── Utilities (for advanced use) ───────────────────────────────────────────────
export {
  SCHEMA_VERSION,
  MAJIK_UNIVERSAL_ID_VERSION,
  VERIFICATION_LOCK_DAYS,
  uuidv7,
  computeIDHash,
  verifyIDHash,
  bytesToBase64,
  base64ToBytes,
  bundleToSignerKeys,
  deriveIDTier,
  computePassedStages,
  mapNodeStatus,
  mapSessionStatus,
  normalizeCountryCode,
  normalizeGender,
  normalizeDocumentType,
  normalizeToE164,
  isVerificationLocked,
  verificationLockDaysRemaining,
  computeBundleHash,             // NEW
  bundleToSigningKeyMaterial,    // NEW
  signatureToSigningKeyMaterial, // NEW
  type IDHashKeyMaterial,
  type SigningKeyMaterial,       // NEW
} from "./core/utils";

// ── Mapper (for advanced use — build your own webhook handler) ────────────────
export { DiditWebhookMapperImpl, diditMapper } from "./core/didit/webhook";