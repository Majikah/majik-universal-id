/**
 * src/index.ts
 *
 * Public API for @majikah/majik-universal-id
 *
 * Usage:
 *   import { MajikUniversalID } from "@majikah/majik-universal-id";
 *   import type { DiditWebhookPayload } from "@majikah/majik-universal-id";
 */

// ── Main class ────────────────────────────────────────────────────────────────
export { MajikUniversalID } from "./majik-universal-id";

// ── Errors ────────────────────────────────────────────────────────────────────
export {
  MajikUniversalIDError,
  MajikUniversalIDValidationError,
  MajikUniversalIDDeserializationError,
  MajikUniversalIDKeyError,
  MajikUniversalIDKeyNotFoundError,
  MajikUniversalIDSigningError,
  MajikUniversalIDVerificationError,
  MajikUniversalIDWebhookSignatureError,
  MajikUniversalIDWebhookPayloadError,
  MajikUniversalIDRestrictedError,
  MajikUniversalIDTierRequiredError,
  MajikUniversalIDIntegrityError,
  MajikUniversalIDImmutableError,
  MajikUniversalIDVerificationLockedError,
  MajikUniversalIDPrivateInfoLockedError,
  MajikUniversalIDPrivateInfoEncryptionError,
  isUniversalIDError,
  isValidationError,
  isWebhookError,
  isImmutableError,
  isLockedError,
  isPrivateInfoLockedError,
} from "./core/errors";

// ── Schema enums ──────────────────────────────────────────────────────────────
export {
  IDStatus,
  IDTier,
  Gender,
  DocumentType,
  DeviceType,
  BiometricStatus,
  VerificationProvider,
  SignatureAlgorithm,
  VisibilityScope,
  NotificationChannel,
  ThemePreference,
  LanguageCode,
  SocialPlatform,
  DiditStage,
  DiditStageStatus,
  IPRiskLevel,
  SignatureVerificationOutcome,
} from "./core/schema";

// ── Schema types ──────────────────────────────────────────────────────────────
export type {
  MajikID,
  MajikIDMetadata,
  MajikIDSignature,
  MajikIDSettings,
  MajikIDPublicView,
  MajikIDVerificationSummary,
  MajikKeyPublicBundle,
  MajikSignatureRecord,
  MajikSignatureEnvelope,
  MajikUserRef,
  PublicProfile,
  PrivatePersonalInfo,
  PrivateInfoField,
  EncryptedPrivateInfo,
  PostalAddress,
  DiditVerification,
  DiditIDVerification,
  DiditLiveness,
  DiditFaceMatch,
  DiditPhoneVerification,
  DiditIPAnalysis,
  DiditAMLScreening,
  DiditSessionLog,
  GeoLocation,
  GeoCoordinates,
  DeviceFingerprint,
  ConsentEntry,
  UserVerificationBridge,
  ResolvedSignerPublicKeys,
  MajikUniversalIDData,
  // Primitives
  ISODateTime,
  SHA3_512Hash,
  SHA256Base64,
  Base64,
  Base64URL,
  E164Phone,
  CountryCode,
  LanguageTag,
  YYYYMMDD,
  SemVer,
  URLString,
} from "./core/schema";

// ── Didit webhook types ───────────────────────────────────────────────────────
export type {
  DiditWebhookPayload,
  DiditWebhookHeaders,
  DiditDecision,
  DiditRawIDVerification,
  DiditRawLivenessCheck,
  DiditRawFaceMatch,
  DiditRawPhoneVerification,
  DiditRawIPAnalysis,
  DiditRawAMLScreening,
  DiditWarning,
  DiditSessionStatus,
  DiditNodeStatus,
  DiditWebhookType,
  DiditMapperContext,
  DiditMapperResult,
  DiditWebhookMapperInterface,
  UnixTimestamp,
} from "./core/didit/schema";

// ── Class-layer types ─────────────────────────────────────────────────────────
export type {
  CreateUniversalIDOptions,
  ContentVerificationResult,
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

// ── Utilities (for advanced use) ──────────────────────────────────────────────
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
  verifyWebhookSignature,
  isVerificationLocked,
  verificationLockDaysRemaining,
  type IDHashKeyMaterial,
} from "./core/utils";

// ── Mapper (for advanced use — build your own webhook handler) ────────────────
export { DiditWebhookMapperImpl, diditMapper } from "./core/didit/webhook";
