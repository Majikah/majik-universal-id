// ── Errors ──────────────────────────────────────────────────────────────────
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
  MajikUniversalIDRotationCooldownError,        // NEW
  MajikUniversalIDRotationCapExceededError,      // NEW
  MajikUniversalIDKeyGenerationMismatchError,    // NEW
  MajikUniversalIDPrivateInfoNotYetAvailableError, // NEW
  isUniversalIDError,
  isValidationError,
  isWebhookError,
  isImmutableError,
  isLockedError,
  isPrivateInfoLockedError,
  isRotationCooldownError, // NEW
} from "./core/errors";

// ── Schema enums ──────────────────────────────────────────────────────────────
export {
  IDStatus,
  IDTier, // unchanged export, now includes PENDING_REVERIFICATION member
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
  KeyGenerationRecord,       // NEW
  RotationReason,            // NEW
  RotationAuthorizedVia,     // NEW
  KeyGenerationStatus,       // NEW
  SignatureTrustLevel,       // NEW
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