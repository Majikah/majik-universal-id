// ─────────────────────────────────────────────
// ID ENUM-LIKE CONSTANTS
// ─────────────────────────────────────────────

export const IDStatus = {
  ACTIVE: "active",
  SUSPENDED: "suspended",
  REVOKED: "revoked",
  PENDING_VERIFICATION: "pending_verification",
  EXPIRED: "expired",
} as const;

export type IDStatus = (typeof IDStatus)[keyof typeof IDStatus];

export const IDTier = {
  UNVERIFIED: "unverified", // No Didit verification yet
  PENDING_REVERIFICATION: "pending_reverification", // For rotation
  BASIC: "basic", // Phone verified only (Stage 4 only)
  VERIFIED: "verified", // Stage 1 (ID verification) passed
  ENHANCED: "enhanced", // Stages 1–3 passed (ID + liveness + face match)
  TRUSTED: "trusted", // All 5 stages passed
} as const;

export type IDTier = (typeof IDTier)[keyof typeof IDTier];

/**
 * Gender options.
 *
 * Values match UserGenderOptions from @thezelijah/majik-user:
 * Male | Female | Other
 *
 * Extra values (NON_BINARY, PREFER_NOT_TO_SAY) are MajikID-only
 * from Didit documentation.
 */
export const Gender = {
  MALE: "Male",
  FEMALE: "Female",
  NON_BINARY: "Non-Binary",
  PREFER_NOT_TO_SAY: "Prefer not to say",
  OTHER: "Other",
} as const;

export type Gender = (typeof Gender)[keyof typeof Gender];

export const DocumentType = {
  PASSPORT: "passport",
  NATIONAL_ID: "national_id",
  DRIVERS_LICENSE: "drivers_license",
  RESIDENCE_PERMIT: "residence_permit",
  VOTER_ID: "voter_id",
  BIRTH_CERTIFICATE: "birth_certificate",
  OTHER: "other",
} as const;

export type DocumentType = (typeof DocumentType)[keyof typeof DocumentType];

export const DeviceType = {
  MOBILE: "mobile",
  TABLET: "tablet",
  DESKTOP: "desktop",
  UNKNOWN: "unknown",
} as const;

export type DeviceType = (typeof DeviceType)[keyof typeof DeviceType];

export const BiometricStatus = {
  NOT_SUBMITTED: "not_submitted",
  PENDING: "pending",
  PASSED: "passed",
  FAILED: "failed",
  REQUIRES_REVIEW: "requires_review",
} as const;

export type BiometricStatus =
  (typeof BiometricStatus)[keyof typeof BiometricStatus];

export const VerificationProvider = {
  DIDIT: "didit",
  MANUAL: "manual",
  THIRD_PARTY: "third_party",
} as const;

export type VerificationProvider =
  (typeof VerificationProvider)[keyof typeof VerificationProvider];

export const SignatureAlgorithm = {
  ED25519: "Ed25519",
  ML_DSA_87: "ML-DSA-87",

  /** Both required — classical + post-quantum */
  HYBRID_ED25519_ML_DSA_87: "Ed25519+ML-DSA-87",
} as const;

export type SignatureAlgorithm =
  (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];

export const VisibilityScope = {
  PUBLIC: "public",
  PRIVATE: "private",
  INTERNAL: "internal",
} as const;

export type VisibilityScope =
  (typeof VisibilityScope)[keyof typeof VisibilityScope];

export const NotificationChannel = {
  EMAIL: "email",
  SMS: "sms",
  PUSH: "push",
  WEBHOOK: "webhook",
} as const;

export type NotificationChannel =
  (typeof NotificationChannel)[keyof typeof NotificationChannel];

export const ThemePreference = {
  LIGHT: "light",
  DARK: "dark",
  SYSTEM: "system",
} as const;

export type ThemePreference =
  (typeof ThemePreference)[keyof typeof ThemePreference];

export const LanguageCode = {
  EN: "en",
  FIL: "fil",
  ES: "es",
  FR: "fr",
  ZH: "zh",
  JA: "ja",
  AR: "ar",
} as const;

export type LanguageCode = (typeof LanguageCode)[keyof typeof LanguageCode];

/**
 * Social platform keys.
 *
 * Values match SocialLinkType from @thezelijah/majik-user.
 */
export const SocialPlatform = {
  FACEBOOK: "Facebook",
  X: "X",
  TIKTOK: "Tik-Tok",
  THREADS: "Threads",
  INSTAGRAM: "Instagram",
  YOUTUBE: "Youtube",
  SPOTIFY: "Spotify",
  APPLE_MUSIC: "Apple Music",
  LINKEDIN: "LinkedIn",
  GITHUB: "GitHub",
  WEBSITE: "Website URL",
} as const;

export type SocialPlatform =
  (typeof SocialPlatform)[keyof typeof SocialPlatform];

// ─────────────────────────────────────────────
// DIDIT-SPECIFIC CONSTANTS
// ─────────────────────────────────────────────

/**
 * The 5 stages of the Didit verification workflow,
 * in execution order.
 */
export const DiditStage = {
  ID_VERIFICATION: "id_verification", // Stage 1
  LIVENESS: "liveness", // Stage 2
  FACE_MATCH: "face_match", // Stage 3
  PHONE_VERIFICATION: "phone_verification", // Stage 4
  IP_ANALYSIS: "ip_analysis", // Stage 5
} as const;

export type DiditStage = (typeof DiditStage)[keyof typeof DiditStage];

export const DiditStageStatus = {
  NOT_STARTED: "not_started",
  IN_PROGRESS: "in_progress",
  PASSED: "passed",
  FAILED: "failed",
  SKIPPED: "skipped",
  REQUIRES_REVIEW: "requires_review",
} as const;

export type DiditStageStatus =
  (typeof DiditStageStatus)[keyof typeof DiditStageStatus];

export const IPRiskLevel = {
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
} as const;

export type IPRiskLevel = (typeof IPRiskLevel)[keyof typeof IPRiskLevel];

export const SignatureVerificationOutcome = {
  VALID: "valid",
  INVALID_CONTENT_HASH: "invalid_content_hash",
  INVALID_ED25519: "invalid_ed25519",
  INVALID_ML_DSA: "invalid_ml_dsa",
  INVALID_STRUCTURE: "invalid_structure",
  KEY_MISMATCH: "key_mismatch",
  EXPIRED: "expired",
  ERROR: "error",
} as const;

export type SignatureVerificationOutcome =
  (typeof SignatureVerificationOutcome)[keyof typeof SignatureVerificationOutcome];
