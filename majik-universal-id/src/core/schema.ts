/**
 * src/core/schema.ts
 *
 * MajikID — Universal Identity Schema
 * Full type definitions, interfaces, and enums.
 * No class implementations — pure schema layer.
 *
 * v1.2.0 — MajikUser integration
 * v1.3.0 — Moved into src/core/schema.ts; added MajikUniversalIDData
 */

// ─────────────────────────────────────────────
// ENUMS
// ─────────────────────────────────────────────

export enum IDStatus {
  ACTIVE = "active",
  SUSPENDED = "suspended",
  REVOKED = "revoked",
  PENDING_VERIFICATION = "pending_verification",
  EXPIRED = "expired",
}

export enum IDTier {
  UNVERIFIED = "unverified", // No didit verification yet
  BASIC = "basic", // Phone verified only (Stage 4 only)
  VERIFIED = "verified", // Stage 1 (ID verification) passed
  ENHANCED = "enhanced", // Stages 1–3 passed (ID + liveness + face match)
  TRUSTED = "trusted", // All 5 stages passed
}

/**
 * Gender options.
 * Values match UserGenderOptions from @thezelijah/majik-user:
 *   Male | Female | Other
 * Extra values (NON_BINARY, PREFER_NOT_TO_SAY) are MajikID-only — from Didit docs.
 */
export enum Gender {
  MALE = "Male",
  FEMALE = "Female",
  NON_BINARY = "Non-Binary",
  PREFER_NOT_TO_SAY = "Prefer not to say",
  OTHER = "Other",
}

export enum DocumentType {
  PASSPORT = "passport",
  NATIONAL_ID = "national_id",
  DRIVERS_LICENSE = "drivers_license",
  RESIDENCE_PERMIT = "residence_permit",
  VOTER_ID = "voter_id",
  BIRTH_CERTIFICATE = "birth_certificate",
  OTHER = "other",
}

export enum DeviceType {
  MOBILE = "mobile",
  TABLET = "tablet",
  DESKTOP = "desktop",
  UNKNOWN = "unknown",
}

export enum BiometricStatus {
  NOT_SUBMITTED = "not_submitted",
  PENDING = "pending",
  PASSED = "passed",
  FAILED = "failed",
  REQUIRES_REVIEW = "requires_review",
}

export enum VerificationProvider {
  DIDIT = "didit",
  MANUAL = "manual",
  THIRD_PARTY = "third_party",
}

export enum SignatureAlgorithm {
  ED25519 = "Ed25519",
  ML_DSA_87 = "ML-DSA-87",
  /** Both required — classical + post-quantum */
  HYBRID_ED25519_ML_DSA_87 = "Ed25519+ML-DSA-87",
}

export enum VisibilityScope {
  PUBLIC = "public",
  PRIVATE = "private",
  INTERNAL = "internal",
}

export enum NotificationChannel {
  EMAIL = "email",
  SMS = "sms",
  PUSH = "push",
  WEBHOOK = "webhook",
}

export enum ThemePreference {
  LIGHT = "light",
  DARK = "dark",
  SYSTEM = "system",
}

export enum LanguageCode {
  EN = "en",
  FIL = "fil",
  ES = "es",
  FR = "fr",
  ZH = "zh",
  JA = "ja",
  AR = "ar",
}

/**
 * Social platform keys.
 * Values match SocialLinkType from @thezelijah/majik-user.
 */
export enum SocialPlatform {
  FACEBOOK = "Facebook",
  X = "X",
  TIKTOK = "Tik-Tok",
  THREADS = "Threads",
  INSTAGRAM = "Instagram",
  YOUTUBE = "Youtube",
  SPOTIFY = "Spotify",
  APPLE_MUSIC = "Apple Music",
  LINKEDIN = "LinkedIn",
  GITHUB = "GitHub",
  WEBSITE = "Website URL",
}

// ── Didit-specific enums ──────────────────────────────────────────────────────

/** The 5 stages of the Didit verification workflow, in execution order */
export enum DiditStage {
  ID_VERIFICATION = "id_verification", // Stage 1
  LIVENESS = "liveness", // Stage 2
  FACE_MATCH = "face_match", // Stage 3
  PHONE_VERIFICATION = "phone_verification", // Stage 4
  IP_ANALYSIS = "ip_analysis", // Stage 5
}

export enum DiditStageStatus {
  NOT_STARTED = "not_started",
  IN_PROGRESS = "in_progress",
  PASSED = "passed",
  FAILED = "failed",
  SKIPPED = "skipped",
  REQUIRES_REVIEW = "requires_review",
}

export enum IPRiskLevel {
  LOW = "low",
  MEDIUM = "medium",
  HIGH = "high",
  CRITICAL = "critical",
}

export enum SignatureVerificationOutcome {
  VALID = "valid",
  INVALID_CONTENT_HASH = "invalid_content_hash",
  INVALID_ED25519 = "invalid_ed25519",
  INVALID_ML_DSA = "invalid_ml_dsa",
  INVALID_STRUCTURE = "invalid_structure",
  KEY_MISMATCH = "key_mismatch",
  EXPIRED = "expired",
  ERROR = "error",
}

// ─────────────────────────────────────────────
// PRIMITIVE / SHARED TYPES
// ─────────────────────────────────────────────

export type CountryCode = string;
export type LanguageTag = string;
export type CurrencyCode = string;
export type ISODateTime = string;
export type YYYYMMDD = `${number}-${number}-${number}`;
export type SHA3_512Hash = string;
export type SHA256Base64 = string;
export type Base64URL = string;
export type Base64 = string;
export type SemVer = string;
export type E164Phone = string;
export type URLString = string;

// ─────────────────────────────────────────────
// GEOLOCATION
// ─────────────────────────────────────────────

export interface GeoCoordinates {
  latitude: number;
  longitude: number;
  accuracy_meters?: number;
}

export interface GeoLocation {
  ip_address: string;
  ip_version: 4 | 6;
  country_code: CountryCode;
  country_name: string;
  region?: string;
  city?: string;
  postal_code?: string;
  timezone?: string;
  coordinates?: GeoCoordinates;
  isp?: string;
  is_vpn?: boolean;
  is_proxy?: boolean;
  is_tor?: boolean;
}

// ─────────────────────────────────────────────
// DEVICE FINGERPRINT
// ─────────────────────────────────────────────

export interface DeviceFingerprint {
  device_id: string;
  device_type: DeviceType;
  device_name?: string;
  os_name: string;
  os_version: string;
  browser_name?: string;
  browser_version?: string;
  user_agent: string;
  screen_resolution?: string;
  language: LanguageTag;
  timezone: string;
  hardware_concurrency?: number;
  canvas_fingerprint?: string;
  webgl_fingerprint?: string;
  installed_fonts_hash?: string;
  is_emulator?: boolean;
  is_rooted?: boolean;
}

// ─────────────────────────────────────────────
// MAJIK USER REFERENCE
// ─────────────────────────────────────────────

export interface MajikUserRef {
  user_id: string;
  email: string;
  display_name: string;
  /** SHA-256 of MajikUser.id, base64 */
  user_hash: Base64;
  is_restricted: boolean;
  restricted_until?: ISODateTime;
  email_verified: boolean;
  phone_verified: boolean;
  identity_verified: boolean;
  last_synced_at: ISODateTime;
}

// ─────────────────────────────────────────────
// MAJIK KEY — PUBLIC BUNDLE
// ─────────────────────────────────────────────

export interface MajikKeyPublicBundle {
  fingerprint: string;
  x25519_public_key: Base64; // 32 bytes
  ed_public_key: Base64; // 32 bytes
  ml_dsa_public_key: Base64; // 2592 bytes
  ml_kem_public_key: Base64; // 1184 bytes
  kdf_version: 1 | 2;
  registered_at: ISODateTime;
}

// ─────────────────────────────────────────────
// MAJIK SIGNATURE RECORD
// ─────────────────────────────────────────────

export interface MajikSignatureEnvelope {
  version: 1;
  signer_id: string;
  signer_ed_public_key: Base64;
  signer_ml_dsa_public_key: Base64;
  content_hash: SHA256Base64;
  ed_signature: Base64;
  ml_dsa_signature: Base64;
  content_type?: string;
  signed_at: ISODateTime;
}

export interface SignatureVerificationEntry {
  verification_id: string;
  signature_record_id: string;
  verified_with_fingerprint: string;
  outcome: SignatureVerificationOutcome;
  both_algorithms_passed: boolean;
  ed25519_passed: boolean;
  ml_dsa_passed: boolean;
  content_hash_matched: boolean;
  verified_at: ISODateTime;
  verifier_ip?: string;
  context?: string;
}

export interface MajikSignatureRecord {
  record_id: string;
  envelope: MajikSignatureEnvelope;
  serialized: Base64;
  content_label?: string;
  content_type?: string;
  content_size_bytes?: number;
  content_sha3_hash?: SHA3_512Hash;
  registered_at: ISODateTime;
  is_revoked: boolean;
  revoked_at?: ISODateTime;
  revocation_reason?: string;
  verification_log?: SignatureVerificationEntry[];
}

// ─────────────────────────────────────────────
// DIDIT — 5-STAGE VERIFICATION WORKFLOW
// ─────────────────────────────────────────────

export interface DiditSessionLog {
  session_id: string;
  initiated_at: ISODateTime;
  completed_at?: ISODateTime;
  ip_address: string;
  location: GeoLocation;
  device: DeviceFingerprint;
  provider: VerificationProvider;
  sdk_version?: SemVer;
}

export interface DiditIDVerification {
  stage: DiditStage.ID_VERIFICATION;
  status: DiditStageStatus;
  document_type: DocumentType;
  document_number: string; // encrypted at rest
  issuing_country: CountryCode;
  issuing_authority?: string;
  issue_date?: ISODateTime;
  expiry_date?: ISODateTime;
  mrz_line1?: string; // encrypted
  mrz_line2?: string; // encrypted
  document_image_front_hash: SHA3_512Hash;
  document_image_back_hash?: SHA3_512Hash;
  nfc_chip_read?: boolean;
  document_verified: boolean;
  verification_score?: number;
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditLiveness {
  stage: DiditStage.LIVENESS;
  status: DiditStageStatus;
  liveness_check_passed: boolean;
  liveness_score?: number;
  spoof_detection_passed?: boolean;
  spoof_type_detected?: string;
  biometric_status: BiometricStatus;
  selfie_image_hash: SHA3_512Hash;
  audit_image_urls?: URLString[];
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditFaceMatch {
  stage: DiditStage.FACE_MATCH;
  status: DiditStageStatus;
  face_match_passed: boolean;
  face_match_score?: number;
  match_threshold?: number;
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditPhoneVerification {
  stage: DiditStage.PHONE_VERIFICATION;
  status: DiditStageStatus;
  phone_number: E164Phone;
  carrier?: string;
  line_type?: "mobile" | "landline" | "voip" | "unknown";
  country_code: CountryCode;
  otp_verified: boolean;
  otp_method?: "sms" | "call" | "whatsapp" | "string";
  phone_matches_document_country?: boolean;
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditIPAnalysis {
  stage: DiditStage.IP_ANALYSIS;
  status: DiditStageStatus;
  ip_address: string;
  ip_version: 4 | 6;
  risk_level: IPRiskLevel;
  risk_score?: number;
  country_code: CountryCode;
  is_vpn: boolean;
  is_proxy: boolean;
  is_tor: boolean;
  is_hosting_provider: boolean;
  is_known_attacker?: boolean;
  isp?: string;
  asn?: string;
  ip_matches_phone_country?: boolean;
  ip_matches_document_country?: boolean;
  geo_location: GeoLocation;
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditAMLScreening {
  screened_at: ISODateTime;
  is_pep: boolean;
  is_sanctioned: boolean;
  watchlist_hits: string[];
  risk_score?: number;
  screening_provider?: string;
}

export interface DiditVerification {
  verification_id: string;
  didit_reference_id: string;
  tier: IDTier;
  status: IDStatus;
  session: DiditSessionLog;
  id_verification?: DiditIDVerification;
  liveness?: DiditLiveness;
  face_match?: DiditFaceMatch;
  phone_verification?: DiditPhoneVerification;
  ip_analysis?: DiditIPAnalysis;
  aml_screening?: DiditAMLScreening;
  all_stages_passed: boolean;
  completed_stages: DiditStage[];
  verified_at?: ISODateTime;
  expires_at?: ISODateTime;
  re_verification_required: boolean;
  rejection_reason?: string;
  raw_result_hash?: SHA3_512Hash;
}

// ─────────────────────────────────────────────
// METADATA
// ─────────────────────────────────────────────

export interface PublicProfile {
  display_name?: string;
  avatar_url?: URLString;
  bio?: string;
  website?: URLString;
  location_label?: string;
  preferred_language: LanguageCode;
  preferred_currency?: CurrencyCode;
  theme?: ThemePreference;
  social_handles?: Partial<Record<SocialPlatform, string>>;
  badges?: string[];
  verified_at_display?: ISODateTime;
}

export interface PostalAddress {
  line1: string;
  line2?: string;
  barangay?: string;
  city: string;
  state_province?: string;
  postal_code: string;
  country: CountryCode;
  is_verified?: boolean;
  verified_at?: ISODateTime;
}

/**
 * The plaintext private personal information fields.
 * These are NEVER stored or serialized in plaintext — they are always
 * encrypted into an EncryptedPrivateInfo envelope before persistence.
 *
 * Only accessible in memory after successful decryption via:
 *   - MajikUniversalID.fromJSON(json, key)
 *   - majikId.decryptPrivate(key)
 */
export interface PrivatePersonalInfo {
  legal_first_name: string;
  legal_middle_name?: string;
  legal_last_name: string;
  legal_name_suffix?: string;
  date_of_birth: YYYYMMDD;
  place_of_birth?: string;
  nationality: CountryCode;
  dual_nationality?: CountryCode;
  gender: Gender;
  civil_status?: string;
  primary_email: string;
  secondary_email?: string;
  primary_phone: E164Phone;
  secondary_phone?: E164Phone;
  home_address?: PostalAddress;
  mailing_address?: PostalAddress;
  // Government IDs
  tax_id?: string;
  national_id_number?: string;
  social_security_number?: string;
  philhealth_id?: string;
  pagibig_id?: string;
  sss_id?: string;
  bank_verification_number?: string;
  credit_score_tier?: string;
}

/**
 * The encrypted form of PrivatePersonalInfo.
 *
 * `envelope` is a serialized MajikEnvelopeJSON — the plaintext was
 * JSON.stringify(PrivatePersonalInfo) before encryption.
 *
 * `rehydrated` is the in-memory decrypted value after a successful
 * decryptPrivate() call. It is:
 *   - NEVER included in toJSON() output
 *   - NEVER serialized to disk or transmitted
 *   - Present only for the lifetime of the current class instance
 *
 * The `encrypted` discriminant allows TypeScript to narrow the union.
 */
export interface EncryptedPrivateInfo {
  readonly encrypted: true;
  /**
   * Serialized MajikEnvelopeJSON.
   * Decrypt with the bound MajikKey's ML-KEM secret key.
   */
  envelope: import("@majikah/majik-envelope").MajikEnvelopeJSON;
  /**
   * In-memory only — populated after decryptPrivate().
   * Stripped from toJSON() output — never persisted.
   */
  rehydrated?: PrivatePersonalInfo;
}

/**
 * The private info field on MajikIDMetadata.
 * Always serialized as EncryptedPrivateInfo.
 * The PrivatePersonalInfo union arm only ever exists in-memory
 * during create() before the first encryption.
 */
export type PrivateInfoField = EncryptedPrivateInfo;

export interface ConsentEntry {
  consent_id: string;
  granted_to: string;
  scopes: string[];
  granted_at: ISODateTime;
  expires_at?: ISODateTime;
  revoked_at?: ISODateTime;
  is_active: boolean;
}

export interface MajikIDMetadata {
  schema_version: SemVer;
  public: PublicProfile;
  /**
   * Private personal info — always encrypted at rest.
   * Access the decrypted data via MajikUniversalID.privateInfo getter
   * (requires prior decryptPrivate() call or key provided to fromJSON()).
   */
  private: PrivateInfoField;
  didit: DiditVerification;
  custom_claims?: Record<string, unknown>;
  consent_log?: ConsentEntry[];
}

// ─────────────────────────────────────────────
// MAJIKID SIGNATURE
// ─────────────────────────────────────────────

export interface MajikIDSignature {
  algorithm: SignatureAlgorithm.HYBRID_ED25519_ML_DSA_87;
  signer_fingerprint: string;
  signer_ed_public_key: Base64;
  signer_ml_dsa_public_key: Base64;
  content_hash: SHA256Base64;
  ed_signature: Base64;
  ml_dsa_signature: Base64;
  signed_fields: string[];
  signed_at: ISODateTime;
  serialized_envelope: Base64;
}

// ─────────────────────────────────────────────
// SETTINGS
// ─────────────────────────────────────────────

export interface NotificationSettings {
  channels: NotificationChannel[];
  security_alerts: boolean;
  login_notifications: boolean;
  verification_updates: boolean;
  marketing: boolean;
}

export interface PrivacySettings {
  profile_visibility: VisibilityScope;
  share_with_partners: boolean;
  allow_analytics: boolean;
  data_retention_years?: number;
  gdpr_consent?: boolean;
  data_portability_enabled: boolean;
}

export interface SecuritySettings {
  two_factor_enabled: boolean;
  two_factor_method?: "totp" | "sms" | "email" | "hardware_key";
  login_session_timeout_minutes: number;
  trusted_devices: string[];
  ip_allowlist?: string[];
  require_reverification_days?: number;
}

export interface MajikIDSettings {
  notification: NotificationSettings;
  privacy: PrivacySettings;
  security: SecuritySettings;
  locale: LanguageTag;
  timezone: string;
}

// ─────────────────────────────────────────────
// ROOT MAJIKID INTERFACE
// ─────────────────────────────────────────────

export interface MajikID {
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
  signature_records?: MajikSignatureRecord[];
  settings: MajikIDSettings;
  timestamp: ISODateTime;
  last_update: ISODateTime;
  hash: SHA3_512Hash;
}

// ─────────────────────────────────────────────
// PROJECTION TYPES
// ─────────────────────────────────────────────

export interface UserVerificationBridge {
  email_verified: boolean;
  phone_verified: boolean;
  identity_verified: boolean;
}

export type MajikIDPublicView = Pick<
  MajikID,
  "id" | "public_key" | "hash" | "timestamp"
> & {
  public_profile: PublicProfile;
  tier: IDTier;
  status: IDStatus;
  display_name: string;
  /** Public key material needed to verify any content signed by this identity */
  signing_key: Pick<
    MajikKeyPublicBundle,
    "fingerprint" | "ed_public_key" | "ml_dsa_public_key" | "registered_at"
  >;
  /**
   * Per-stage verification pass/fail map derived from completed_stages.
   * All five DiditStage keys are always present — false means not yet passed.
   * This is safe for public consumption: it reveals verification state only,
   * never the underlying personal data that drove each stage outcome.
   */
  verification_stages: Record<DiditStage, boolean>;
  user_id: string;
};

export interface MajikIDVerificationSummary {
  id: string;
  tier: IDTier;
  status: IDStatus;
  is_verified: boolean;
  verified_at?: ISODateTime;
  didit_reference_id: string;
  all_stages_passed: boolean;
  completed_stages: DiditStage[];
  biometric_status: BiometricStatus;
  aml_clear: boolean;
  ip_risk_level?: IPRiskLevel;
  user_verification: UserVerificationBridge;
}

export interface ResolvedSignerPublicKeys {
  signerId: string;
  edPublicKey: Uint8Array;
  mlDsaPublicKey: Uint8Array;
}

// ─────────────────────────────────────────────
// INTERNAL CONSTRUCTOR DATA
// (used only by MajikUniversalID constructor)
// ─────────────────────────────────────────────

export interface MajikUniversalIDData {
  id: string;
  user_id: string;
  account_id: string;
  public_key: Base64;
  signing_key: MajikKeyPublicBundle;
  user_ref: MajikUserRef;
  metadata: MajikIDMetadata;
  signature: MajikIDSignature;
  settings: MajikIDSettings;
  timestamp: ISODateTime;
  last_update: ISODateTime;
  hash: SHA3_512Hash;
}
