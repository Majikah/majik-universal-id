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

import {
  DeviceType,
  DiditStageStatus,
  SignatureVerificationOutcome,
  VerificationProvider,
  DiditStage,
  BiometricStatus,
  IPRiskLevel,
  IDTier,
  IDStatus,
  LanguageCode,
  ThemePreference,
  SocialPlatform,
  Gender,
  SignatureAlgorithm,
  NotificationChannel,
  VisibilityScope,
} from "./enums";

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
  stage: "id_verification";
  status: DiditStageStatus;
  document_type: DocumentType | string;
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
  stage: "liveness";
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
  stage: "face_match";
  status: DiditStageStatus;
  face_match_passed: boolean;
  face_match_score?: number;
  match_threshold?: number;
  failure_reason?: string;
  completed_at?: ISODateTime;
}

export interface DiditPhoneVerification {
  stage: "phone_verification";
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
  stage: "ip_analysis";
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
   * Serialized MajikEnvelopeJSON. Decrypt with the bound MajikKey's ML-KEM
   * secret key.
   *
   * Absent only when metadata.didit.tier === IDTier.PENDING_REVERIFICATION —
   * i.e. immediately after rotateKey(), before the next Didit session
   * completes and rebuilds private info under the new key. Every other
   * tier value requires this to be present; see _validateJSON().
   */
  envelope?: import("@majikah/majik-envelope").MajikEnvelopeJSON;
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
  algorithm: SignatureAlgorithm;
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
  username: string | null;
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
  username: string | null;
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
  username: string | null;
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
  username: string | null;
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

export type RotationReason = "voluntary" | "compromised";
export type RotationAuthorizedVia = "old_key_signature" | "step_up_auth";
export type KeyGenerationStatus = "active" | "rotated" | "revoked_compromised";

export interface KeyGenerationRecord {
  id: string;
  muid_id: string;
  fingerprint: string;
  bundle_hash: SHA3_512Hash;
  kdf_version: 1 | 2;
  status: KeyGenerationStatus;
  activated_at: ISODateTime;
  deactivated_at?: ISODateTime;
  reason?: RotationReason;
  authorized_via?: RotationAuthorizedVia;
  rotation_certificate?: unknown; // MajikSignatureJSON — typed loosely here to avoid a schema.ts → majik-signature dependency
}

export type SignatureTrustLevel =
  | "active_at_signing" // verified against current signing_key — fast path
  | "historically_valid" // verified against a past generation, inside its valid window
  | "signed_after_rotation" // signed_at falls after deactivated_at — tamper/reuse signal
  | "signed_before_activation" // signed_at falls before activated_at — clock skew or backdating
  | "key_mismatch" // embedded keys don't match the ledger's bundle_hash for this fingerprint
  | "unknown_signer"; // fingerprint never bound to this identity
