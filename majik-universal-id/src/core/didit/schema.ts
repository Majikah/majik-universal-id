/**
 * src/core/didit/schema.ts
 *
 * Didit V3 API webhook types — scoped to MajikID's 5-stage workflow:
 *   ID_VERIFICATION → LIVENESS → FACE_MATCH → PHONE → IP_ANALYSIS
 *
 * AML screening is also typed here as a supplemental check.
 * Fields not in the workflow (NFC, POA, email, database_validation,
 * questionnaire) are intentionally excluded.
 *
 * All types reference ../schema for MajikID domain types.
 * No class implementations — pure type/interface layer.
 *
 * ── CHANGELOG (vs previous version) ────────────────────────────────────────
 *
 * DiditSessionStatus
 *   + "Kyc Expired"  — observed in samples, was missing
 *   + "Resubmitted"  — observed in samples, was missing
 *
 * DiditWarning
 *   + feature        — present in Declined sample ("ID_VERIFICATION")
 *   + node_id        — present in Declined sample ("feature_ocr")
 *   (risk, log_type, short_description, long_description were already present)
 *
 * DiditRawIDVerification
 *   + front_image_quality_score / back_image_quality_score made optional+nullable
 *     (absent in Declined / minimal payloads)
 *   + matches typed as DiditIDVerificationMatch[] | null (null in Declined sample)
 *   + warnings typed as DiditWarning[] (was already correct, confirmed present
 *     even when status = Declined with a non-empty array)
 *   + extra_fields: added explicit first_surname / second_surname (observed in
 *     all id_verification samples alongside the existing [key] escape hatch)
 *
 * DiditRawLivenessCheck
 *   + face_quality / face_luminance typed as null (both null in every sample)
 *   + method: added "FLASHING" literal (observed, was only "ACTIVE_3D"|"PASSIVE")
 *   + matches typed as unknown[] | null
 *
 * DiditRawFaceMatch
 *   + source_image_session_id: string | null  (present in samples, was missing)
 *
 * DiditRawIPAnalysis
 *   + browser_family / os_family / platform / device_brand — confirmed present
 *   + device_fingerprint: string | null  (null in all samples)
 *   + device_model: string | null        (null in all samples)
 *   + time_zone_offset typed as number (samples show integer, was string)
 *   + ip / id_document / poa_document distance blocks typed explicitly
 *     (was locations_info?: DiditLocationsInfo — renamed to match real payload shape)
 *   + ip_country_code confirmed present (was optional, now required in full payloads)
 *
 * DiditDecision
 *   + session_url renamed from session_url (already present, confirmed)
 *   + All array node fields typed as T[] | null (null observed when stage not
 *     included in workflow, e.g. aml_screenings: null in minimal Abandoned payload)
 *   + reviews typed as DiditReview[] | null (null not seen but null arrays expected)
 *   + created_at: ISO string on decision, Unix number on root payload (was ambiguous)
 *
 * DiditWebhookPayload (root)
 *   + resubmit_info block typed here (was only in local muid.ts inline type)
 *   + decision marked as present on: Approved, Declined, In Review, Abandoned,
 *     Expired, Kyc Expired  (absent on: Not Started, In Progress, Resubmitted)
 *   + vendor_data: confirmed absent (undefined, not null) on Not Started /
 *     In Progress / some Declined payloads — typed as string | null | undefined
 *
 * ── END CHANGELOG ────────────────────────────────────────────────────────────
 */

import type {
  ISODateTime,
  CountryCode,
  E164Phone,
  SHA3_512Hash,
  DiditVerification,
  DiditStage,
  DiditStageStatus,
  DiditIDVerification,
  DiditLiveness,
  DiditFaceMatch,
  DiditPhoneVerification,
  DiditIPAnalysis,
  DiditAMLScreening,
} from "../schema";

// ─────────────────────────────────────────────
// SHARED PRIMITIVES
// ─────────────────────────────────────────────

export type UnixTimestamp = number;

/**
 * All observable session-level statuses from Didit V3 webhooks.
 *
 * CHANGES: Added "Kyc Expired" and "Resubmitted" which appear in real payloads.
 * "Kyc Expired" is distinct from "Expired" — Didit uses both spellings.
 */
export type DiditSessionStatus =
  | "Not Started"
  | "In Progress"
  | "In Review"
  | "Approved"
  | "Declined"
  | "Abandoned"
  | "Expired"
  | "Kyc Expired" // Added: observed in webhook samples
  | "Resubmitted"; // Added: observed in webhook samples

export type DiditNodeStatus =
  | "Approved"
  | "Declined"
  | "In Review"
  | "Not Started"
  | "In Progress"
  | "Expired"; // Added: id_verification node can be "Expired" (Kyc Expired payload)

export type DiditWebhookType = "status.updated" | "data.updated";

/**
 * Per-node warning object.
 *
 * CHANGES:
 *   + feature  — which workflow feature flagged this (e.g. "ID_VERIFICATION")
 *   + node_id  — internal node ref (e.g. "feature_ocr")
 * Both were observed in the Declined sample payload.
 */
export interface DiditWarning {
  risk: string; // e.g. "DOCUMENT_EXPIRED"
  additional_data: unknown | null;
  log_type: "information" | "warning" | "error";
  short_description: string; // e.g. "Document expired"
  long_description: string;
  feature?: string; // Added: e.g. "ID_VERIFICATION"
  node_id?: string; // Added: e.g. "feature_ocr"
}

// ─────────────────────────────────────────────
// STAGE 1: ID_VERIFICATION
// ─────────────────────────────────────────────

export interface DiditParsedAddress {
  id?: string;
  address_type?: string;
  city?: string;
  label?: string;
  region?: string;
  street_1?: string;
  street_2?: string | null;
  postal_code?: string;
  country?: string; // Confirmed present in samples (e.g. "US")
  formatted_address?: string; // Confirmed present in samples
  is_verified?: boolean; // Confirmed present in samples
  document_location?: {
    // Confirmed present in samples
    latitude: number;
    longitude: number;
  };
  raw_results?: Record<string, unknown>;
}

export interface DiditImageQualityScore {
  focus_score: number;
  brightness_score: number;
  brightness_issue: string;
  is_document_fully_visible: boolean;
  resolution_score: number;
  overall_score: number;
}

export interface DiditIDVerificationMatch {
  session_id: string;
  session_number: number;
  vendor_data: string;
  verification_date: ISODateTime;
  user_details: {
    name: string;
    document_type: string;
    document_number: string;
  };
  status: DiditNodeStatus;
  is_blocklisted: boolean;
  api_service: string;
  front_image_url?: string;
}

/**
 * Raw Didit ID verification node.
 *
 * Storage notes:
 *   portrait_image / front_image / back_image → SHA3-512 hash, discard URLs
 *   document_number / personal_number         → encrypt at rest
 *   date_of_birth                             → PrivatePersonalInfo.date_of_birth
 *   first_name / last_name                    → PrivatePersonalInfo.legal_*_name
 *   gender "F"/"M"                            → normalize to Gender enum
 *   issuing_state                             → alpha-3, normalize to alpha-2
 *   parsed_address                            → PostalAddress
 *   marital_status                            → PrivatePersonalInfo.civil_status
 *   nationality                               → alpha-3, normalize to alpha-2
 *
 * CHANGES:
 *   + extra_fields.first_surname / second_surname — observed in all ID samples
 *   + matches typed as DiditIDVerificationMatch[] | null (null in Declined sample)
 *   + front/back_image_camera_front_face_match_score: number | null (null in samples)
 *   + front/back_image_quality_score: DiditImageQualityScore | null (null in Declined)
 *   + front/back_image_camera_front: string | null (null in minimal payloads)
 */
export interface DiditRawIDVerification {
  node_id: string;
  status: DiditNodeStatus;
  document_type: string;
  document_number: string; // SENSITIVE — encrypt at rest
  personal_number?: string | null; // SENSITIVE — encrypt at rest
  portrait_image?: string | null; // DO NOT store — hash only
  front_image?: string | null; // DO NOT store — hash only
  front_video?: string | null;
  back_image?: string | null; // DO NOT store — hash only
  back_video?: string | null;
  full_front_image?: string | null;
  full_back_image?: string | null;
  front_image_camera_front?: string | null; // null in minimal payloads
  back_image_camera_front?: string | null; // null in minimal payloads
  front_image_camera_front_face_match_score?: number | null; // null when camera_front absent
  back_image_camera_front_face_match_score?: number | null; // null when camera_front absent
  front_image_quality_score?: DiditImageQualityScore | null; // null in Declined/minimal
  back_image_quality_score?: DiditImageQualityScore | null; // null in Declined/minimal
  date_of_birth?: string; // "YYYY-MM-DD"
  age?: number | null;
  expiration_date?: string | null;
  date_of_issue?: string | null;
  issuing_state?: string; // ISO 3166-1 alpha-3, e.g. "ESP"
  issuing_state_name?: string;
  first_name?: string;
  last_name?: string;
  full_name?: string;
  gender?: string; // "F" | "M" | "X"
  address?: string | null;
  formatted_address?: string | null;
  place_of_birth?: string | null;
  marital_status?: string; // "UNKNOWN" | "SINGLE" | "MARRIED" etc.
  nationality?: string; // ISO 3166-1 alpha-3, e.g. "ESP"
  extra_fields?: {
    first_surname?: string; // Added: observed in samples
    second_surname?: string; // Added: observed in samples
    dl_categories?: string[];
    blood_group?: string | null;
    [key: string]: unknown;
  };
  parsed_address?: DiditParsedAddress | null;
  extra_files?: string[];
  warnings: DiditWarning[];
  matches?: DiditIDVerificationMatch[] | null; // null in Declined/minimal payloads
}

// ─────────────────────────────────────────────
// STAGE 2: LIVENESS
// ─────────────────────────────────────────────

/**
 * Raw Didit liveness check node.
 *
 * Storage notes:
 *   reference_image → SHA3-512 hash → DiditLiveness.selfie_image_hash
 *   video_url       → discard
 *   score           → divide by 100 → 0.00–1.00
 *
 * CHANGES:
 *   + method: added "FLASHING" literal (observed in all samples)
 *   + face_quality / face_luminance: null in all observed samples — typed as null
 *   + matches: unknown[] | null  (null in some samples)
 *   + age_estimation: number | null
 *   + video_url: string | null (null in all observed samples)
 */
export interface DiditRawLivenessCheck {
  node_id: string;
  status: DiditNodeStatus;
  method: "ACTIVE_3D" | "PASSIVE" | "FLASHING" | string; // Added: "FLASHING"
  score: number; // 0–100
  reference_image?: string | null; // DO NOT store — hash only
  video_url?: string | null; // null in observed samples
  age_estimation?: number | null;
  face_quality?: null; // Always null in observed samples
  face_luminance?: null; // Always null in observed samples
  matches?: unknown[] | null;
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// STAGE 3: FACE_MATCH
// ─────────────────────────────────────────────

/**
 * Raw Didit face match node.
 *
 * Storage notes:
 *   score                      → divide by 100 → 0.00–1.00
 *   source_image / target_image → discard URLs
 *
 * CHANGES:
 *   + source_image_session_id: string | null — present in all observed samples,
 *     was missing from schema entirely
 */
export interface DiditRawFaceMatch {
  node_id: string;
  status: DiditNodeStatus;
  score: number; // 0–100
  source_image?: string | null; // DO NOT store
  source_image_session_id?: string | null; // Added: present in all samples
  target_image?: string | null; // DO NOT store
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// STAGE 4: PHONE
// ─────────────────────────────────────────────

export interface DiditPhoneCarrier {
  name: string;
  type: "mobile" | "landline" | "voip" | "unknown";
}

export interface DiditPhoneLifecycleEvent {
  type: string;
  timestamp: ISODateTime;
  details: Record<string, unknown> | null;
  fee: number;
}

/**
 * Raw Didit phone verification node.
 *
 * Storage notes:
 *   full_number         → normalize to E.164 → DiditPhoneVerification.phone_number
 *   carrier.name        → DiditPhoneVerification.carrier
 *   carrier.type        → DiditPhoneVerification.line_type
 *   verification_method → DiditPhoneVerification.otp_method
 *   status "Approved"   → otp_verified = true
 *   lifecycle           → discard (operational detail)
 *
 * CHANGES:
 *   + verification_method: added "whatsapp" literal (observed in samples alongside
 *     "sms" | "call" — Didit supports WhatsApp OTP)
 *   + verified_at: ISODateTime | null
 *   + carrier: DiditPhoneCarrier | null (null possible if carrier lookup fails)
 */
export interface DiditRawPhoneVerification {
  node_id: string;
  status: DiditNodeStatus;
  phone_number_prefix: string;
  phone_number: string;
  full_number: E164Phone;
  country_code: string;
  country_name: string;
  carrier?: DiditPhoneCarrier | null;
  is_disposable: boolean;
  is_virtual: boolean;
  verification_method: "sms" | "call" | "whatsapp" | string; // Added: "whatsapp"
  verification_attempts: number;
  verified_at?: ISODateTime | null;
  lifecycle?: DiditPhoneLifecycleEvent[];
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// STAGE 5: IP_ANALYSIS
// ─────────────────────────────────────────────

/**
 * Per-entity location + distance block used inside DiditRawIPAnalysis.
 * Each entity (ip, id_document, poa_document) carries its own location
 * and distances to the other two entities.
 *
 * CHANGES: Renamed from DiditLocationPoint / DiditLocationsInfo to match
 * the actual payload shape observed in samples. The samples nest these
 * directly as ip / id_document / poa_document on the root node object,
 * not under a locations_info wrapper key.
 */
export interface DiditGeoPoint {
  location: {
    latitude: number;
    longitude: number;
  };
}

export interface DiditIPGeoPoint extends DiditGeoPoint {
  distance_from_id_document?: { direction: string; distance: number };
  distance_from_poa_document?: { direction: string; distance: number };
}

export interface DiditDocumentGeoPoint extends DiditGeoPoint {
  distance_from_ip?: { direction: string; distance: number };
  distance_from_poa_document?: { direction: string; distance: number };
}

export interface DiditPOAGeoPoint extends DiditGeoPoint {
  distance_from_id_document?: { direction: string; distance: number };
  distance_from_ip?: { direction: string; distance: number };
}

/**
 * Raw Didit IP analysis node.
 *
 * Storage notes:
 *   is_vpn_or_tor  → split: is_vpn = is_vpn_or_tor, is_tor = is_vpn_or_tor
 *   is_data_center → is_hosting_provider
 *
 * CHANGES:
 *   + device_fingerprint: string | null  (null in all observed samples)
 *   + device_model: string | null        (null in all observed samples)
 *   + time_zone_offset: number           (samples show integer -8, was typed as string)
 *   + ip / id_document / poa_document    (typed explicitly; previously was
 *                                         locations_info?: DiditLocationsInfo which
 *                                         did not match the real payload shape)
 *   + Removed locations_info — it doesn't exist as a key in real payloads
 *   + ip_country_code confirmed required (string, always present in full payloads)
 */
export interface DiditRawIPAnalysis {
  node_id: string;
  status: DiditNodeStatus;
  device_brand?: string | null;
  device_model?: string | null; // null in all observed samples
  browser_family?: string | null;
  os_family?: string | null;
  platform?: string | null;
  device_fingerprint?: string | null; // null in all observed samples
  ip_address: string;
  ip_country: string;
  ip_country_code: string;
  ip_state?: string | null;
  ip_city?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  isp?: string | null;
  organization?: string | null;
  is_vpn_or_tor: boolean;
  is_data_center: boolean;
  time_zone?: string | null;
  time_zone_offset?: number; // Changed: number (integer), not string
  /** IP geolocation with distances to document locations */
  ip?: DiditIPGeoPoint;
  /** ID document address location with distances */
  id_document?: DiditDocumentGeoPoint;
  /** Proof-of-address document location with distances */
  poa_document?: DiditPOAGeoPoint;
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// SUPPLEMENTAL: AML SCREENING
// ─────────────────────────────────────────────

export interface DiditAMLRiskView {
  crimes: {
    score: number;
    weightage: number;
    risk_level: string;
    risk_scores: Record<string, number>;
  };
  countries: {
    score: number;
    weightage: number;
    risk_level: string;
    risk_scores: Record<string, number>;
  };
  categories: {
    score: number;
    weightage: number;
    risk_level: string;
    risk_scores: Record<string, number>;
  };
  custom_list?: Record<string, unknown>;
}

export interface DiditAMLHit {
  id: string;
  url?: string | null;
  match: boolean;
  score: number;
  target?: unknown | null; // present in sample (null)
  caption?: string | null;
  datasets: string[];
  features?: unknown | null; // Added: present in sample (null)
  rca_name?: string; // Added: present in sample (empty string)
  risk_view?: DiditAMLRiskView | null;
  first_seen?: ISODateTime | null;
  last_seen?: ISODateTime | null;
  match_score?: number;
  risk_score?: number; // Added: present in sample (73)
  review_status?: string | null; // Added: e.g. "False Positive"
  pep_matches?: {
    aliases: string[];
    list_name: string;
    publisher: string;
    source_url?: string; // Added: present in sample
    description?: string; // Added: present in sample
    matched_name: string;
    pep_position?: string;
    date_of_birth?: string;
    place_of_birth?: string;
    other_sources?: unknown[]; // Added: present in sample
    education?: unknown[]; // Added: present in sample
  }[];
  sanction_matches?: unknown[];
  warning_matches?: unknown[];
  linked_entities?: unknown[];
  score_breakdown?: {
    // Added: full block present in sample
    name_score: number;
    name_weight: number;
    name_weight_normalized: number;
    name_contribution: number;
    dob_score: number;
    dob_weight: number;
    dob_weight_normalized: number;
    dob_contribution: number;
    country_score: number;
    country_weight: number;
    country_weight_normalized: number;
    country_contribution: number;
    document_number_match_type: string;
    document_number_effect: string;
    total_score: number;
  };
  properties?: {
    name?: string[];
    alias?: string[];
    notes?: string[];
    title?: null;
    gender?: string[];
    country?: string[];
    lastName?: string[];
    position?: string[];
    birthDate?: string[];
    firstName?: string[];
    birthPlace?: string[];
    nationality?: string[];
    education?: unknown[];
    [key: string]: unknown;
  };
  adverse_media_details?: {
    sentiment: string;
    entity_type: string;
    sentiment_score: number;
    adverse_keywords: Record<string, number>;
  } | null;
  adverse_media_matches?: {
    country?: string;
    summary?: string;
    headline?: string;
    sentiment?: string;
    source_url?: string;
    adverse_keywords?: string[];
    sentiment_score?: number;
    publication_date?: ISODateTime;
  }[];
  additional_information?: {
    flag_summary?: unknown[]; // Added: present in sample
    [key: string]: unknown;
  } | null;
}

/**
 * Raw Didit AML screening node.
 *
 * Storage notes:
 *   hits[].datasets includes "PEP"      → is_pep = true
 *   hits[].datasets includes "SANCTION" → is_sanctioned = true
 *   hits[].match = true                 → confirmed match
 *   score                               → DiditAMLScreening.risk_score
 *   Raw hits are NOT stored — only the derived summary fields.
 *
 * CHANGES:
 *   + is_ongoing_monitoring_enabled: boolean  — Added: present in sample
 *   + next_ongoing_monitoring_bill_date: ISODateTime | null — Added: present in sample
 */
export interface DiditRawAMLScreening {
  node_id: string;
  status: DiditNodeStatus;
  total_hits: number;
  entity_type: "person" | "organization";
  hits: DiditAMLHit[];
  score: number;
  is_ongoing_monitoring_enabled?: boolean; // Added: present in sample
  next_ongoing_monitoring_bill_date?: ISODateTime | null; // Added: present in sample
  screened_data: {
    full_name?: string;
    nationality?: string;
    date_of_birth?: string;
    document_number?: string | null;
  };
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// DECISION OBJECT
// ─────────────────────────────────────────────

/**
 * Admin review entry on a decision.
 */
export interface DiditReview {
  user: string;
  new_status: DiditSessionStatus;
  comment?: string;
  created_at: ISODateTime;
}

/**
 * Full decision payload attached to terminal/review webhook events.
 *
 * CHANGES:
 *   + All node arrays typed as T[] | null — null is the real payload value when
 *     a stage is not part of the workflow (e.g. aml_screenings: null in Abandoned)
 *   + reviews typed as DiditReview[] | null ([] in samples, but null possible)
 *   + created_at: ISODateTime — this field on the decision object is an ISO string
 *     (e.g. "2022-01-01T12:00:00Z"), distinct from the root payload's Unix timestamp
 *   + session_url confirmed present (already was, just reinforced)
 *   + contact_details: typed structure (was Record<string,unknown> or absent)
 */
export interface DiditDecision {
  session_id: string;
  session_number: number;
  session_url: string;
  status: DiditSessionStatus;
  workflow_id: string;
  features: string[];
  vendor_data?: string | null;
  metadata?: Record<string, unknown> | null;
  expected_details?: {
    first_name?: string;
    last_name?: string;
  } | null;
  contact_details?: {
    email?: string;
    email_lang?: string;
    send_notification_emails?: boolean;
  } | null;
  callback?: string | null;

  // ── Your 5 workflow stages — null when stage not in workflow ────────────
  id_verifications?: DiditRawIDVerification[] | null;
  liveness_checks?: DiditRawLivenessCheck[] | null;
  face_matches?: DiditRawFaceMatch[] | null;
  phone_verifications?: DiditRawPhoneVerification[] | null;
  ip_analyses?: DiditRawIPAnalysis[] | null;

  // ── Supplemental — null when not enabled in workflow ────────────────────
  aml_screenings?: DiditRawAMLScreening[] | null;

  // ── Always present — empty array [] when no manual reviews ──────────────
  reviews?: DiditReview[] | null;

  /**
   * ISO 8601 string (e.g. "2022-01-01T12:00:00Z").
   * NOTE: This is different from the root payload's created_at which is a
   * Unix timestamp (number). Do not confuse the two.
   */
  created_at: ISODateTime;
}

// ─────────────────────────────────────────────
// RESUBMIT INFO
// ─────────────────────────────────────────────

/**
 * Present only on Resubmitted payloads.
 * Tells the client which nodes need to be redone and why.
 */
export interface DiditResubmitInfo {
  nodes_to_resubmit: Array<{
    feature: string; // e.g. "OCR"
    node_id: string; // e.g. "feature_ocr"
  }>;
  reasons: Record<string, string>; // e.g. { "feature_ocr": "DOCUMENT_EXPIRED" }
}

// ─────────────────────────────────────────────
// ROOT WEBHOOK PAYLOAD
// ─────────────────────────────────────────────

/**
 * Full Didit V3 webhook payload.
 *
 * `vendor_data` should equal MajikID.id — used to look up the record on receipt.
 *
 * Decision presence by status:
 *   WITH decision:    Approved, Declined, In Review, Abandoned, Expired, Kyc Expired
 *   WITHOUT decision: Not Started, In Progress, Resubmitted
 *
 * CHANGES:
 *   + DiditSessionStatus now includes "Kyc Expired" and "Resubmitted"
 *   + resubmit_info block added (only present on status = "Resubmitted")
 *   + vendor_data typed as string | null | undefined — observed absent on some
 *     Declined payloads (decision.vendor_data was null while root was missing)
 *   + created_at and timestamp are both Unix timestamps (number) at root level
 *     (distinct from decision.created_at which is an ISO string)
 */
export interface DiditWebhookPayload {
  session_id: string;
  status: DiditSessionStatus;
  webhook_type: DiditWebhookType;

  /**
   * Unix epoch seconds — when the session was created.
   * NOTE: Use timestamp (not created_at) for HMAC age verification.
   */
  created_at: UnixTimestamp;

  /**
   * Unix epoch seconds — used for HMAC signature freshness check.
   * Reject if Math.abs(now - timestamp) > 300 (5 minutes).
   */
  timestamp: UnixTimestamp;

  workflow_id: string;
  workflow_version?: number;

  /**
   * Should equal MajikUniversalID.id — set as vendor_data when creating the session.
   * Absent (undefined) on early lifecycle events (Not Started, In Progress).
   * null on some Declined payloads at decision level — treat missing as unroutable.
   */
  vendor_data?: string | null;

  metadata?: Record<string, unknown> | null;

  /**
   * Only present on status = "Resubmitted".
   * Tells the client which nodes must be resubmitted and the reason codes.
   */
  resubmit_info?: DiditResubmitInfo;

  /**
   * Full decision block.
   * Present on: Approved, Declined, In Review, Abandoned, Expired, Kyc Expired
   * Absent on:  Not Started, In Progress, Resubmitted
   */
  decision?: DiditDecision;
}

// ─────────────────────────────────────────────
// WEBHOOK HEADERS
// ─────────────────────────────────────────────

export interface DiditWebhookHeaders {
  "x-signature-v2"?: string; // Recommended — HMAC-SHA256 of body
  "x-signature-simple"?: string; // Fallback
  "x-signature"?: string; // Original (raw body)
  "x-timestamp": string; // Unix timestamp string — used for HMAC freshness
}

// ─────────────────────────────────────────────
// MAPPER TYPES
// ─────────────────────────────────────────────

export interface DiditMapperContext {
  verification_id: string;
  majik_id: string;
  user_id: string;
  existing?: DiditVerification;
}

export interface DiditMapperResult {
  verification: DiditVerification;

  /**
   * Flattened personal data from Stage 1.
   * All values raw — class layer normalizes before storage.
   */
  extracted_personal_data: {
    first_name?: string;
    last_name?: string;
    full_name?: string;
    date_of_birth?: string;
    place_of_birth?: string;
    gender_raw?: string;
    nationality_alpha3?: string;
    issuing_country_alpha3?: string;
    document_type_raw?: string;
    document_number?: string; // SENSITIVE — encrypt before storing
    personal_number?: string; // SENSITIVE — encrypt before storing
    marital_status?: string;
    phone_number_e164?: string;
    parsed_address?: {
      street_1?: string;
      street_2?: string | null;
      city?: string;
      region?: string;
      postal_code?: string;
      country_alpha2?: string;
    };
  };

  /**
   * Image URLs from the payload.
   * MUST be SHA3-512 hashed and discarded — never stored as-is.
   */
  image_urls_to_hash: {
    portrait_image?: string;
    front_image?: string;
    back_image?: string;
    reference_image?: string;
  };

  session_meta: {
    session_id: string;
    session_url: string;
    didit_reference_id: string;
    status: DiditSessionStatus;
    created_at: ISODateTime;
  };

  is_terminal: boolean;
  all_stages_passed: boolean;
  updated_stages: DiditStage[];
}

/**
 * Interface contract for the mapper class.
 * Each stage method is exposed individually for unit testing.
 */
export interface DiditWebhookMapperInterface {
  map(
    payload: DiditWebhookPayload,
    context: DiditMapperContext,
  ): DiditMapperResult | null;
  mapIDVerification(raw: DiditRawIDVerification): DiditIDVerification;
  mapLiveness(
    raw: DiditRawLivenessCheck,
    portraitImageHash?: SHA3_512Hash,
  ): DiditLiveness;
  mapFaceMatch(raw: DiditRawFaceMatch): DiditFaceMatch;
  mapPhoneVerification(raw: DiditRawPhoneVerification): DiditPhoneVerification;
  mapIPAnalysis(raw: DiditRawIPAnalysis): DiditIPAnalysis;
  mapAMLScreening(raw: DiditRawAMLScreening): DiditAMLScreening;
}
