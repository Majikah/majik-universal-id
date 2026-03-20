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

export type DiditSessionStatus =
  | "Not Started"
  | "In Progress"
  | "In Review"
  | "Approved"
  | "Declined"
  | "Abandoned"
  | "Expired";

export type DiditNodeStatus =
  | "Approved"
  | "Declined"
  | "In Review"
  | "Not Started"
  | "In Progress";

export type DiditWebhookType = "status.updated" | "data.updated";

export interface DiditWarning {
  risk: string;
  additional_data: unknown | null;
  log_type: "information" | "warning" | "error";
  short_description: string;
  long_description: string;
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
 */
export interface DiditRawIDVerification {
  node_id: string;
  status: DiditNodeStatus;
  document_type: string;
  document_number: string; // SENSITIVE — encrypt at rest
  personal_number?: string; // SENSITIVE — encrypt at rest
  portrait_image?: string; // DO NOT store — hash only
  front_image?: string; // DO NOT store — hash only
  front_video?: string;
  back_image?: string; // DO NOT store — hash only
  back_video?: string;
  full_front_image?: string;
  full_back_image?: string;
  front_image_camera_front?: string;
  back_image_camera_front?: string;
  date_of_birth?: string; // "YYYY-MM-DD"
  age?: number;
  expiration_date?: string;
  date_of_issue?: string;
  issuing_state?: string; // ISO 3166-1 alpha-3, e.g. "ESP"
  issuing_state_name?: string;
  first_name?: string;
  last_name?: string;
  full_name?: string;
  gender?: string; // "F" | "M" | "X"
  address?: string;
  formatted_address?: string;
  place_of_birth?: string;
  marital_status?: string;
  nationality?: string; // ISO 3166-1 alpha-3, e.g. "ESP"
  extra_fields?: {
    dl_categories?: string[];
    blood_group?: string | null;
    [key: string]: unknown;
  };
  parsed_address?: DiditParsedAddress;
  front_image_camera_front_face_match_score?: number;
  back_image_camera_front_face_match_score?: number;
  front_image_quality_score?: DiditImageQualityScore;
  back_image_quality_score?: DiditImageQualityScore;
  extra_files?: string[];
  warnings: DiditWarning[];
  matches?: DiditIDVerificationMatch[];
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
 */
export interface DiditRawLivenessCheck {
  node_id: string;
  status: DiditNodeStatus;
  method: string; // e.g. "ACTIVE_3D", "PASSIVE"
  score: number; // 0–100
  reference_image?: string; // DO NOT store — hash only
  video_url?: string;
  age_estimation?: number;
  matches?: unknown[];
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
 */
export interface DiditRawFaceMatch {
  node_id: string;
  status: DiditNodeStatus;
  score: number; // 0–100
  source_image?: string; // DO NOT store
  target_image?: string; // DO NOT store
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
 */
export interface DiditRawPhoneVerification {
  node_id: string;
  status: DiditNodeStatus;
  phone_number_prefix: string;
  phone_number: string;
  full_number: E164Phone;
  country_code: string;
  country_name: string;
  carrier?: DiditPhoneCarrier;
  is_disposable: boolean;
  is_virtual: boolean;
  verification_method: "sms" | "call";
  verification_attempts: number;
  verified_at?: ISODateTime;
  lifecycle?: DiditPhoneLifecycleEvent[];
  warnings: DiditWarning[];
}

// ─────────────────────────────────────────────
// STAGE 5: IP_ANALYSIS
// ─────────────────────────────────────────────

export interface DiditLocationPoint {
  location: { latitude: number; longitude: number };
  distance_from_id_document?: number; // km
  distance_from_poa_document?: number; // km
  distance_from_ip?: number; // km
}

export interface DiditLocationsInfo {
  ip?: DiditLocationPoint;
  id_document?: DiditLocationPoint;
  poa_document?: DiditLocationPoint;
}

/**
 * Raw Didit IP analysis node.
 *
 * Storage notes:
 *   is_vpn_or_tor  → split: is_vpn = is_vpn_or_tor, is_tor = is_vpn_or_tor
 *                    (Didit combines these — store both as same value)
 *   is_data_center → is_hosting_provider
 */
export interface DiditRawIPAnalysis {
  node_id: string;
  status: DiditNodeStatus;
  device_brand?: string;
  device_model?: string;
  browser_family?: string;
  os_family?: string;
  platform?: string;
  device_fingerprint?: string;
  ip_address: string;
  ip_country: string;
  ip_country_code: string;
  ip_state?: string;
  ip_city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string | null;
  organization?: string | null;
  is_vpn_or_tor: boolean;
  is_data_center: boolean;
  time_zone?: string;
  time_zone_offset?: string;
  locations_info?: DiditLocationsInfo;
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
  url?: string;
  match: boolean;
  score: number;
  caption?: string;
  datasets: string[];
  risk_view?: DiditAMLRiskView;
  first_seen?: ISODateTime;
  last_seen?: ISODateTime;
  match_score?: number;
  pep_matches?: {
    aliases: string[];
    list_name: string;
    publisher: string;
    matched_name: string;
    pep_position?: string;
    date_of_birth?: string;
    place_of_birth?: string;
  }[];
  sanction_matches?: unknown[];
  warning_matches?: unknown[];
  properties?: Record<string, unknown>;
  linked_entities?: unknown[];
  adverse_media_details?: {
    sentiment: string;
    entity_type: string;
    sentiment_score: number;
    adverse_keywords: Record<string, number>;
  };
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
  additional_information?: Record<string, unknown>;
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
 */
export interface DiditRawAMLScreening {
  node_id: string;
  status: DiditNodeStatus;
  total_hits: number;
  entity_type: "person" | "organization";
  hits: DiditAMLHit[];
  score: number;
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

export interface DiditDecision {
  session_id: string;
  session_number: number;
  session_url: string;
  status: DiditSessionStatus;
  workflow_id: string;
  features: string[];
  vendor_data?: string;
  metadata?: Record<string, unknown>;
  expected_details?: {
    first_name?: string;
    last_name?: string;
  };
  contact_details?: {
    email?: string;
    email_lang?: string;
    send_notification_emails?: boolean;
  };
  callback?: string;

  // ── Your 5 workflow stages ───────────────────
  id_verifications?: DiditRawIDVerification[];
  liveness_checks?: DiditRawLivenessCheck[];
  face_matches?: DiditRawFaceMatch[];
  phone_verifications?: DiditRawPhoneVerification[];
  ip_analyses?: DiditRawIPAnalysis[];

  // ── Supplemental ─────────────────────────────
  aml_screenings?: DiditRawAMLScreening[];

  reviews?: {
    user: string;
    new_status: DiditSessionStatus;
    comment?: string;
    created_at: ISODateTime;
  }[];

  created_at: ISODateTime;
}

// ─────────────────────────────────────────────
// ROOT WEBHOOK PAYLOAD
// ─────────────────────────────────────────────

/**
 * Full Didit V3 webhook payload.
 * `vendor_data` should equal MajikID.id — used to look up the record on receipt.
 * `decision` is only present when status ∈ { Approved, Declined, In Review }.
 */
export interface DiditWebhookPayload {
  session_id: string;
  status: DiditSessionStatus;
  webhook_type: DiditWebhookType;
  created_at: UnixTimestamp; // Unix epoch seconds
  timestamp: UnixTimestamp; // for HMAC verification
  workflow_id: string;
  workflow_version?: number;
  vendor_data?: string; // should equal MajikID.id
  metadata?: Record<string, unknown>;
  decision?: DiditDecision;
}

// ─────────────────────────────────────────────
// WEBHOOK HEADERS
// ─────────────────────────────────────────────

export interface DiditWebhookHeaders {
  "x-signature-v2"?: string; // recommended
  "x-signature-simple"?: string; // fallback
  "x-signature"?: string; // original (raw body)
  "x-timestamp": string; // Unix timestamp string
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
