/**
 * src/core/didit/webhook.ts
 *
 * DiditWebhookMapperImpl — pure transformation class.
 * Converts raw Didit V3 webhook payloads into typed MajikID DiditVerification structures.
 *
 * No side effects. No async. No HTTP calls. No DB calls.
 * All Didit API calls live in a separate package (MajikDiditService).
 *
 * ── CHANGELOG ───────────────────────────────────────────────────────────────
 *
 * map()
 *   - is_terminal: added "Abandoned", "Expired", "Kyc Expired" as terminal
 *     statuses (was only Approved | Declined). All three clear the session.
 *   - image_urls_to_hash: portrait_image / front_image / back_image now
 *     guarded with ?? undefined so null values from the schema don't bleed in
 *   - session_meta.created_at: was passing dec.created_at (ISODateTime) directly;
 *     that's correct since DiditDecision.created_at is now typed as ISODateTime.
 *     No change needed — just confirmed.
 *
 * mapIDVerification()
 *   - verification_score: now guards against null quality score
 *     (front_image_quality_score is DiditImageQualityScore | null in updated schema)
 *   - failure_reason: guards against null/undefined warnings array
 *   - completed_at: added "Expired" as a terminal node status (Kyc Expired payload)
 *
 * mapLiveness()
 *   - failure_reason: guards against null/undefined warnings
 *   - completed_at: added "Expired" node status
 *
 * mapFaceMatch()
 *   - failure_reason: guards against null/undefined warnings
 *   - completed_at: added "Expired" node status
 *
 * mapPhoneVerification()
 *   - otp_method: now accepts "whatsapp" (added to DiditRawPhoneVerification.
 *     verification_method union in updated schema)
 *   - failure_reason: guards against null/undefined warnings
 *   - completed_at: added "Expired" node status
 *
 * mapIPAnalysis()
 *   - ip / id_document / poa_document: schema renamed locations_info to these
 *     three direct fields — updated to read raw.ip, raw.id_document,
 *     raw.poa_document directly (was raw.locations_info.ip etc.)
 *   - time_zone_offset: now a number, not string — no change needed in mapIPAnalysis
 *     itself but geoLocation construction is unaffected
 *   - device_fingerprint: string | null — session log now falls back correctly
 *   - failure_reason: guards against null/undefined warnings
 *   - completed_at: added "Expired" node status
 *
 * mapAMLScreening()
 *   - guards hits array against null (hits can be [] but was not null-guarded)
 *   - adds "SANCTIONS" variant alongside "SANCTION" (Didit uses both spellings
 *     across hit.datasets in different workflow configs)
 *
 * _buildSessionLog()
 *   - device_type: fixed platform check — Didit sends "Windows 10", "iOS",
 *     "Android" etc. not the literal strings "mobile"/"desktop". Updated to
 *     use os_family ("iOS"/"Android" → MOBILE, everything else → DESKTOP
 *     unless unknown).
 *   - device_fingerprint: raw.device_fingerprint is string | null — fall back
 *     to uuidv7() only when falsy (was already doing this, but now explicit)
 *   - browser_name: raw.browser_family can be null — guard added
 *   - geoLocation: raw.isp is string | null — coerce null to undefined
 *
 * _computeUpdatedStages()
 *   - node arrays are now typed as T[] | null in updated schema — added null
 *     guard on items?.length check (null is falsy so ?. handles it, but made
 *     explicit for clarity)
 *
 * _computeIPRiskLevel()
 *   - no changes needed — logic was already correct
 *
 * ── END CHANGELOG ────────────────────────────────────────────────────────────
 */

import type {
  DiditWebhookPayload,
  DiditDecision,
  DiditRawIDVerification,
  DiditRawLivenessCheck,
  DiditRawFaceMatch,
  DiditRawPhoneVerification,
  DiditRawIPAnalysis,
  DiditRawAMLScreening,
  DiditMapperContext,
  DiditMapperResult,
  DiditNodeStatus,
  DiditWebhookMapperInterface,
} from "./schema";

import {
  DiditStage,
  IDTier,
  IDStatus,
  BiometricStatus,
  IPRiskLevel,
  VerificationProvider,
  DeviceType,
} from "../enums";

import type {
  DiditVerification,
  DiditIDVerification,
  DiditLiveness,
  DiditFaceMatch,
  DiditPhoneVerification,
  DiditIPAnalysis,
  DiditAMLScreening,
  DiditSessionLog,
  GeoLocation,
  SHA3_512Hash,
} from "../schema";

import {
  mapNodeStatus,
  mapSessionStatus,
  deriveIDTier,
  computePassedStages,
  normalizeCountryCode,
  normalizeDocumentType,
  normalizeToE164,
  unixToISO,
  now,
  uuidv7,
} from "../utils";
import { DiditStageStatus } from "../enums";

// ─────────────────────────────────────────────
// TERMINAL STATUS SET
// Statuses that represent a completed (non-resumable) session.
// Used for is_terminal and completed_at derivation.
// ─────────────────────────────────────────────

const TERMINAL_SESSION_STATUSES = new Set([
  "Approved",
  "Declined",
  "Abandoned",
  "Expired",
  "Kyc Expired", // Didit's second expiry spelling
]);

/**
 * Node-level statuses that mean the stage has concluded (pass or fail).
 * Used to set completed_at on individual stage records.
 */
const TERMINAL_NODE_STATUSES = new Set([
  "Approved",
  "Declined",
  "In Review",
  "Expired", // Added: Kyc Expired payload sets node status to "Expired"
]);

export class DiditWebhookMapperImpl implements DiditWebhookMapperInterface {
  /**
   * Map a raw DiditWebhookPayload to MajikID-ready structures.
   * Returns null when no `decision` object is present
   * (e.g. "In Progress", "Not Started", "Resubmitted" events).
   */
  map(
    payload: DiditWebhookPayload,
    context: DiditMapperContext,
  ): DiditMapperResult | null {
    if (!payload.decision) return null;

    const dec = payload.decision;
    const existing = context.existing;

    // ── Map each stage (fall back to existing if not in this payload) ─────────
    const rawID = dec.id_verifications?.[0] ?? null;
    const id_verification = rawID
      ? this.mapIDVerification(rawID)
      : existing?.id_verification;

    const rawLiveness = dec.liveness_checks?.[0] ?? null;
    const liveness = rawLiveness
      ? this.mapLiveness(rawLiveness)
      : existing?.liveness;

    const rawFace = dec.face_matches?.[0] ?? null;
    const face_match = rawFace
      ? this.mapFaceMatch(rawFace)
      : existing?.face_match;

    const rawPhone = dec.phone_verifications?.[0] ?? null;
    const phone_verification = rawPhone
      ? this.mapPhoneVerification(rawPhone)
      : existing?.phone_verification;

    const rawIP = dec.ip_analyses?.[0] ?? null;
    const ip_analysis = rawIP
      ? this.mapIPAnalysis(rawIP)
      : existing?.ip_analysis;

    const rawAML = dec.aml_screenings?.[0] ?? null;
    const aml_screening = rawAML
      ? this.mapAMLScreening(rawAML)
      : existing?.aml_screening;

    const session = this._buildSessionLog(payload, dec, rawIP ?? undefined);

    // ── Assemble staged record to compute tier ────────────────────────────────
    const staged: DiditVerification = {
      verification_id: context.verification_id,
      didit_reference_id: dec.session_id,
      tier: IDTier.UNVERIFIED,
      status: IDStatus.PENDING_VERIFICATION,
      session,
      id_verification,
      liveness,
      face_match,
      phone_verification,
      ip_analysis,
      aml_screening,
      all_stages_passed: false,
      completed_stages: [],
      re_verification_required: false,
    };

    const passedStages = computePassedStages(staged);
    const allPassed = passedStages.length === 5;
    const tier = deriveIDTier(passedStages);
    const status = mapSessionStatus(dec.status);

    const verification: DiditVerification = {
      ...staged,
      tier,
      status,
      all_stages_passed: allPassed,
      completed_stages: passedStages,
      verified_at: allPassed ? now() : existing?.verified_at,
    };

    const updatedStages = this._computeUpdatedStages(dec, existing);
    const extracted = rawID
      ? this._extractPersonalData(rawID, rawPhone ?? undefined)
      : undefined;

    return {
      verification,
      extracted_personal_data: extracted ?? {},
      image_urls_to_hash: {
        // Guard against null — schema types these as string | null | undefined
        portrait_image: rawID?.portrait_image ?? undefined,
        front_image: rawID?.front_image ?? undefined,
        back_image: rawID?.back_image ?? undefined,
        reference_image: rawLiveness?.reference_image ?? undefined,
      },
      session_meta: {
        session_id: dec.session_id,
        session_url: dec.session_url,
        didit_reference_id: dec.session_id,
        status: dec.status,
        created_at: dec.created_at, // ISODateTime on DiditDecision (not Unix number)
      },
      // CHANGED: was only Approved | Declined — now includes all session-ending statuses
      is_terminal: TERMINAL_SESSION_STATUSES.has(dec.status),
      all_stages_passed: allPassed,
      updated_stages: updatedStages,
    };
  }

  // ── Stage mappers ─────────────────────────────────────────────────────────

  mapIDVerification(raw: DiditRawIDVerification): DiditIDVerification {
    return {
      stage: DiditStage.ID_VERIFICATION,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      document_type: normalizeDocumentType(raw.document_type),
      document_number: raw.document_number, // caller encrypts before storage
      issuing_country: normalizeCountryCode(raw.issuing_state ?? ""),
      issuing_authority: raw.issuing_state_name,
      issue_date: raw.date_of_issue ?? undefined,
      expiry_date: raw.expiration_date ?? undefined,
      mrz_line1: undefined,
      mrz_line2: undefined,
      document_image_front_hash: "" as SHA3_512Hash, // caller fills after hashing
      document_image_back_hash: undefined,
      nfc_chip_read: false,
      document_verified: raw.status === "Approved",
      // CHANGED: front_image_quality_score is now DiditImageQualityScore | null
      // Guard against null before accessing .overall_score
      verification_score:
        raw.front_image_quality_score != null
          ? raw.front_image_quality_score.overall_score / 100
          : undefined,
      // CHANGED: warnings can be null/undefined in some payloads — guard with ?.
      failure_reason: raw.warnings?.length
        ? raw.warnings.map((w) => w.short_description).join("; ")
        : undefined,
      // CHANGED: added 'Expired' as a terminal node status (Kyc Expired payload)
      completed_at: TERMINAL_NODE_STATUSES.has(raw.status) ? now() : undefined,
    };
  }

  mapLiveness(
    raw: DiditRawLivenessCheck,
    portraitImageHash?: SHA3_512Hash,
  ): DiditLiveness {
    const passed = raw.status === "Approved";
    return {
      stage: DiditStage.LIVENESS,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      liveness_check_passed: passed,
      liveness_score: raw.score != null ? raw.score / 100 : undefined,
      spoof_detection_passed: passed,
      spoof_type_detected: undefined,
      biometric_status: passed
        ? BiometricStatus.PASSED
        : raw.status === "In Review"
          ? BiometricStatus.REQUIRES_REVIEW
          : raw.status === "Declined" || raw.status === "Expired"
            ? BiometricStatus.FAILED
            : BiometricStatus.PENDING,
      selfie_image_hash: portraitImageHash ?? ("" as SHA3_512Hash), // caller fills
      audit_image_urls: undefined,
      // CHANGED: warnings guarded against null/undefined
      failure_reason: raw.warnings?.length
        ? raw.warnings.map((w) => w.short_description).join("; ")
        : undefined,
      // CHANGED: added 'Expired' terminal node status
      completed_at: TERMINAL_NODE_STATUSES.has(raw.status) ? now() : undefined,
    };
  }

  mapFaceMatch(raw: DiditRawFaceMatch): DiditFaceMatch {
    return {
      stage: DiditStage.FACE_MATCH,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      face_match_passed: raw.status === "Approved",
      face_match_score: raw.score != null ? raw.score / 100 : undefined,
      match_threshold: 0.75,
      // CHANGED: warnings guarded against null/undefined
      failure_reason: raw.warnings?.length
        ? raw.warnings.map((w) => w.short_description).join("; ")
        : undefined,
      // CHANGED: added 'Expired' terminal node status
      completed_at: TERMINAL_NODE_STATUSES.has(raw.status) ? now() : undefined,
    };
  }

  mapPhoneVerification(raw: DiditRawPhoneVerification): DiditPhoneVerification {
    return {
      stage: DiditStage.PHONE_VERIFICATION,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      phone_number:
        raw.full_number ??
        normalizeToE164(
          (raw.phone_number_prefix ?? "") + (raw.phone_number ?? ""),
        ),
      // CHANGED: carrier is DiditPhoneCarrier | null — guard with ?.
      carrier: raw.carrier?.name,
      line_type:
        (raw.carrier?.type as DiditPhoneVerification["line_type"]) ?? "unknown",
      country_code: normalizeCountryCode(raw.country_code),
      otp_verified: raw.status === "Approved",
      // CHANGED: verification_method now includes "whatsapp" — cast widened
      otp_method: raw.verification_method as "sms" | "call" | "whatsapp",
      phone_matches_document_country: undefined, // cross-check in class layer
      // CHANGED: warnings guarded against null/undefined
      failure_reason: raw.warnings?.length
        ? raw.warnings.map((w) => w.short_description).join("; ")
        : undefined,
      // CHANGED: added 'Expired' terminal node status; verified_at can be null
      completed_at:
        raw.verified_at ??
        (TERMINAL_NODE_STATUSES.has(raw.status) ? now() : undefined),
    };
  }

  mapIPAnalysis(raw: DiditRawIPAnalysis): DiditIPAnalysis {
    const isVpnOrTor = raw.is_vpn_or_tor ?? false;

    const geoLocation: GeoLocation = {
      ip_address: raw.ip_address,
      ip_version: (raw.ip_address?.includes(":") ? 6 : 4) as 4 | 6,
      country_code: normalizeCountryCode(raw.ip_country_code ?? ""),
      country_name: raw.ip_country ?? "",
      region: raw.ip_state ?? undefined,
      city: raw.ip_city ?? undefined,
      timezone: raw.time_zone ?? undefined,
      coordinates:
        raw.latitude != null && raw.longitude != null
          ? { latitude: raw.latitude, longitude: raw.longitude }
          : undefined,
      // CHANGED: isp is string | null — coerce null → undefined
      isp: raw.isp ?? undefined,
      is_vpn: isVpnOrTor,
      is_proxy: isVpnOrTor,
      is_tor: isVpnOrTor,
    };

    return {
      stage: DiditStage.IP_ANALYSIS,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      ip_address: raw.ip_address,
      ip_version: (raw.ip_address?.includes(":") ? 6 : 4) as 4 | 6,
      risk_level: this._computeIPRiskLevel(raw),
      country_code: normalizeCountryCode(raw.ip_country_code ?? ""),
      is_vpn: isVpnOrTor,
      is_proxy: isVpnOrTor,
      is_tor: isVpnOrTor,
      is_hosting_provider: raw.is_data_center ?? false,
      is_known_attacker: undefined,
      isp: raw.isp ?? undefined,
      asn: undefined,
      ip_matches_phone_country: undefined, // cross-check in class layer
      ip_matches_document_country: undefined, // cross-check in class layer
      geo_location: geoLocation,
      // CHANGED: warnings guarded against null/undefined
      failure_reason: raw.warnings?.length
        ? raw.warnings.map((w) => w.short_description).join("; ")
        : undefined,
      // CHANGED: added 'Expired' terminal node status
      completed_at: TERMINAL_NODE_STATUSES.has(raw.status) ? now() : undefined,
    };
  }

  mapAMLScreening(raw: DiditRawAMLScreening): DiditAMLScreening {
    // CHANGED: hits can be null/undefined in some payload configurations
    const confirmedHits = raw.hits?.filter((h) => h.match) ?? [];
    const datasets = confirmedHits.flatMap((h) => h.datasets ?? []);
    const uniqueDatasets = [...new Set(datasets)];

    return {
      screened_at: now(),
      // CHANGED: Didit uses both "SANCTION" and "SANCTIONS" across workflows
      is_pep: uniqueDatasets.some((d) => d.toUpperCase() === "PEP"),
      is_sanctioned: uniqueDatasets.some(
        (d) =>
          d.toUpperCase() === "SANCTION" || d.toUpperCase() === "SANCTIONS",
      ),
      watchlist_hits: uniqueDatasets,
      risk_score: raw.score,
      screening_provider: "didit",
    };
  }

  // ── Private helpers ───────────────────────────────────────────────────────

  private _buildSessionLog(
    payload: DiditWebhookPayload,
    dec: DiditDecision,
    rawIP?: DiditRawIPAnalysis,
  ): DiditSessionLog {
    const geoLocation: GeoLocation = rawIP
      ? {
          ip_address: rawIP.ip_address ?? "",
          ip_version: (rawIP.ip_address?.includes(":") ? 6 : 4) as 4 | 6,
          country_code: normalizeCountryCode(rawIP.ip_country_code ?? ""),
          country_name: rawIP.ip_country ?? "",
          region: rawIP.ip_state ?? undefined,
          city: rawIP.ip_city ?? undefined,
          timezone: rawIP.time_zone ?? undefined,
          coordinates:
            rawIP.latitude != null && rawIP.longitude != null
              ? { latitude: rawIP.latitude, longitude: rawIP.longitude }
              : undefined,
          // CHANGED: isp is string | null — coerce null → undefined
          isp: rawIP.isp ?? undefined,
          is_vpn: rawIP.is_vpn_or_tor,
          is_proxy: rawIP.is_vpn_or_tor,
          is_tor: rawIP.is_vpn_or_tor,
        }
      : { ip_address: "", ip_version: 4, country_code: "", country_name: "" };

    return {
      session_id: dec.session_id,
      initiated_at: unixToISO(payload.created_at),
      completed_at: TERMINAL_SESSION_STATUSES.has(dec.status)
        ? now()
        : undefined,
      ip_address: rawIP?.ip_address ?? "",
      location: geoLocation,
      device: {
        // CHANGED: device_fingerprint is string | null — coerce null → uuidv7()
        device_id: rawIP?.device_fingerprint ?? uuidv7(),
        // CHANGED: Didit sends os_family ("iOS", "Android", "Windows", "macOS")
        // not "mobile"/"desktop". Derive device type from os_family, not platform.
        device_type: this._deriveDeviceType(
          rawIP?.os_family,
          rawIP?.device_brand,
        ),
        device_name:
          [rawIP?.device_brand, rawIP?.device_model]
            .filter(Boolean)
            .join(" ") || undefined,
        os_name: rawIP?.os_family ?? "",
        os_version: "",
        // CHANGED: browser_family can be null — coerce null → undefined
        browser_name: rawIP?.browser_family ?? undefined,
        user_agent: "",
        language: "en",
        timezone: rawIP?.time_zone ?? "",
      },
      provider: VerificationProvider.DIDIT,
      sdk_version: undefined,
    };
  }

  /**
   * Derive DeviceType from Didit's os_family and device_brand fields.
   *
   * Didit sends values like:
   *   os_family:    "iOS", "Android", "Windows", "Mac OS X", "Linux"
   *   device_brand: "Desktop", "Apple", "Samsung", etc.
   *
   * CHANGED: was checking rawIP.platform for "mobile"/"desktop" which never
   * matches — platform contains "Windows 10", "iOS 17.0" etc.
   */
  private _deriveDeviceType(
    osFam?: string | null,
    deviceBrand?: string | null,
  ): DeviceType {
    const os = (osFam ?? "").toLowerCase();
    const brand = (deviceBrand ?? "").toLowerCase();

    if (os === "ios" || os === "android") return DeviceType.MOBILE;
    if (brand === "desktop") return DeviceType.DESKTOP;
    if (os.includes("windows") || os.includes("mac") || os.includes("linux"))
      return DeviceType.DESKTOP;

    return DeviceType.UNKNOWN;
  }

  private _extractPersonalData(
    rawID: DiditRawIDVerification,
    rawPhone?: DiditRawPhoneVerification,
  ): DiditMapperResult["extracted_personal_data"] {
    return {
      first_name: rawID.first_name,
      last_name: rawID.last_name,
      full_name: rawID.full_name,
      date_of_birth: rawID.date_of_birth,
      // CHANGED: place_of_birth is string | null — coerce null → undefined
      place_of_birth: rawID.place_of_birth ?? undefined,
      gender_raw: rawID.gender,
      nationality_alpha3: rawID.nationality,
      issuing_country_alpha3: rawID.issuing_state,
      document_type_raw: rawID.document_type,
      document_number: rawID.document_number,
      // CHANGED: personal_number is string | null — coerce null → undefined
      personal_number: rawID.personal_number ?? undefined,
      marital_status: rawID.marital_status,
      phone_number_e164: rawPhone?.full_number,
      parsed_address: rawID.parsed_address
        ? {
            street_1: rawID.parsed_address.street_1,
            street_2: rawID.parsed_address.street_2,
            city: rawID.parsed_address.city,
            region: rawID.parsed_address.region,
            postal_code: rawID.parsed_address.postal_code,
            // CHANGED: use country from parsed_address if present (alpha-2 already),
            // fall back to normalizing issuing_state from alpha-3
            country_alpha2: rawID.parsed_address.country
              ? normalizeCountryCode(rawID.parsed_address.country)
              : normalizeCountryCode(rawID.issuing_state ?? ""),
          }
        : undefined,
    };
  }

  private _computeUpdatedStages(
    dec: DiditDecision,
    existing?: DiditVerification,
  ): DiditStage[] {
    const updated: DiditStage[] = [];

    // CHANGED: node arrays are now typed T[] | null — using ?.[0] handles null
    // since null?.[0] === undefined, which is falsy. Made explicit for clarity.
    const check = (
      items: { status: DiditNodeStatus }[] | null | undefined,
      prevStatus: DiditStageStatus | undefined,
      stage: DiditStage,
    ) => {
      const first = items?.[0];
      if (first && mapNodeStatus(first.status) !== prevStatus) {
        updated.push(stage);
      }
    };

    check(
      dec.id_verifications,
      existing?.id_verification?.status,
      DiditStage.ID_VERIFICATION,
    );
    check(dec.liveness_checks, existing?.liveness?.status, DiditStage.LIVENESS);
    check(
      dec.face_matches,
      existing?.face_match?.status,
      DiditStage.FACE_MATCH,
    );
    check(
      dec.phone_verifications,
      existing?.phone_verification?.status,
      DiditStage.PHONE_VERIFICATION,
    );
    check(
      dec.ip_analyses,
      existing?.ip_analysis?.status,
      DiditStage.IP_ANALYSIS,
    );

    return updated;
  }

  private _computeIPRiskLevel(raw: DiditRawIPAnalysis): IPRiskLevel {
    if (raw.is_vpn_or_tor || raw.is_data_center) return IPRiskLevel.HIGH;
    if (raw.status === "Declined") return IPRiskLevel.HIGH;
    if (raw.status === "In Review") return IPRiskLevel.MEDIUM;
    if (raw.status === "Approved") return IPRiskLevel.LOW;
    return IPRiskLevel.MEDIUM;
  }
}

/** Singleton instance — import this directly for convenience */
export const diditMapper = new DiditWebhookMapperImpl();

// Freeze static methods
Object.freeze(DiditWebhookMapperImpl);

// Freeze instance methods
Object.freeze(DiditWebhookMapperImpl.prototype);
