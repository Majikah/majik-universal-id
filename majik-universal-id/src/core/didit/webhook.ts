/**
 * src/core/didit/webhook.ts
 *
 * DiditWebhookMapperImpl — pure transformation class.
 * Converts raw Didit V3 webhook payloads into typed MajikID DiditVerification structures.
 *
 * No side effects. No async. No HTTP calls. No DB calls.
 * All Didit API calls live in a separate package (MajikDiditService).
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
} from "../schema";

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

export class DiditWebhookMapperImpl implements DiditWebhookMapperInterface {
  /**
   * Map a raw DiditWebhookPayload to MajikID-ready structures.
   * Returns null when no `decision` object is present
   * (e.g. "In Progress", "Not Started" events).
   */
  map(
    payload: DiditWebhookPayload,
    context: DiditMapperContext,
  ): DiditMapperResult | null {
    if (!payload.decision) return null;

    const dec = payload.decision;
    const existing = context.existing;

    // ── Map each stage (fall back to existing if not in this payload) ─────────
    const rawID = dec.id_verifications?.[0];
    const id_verification = rawID
      ? this.mapIDVerification(rawID)
      : existing?.id_verification;

    const rawLiveness = dec.liveness_checks?.[0];
    const liveness = rawLiveness
      ? this.mapLiveness(rawLiveness)
      : existing?.liveness;

    const rawFace = dec.face_matches?.[0];
    const face_match = rawFace
      ? this.mapFaceMatch(rawFace)
      : existing?.face_match;

    const rawPhone = dec.phone_verifications?.[0];
    const phone_verification = rawPhone
      ? this.mapPhoneVerification(rawPhone)
      : existing?.phone_verification;

    const rawIP = dec.ip_analyses?.[0];
    const ip_analysis = rawIP
      ? this.mapIPAnalysis(rawIP)
      : existing?.ip_analysis;

    const rawAML = dec.aml_screenings?.[0];
    const aml_screening = rawAML
      ? this.mapAMLScreening(rawAML)
      : existing?.aml_screening;

    const session = this._buildSessionLog(payload, dec, rawIP);

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
      ? this._extractPersonalData(rawID, rawPhone)
      : undefined;

    return {
      verification,
      extracted_personal_data: extracted ?? {},
      image_urls_to_hash: {
        portrait_image: rawID?.portrait_image,
        front_image: rawID?.front_image,
        back_image: rawID?.back_image,
        reference_image: rawLiveness?.reference_image,
      },
      session_meta: {
        session_id: dec.session_id,
        session_url: dec.session_url,
        didit_reference_id: dec.session_id,
        status: dec.status,
        created_at: dec.created_at,
      },
      is_terminal: dec.status === "Approved" || dec.status === "Declined",
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
      issue_date: raw.date_of_issue,
      expiry_date: raw.expiration_date,
      mrz_line1: undefined,
      mrz_line2: undefined,
      document_image_front_hash: "" as SHA3_512Hash, // caller fills after hashing
      document_image_back_hash: undefined,
      nfc_chip_read: false,
      document_verified: raw.status === "Approved",
      verification_score:
        raw.front_image_quality_score?.overall_score !== undefined
          ? raw.front_image_quality_score.overall_score / 100
          : undefined,
      failure_reason:
        raw.warnings?.length > 0
          ? raw.warnings.map((w) => w.short_description).join("; ")
          : undefined,
      completed_at:
        raw.status !== "Not Started" && raw.status !== "In Progress"
          ? now()
          : undefined,
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
      liveness_score: raw.score !== undefined ? raw.score / 100 : undefined,
      spoof_detection_passed: passed,
      spoof_type_detected: undefined,
      biometric_status: passed
        ? BiometricStatus.PASSED
        : raw.status === "In Review"
          ? BiometricStatus.REQUIRES_REVIEW
          : raw.status === "Declined"
            ? BiometricStatus.FAILED
            : BiometricStatus.PENDING,
      selfie_image_hash: portraitImageHash ?? ("" as SHA3_512Hash), // caller fills
      audit_image_urls: undefined,
      failure_reason:
        raw.warnings?.length > 0
          ? raw.warnings.map((w) => w.short_description).join("; ")
          : undefined,
      completed_at:
        raw.status !== "Not Started" && raw.status !== "In Progress"
          ? now()
          : undefined,
    };
  }

  mapFaceMatch(raw: DiditRawFaceMatch): DiditFaceMatch {
    return {
      stage: DiditStage.FACE_MATCH,
      status: mapNodeStatus(raw.status as DiditNodeStatus),
      face_match_passed: raw.status === "Approved",
      face_match_score: raw.score !== undefined ? raw.score / 100 : undefined,
      match_threshold: 0.75,
      failure_reason:
        raw.warnings?.length > 0
          ? raw.warnings.map((w) => w.short_description).join("; ")
          : undefined,
      completed_at:
        raw.status !== "Not Started" && raw.status !== "In Progress"
          ? now()
          : undefined,
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
      carrier: raw.carrier?.name,
      line_type:
        (raw.carrier?.type as DiditPhoneVerification["line_type"]) ?? "unknown",
      country_code: normalizeCountryCode(raw.country_code),
      otp_verified: raw.status === "Approved",
      otp_method: raw.verification_method as "sms" | "call",
      phone_matches_document_country: undefined, // cross-check in class layer
      failure_reason:
        raw.warnings?.length > 0
          ? raw.warnings.map((w) => w.short_description).join("; ")
          : undefined,
      completed_at:
        raw.verified_at ??
        (raw.status !== "Not Started" && raw.status !== "In Progress"
          ? now()
          : undefined),
    };
  }

  mapIPAnalysis(raw: DiditRawIPAnalysis): DiditIPAnalysis {
    const isVpnOrTor = raw.is_vpn_or_tor ?? false;

    const geoLocation: GeoLocation = {
      ip_address: raw.ip_address,
      ip_version: (raw.ip_address?.includes(":") ? 6 : 4) as 4 | 6,
      country_code: normalizeCountryCode(raw.ip_country_code ?? ""),
      country_name: raw.ip_country ?? "",
      region: raw.ip_state,
      city: raw.ip_city,
      timezone: raw.time_zone,
      coordinates:
        raw.latitude !== undefined && raw.longitude !== undefined
          ? { latitude: raw.latitude, longitude: raw.longitude }
          : undefined,
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
      failure_reason:
        raw.warnings?.length > 0
          ? raw.warnings.map((w) => w.short_description).join("; ")
          : undefined,
      completed_at:
        raw.status !== "Not Started" && raw.status !== "In Progress"
          ? now()
          : undefined,
    };
  }

  mapAMLScreening(raw: DiditRawAMLScreening): DiditAMLScreening {
    const confirmedHits = raw.hits?.filter((h) => h.match) ?? [];
    const datasets = confirmedHits.flatMap((h) => h.datasets ?? []);
    const uniqueDatasets = [...new Set(datasets)];

    return {
      screened_at: now(),
      is_pep: uniqueDatasets.includes("PEP"),
      is_sanctioned: uniqueDatasets.includes("SANCTION"),
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
          region: rawIP.ip_state,
          city: rawIP.ip_city,
          timezone: rawIP.time_zone,
          coordinates:
            rawIP.latitude !== undefined && rawIP.longitude !== undefined
              ? { latitude: rawIP.latitude, longitude: rawIP.longitude }
              : undefined,
          isp: rawIP.isp ?? undefined,
          is_vpn: rawIP.is_vpn_or_tor,
          is_proxy: rawIP.is_vpn_or_tor,
          is_tor: rawIP.is_vpn_or_tor,
        }
      : { ip_address: "", ip_version: 4, country_code: "", country_name: "" };

    return {
      session_id: dec.session_id,
      initiated_at: unixToISO(payload.created_at),
      completed_at:
        dec.status === "Approved" || dec.status === "Declined"
          ? now()
          : undefined,
      ip_address: rawIP?.ip_address ?? "",
      location: geoLocation,
      device: {
        device_id: rawIP?.device_fingerprint ?? uuidv7(),
        device_type:
          rawIP?.platform === "mobile"
            ? DeviceType.MOBILE
            : rawIP?.platform === "desktop"
              ? DeviceType.DESKTOP
              : DeviceType.UNKNOWN,
        device_name:
          [rawIP?.device_brand, rawIP?.device_model]
            .filter(Boolean)
            .join(" ") || undefined,
        os_name: rawIP?.os_family ?? "",
        os_version: "",
        browser_name: rawIP?.browser_family,
        user_agent: "",
        language: "en",
        timezone: rawIP?.time_zone ?? "",
      },
      provider: VerificationProvider.DIDIT,
      sdk_version: undefined,
    };
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
      place_of_birth: rawID.place_of_birth,
      gender_raw: rawID.gender,
      nationality_alpha3: rawID.nationality,
      issuing_country_alpha3: rawID.issuing_state,
      document_type_raw: rawID.document_type,
      document_number: rawID.document_number,
      personal_number: rawID.personal_number,
      marital_status: rawID.marital_status,
      phone_number_e164: rawPhone?.full_number,
      parsed_address: rawID.parsed_address
        ? {
            street_1: rawID.parsed_address.street_1,
            street_2: rawID.parsed_address.street_2,
            city: rawID.parsed_address.city,
            region: rawID.parsed_address.region,
            postal_code: rawID.parsed_address.postal_code,
            country_alpha2: normalizeCountryCode(rawID.issuing_state ?? ""),
          }
        : undefined,
    };
  }

  private _computeUpdatedStages(
    dec: DiditDecision,
    existing?: DiditVerification,
  ): DiditStage[] {
    const updated: DiditStage[] = [];

    const check = (
      items: { status: DiditNodeStatus }[] | undefined,
      prevStatus: import("../schema").DiditStageStatus | undefined,
      stage: DiditStage,
    ) => {
      if (items?.length) {
        if (mapNodeStatus(items[0].status) !== prevStatus) updated.push(stage);
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
