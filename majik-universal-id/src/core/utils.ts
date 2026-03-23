/**
 * src/core/utils.ts
 *
 * Pure utility functions for MajikUniversalID.
 * No side effects. No class dependencies. No I/O.
 *
 * ── CHANGELOG ───────────────────────────────────────────────────────────────
 *
 * mapNodeStatus()
 *   - Added "Expired" → DiditStageStatus.FAILED.
 *     The Kyc Expired webhook sets individual node statuses to "Expired"
 *     (e.g. id_verification.status = "Expired"). Without this entry the
 *     function fell through to the ?? default (NOT_STARTED), which is wrong —
 *     an expired document node should be treated as a failure, not unstarted.
 *
 * mapSessionStatus()
 *   - "Kyc Expired" and "Resubmitted" were already present. Confirmed correct.
 *
 * verifyWebhookSignature()
 *   - Renamed _shortenFloats → _roundFloats and fixed the condition.
 *     The old condition `obj % 1 === 0` is always true for integers AND for
 *     whole-number floats, so it never rounded anything. Didit's V2 canonical
 *     form rounds non-integer floats to 4 decimal places. Fixed accordingly.
 *   - Renamed internal _hmacSHA256 → _hmacSHA256Match (returns boolean directly).
 *
 * verifyWebhookSignatureRaw() — NEW
 *   - Accepts rawBody string directly (preferred in CF Workers where the raw
 *     bytes are available before parsing). Verifies HMAC against the raw string
 *     first, then falls back to object canonical form, then simple signature.
 *
 * normalizeToE164()
 *   - Strips "tel:" prefix (observed in carrier data).
 *   - No longer fabricates a "+" prefix for ambiguous numbers — returns the
 *     cleaned string as-is if it doesn't already start with "+".
 *
 * ── END CHANGELOG ────────────────────────────────────────────────────────────
 */

import { sha3_512 } from "@noble/hashes/sha3.js";

import {
  IDTier,
  IDStatus,
  DiditStage,
  DiditStageStatus,
  DocumentType,
  Gender,
} from "./schema";

import type {
  MajikID,
  MajikKeyPublicBundle,
  DiditVerification,
  ISODateTime,
  SHA3_512Hash,
  Base64,
  CountryCode,
  YYYYMMDD,
} from "./schema";

import type {
  DiditNodeStatus,
  DiditSessionStatus,
  DiditWebhookHeaders,
} from "./didit/schema";

import {
  MajikUniversalIDKeyError,
  MajikUniversalIDValidationError,
  MajikUniversalIDWebhookSignatureError,
} from "./errors";

// ─────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────

export const SCHEMA_VERSION = "1.3.0" as const;
export const MAJIK_UNIVERSAL_ID_VERSION = "1.0.0" as const;

/** Days a verified identity is locked from mutation after verification */
export const VERIFICATION_LOCK_DAYS = 30;

// ─────────────────────────────────────────────
// UUID v7
// ─────────────────────────────────────────────

export function uuidv7(): string {
  const nowMs = Date.now();
  const timeHigh = Math.floor(nowMs / 0x100000000);
  const timeLow = nowMs & 0xffffffff;

  const bytes = new Uint8Array(16);
  const view = new DataView(bytes.buffer);

  view.setUint32(0, timeHigh & 0xffff);
  view.setUint32(2, timeLow);

  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const rand = new Uint8Array(10);
  crypto.getRandomValues(rand);
  bytes.set(rand, 6);
  bytes[6] = (bytes[6] & 0x0f) | 0x70;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join("-");
}

// ─────────────────────────────────────────────
// HASHING
// ─────────────────────────────────────────────

export function computeSHA3_512(input: string): SHA3_512Hash {
  const bytes = sha3_512(new TextEncoder().encode(input));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function computeSHA3_512Bytes(input: Uint8Array): SHA3_512Hash {
  const bytes = sha3_512(input);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface IDHashKeyMaterial {
  x25519_public_key: Base64;
  ed_public_key: Base64;
  ml_kem_public_key: Base64;
  ml_dsa_public_key: Base64;
}

/**
 * Compute the MajikID integrity hash.
 * Canonical: `${id}:${user_id}:${timestamp}:${x25519}:${ed25519}:${mlkem}:${mldsa}`
 */
export function computeIDHash(
  id: string,
  user_id: string,
  timestamp: ISODateTime,
  keys: IDHashKeyMaterial,
): SHA3_512Hash {
  const canonical = [
    id,
    user_id,
    timestamp,
    keys.x25519_public_key,
    keys.ed_public_key,
    keys.ml_kem_public_key,
    keys.ml_dsa_public_key,
  ].join(":");
  return computeSHA3_512(canonical);
}

export function verifyIDHash(record: MajikID): boolean {
  const k = record.signing_key;
  if (!k) return false;
  const expected = computeIDHash(record.id, record.user_id, record.timestamp, {
    x25519_public_key: k.x25519_public_key,
    ed_public_key: k.ed_public_key,
    ml_kem_public_key: k.ml_kem_public_key,
    ml_dsa_public_key: k.ml_dsa_public_key,
  });
  return expected === record.hash;
}

// ─────────────────────────────────────────────
// VERIFICATION AGE HELPERS
// ─────────────────────────────────────────────

export function isVerificationLocked(verified_at: ISODateTime): boolean {
  const diffDays =
    (Date.now() - new Date(verified_at).getTime()) / (1000 * 60 * 60 * 24);
  return diffDays < VERIFICATION_LOCK_DAYS;
}

export function verificationLockDaysRemaining(
  verified_at: ISODateTime,
): number {
  const diffDays =
    (Date.now() - new Date(verified_at).getTime()) / (1000 * 60 * 60 * 24);
  return Math.max(0, Math.ceil(VERIFICATION_LOCK_DAYS - diffDays));
}

// ─────────────────────────────────────────────
// BASE64
// ─────────────────────────────────────────────

export function bytesToBase64(bytes: Uint8Array): Base64 {
  let binary = "";
  for (let i = 0; i < bytes.length; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64: Base64): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function objectToBase64(obj: unknown): Base64 {
  return bytesToBase64(new TextEncoder().encode(JSON.stringify(obj)));
}

export function base64ToObject<T>(b64: Base64): T {
  return JSON.parse(new TextDecoder().decode(base64ToBytes(b64))) as T;
}

// ─────────────────────────────────────────────
// KEY BUNDLE HELPERS
// ─────────────────────────────────────────────

export function bundleToSignerKeys(bundle: MajikKeyPublicBundle): {
  signerId: string;
  edPublicKey: Uint8Array;
  mlDsaPublicKey: Uint8Array;
} {
  return {
    signerId: bundle.fingerprint,
    edPublicKey: base64ToBytes(bundle.ed_public_key),
    mlDsaPublicKey: base64ToBytes(bundle.ml_dsa_public_key),
  };
}

// ─────────────────────────────────────────────
// DIDIT STATUS MAPPING
// ─────────────────────────────────────────────

/**
 * Map a Didit node-level status to MajikID DiditStageStatus.
 *
 * CHANGED: Added "Expired" -> FAILED.
 * The Kyc Expired webhook sets node-level statuses to "Expired".
 * Previously this fell through to NOT_STARTED via the ?? default — wrong.
 */
export function mapNodeStatus(raw: DiditNodeStatus | string): DiditStageStatus {
  const map: Record<string, DiditStageStatus> = {
    Approved: DiditStageStatus.PASSED,
    Declined: DiditStageStatus.FAILED,
    Expired: DiditStageStatus.FAILED, // ADDED
    "In Review": DiditStageStatus.REQUIRES_REVIEW,
    "In Progress": DiditStageStatus.IN_PROGRESS,
    "Not Started": DiditStageStatus.NOT_STARTED,
  };
  return map[raw] ?? DiditStageStatus.NOT_STARTED;
}

/**
 * Map a Didit session-level status to MajikID IDStatus.
 */
export function mapSessionStatus(raw: DiditSessionStatus): IDStatus {
  const map: Record<DiditSessionStatus, IDStatus> = {
    Approved: IDStatus.ACTIVE,
    Declined: IDStatus.REVOKED,
    "In Review": IDStatus.PENDING_VERIFICATION,
    "In Progress": IDStatus.PENDING_VERIFICATION,
    "Not Started": IDStatus.PENDING_VERIFICATION,
    Abandoned: IDStatus.EXPIRED,
    Expired: IDStatus.EXPIRED,
    "Kyc Expired": IDStatus.EXPIRED,
    Resubmitted: IDStatus.PENDING_VERIFICATION,
  };
  return map[raw] ?? IDStatus.PENDING_VERIFICATION;
}

/**
 * Derive IDTier from the set of passed DiditStage values.
 *   none              → UNVERIFIED
 *   PHONE only        → BASIC
 *   ID                → VERIFIED
 *   ID+LIVENESS+FACE  → ENHANCED
 *   all 5             → TRUSTED
 */
export function deriveIDTier(passedStages: DiditStage[]): IDTier {
  const s = new Set(passedStages);
  const all5 = [
    DiditStage.ID_VERIFICATION,
    DiditStage.LIVENESS,
    DiditStage.FACE_MATCH,
    DiditStage.PHONE_VERIFICATION,
    DiditStage.IP_ANALYSIS,
  ];
  if (all5.every((stage) => s.has(stage))) return IDTier.TRUSTED;
  if (
    s.has(DiditStage.ID_VERIFICATION) &&
    s.has(DiditStage.LIVENESS) &&
    s.has(DiditStage.FACE_MATCH)
  )
    return IDTier.ENHANCED;
  if (s.has(DiditStage.ID_VERIFICATION)) return IDTier.VERIFIED;
  if (s.has(DiditStage.PHONE_VERIFICATION)) return IDTier.BASIC;
  return IDTier.UNVERIFIED;
}

export function computePassedStages(didit: DiditVerification): DiditStage[] {
  const passed: DiditStage[] = [];
  if (didit.id_verification?.status === DiditStageStatus.PASSED)
    passed.push(DiditStage.ID_VERIFICATION);
  if (didit.liveness?.status === DiditStageStatus.PASSED)
    passed.push(DiditStage.LIVENESS);
  if (didit.face_match?.status === DiditStageStatus.PASSED)
    passed.push(DiditStage.FACE_MATCH);
  if (didit.phone_verification?.status === DiditStageStatus.PASSED)
    passed.push(DiditStage.PHONE_VERIFICATION);
  if (didit.ip_analysis?.status === DiditStageStatus.PASSED)
    passed.push(DiditStage.IP_ANALYSIS);
  return passed;
}

// ─────────────────────────────────────────────
// NORMALIZATION
// ─────────────────────────────────────────────

const ALPHA3_TO_ALPHA2: Record<string, CountryCode> = {
  PHL: "PH",
  USA: "US",
  ESP: "ES",
  GBR: "GB",
  AUS: "AU",
  CAN: "CA",
  DEU: "DE",
  FRA: "FR",
  ITA: "IT",
  JPN: "JP",
  KOR: "KR",
  CHN: "CN",
  IND: "IN",
  BRA: "BR",
  MEX: "MX",
  ARG: "AR",
  NLD: "NL",
  BEL: "BE",
  CHE: "CH",
  AUT: "AT",
  SWE: "SE",
  NOR: "NO",
  DNK: "DK",
  FIN: "FI",
  SGP: "SG",
  HKG: "HK",
  NZL: "NZ",
  ZAF: "ZA",
  NGA: "NG",
  KEN: "KE",
  ARE: "AE",
  SAU: "SA",
  IDN: "ID",
  MYS: "MY",
  THA: "TH",
  VNM: "VN",
  PRT: "PT",
  GRC: "GR",
  POL: "PL",
  CZE: "CZ",
  HUN: "HU",
  ROU: "RO",
  BGR: "BG",
  HRV: "HR",
  SVK: "SK",
  SVN: "SI",
  EST: "EE",
  LVA: "LV",
  LTU: "LT",
};

export function normalizeCountryCode(raw: string): CountryCode {
  if (!raw) return raw as CountryCode;
  if (raw.length === 2) return raw.toUpperCase() as CountryCode;
  return (ALPHA3_TO_ALPHA2[raw.toUpperCase()] ??
    raw.toUpperCase()) as CountryCode;
}

export function normalizeGender(raw: string): Gender {
  const upper = (raw ?? "").toUpperCase().trim();
  if (upper === "F" || upper === "FEMALE") return Gender.FEMALE;
  if (upper === "M" || upper === "MALE") return Gender.MALE;
  if (upper === "X" || upper === "NON-BINARY" || upper === "NON_BINARY")
    return Gender.NON_BINARY;
  if (upper === "PREFER_NOT_TO_SAY" || upper === "PREFER NOT TO SAY")
    return Gender.PREFER_NOT_TO_SAY;
  return Gender.OTHER;
}

export function normalizeDocumentType(raw: string): DocumentType {
  const lower = (raw ?? "").toLowerCase();
  if (lower.includes("passport")) return DocumentType.PASSPORT;
  if (lower.includes("identity") || lower.includes("national"))
    return DocumentType.NATIONAL_ID;
  if (
    lower.includes("driver") ||
    lower.includes("licence") ||
    lower.includes("license")
  )
    return DocumentType.DRIVERS_LICENSE;
  if (lower.includes("residence") || lower.includes("permit"))
    return DocumentType.RESIDENCE_PERMIT;
  if (lower.includes("voter")) return DocumentType.VOTER_ID;
  if (lower.includes("birth")) return DocumentType.BIRTH_CERTIFICATE;
  return DocumentType.OTHER;
}

/**
 * Normalize a phone string to E.164.
 *
 * CHANGED:
 *   - Strips "tel:" URI prefix (seen in carrier lookup data)
 *   - Cleans spaces, hyphens, parens, dots
 *   - Returns as-is if already starts with "+" (already E.164)
 *   - Does NOT fabricate a "+" prefix for ambiguous bare numbers
 */
export function normalizeToE164(phone: string): string {
  if (!phone) return phone;
  const stripped = phone.replace(/^tel:/i, "");
  const cleaned = stripped.replace(/[\s\-().]/g, "");
  if (cleaned.startsWith("+")) return cleaned;
  return cleaned;
}

// ─────────────────────────────────────────────
// DATE HELPERS
// ─────────────────────────────────────────────

export function now(): ISODateTime {
  return new Date().toISOString();
}

export function unixToISO(unix: number): ISODateTime {
  return new Date(unix * 1000).toISOString();
}

export function isValidYYYYMMDD(value: string): value is YYYYMMDD {
  return /^\d{4}-\d{2}-\d{2}$/.test(value);
}

// ─────────────────────────────────────────────
// ASSERTION HELPERS
// ─────────────────────────────────────────────

export function assertDefined<T>(
  value: T | null | undefined,
  label: string,
): asserts value is T {
  if (value === null || value === undefined) {
    throw new MajikUniversalIDValidationError(
      `${label} is required but was ${value === null ? "null" : "undefined"}`,
      label,
    );
  }
}

export function assertNonEmptyString(
  value: unknown,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new MajikUniversalIDValidationError(
      `${label} must be a non-empty string`,
      label,
    );
  }
}

export function assertUint8Array(
  value: unknown,
  label: string,
  expectedLength?: number,
): asserts value is Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new MajikUniversalIDKeyError(`${label} must be a Uint8Array`);
  }
  if (expectedLength !== undefined && value.length !== expectedLength) {
    throw new MajikUniversalIDKeyError(
      `${label} must be ${expectedLength} bytes, got ${value.length}`,
    );
  }
}

export function assertHasSigningKeys(key: {
  hasSigningKeys: boolean;
  fingerprint: string;
}): void {
  if (!key.hasSigningKeys) {
    throw new MajikUniversalIDKeyError(
      `MajikKey (fingerprint: ${key.fingerprint}) has no signing keys. ` +
        "Re-import via importFromMnemonicBackup() to enable signing.",
    );
  }
}

export function assertTimestampFresh(
  unixTimestamp: number,
  windowSeconds = 300,
): void {
  const diff = Math.abs(Math.floor(Date.now() / 1000) - unixTimestamp);
  if (diff > windowSeconds) {
    throw new MajikUniversalIDValidationError(
      `Timestamp is stale (${diff}s old, max ${windowSeconds}s)`,
      "timestamp",
    );
  }
}

// ─────────────────────────────────────────────
// WEBHOOK HMAC VERIFICATION
// ─────────────────────────────────────────────


/**
 * Verify a Didit webhook HMAC from the raw request body string.
 *
 * ADDED: Preferred in Cloudflare Workers — verifies against the raw bytes
 * before any JSON parsing. Falls back to canonical object form, then simple.
 * Throws MajikUniversalIDWebhookSignatureError if none pass.
 */
export async function verifyWebhookSignatureRaw(
  rawBody: string,
  headers: DiditWebhookHeaders,
  secret: string,
): Promise<void> {
  assertNonEmptyString(headers["x-timestamp"], "x-timestamp header");
  assertNonEmptyString(secret, "webhook secret");

  const timestamp = parseInt(headers["x-timestamp"], 10);
  assertTimestampFresh(timestamp);

  if (headers["x-signature-v2"]) {
    // Try raw string first (avoids re-serialization risk)
    if (await _hmacSHA256Match(rawBody, headers["x-signature-v2"], secret))
      return;

    // Fallback: canonical sorted+rounded JSON object form
    try {
      const parsed = JSON.parse(rawBody) as Record<string, unknown>;
      if (await _verifyV2Object(parsed, headers["x-signature-v2"], secret))
        return;
    } catch {
      /* not valid JSON */
    }
  }

  if (headers["x-signature-simple"]) {
    try {
      const parsed = JSON.parse(rawBody) as Record<string, unknown>;
      if (await _verifySimple(parsed, headers["x-signature-simple"], secret))
        return;
    } catch {
      /* ignore */
    }
  }

  throw new MajikUniversalIDWebhookSignatureError();
}

// ── Private HMAC helpers ──────────────────────────────────────────────────

async function _verifyV2Object(
  body: Record<string, unknown>,
  signature: string,
  secret: string,
): Promise<boolean> {
  try {
    const canonical = JSON.stringify(_sortKeys(_roundFloats(body)));
    return _hmacSHA256Match(canonical, signature, secret);
  } catch {
    return false;
  }
}

async function _verifySimple(
  body: Record<string, unknown>,
  signature: string,
  secret: string,
): Promise<boolean> {
  try {
    const canonical = [
      body["timestamp"] ?? "",
      body["session_id"] ?? "",
      body["status"] ?? "",
      body["webhook_type"] ?? "",
    ].join(":");
    return _hmacSHA256Match(canonical, signature, secret);
  } catch {
    return false;
  }
}

async function _hmacSHA256Match(
  message: string,
  expected: string,
  secret: string,
): Promise<boolean> {
  try {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
    const hex = Array.from(new Uint8Array(sig))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return _timingSafeEqual(hex, expected);
  } catch {
    return false;
  }
}

function _timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function _sortKeys(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(_sortKeys);
  if (obj !== null && typeof obj === "object") {
    return Object.keys(obj as object)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = _sortKeys((obj as Record<string, unknown>)[k]);
        return acc;
      }, {});
  }
  return obj;
}

/**
 * Round non-integer floats to 4 decimal places for Didit V2 canonical form.
 *
 * CHANGED: Previous implementation checked `obj % 1 === 0` which is always
 * true for integers and never triggers rounding. The correct condition is
 * `!Number.isInteger(obj)` — only round numbers that have a fractional part.
 */
function _roundFloats(obj: unknown): unknown {
  if (Array.isArray(obj)) return obj.map(_roundFloats);
  if (obj !== null && typeof obj === "object") {
    return Object.fromEntries(
      Object.entries(obj as object).map(([k, v]) => [k, _roundFloats(v)]),
    );
  }
  if (typeof obj === "number" && !Number.isInteger(obj)) {
    return Math.round(obj * 10000) / 10000;
  }
  return obj;
}
