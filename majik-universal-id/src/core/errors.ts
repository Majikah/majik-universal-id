/**
 * src/core/errors.ts
 *
 * Typed error hierarchy for MajikUniversalID.
 * Every public method throws one of these — never a bare Error.
 */

// ─────────────────────────────────────────────
// BASE
// ─────────────────────────────────────────────

export class MajikUniversalIDError extends Error {
  readonly code: string;
  readonly cause?: unknown;

  constructor(message: string, cause?: unknown, code = "UNIVERSAL_ID_ERROR") {
    super(message);
    this.name = "MajikUniversalIDError";
    this.code = code;
    this.cause = cause;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ─────────────────────────────────────────────
// CONSTRUCTION / FACTORY
// ─────────────────────────────────────────────

/** Thrown when create() or fromJSON() receives invalid or missing inputs */
export class MajikUniversalIDValidationError extends MajikUniversalIDError {
  readonly field?: string;

  constructor(message: string, field?: string, cause?: unknown) {
    super(message, cause, "VALIDATION_ERROR");
    this.name = "MajikUniversalIDValidationError";
    this.field = field;
  }
}

/** Thrown when fromJSON() or fromBase64() receives malformed data */
export class MajikUniversalIDDeserializationError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "DESERIALIZATION_ERROR");
    this.name = "MajikUniversalIDDeserializationError";
  }
}

// ─────────────────────────────────────────────
// KEY MANAGEMENT
// ─────────────────────────────────────────────

/** Thrown when a MajikKey is missing required public key fields */
export class MajikUniversalIDKeyError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "KEY_ERROR");
    this.name = "MajikUniversalIDKeyError";
  }
}

/** Thrown when no signing key bundle matches a given fingerprint */
export class MajikUniversalIDKeyNotFoundError extends MajikUniversalIDError {
  readonly fingerprint: string;

  constructor(fingerprint: string, cause?: unknown) {
    super(
      `No signing key bundle found for fingerprint: ${fingerprint}`,
      cause,
      "KEY_NOT_FOUND",
    );
    this.name = "MajikUniversalIDKeyNotFoundError";
    this.fingerprint = fingerprint;
  }
}

// ─────────────────────────────────────────────
// SIGNING & VERIFICATION
// ─────────────────────────────────────────────

/** Thrown when signing fails */
export class MajikUniversalIDSigningError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "SIGNING_ERROR");
    this.name = "MajikUniversalIDSigningError";
  }
}

/** Thrown when content/file verification encounters a structural error */
export class MajikUniversalIDVerificationError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "VERIFICATION_ERROR");
    this.name = "MajikUniversalIDVerificationError";
  }
}

// ─────────────────────────────────────────────
// DIDIT
// ─────────────────────────────────────────────

/** Thrown when a webhook payload fails HMAC signature verification */
export class MajikUniversalIDWebhookSignatureError extends MajikUniversalIDError {
  constructor(
    message = "Webhook HMAC signature verification failed",
    cause?: unknown,
  ) {
    super(message, cause, "WEBHOOK_SIGNATURE_INVALID");
    this.name = "MajikUniversalIDWebhookSignatureError";
  }
}

/** Thrown when a webhook payload is structurally invalid */
export class MajikUniversalIDWebhookPayloadError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "WEBHOOK_PAYLOAD_INVALID");
    this.name = "MajikUniversalIDWebhookPayloadError";
  }
}

// ─────────────────────────────────────────────
// PRIVATE INFO ENCRYPTION
// ─────────────────────────────────────────────

/**
 * Thrown when accessing the decrypted privateInfo getter but the private
 * info has not yet been decrypted in this session.
 *
 * Resolution: call majikId.decryptPrivate(unlockedKey) first, or provide
 * the key to MajikUniversalID.fromJSON(json, key).
 */
export class MajikUniversalIDPrivateInfoLockedError extends MajikUniversalIDError {
  constructor() {
    super(
      "Private info is encrypted and has not been decrypted in this session. " +
        "Call decryptPrivate(key) with an unlocked MajikKey first, or provide " +
        "the key to MajikUniversalID.fromJSON(json, key).",
      undefined,
      "PRIVATE_INFO_LOCKED",
    );
    this.name = "MajikUniversalIDPrivateInfoLockedError";
  }
}

/**
 * Thrown when encrypting private info fails — e.g. the key is missing
 * ML-KEM public key fields or the envelope encryption encounters an error.
 */
export class MajikUniversalIDPrivateInfoEncryptionError extends MajikUniversalIDError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, "PRIVATE_INFO_ENCRYPTION_ERROR");
    this.name = "MajikUniversalIDPrivateInfoEncryptionError";
  }
}

// ─────────────────────────────────────────────
// IDENTITY STATE
// ─────────────────────────────────────────────

/** Thrown when the MajikID is restricted and an operation is blocked */
export class MajikUniversalIDRestrictedError extends MajikUniversalIDError {
  readonly restricted_until?: string;

  constructor(restricted_until?: string) {
    super(
      restricted_until
        ? `This MajikID is restricted until ${restricted_until}`
        : "This MajikID is currently restricted",
      undefined,
      "IDENTITY_RESTRICTED",
    );
    this.name = "MajikUniversalIDRestrictedError";
    this.restricted_until = restricted_until;
  }
}

/** Thrown when an operation requires a minimum IDTier that hasn't been reached */
export class MajikUniversalIDTierRequiredError extends MajikUniversalIDError {
  readonly required_tier: string;
  readonly current_tier: string;

  constructor(required: string, current: string) {
    super(
      `Operation requires tier '${required}', current tier is '${current}'`,
      undefined,
      "TIER_REQUIRED",
    );
    this.name = "MajikUniversalIDTierRequiredError";
    this.required_tier = required;
    this.current_tier = current;
  }
}

/** Thrown when an integrity hash check fails on deserialization */
export class MajikUniversalIDIntegrityError extends MajikUniversalIDError {
  constructor(
    message = "Integrity hash mismatch — data may have been tampered with",
  ) {
    super(message, undefined, "INTEGRITY_ERROR");
    this.name = "MajikUniversalIDIntegrityError";
  }
}

/**
 * Thrown when a mutating operation is attempted on a verified identity.
 * The identity must be UNVERIFIED (isMutable === true) before any fields
 * can be changed. Call revokeVerification() first.
 */
export class MajikUniversalIDImmutableError extends MajikUniversalIDError {
  readonly current_tier: string;

  constructor(current_tier: string, field?: string) {
    super(
      field
        ? `Cannot modify '${field}': this MajikID is verified (tier: ${current_tier}). ` +
            "Call revokeVerification() to reset to UNVERIFIED before making changes."
        : `This MajikID is verified (tier: ${current_tier}) and cannot be modified. ` +
            "Call revokeVerification() to reset to UNVERIFIED before making changes.",
      undefined,
      "IDENTITY_IMMUTABLE",
    );
    this.name = "MajikUniversalIDImmutableError";
    this.current_tier = current_tier;
  }
}

/**
 * Thrown when revokeVerification() is called but the 30-day lock is active.
 * The user must wait until the verification is older than 30 days.
 */
export class MajikUniversalIDVerificationLockedError extends MajikUniversalIDError {
  readonly verified_at: string;
  readonly days_remaining: number;

  constructor(verified_at: string, days_remaining: number) {
    super(
      `Verification cannot be revoked yet — it was completed on ${verified_at} ` +
        `and is locked for ${days_remaining} more day${days_remaining === 1 ? "" : "s"}. ` +
        `Verifications are locked for 30 days after completion to prevent abuse.`,
      undefined,
      "VERIFICATION_LOCKED",
    );
    this.name = "MajikUniversalIDVerificationLockedError";
    this.verified_at = verified_at;
    this.days_remaining = days_remaining;
  }
}

// ─────────────────────────────────────────────
// TYPE GUARDS
// ─────────────────────────────────────────────

export function isUniversalIDError(e: unknown): e is MajikUniversalIDError {
  return e instanceof MajikUniversalIDError;
}

export function isValidationError(
  e: unknown,
): e is MajikUniversalIDValidationError {
  return e instanceof MajikUniversalIDValidationError;
}

export function isWebhookError(
  e: unknown,
): e is
  | MajikUniversalIDWebhookSignatureError
  | MajikUniversalIDWebhookPayloadError {
  return (
    e instanceof MajikUniversalIDWebhookSignatureError ||
    e instanceof MajikUniversalIDWebhookPayloadError
  );
}

export function isImmutableError(
  e: unknown,
): e is MajikUniversalIDImmutableError {
  return e instanceof MajikUniversalIDImmutableError;
}

export function isLockedError(
  e: unknown,
): e is MajikUniversalIDVerificationLockedError {
  return e instanceof MajikUniversalIDVerificationLockedError;
}

export function isPrivateInfoLockedError(
  e: unknown,
): e is MajikUniversalIDPrivateInfoLockedError {
  return e instanceof MajikUniversalIDPrivateInfoLockedError;
}
