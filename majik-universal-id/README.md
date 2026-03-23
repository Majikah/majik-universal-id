# Majik Universal ID

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik Universal ID** is a cryptographically anchored identity layer for the Majikah ecosystem. Built on top of **Majik Key** and **Majik Signature**, it provides a tamper-proof, post-quantum-ready universal identity record that binds a user, a signing key, and a multi-stage verification state into a single, integrity-hashed document.

Every `MajikUniversalID` is permanently bound to exactly one `MajikKey` bundle. Private personal information is always encrypted at rest using **ML-KEM-768** (FIPS-203). Identity signing uses the hybrid **Ed25519 + ML-DSA-87** scheme from Majik Signature — both algorithms must verify for any signed content to be considered authentic.

Identities can be created and managed via the web application at **[https://id.majikah.solutions](https://id.majikah.solutions)** using your own Majik Keys.

![npm](https://img.shields.io/npm/v/@majikah/majik-universal-id) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-universal-id) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)

---

- [Majik Universal ID](#majik-universal-id)
  - [Security Architecture](#security-architecture)
  - [Overview](#overview)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [API Reference](#api-reference)
    - [Factory Methods](#factory-methods)
    - [Content Signing](#content-signing)
    - [Content Verification](#content-verification)
    - [Private Info — Decrypt & Share](#private-info--decrypt--share)
    - [Didit Verification Lifecycle](#didit-verification-lifecycle)
    - [Serialization](#serialization)
    - [Getters](#getters)
  - [ID Tiers](#id-tiers)
  - [Verification Stages](#verification-stages)
  - [Immutability & Locking](#immutability--locking)
  - [Usage Examples](#usage-examples)
  - [Error Reference](#error-reference)
  - [Security Considerations](#security-considerations)
  - [Related Projects](#related-projects)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [Contact](#contact)

---

## Security Architecture

### 1. Hybrid Post-Quantum Identity Signing

Every `MajikUniversalID` is created with a hybrid **Ed25519 + ML-DSA-87** signature over its core identity fields (`id`, `user_id`, `timestamp`, `hash`). This is the same dual-algorithm architecture used by Majik Signature — both algorithms must verify for the identity record to be considered authentic. A break in either algorithm alone is not sufficient to forge a valid identity.

### 2. Integrity Hash

A **SHA3-512** integrity hash is computed over the identity's canonical fields at creation time:

```
hash = SHA3-512(id : user_id : timestamp : x25519_pk : ed_pk : ml_kem_pk : ml_dsa_pk)
```

All four public keys from the bound `MajikKey` are committed into this hash. Any modification to the stored identity — including key material substitution — will fail the hash check on deserialization.

### 3. Private Info Encryption

Private personal information (`PrivatePersonalInfo`) is **never stored in plaintext**. It is immediately encrypted with the bound key's **ML-KEM-768** public key on creation via `MajikEnvelope`. The encrypted envelope is the only form ever serialized or persisted. Decrypted data (`rehydrated`) exists only in memory and is stripped from all serialization outputs.

### 4. Immutability After Verification

Once a `MajikUniversalID` reaches any verified tier (any tier above `UNVERIFIED`), the identity becomes **immutable**. Mutating operations (`signContent`, `signFile`, `syncUserRef`, `updateDisplayName`, `updateSettings`, `grantConsent`, `revokeConsent`) all throw `MajikUniversalIDImmutableError` on a verified identity. The identity can only be modified again after calling `revokeVerification()`, which itself is blocked for **30 days** after verification (`isVerificationLocked`).

### 5. 1:1:1 Key Binding

A `MajikUniversalID` is permanently bound to exactly one `MajikKey` bundle at creation. The bound key's fingerprint, and all four of its public keys (X25519, Ed25519, ML-KEM-768, ML-DSA-87), are committed into the integrity hash. There is no key rotation — to use a different key, a new `MajikUniversalID` must be created.

---

## Overview

### What is a Majik Universal ID?

A `MajikUniversalID` is a structured identity record that anchors:

- A **MajikUser** (the account holder)
- A **MajikKey** bundle (the cryptographic signing and encryption identity)
- A **verification state** derived from up to five Didit verification stages
- **Encrypted private personal info** (legal name, date of birth, contact details, address, government IDs)
- A **public profile** (display name, avatar, bio, social handles)
- A **consent log**, **settings**, and a **signature history**

The identity is self-contained and portable — it serializes to JSON or base64, carries its own public keys, and can be verified without a key registry.

Verification is performed through **Didit**, a third-party KYC/identity verification provider. Webhook payloads from Didit are processed by the `processWebhook()` method, which maps raw stage results to typed structures and graduates the identity's `IDTier`.

### Use Cases

- **Identity Anchoring**: Bind a Majikah user account to a specific MajikKey for provenance and non-repudiation
- **KYC Graduation**: Track a user's verification progress across five Didit stages and automatically derive their identity tier
- **Content Provenance**: Sign and verify documents, files, and API payloads as a verified Majikah identity
- **Private Data Custody**: Store encrypted personal info alongside the identity — decryptable only with the bound key
- **Consent Management**: Record and revoke data-sharing consents with a structured, auditable consent log
- **Majikah Ecosystem**: Integrate with Majik Message and other Majikah products for identity-bound communication

---

## Features

### Security & Post-Quantum Readiness

- **Hybrid Identity Signature**: Ed25519 + ML-DSA-87 over core identity fields — both must verify
- **Integrity-Hashed**: SHA3-512 over all four bound public keys — tampering invalidates the hash
- **ML-KEM-768 Private Encryption**: Private personal info is always encrypted at rest with a post-quantum KEM
- **Immutable After Verification**: Verified identities cannot be mutated — enforced at the class boundary
- **30-Day Revocation Lock**: `revokeVerification()` is blocked for 30 days after verification to prevent abuse
- **No Private Key for Verification**: Content and file verification uses public keys only

### Identity & Verification

- **5-Stage Didit Workflow**: ID Verification → Liveness → Face Match → Phone Verification → IP Analysis
- **Automatic Tier Derivation**: `IDTier` (UNVERIFIED → BASIC → VERIFIED → ENHANCED → TRUSTED) derived from completed stages
- **Webhook Processing**: `processWebhook()` maps raw Didit V3 payloads to typed structures and computes user sync actions
- **AML Screening**: PEP and sanctions screening from Didit AML nodes

### Content Signing & Verification (via Majik Signature)

- **Sign arbitrary content**: `signContent()` — bytes, strings, JSON payloads
- **Sign files with embedded signatures**: `signFile()` — all formats supported by Majik Signature
- **Verify content**: `verifyContent()`, `verifyText()` — both Ed25519 and ML-DSA-87 must pass
- **Verify files**: `verifyFile()` — extracts and verifies embedded signatures
- **Signer binding enforced**: All signing and verification checks the fingerprint against the bound key

### Private Info

- **Encrypted at rest**: `PrivatePersonalInfo` is always stored as an `MajikEnvelope`-encrypted payload
- **Session decryption**: `decryptPrivate(key)` — decrypts and caches in memory for the session
- **Silent load decryption**: `fromJSON(json, { key })` — attempts decryption on load, swallows failures
- **Secure sharing**: `sharePrivate({ senderKey, recipients })` — re-encrypts for multiple recipients via `MajikEnvelope` group encryption, returns a scanner string
- **Never serialized**: `rehydrated` is stripped from all `toJSON()` / `toBase64()` outputs

### Developer Experience

- **First-Class TypeScript**: Full type definitions for all interfaces, enums, and classes
- **Structured Errors**: Typed error hierarchy — every public method throws a named subclass
- **JSON & Base64 Round-Trip**: `toJSON()`, `fromJSON()`, `toBase64()`, `fromBase64()`
- **Public View Projection**: `toPublicView()` — safe public projection with no private info
- **Validation**: `validate()` — structural and integrity checks with detailed error and warning lists
- **Isomorphic**: Works in Node.js 18+, modern browsers, Deno, and Bun

---

## Installation

```bash
# Using npm
npm install @majikah/majik-universal-id

# Peer dependencies — must also be installed
npm install @majikah/majik-key
npm install @majikah/majik-signature
npm install @majikah/majik-envelope
```

No native bindings. Works in Node.js 18+, all modern browsers, Deno, and Bun.

---

## Quick Start

```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikUser } from '@thezelijah/majik-user';
import { MajikUniversalID } from '@majikah/majik-universal-id';

// ── Step 1: Create and unlock a MajikKey ─────────────────────────────────────
const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'my-passphrase', 'My Identity Key');

// ── Step 2: Create a MajikUniversalID ─────────────────────────────────────────
const majikId = await MajikUniversalID.create(user, key, {
  account_id: 'acct_your_tenant_id',
});

console.log('ID:', majikId.id);
console.log('Tier:', majikId.tier);       // IDTier.UNVERIFIED
console.log('Hash:', majikId.hash);       // SHA3-512 integrity hash
console.log('Signer:', majikId.signingKey.fingerprint);

// ── Step 3: Access decrypted private info (available right after create()) ───
const info = majikId.privateInfo;
console.log('Legal name:', info.legal_first_name, info.legal_last_name);

// ── Step 4: Sign content ──────────────────────────────────────────────────────
const signature = await majikId.signContent('My signed document', key);

// ── Step 5: Verify content ────────────────────────────────────────────────────
const result = majikId.verifyContent('My signed document', signature);
console.log('Valid:', result.valid); // true

// ── Step 6: Serialize for storage ────────────────────────────────────────────
const json = majikId.toJSON();   // private info is stripped — never persisted
const b64  = majikId.toBase64(); // compact base64 representation

// ── Step 7: Restore from storage ─────────────────────────────────────────────
const restored = await MajikUniversalID.fromJSON(json, { key });
// If key is provided and unlocked, private info is silently decrypted on load.
```

---

## API Reference

### Factory Methods

#### `MajikUniversalID.create(user, key, options)`

Create a new `MajikUniversalID` from a `MajikUser` and an unlocked `MajikKey`. The key must be unlocked and must have all public key fields (Ed25519, ML-DSA-87, ML-KEM-768, X25519). Private personal info is encrypted immediately. The identity starts at `IDTier.UNVERIFIED`.

**Parameters:**
- `user: MajikUser` — A valid, fully constructed `MajikUser` instance.
- `key: MajikKey` — An unlocked `MajikKey` with all signing and encryption keys present.
- `options: CreateUniversalIDOptions`
  - `account_id: string` — The Majikah tenant account ID. Required.
  - `locale?: string` — Preferred locale (e.g. `"en-PH"`). Defaults to `"en-PH"`.
  - `schema_version?: string` — Schema version override. Defaults to the current `SCHEMA_VERSION` constant.

**Returns:** `Promise<MajikUniversalID>`

**Throws:** `MajikUniversalIDKeyError` if the key is locked or missing required fields. `MajikUniversalIDValidationError` if the user fails validation.

---

#### `MajikUniversalID.fromJSON(json, options?)`

Reconstruct a `MajikUniversalID` from its JSON representation. Validates structure and verifies the SHA3-512 integrity hash on load. Optionally attempts silent decryption of private info.

**Parameters:**
- `json: MajikUniversalIDJSON | string` — The serialized identity JSON (object or string).
- `options?: FromJSONOptions`
  - `key?: MajikKey` — An unlocked `MajikKey` to attempt private info decryption. All failures are silently swallowed — no exception is thrown on decryption failure.

**Returns:** `Promise<MajikUniversalID>`

**Throws:** `MajikUniversalIDIntegrityError` if the hash check fails. `MajikUniversalIDDeserializationError` if the JSON is malformed.

---

#### `MajikUniversalID.fromBase64(b64, options?)`

Reconstruct from a base64-serialized string. Accepts the same optional key for silent decryption.

**Returns:** `Promise<MajikUniversalID>`

---

### Content Signing

Signing methods require `isMutable === true` (the identity must be at `IDTier.UNVERIFIED`). The provided key's fingerprint must match the bound `signing_key.fingerprint`.

---

#### `majikId.signContent(content, key, options?)`

Sign arbitrary content and return a `MajikSignature`. Uses the hybrid Ed25519 + ML-DSA-87 scheme from Majik Signature.

**Parameters:**
- `content: Uint8Array | string` — Content to sign.
- `key: MajikKey` — An unlocked `MajikKey` matching the bound fingerprint.
- `options?: SignOptions & { label?: string }` — Optional content type, timestamp override, and label.

**Returns:** `Promise<MajikSignature>`

**Throws:** `MajikUniversalIDImmutableError` if the identity is verified. `MajikUniversalIDSigningError` on signing failure. `MajikUniversalIDKeyNotFoundError` if the fingerprint doesn't match.

---

#### `majikId.signFile(file, key, options?)`

Sign a file and embed the signature into it. Delegates to `MajikSignature.signFile()` — all file formats supported by Majik Signature are supported here.

**Parameters:**
- `file: Blob` — The file to sign.
- `key: MajikKey` — An unlocked `MajikKey` matching the bound fingerprint.
- `options?` — Optional `contentType`, `timestamp`, `mimeType`, and `label`.

**Returns:** `Promise<{ blob: Blob; signature: MajikSignature; handler: string; mimeType: string }>`

---

### Content Verification

Verification methods are read-only and have no `isMutable` requirement.

---

#### `majikId.verifyContent(content, signature, context?)`

Verify that content was signed by the key bound to this identity. Both Ed25519 and ML-DSA-87 must pass. The signer fingerprint embedded in the signature is checked against the bound key's fingerprint before cryptographic verification.

**Parameters:**
- `content: Uint8Array | string` — The original signed content.
- `signature: MajikSignature | MajikSignatureJSON | string` — The signature to verify (instance, JSON object, or base64 string).
- `context?: string` — Optional context label for auditing.

**Returns:** `ContentVerificationResult`
```typescript
{
  valid: boolean;
  signer_fingerprint: string;
  signer_registered: boolean;  // Whether fingerprint matched the bound key
  content_hash?: string;
  signed_at?: string;
  content_type?: string;
  reason?: string;             // Present when valid is false
}
```

---

#### `majikId.verifyFile(file, context?)`

Extract and verify a file's embedded `MajikSignature` against this identity's bound public keys.

**Returns:** `Promise<FileVerificationResult>` — extends `ContentVerificationResult` with an optional `handler` field (e.g. `"PDF"`, `"WAV"`, `"MP4/MOV"`).

---

#### `majikId.verifyText(text, signature, context?)`

Convenience wrapper for `verifyContent()` for string content.

---

### Private Info — Decrypt & Share

---

#### `majikId.decryptPrivate(key)`

Decrypt and rehydrate private personal info with the provided `MajikKey`. On success, `isPrivateDecrypted` becomes `true` and `privateInfo` is accessible. If already decrypted in this session, the cached value is returned immediately. Never throws — returns a result object.

**Parameters:**
- `key: MajikKey` — The bound unlocked `MajikKey`. Fingerprint must match `signing_key.fingerprint`.

**Returns:** `Promise<DecryptPrivateResult>`
```typescript
{
  success: boolean;
  data?: PrivatePersonalInfo;  // Present when success === true
  reason?: string;             // Present when success === false
}
```

---

#### `majikId.sharePrivate(options)`

Share private info with one or more recipients by re-encrypting it for their `MajikKey`s using `MajikEnvelope` group encryption. Returns a scanner string that each recipient can decrypt with their own `MajikKey`. The sender's key is always included as a recipient. Does not mutate the current instance.

**Parameters:**
- `options.senderKey: MajikKey` — The unlocked bound `MajikKey`. Used to decrypt first.
- `options.recipients: MajikKey[]` — One or more recipient keys. Only `mlKemPublicKey` is used — they do not need to be unlocked.

**Returns:** `Promise<string>` — A `MajikEnvelope` scanner string (`~*$MJKMSG:<base64>`).

Recipients can decrypt with:
```typescript
const env = MajikEnvelope.fromScannerString(scannerString);
const json = await env.decrypt({ fingerprint, mlKemSecretKey });
const privateInfo: PrivatePersonalInfo = JSON.parse(json);
```

---

### Didit Verification Lifecycle

---

#### `majikId.processWebhook(payload, headers, secret)`

Process an incoming Didit V3 webhook payload. Verifies the HMAC signature, maps the payload to typed `DiditVerification` structures, graduates `IDTier`, and returns actions for the caller to apply on the linked `MajikUser`.

> **Important:** `payload.vendor_data` must equal `MajikUniversalID.id`. Set this value as `vendor_data` when creating the Didit session.

**Parameters:**
- `payload: DiditWebhookPayload` — The raw Didit webhook body.
- `headers: DiditWebhookHeaders` — The webhook request headers (must include `x-timestamp` and at least one signature header).
- `secret: string` — The HMAC secret configured in the Didit dashboard.

**Returns:** `Promise<WebhookProcessResult>`
```typescript
{
  success: boolean;
  session_id: string;
  session_status: string;
  previous_tier: IDTier;
  new_tier: IDTier;
  tier_changed: boolean;
  all_stages_passed: boolean;
  updated_stages: DiditStage[];
  user_sync_actions: UserSyncAction[];  // e.g. ["verifyPhone", "verifyIdentity"]
  extracted_personal_data?: { ... };   // Flattened Stage 1 personal data
}
```

---

#### `majikId.revokeVerification(reason)`

Revoke all Didit verification and reset the identity to `IDTier.UNVERIFIED`. Throws `MajikUniversalIDVerificationLockedError` if the identity was verified within the last 30 days. Safe no-op if already `UNVERIFIED`.

**Parameters:**
- `reason: string` — Required justification stored in the audit trail.

---

#### `majikId.requireReverification(reason?)`

Flag the identity for re-verification (admin use). Does not unlock the identity or reset its tier.

---

#### `majikId.isVerificationPassed(stage)`

Check whether a specific `DiditStage` has been passed.

```typescript
if (majikId.isVerificationPassed(DiditStage.LIVENESS)) {
  // liveness check was passed
}
```

---

#### `majikId.getPassedVerifications()`

Returns the list of `DiditStage` values that have been passed, in the order they were completed.

**Returns:** `DiditStage[]`

---

### Serialization

#### `majikId.toJSON()`

Export the full identity as a plain `MajikUniversalIDJSON` object. The `rehydrated` field is **always stripped** — decrypted private info is never serialized.

#### `majikId.toBase64()`

Serialize the identity to a compact base64 string. Equivalent to `objectToBase64(toJSON())`.

#### `majikId.toPublicView()`

Returns a public-safe projection (`MajikIDPublicView`) — no private info, no signature records. Includes the public profile, tier, status, display name, and public signing key material. Also includes `verification_stages`, a `Record<DiditStage, boolean>` derived from `completed_stages`, where all five stage keys are always present.

#### `majikId.validate()`

Run structural and integrity checks. Returns a `UniversalIDValidationResult` with `is_valid`, `errors`, and `warnings` arrays.

---

### Getters

**Identity**

| Getter | Type | Description |
|---|---|---|
| `id` | `string` | UUIDv7 identity record ID |
| `userId` | `string` | The bound `MajikUser` ID |
| `accountId` | `string` | The Majikah tenant account ID |
| `publicKey` | `Base64` | Bound X25519 public key, base64 (32 bytes) |
| `hash` | `SHA3_512Hash` | Integrity hash over id, user_id, timestamp, and all four public keys |
| `timestamp` | `ISODateTime` | ISO 8601 creation timestamp |
| `lastUpdate` | `ISODateTime` | ISO 8601 timestamp of last mutation |

**Verification State**

| Getter | Type | Description |
|---|---|---|
| `tier` | `IDTier` | Current verification tier |
| `status` | `IDStatus` | Current status |
| `isVerified` | `boolean` | `true` if tier is not `UNVERIFIED` |
| `isTrusted` | `boolean` | `true` if tier is `TRUSTED` |
| `isMutable` | `boolean` | `true` if tier is `UNVERIFIED` |
| `verifiedAt` | `ISODateTime \| undefined` | Timestamp of last verified tier |
| `isVerificationLocked` | `boolean` | `true` if verified within the last 30 days |
| `verificationLockDaysRemaining` | `number` | Days until the 30-day lock expires |
| `isRestricted` | `boolean` | `true` if the identity is currently restricted |
| `verificationSummary` | `MajikIDVerificationSummary` | Full verification summary including stage states |

**Key & Data**

| Getter | Type | Description |
|---|---|---|
| `signingKey` | `Readonly<MajikKeyPublicBundle>` | The bound MajikKey public bundle |
| `userRef` | `Readonly<MajikUserRef>` | Cached MajikUser reference fields |
| `settings` | `Readonly<MajikIDSettings>` | Identity settings |
| `metadata` | `Readonly<MajikIDMetadata>` | Full metadata (private field has `rehydrated` stripped) |

**Private Info**

| Getter | Type | Description |
|---|---|---|
| `isPrivateDecrypted` | `boolean` | Whether private info has been decrypted this session |
| `privateInfo` | `Readonly<PrivatePersonalInfo>` | Decrypted private info — throws `MajikUniversalIDPrivateInfoLockedError` if not yet decrypted |

---

## ID Tiers

Tiers are automatically derived from the set of Didit stages that have been passed. A tier can only increase through webhook processing and can only decrease via `revokeVerification()`.

| Tier | Stages Required | Description |
|---|---|---|
| `UNVERIFIED` | None | No verification stages passed. Identity is mutable. |
| `BASIC` | Stage 4 (Phone) only | Phone OTP verified. |
| `VERIFIED` | Stage 1 (ID) | Government ID document verified. |
| `ENHANCED` | Stages 1 + 2 + 3 | ID + Liveness + Face Match. |
| `TRUSTED` | All 5 stages | Full verification including Phone and IP Analysis. Identity is immutable. |

---

## Verification Stages

Didit verification is a 5-stage workflow. Each stage maps to a `DiditStage` enum value:

| Stage | Enum | Description |
|---|---|---|
| 1 | `DiditStage.ID_VERIFICATION` | Government ID document scan and OCR |
| 2 | `DiditStage.LIVENESS` | Biometric liveness check |
| 3 | `DiditStage.FACE_MATCH` | Face match against ID document |
| 4 | `DiditStage.PHONE_VERIFICATION` | Phone OTP verification (SMS, call, or WhatsApp) |
| 5 | `DiditStage.IP_ANALYSIS` | IP address risk analysis |

AML (Anti-Money Laundering) screening is a supplemental check that runs alongside the main workflow.

---

## Immutability & Locking

Mutating operations on a `MajikUniversalID` follow two rules:

**Rule 1 — Tier gate.** Any operation that modifies the identity (signing, updating display name, syncing user ref, managing consents, updating settings) requires `isMutable === true`. A verified identity (`tier !== UNVERIFIED`) is immutable. Attempting to mutate a verified identity throws `MajikUniversalIDImmutableError`.

**Rule 2 — Revocation lock.** Once an identity becomes verified, `revokeVerification()` is blocked for **30 days** from `verifiedAt`. Attempting revocation within this window throws `MajikUniversalIDVerificationLockedError` with the number of remaining days.

```typescript
// Check before attempting revocation
if (!majikId.isVerificationLocked) {
  majikId.revokeVerification('User requested account reset');
}

// Check remaining lock time
console.log('Days remaining:', majikId.verificationLockDaysRemaining);
```

Note: `processWebhook()` and `applyDiditResult()` are **not** subject to the mutable check — they are the graduation path and must be able to run regardless of the current tier.

---

## Usage Examples

### Example 1: Create and Serialize an Identity

```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikUniversalID } from '@majikah/majik-universal-id';

const mnemonic = MajikKey.generateMnemonic();
const key = await MajikKey.create(mnemonic, 'passphrase', 'My Key');

const majikId = await MajikUniversalID.create(user, key, {
  account_id: 'acct_my_tenant',
});

console.log('Created ID:', majikId.id);
console.log('Tier:', majikId.tier); // IDTier.UNVERIFIED

// Serialize — rehydrated private info is stripped automatically
const json = majikId.toJSON();
await db.identities.insert({ id: majikId.id, data: json });
```

---

### Example 2: Load and Decrypt Private Info

```typescript
import { MajikKey } from '@majikah/majik-key';
import { MajikUniversalID } from '@majikah/majik-universal-id';

// Option A: Provide the key on load — silent decryption attempt
const key = await MajikKey.fromJSON(storedKey);
await key.unlock('passphrase');

const majikId = await MajikUniversalID.fromJSON(storedJson, { key });

if (majikId.isPrivateDecrypted) {
  const info = majikId.privateInfo;
  console.log('Name:', info.legal_first_name, info.legal_last_name);
}

// Option B: Explicit decryption after load
const majikId2 = await MajikUniversalID.fromJSON(storedJson);
const result = await majikId2.decryptPrivate(key);

if (result.success) {
  console.log('DOB:', result.data!.date_of_birth);
} else {
  console.log('Decryption failed:', result.reason);
}
```

---

### Example 3: Sign and Verify Content

```typescript
import { MajikUniversalID } from '@majikah/majik-universal-id';

// Sign a text document (identity must be UNVERIFIED / mutable)
const signature = await majikId.signContent(
  'This is my signed statement.',
  key,
  { contentType: 'text/plain' },
);

// Verify — both Ed25519 and ML-DSA-87 must pass
const result = majikId.verifyContent('This is my signed statement.', signature);
console.log('Valid:', result.valid);         // true
console.log('Signed at:', result.signed_at);

// Tamper detection
const tamperResult = majikId.verifyContent('This is modified.', signature);
console.log('Tampered rejected:', tamperResult.valid); // false
```

---

### Example 4: Sign and Verify a File

```typescript
import { MajikUniversalID } from '@majikah/majik-universal-id';

// Sign a file and embed the signature
const { blob: signedPdf, handler } = await majikId.signFile(pdfBlob, key);
console.log('Handler:', handler); // "PDF"

// Verify the embedded signature later
const result = await majikId.verifyFile(signedPdf);
if (result.valid) {
  console.log('Authentic. Signed by:', result.signer_fingerprint);
  console.log('Handler used:', result.handler);
} else {
  console.log('Invalid:', result.reason);
}
```

---

### Example 5: Process a Didit Webhook

```typescript
import { MajikUniversalID, DiditStage } from '@majikah/majik-universal-id';

// In your webhook handler (e.g. Cloudflare Worker or Express route)
const result = await majikId.processWebhook(payload, headers, webhookSecret);

console.log('Previous tier:', result.previous_tier);
console.log('New tier:', result.new_tier);
console.log('Tier changed:', result.tier_changed);
console.log('Stages updated:', result.updated_stages);
console.log('User sync actions:', result.user_sync_actions);
// e.g. ["verifyPhone", "verifyIdentity"]

// Apply user_sync_actions to the linked MajikUser
for (const action of result.user_sync_actions) {
  if (action === 'verifyIdentity') await user.setIdentityVerified(true);
  if (action === 'verifyPhone')    await user.setPhoneVerified(true);
  if (action === 'restrict')       await user.restrict();
}

// Persist the updated identity
await db.identities.update({ id: majikId.id, data: majikId.toJSON() });
```

---

### Example 6: Check Verification Stages

```typescript
import { MajikUniversalID, DiditStage } from '@majikah/majik-universal-id';

// Check individual stages
const phonePassed = majikId.isVerificationPassed(DiditStage.PHONE_VERIFICATION);
const livenessPassed = majikId.isVerificationPassed(DiditStage.LIVENESS);

// Get all passed stages in order
const passed = majikId.getPassedVerifications();
console.log('Passed stages:', passed);

// Full verification summary
const summary = majikId.verificationSummary;
console.log('AML clear:', summary.aml_clear);
console.log('Biometric status:', summary.biometric_status);
console.log('IP risk level:', summary.ip_risk_level);
```

---

### Example 7: Share Private Info With Another Recipient

```typescript
import { MajikUniversalID } from '@majikah/majik-universal-id';

// recipientKey does NOT need to be unlocked — only mlKemPublicKey is used
const scannerString = await majikId.sharePrivate({
  senderKey: myUnlockedKey,
  recipients: [recipientKey],
});

// The recipient decrypts with their own MajikKey
const env = MajikEnvelope.fromScannerString(scannerString);
const json = await env.decrypt({
  fingerprint: recipientKey.fingerprint,
  mlKemSecretKey: recipientKey.mlKemSecretKey,
});
const privateInfo = JSON.parse(json);
```

---

### Example 8: Public View Projection

```typescript
import { MajikUniversalID } from '@majikah/majik-universal-id';

// Safe to return from a public API — contains no private info
const publicView = majikId.toPublicView();

console.log('Display name:', publicView.display_name);
console.log('Tier:', publicView.tier);
console.log('Signing key fingerprint:', publicView.signing_key.fingerprint);
console.log('Verification stages:', publicView.verification_stages);
// {
//   id_verification: true,
//   liveness: true,
//   face_match: false,
//   phone_verification: false,
//   ip_analysis: false
// }
```

---

### Example 9: Revoke Verification

```typescript
import {
  MajikUniversalID,
  MajikUniversalIDVerificationLockedError,
} from '@majikah/majik-universal-id';

try {
  majikId.revokeVerification('User requested account reset');
  console.log('Revoked. Tier:', majikId.tier); // IDTier.UNVERIFIED
} catch (err) {
  if (err instanceof MajikUniversalIDVerificationLockedError) {
    console.log('Cannot revoke yet:', err.days_remaining, 'days remaining');
  }
}
```

---

## Error Reference

All public methods throw typed subclasses of `MajikUniversalIDError`. Use the exported type guards for precise error handling.

| Error Class | Code | Description |
|---|---|---|
| `MajikUniversalIDValidationError` | `VALIDATION_ERROR` | Invalid or missing inputs to factory methods |
| `MajikUniversalIDDeserializationError` | `DESERIALIZATION_ERROR` | Malformed JSON or base64 on load |
| `MajikUniversalIDIntegrityError` | `INTEGRITY_ERROR` | SHA3-512 hash mismatch on deserialization |
| `MajikUniversalIDKeyError` | `KEY_ERROR` | Missing required public key fields on a MajikKey |
| `MajikUniversalIDKeyNotFoundError` | `KEY_NOT_FOUND` | Provided key fingerprint doesn't match the bound key |
| `MajikUniversalIDSigningError` | `SIGNING_ERROR` | Signing operation failed |
| `MajikUniversalIDVerificationError` | `VERIFICATION_ERROR` | Structural error during content/file verification |
| `MajikUniversalIDWebhookSignatureError` | `WEBHOOK_SIGNATURE_INVALID` | Webhook HMAC verification failed |
| `MajikUniversalIDWebhookPayloadError` | `WEBHOOK_PAYLOAD_INVALID` | Webhook `vendor_data` mismatch or invalid structure |
| `MajikUniversalIDImmutableError` | `IDENTITY_IMMUTABLE` | Mutating operation attempted on a verified identity |
| `MajikUniversalIDVerificationLockedError` | `VERIFICATION_LOCKED` | `revokeVerification()` called within the 30-day lock |
| `MajikUniversalIDPrivateInfoLockedError` | `PRIVATE_INFO_LOCKED` | `privateInfo` accessed before `decryptPrivate()` |
| `MajikUniversalIDPrivateInfoEncryptionError` | `PRIVATE_INFO_ENCRYPTION_ERROR` | Encryption of private info failed |
| `MajikUniversalIDRestrictedError` | `IDENTITY_RESTRICTED` | Operation blocked — identity is currently restricted |
| `MajikUniversalIDTierRequiredError` | `TIER_REQUIRED` | Operation requires a higher `IDTier` |

**Type guards:**

```typescript
import {
  isUniversalIDError,
  isValidationError,
  isWebhookError,
  isImmutableError,
  isLockedError,
  isPrivateInfoLockedError,
} from '@majikah/majik-universal-id';
```

---

## Security Considerations

### What is Guaranteed

- **Integrity**: The SHA3-512 hash commits all four bound public keys — key material substitution is detectable on load
- **Content integrity**: Any byte change to signed content invalidates both the Ed25519 and ML-DSA-87 signatures
- **Private info confidentiality**: Private personal info is never stored or serialized in plaintext — only the ML-KEM-768 encrypted envelope is persisted
- **Signer binding**: Signatures are cryptographically bound to a specific `MajikKey` fingerprint
- **Immutability enforcement**: Verified identities cannot be mutated — enforced at every public mutating method
- **Hybrid downgrade resistance**: Both classical and post-quantum algorithms must be broken simultaneously to forge a signature

### What is Your Responsibility

- **Key management**: Lock the `MajikKey` immediately after signing — `key.lock()` purges secret keys from memory
- **Signer identity verification**: The library proves content was signed by a specific key. It does not prove who owns that key in the real world. Maintain the mapping between `signerId` and a real-world identity through your own means
- **`vendor_data` routing**: Always set `MajikUniversalID.id` as `vendor_data` when creating a Didit session. Webhooks with mismatched `vendor_data` are rejected by `processWebhook()`
- **`extractPublicKeys()` caution**: Public keys embedded in a Majik Signature envelope are self-reported by the signer. Always cross-check `signerId` against `majikId.signingKey.fingerprint` before trusting extracted keys
- **Byte-for-byte consistency**: The same bytes must be passed to both `sign()` and `verify()`. For JSON payloads, use the same `JSON.stringify()` output on both sides
- **Key upgrade**: Legacy `MajikKey` accounts without signing keys must be re-imported via `importFromMnemonicBackup()`. Check with `key.hasSigningKeys` before calling any signing method

### What NOT to Do

❌ **DON'T** access `privateInfo` without first calling `decryptPrivate(key)` or providing the key to `fromJSON()`  
❌ **DON'T** trust `verifyContent()` without also checking `result.signer_registered === true` and verifying `result.signer_fingerprint` against a known trusted source  
❌ **DON'T** pass a locked key to `signContent()` or `signFile()` — call `key.unlock(passphrase)` first  
❌ **DON'T** call `processWebhook()` without first checking that `payload.vendor_data === majikId.id`  
❌ **DON'T** modify file bytes (re-encode, compress, transcode) between `signFile()` and `verifyFile()`  
❌ **DON'T** rely on the `contentType` field in a signature for security decisions — it is advisory only  

### What TO Do

✅ **DO** lock the key immediately after any signing operation  
✅ **DO** validate the integrity of a restored identity using `majikId.validate()` after loading from storage  
✅ **DO** use `isSigned()` from Majik Signature as a fast guard before calling `verifyFile()`  
✅ **DO** check `result.signer_fingerprint === majikId.signingKey.fingerprint` in `verifyContent()` results  
✅ **DO** store identities using `toJSON()` — private info is guaranteed stripped  
✅ **DO** use `toPublicView()` for any data returned from public-facing API routes  

---

## Related Projects



### [Majik Signature](https://www.npmjs.com/package/@majikah/majik-signature)
Hybrid post-quantum content signing — the signing engine used by `signContent()` and `signFile()`.

[Read Docs](https://majikah.solutions/products/majik-signature/docs) · [Microsoft Store](https://apps.microsoft.com/detail/9pl9g3xzvd1x)

[![Majik Message Microsoft App Store](https://get.microsoft.com/images/en-us%20light.svg)](https://apps.microsoft.com/detail/9pl9g3xzvd1x)



### [Majik Message](https://message.majikah.solutions)
Secure messaging platform using Majik Keys and Majik Signatures for identity-bound communication.

[Read Docs](https://majikah.solutions/products/majik-message/docs) · [Microsoft Store](https://apps.microsoft.com/detail/9pmjgvzzjspn)

[![Majik Message Microsoft App Store](https://get.microsoft.com/images/en-us%20light.svg)](https://apps.microsoft.com/detail/9pmjgvzzjspn)


### [Majik Key](https://www.npmjs.com/package/@majikah/majik-key)
Seed phrase account library — required peer dependency for signing and encryption.

[Read More Information](https://majikah.solutions/sdk/majik-key)

### [Majik Envelope](https://www.npmjs.com/package/@majikah/majik-envelope)
Post-quantum group encryption — used to encrypt and share private personal info.

[Read More Information](https://majikah.solutions/sdk/majik-envelope)

---

## Contributing

If you want to contribute or help extend support, reach out via email. All contributions are welcome!

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

**Developer**: Josef Elijah Fabian  
**GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)  
**Project Repository**: [https://github.com/Majikah/majik-universal-id](https://github.com/Majikah/majik-universal-id)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **ID Web App**: [https://id.majikah.solutions](https://id.majikah.solutions)