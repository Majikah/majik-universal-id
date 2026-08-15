import { describe, it, expect, beforeEach, beforeAll, vi } from "vitest";
import { MajikUniversalID } from "../src/majik-universal-id";
import { MajikKey } from "@majikah/majik-key";
import { MajikUser } from "@thezelijah/majik-user";
import { MajikSignature } from "@majikah/majik-signature";
import { diditMapper } from "../src/core/didit/webhook";

import {
  IDTier,
  IDStatus,
  DiditStage,
  VisibilityScope,
} from "../src/core/enums";

import {
  MajikUniversalIDValidationError,
  MajikUniversalIDKeyError,
  MajikUniversalIDImmutableError,
  MajikUniversalIDPrivateInfoLockedError,
  MajikUniversalIDIntegrityError,
  MajikUniversalIDVerificationLockedError,
  MajikUniversalIDWebhookPayloadError,
  MajikUniversalIDDeserializationError,
} from "../src/core/errors";
import { getTestKey } from "./helpers/crypto";
import {
  bundleToSigningKeyMaterial,
  computeBundleHash,
} from "../src/core/utils";

// ---------------------------------------------------------------------------
// MOCK DIDIT MAPPER
// (The only mock in this suite, as requested for webhook isolation)
// ---------------------------------------------------------------------------
vi.mock("../src/core/didit/webhook", () => ({
  diditMapper: {
    map: vi.fn(),
  },
}));

function setupTestUser(): MajikUser {
  // Assuming a standard constructor or factory for MajikUser
  // This provides the bare minimum valid payload for UniversalID creation
  return new MajikUser({
    id: "usr_01HGW...",
    email: "test@majikah.dev",
    displayName: "Test User",
    hash: "dummy-hash-base64",
    createdAt: new Date(),
    lastUpdate: new Date(),

    metadata: {
      name: { first_name: "Test", last_name: "User" },
      birthdate: "1990-01-01",
      gender: "Male",
    },
    settings: {
      system: { isRestricted: false },
      notifications: true,
    },
  });
}

// ---------------------------------------------------------------------------
// TEST SUITE
// ---------------------------------------------------------------------------
describe("MajikUniversalID", () => {
  // ── SHARED KEY POOL ─────────────────────────────────────────────────────
  let activeKey: MajikKey;
  let lockedKey: MajikKey;
  let recipientKey: MajikKey;
  let rotationKey: MajikKey;

  let activeUser: MajikUser;
  let baseOptions: any;

  beforeAll(async () => {
    console.log("[majik-key] Generating shared key pool (4 keys, parallel)...");
    [activeKey, lockedKey, recipientKey, rotationKey] = await Promise.all([
      getTestKey(),
      getTestKey(),
      getTestKey(),
      getTestKey(),
    ]);

    // Pre-lock the designated key for negative tests
    lockedKey.lock();

    activeUser = setupTestUser();
    baseOptions = { account_id: "acc_123", username: "testuser" };
    console.log("[majik-key] Shared key pool ready.");
  }, 120000);

  describe("Creation and Initialization", () => {
    it("should create a valid instance with an unlocked MajikKey", async () => {
      const id = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );

      expect(id).toBeInstanceOf(MajikUniversalID);
      expect(id.userId).toBe(activeUser.id);
      expect(id.accountId).toBe(baseOptions.account_id);
      expect(id.username).toBe(baseOptions.username);
      expect(id.isMutable).toBe(true);
      expect(id.tier).toBe(IDTier.UNVERIFIED);

      // Private info should be accessible immediately in memory
      expect(id.isPrivateDecrypted).toBe(true);
      expect(id.privateInfo.legal_first_name).toBe("Test");
    });

    it("should throw MajikUniversalIDKeyError if the key is locked", async () => {
      await expect(
        MajikUniversalID.create(activeUser, lockedKey, baseOptions),
      ).rejects.toThrow(MajikUniversalIDKeyError);
    });

    it("should throw validation error if MajikUser is invalid", async () => {
      const invalidUser = setupTestUser();
      invalidUser.validate = () => ({
        isValid: false,
        errors: ["Invalid email"],
      });

      await expect(
        MajikUniversalID.create(invalidUser, activeKey, baseOptions),
      ).rejects.toThrow(MajikUniversalIDValidationError);
    });
  });

  describe("Serialization and Deserialization", () => {
    let originalId: MajikUniversalID;

    beforeEach(async () => {
      originalId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should serialize to JSON and strictly strip rehydrated private info", () => {
      const json = originalId.toJSON();

      expect(json.id).toBe(originalId.id);
      expect(json.metadata.private.encrypted).toBe(true);
      expect(json.metadata.private.envelope).toBeDefined();
      expect((json.metadata.private as any).rehydrated).toBeUndefined();
    });

    it("should reconstruct successfully from JSON and Base64", async () => {
      const json = originalId.toJSON();
      const b64 = originalId.toBase64();

      const fromJsonInstance = await MajikUniversalID.fromJSON(json);
      const fromB64Instance = await MajikUniversalID.fromBase64(b64);

      expect(fromJsonInstance.id).toBe(originalId.id);
      expect(fromB64Instance.hash).toBe(originalId.hash);

      // On raw load without key, private info is NOT decrypted
      expect(fromJsonInstance.isPrivateDecrypted).toBe(false);
    });

    it("should swallow decryption errors silently if a key is provided during load", async () => {
      const json = originalId.toJSON();
      const instance = await MajikUniversalID.fromJSON(json, {
        key: activeKey,
      });

      expect(instance.isPrivateDecrypted).toBe(true);
      expect(instance.privateInfo).toBeDefined();
    });

    it("should throw an IntegrityError if the hash is tampered with", async () => {
      const json = originalId.toJSON();

      // Tamper with the hash itself to guarantee a mismatch
      json.hash = "tampered-invalid-hash-string";

      await expect(MajikUniversalID.fromJSON(json)).rejects.toThrow(
        MajikUniversalIDIntegrityError,
      );
    });
  });

  describe("Private Info Encryption and Sharing", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
      // Force serialization cycle to drop in-memory rehydrated data
      majikId = await MajikUniversalID.fromJSON(majikId.toJSON());
    });

    it("should throw when accessing privateInfo before decryption", () => {
      expect(majikId.isPrivateDecrypted).toBe(false);
      expect(() => majikId.privateInfo).toThrow(
        MajikUniversalIDPrivateInfoLockedError,
      );
    });

    it("should decrypt private info successfully with the bound key", async () => {
      const result = await majikId.decryptPrivate(activeKey);

      expect(result.success).toBe(true);
      expect(majikId.isPrivateDecrypted).toBe(true);
      expect(majikId.privateInfo.primary_email).toBe("test@majikah.dev");
    });

    it("should generate a valid scanner string when sharing private info", async () => {
      const scannerString = await majikId.sharePrivate({
        senderKey: activeKey,
        recipients: [recipientKey],
      });

      expect(scannerString).toBeTypeOf("string");
      expect(scannerString).toContain("~*$MJKMSG:");
    });
  });

  describe("Content Signing and Verification", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should sign text content successfully when mutable", async () => {
      const signature = await majikId.signContent(
        "Maharlika Project Data",
        activeKey,
      );

      expect(signature).toBeInstanceOf(MajikSignature);
      expect(signature.signerId).toBe(activeKey.fingerprint);
    });

    it("should throw an ImmutableError if trying to sign when verified", async () => {
      // Mock graduation to Verified (Added missing typings)
      vi.mocked(diditMapper.map).mockReturnValueOnce({
        verification: { tier: IDTier.VERIFIED, status: IDStatus.ACTIVE } as any,
        all_stages_passed: true,
        updated_stages: [DiditStage.ID_VERIFICATION],
        extracted_personal_data: {} as any,
        image_urls_to_hash: {},
        session_meta: {} as any,
        is_terminal: true,
      });

      await majikId.processWebhook(
        { vendor_data: majikId.id } as any,
        {} as any,
        "secret",
      );

      expect(majikId.isMutable).toBe(false);
      await expect(majikId.signContent("Data", activeKey)).rejects.toThrow(
        MajikUniversalIDImmutableError,
      );
    });

    it("should verify historically signed content", async () => {
      const content = "Pre-colonial artifacts manifest";
      const signature = await majikId.signContent(content, activeKey);

      const verification = majikId.verifyText(content, signature.toJSON());

      expect(verification.valid).toBe(true);
      expect(verification.trust_level).toBe("active_at_signing");
    });
  });

  describe("Didit Webhooks and Verification Lifecycle", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
      vi.clearAllMocks();
    });

    it("should throw WebhookPayloadError if vendor_data does not match ID", async () => {
      await expect(
        majikId.processWebhook(
          { vendor_data: "wrong-id" } as any,
          {} as any,
          "secret",
        ),
      ).rejects.toThrow(MajikUniversalIDWebhookPayloadError);
    });

    it("should process webhook and graduate tier", async () => {
      // Added missing typings
      vi.mocked(diditMapper.map).mockReturnValueOnce({
        verification: {
          tier: IDTier.TRUSTED,
          completed_stages: [
            DiditStage.ID_VERIFICATION,
            DiditStage.LIVENESS,
            DiditStage.FACE_MATCH,
            DiditStage.PHONE_VERIFICATION,
            DiditStage.IP_ANALYSIS,
          ],
        } as any,
        all_stages_passed: true,
        updated_stages: [DiditStage.IP_ANALYSIS],
        extracted_personal_data: {} as any,
        image_urls_to_hash: {},
        session_meta: {} as any,
        is_terminal: true,
      });

      const result = await majikId.processWebhook(
        { vendor_data: majikId.id } as any,
        {} as any,
        "secret",
      );

      expect(result.success).toBe(true);
      expect(result.tier_changed).toBe(true);
      expect(majikId.tier).toBe(IDTier.TRUSTED);
      expect(majikId.isTrusted).toBe(true);
    });

    it("should lock verification revocation for 30 days after completion", async () => {
      const recentDate = new Date().toISOString();
      // Added missing typings
      vi.mocked(diditMapper.map).mockReturnValueOnce({
        verification: { tier: IDTier.VERIFIED, verified_at: recentDate } as any,
        all_stages_passed: true,
        updated_stages: [DiditStage.ID_VERIFICATION],
        extracted_personal_data: {} as any,
        image_urls_to_hash: {},
        session_meta: {} as any,
        is_terminal: true,
      });

      await majikId.processWebhook(
        { vendor_data: majikId.id } as any,
        {} as any,
        "secret",
      );

      expect(() => majikId.revokeVerification("Manual override")).toThrow(
        MajikUniversalIDVerificationLockedError,
      );
    });
  });

  describe("Key Rotation", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });



    it("should throw a ValidationError if new key is identical to current key", async () => {
      await expect(
        majikId.rotateKey(activeUser, activeKey, { reason: "compromised" }),
      ).rejects.toThrow("nothing to rotate");
    });
  });

  describe("Mutations & User Sync", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should update display name when mutable", () => {
      majikId.updateDisplayName("Zelijah");
      expect(majikId.toPublicView().display_name).toBe("Zelijah");
    });

    it("should update settings", () => {
      majikId.updateSettings({
        privacy: { profile_visibility: VisibilityScope.PUBLIC } as any,
      });
      expect(majikId.settings.privacy.profile_visibility).toBe(
        VisibilityScope.PUBLIC,
      );
    });

    it("should grant and revoke consent", () => {
      majikId.grantConsent("majik-message-client", ["read:profile"]);

      let activeConsents = majikId.getActiveConsents();
      expect(activeConsents.length).toBe(1);
      expect(activeConsents[0].granted_to).toBe("majik-message-client");

      majikId.revokeConsent(activeConsents[0].consent_id);
      expect(majikId.getActiveConsents().length).toBe(0);
    });
  });

  describe("Public Views and Exporters", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should generate a safe public view", () => {
      const view = majikId.toPublicView();

      expect(view.id).toBe(majikId.id);
      expect((view as any).metadata).toBeUndefined();
      expect((view as any).signature_records).toBeUndefined();
      expect(view.verification_stages[DiditStage.LIVENESS]).toBe(false);
    });

    it("should build a valid ExpectedSigner object", () => {
      const expectedSigner = majikId.buildExpectedSigner();

      expect(expectedSigner.signerId).toBe(activeKey.fingerprint);
      expect(expectedSigner.edPublicKey).toBeDefined();
      expect(expectedSigner.mlDsaPublicKey).toBeDefined();
    });

    it("should build a valid MajikRecipient object", () => {
      const recipient = majikId.buildMajikRecipient();

      expect(recipient.fingerprint).toBe(activeKey.fingerprint);
      expect(recipient.mlKemPublicKey).toBeInstanceOf(Uint8Array);
    });
  });

  describe("File Signing and Verification", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should sign a file and verify it successfully using the active key", async () => {
      const dummyBlob = new Blob(["Majikah File Content"], {
        type: "text/plain",
      });

      const signedResult = await majikId.signFile(dummyBlob, activeKey, {
        contentType: "text/plain",
        label: "test-file.txt",
      });

      expect(signedResult.blob).toBeInstanceOf(Blob);
      expect(signedResult.signature).toBeInstanceOf(MajikSignature);
      expect(signedResult.handler).toBeDefined();

      const verification = await majikId.verifyFile(signedResult.blob);

      expect(verification.valid).toBe(true);
      expect(verification.signer_fingerprint).toBe(activeKey.fingerprint);
      expect(verification.signer_registered).toBe(true);
      expect(verification.trust_level).toBe("active_at_signing");
    });

    it("should fail verification if a file contains no embedded signature", async () => {
      const unsignedBlob = new Blob(["Unsigned content"], {
        type: "text/plain",
      });
      const verification = await majikId.verifyFile(unsignedBlob);

      expect(verification.valid).toBe(false);
      expect(verification.signer_registered).toBe(false);
      expect(verification.reason).toContain("No embedded MajikSignature found");
    });
  });

  describe("Historical Trust Boundaries and Key Generation Ledger", () => {
    let majikId: MajikUniversalID;
    let oldKey: MajikKey;
    let historicalSig: MajikSignature;
    let oldKeyBundleHash: string;

    beforeEach(async () => {
      oldKey = activeKey;
      majikId = await MajikUniversalID.create(activeUser, oldKey, baseOptions);

      // Sign content with old key before rotation
      const content = "Historical Artifact Record";
      historicalSig = await majikId.signContent(content, oldKey);

      // Capture the old key's bundle hash BEFORE rotation changes majikId.signingKey
      oldKeyBundleHash = computeBundleHash(
        bundleToSigningKeyMaterial(majikId.signingKey),
      );

      // Rotate to new key
      const rotationResult = await majikId.rotateKey(activeUser, rotationKey, {
        reason: "voluntary",
        oldKey: oldKey,
      });
    });

    it("should reject historically signed content if signed after key deactivation", async () => {
      // Mocking a scenario where signature timestamp is past deactivation
      const tamperedSigJson = historicalSig.toJSON();
      tamperedSigJson.timestamp = new Date(Date.now() + 86400000).toISOString(); // Future date

      const verification = majikId.verifyContent(
        "Historical Artifact Record",
        tamperedSigJson,
        undefined,
        [
          {
            fingerprint: oldKey.fingerprint,
            bundle_hash: oldKeyBundleHash, // Use the correctly preserved old bundle hash here
            kdf_version: 1,
            status: "rotated",
            activated_at: new Date(Date.now() - 200000).toISOString(),
            deactivated_at: new Date(Date.now() - 100000).toISOString(), // Deactivated in the past
            reason: "voluntary",
            authorized_via: "old_key_signature",
            id: "old_key",
            muid_id: oldKey.id,
          },
        ],
      );

      expect(verification.valid).toBe(false);
      expect(verification.trust_level).toBe("signed_after_rotation");
    });
  });

  describe("Identity Validation Suite", () => {
    it("should pass validation for a freshly created identity", async () => {
      const id = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
      const validation = id.validate();

      expect(validation.is_valid).toBe(true);
      expect(validation.errors).toHaveLength(0);
    });

    it("should catch structural and field validation errors", async () => {
      const id = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );

      // Force corruption via internal prototype manipulation or serialization checks
      const json = id.toJSON();
      delete (json as any).account_id;

      await expect(MajikUniversalID.fromJSON(json)).rejects.toThrow(
        MajikUniversalIDDeserializationError,
      );
    });
  });

  describe("Lifecycle Mutations & State Management", () => {
    let majikId: MajikUniversalID;

    beforeEach(async () => {
      majikId = await MajikUniversalID.create(
        activeUser,
        activeKey,
        baseOptions,
      );
    });

    it("should clear the username successfully", () => {
      expect(majikId.username).toBe("testuser");
      majikId.clearUsername();
      expect(majikId.username).toBeNull();
    });

    it("should sync user reference data correctly when mutable", () => {
      const updatedUser = setupTestUser();
      updatedUser.displayName = "Zelijah Updated";

      majikId.syncUserRef(updatedUser);
      expect(majikId.userRef.display_name).toBe("Zelijah Updated");
    });

    it("should allow a successful verification revocation if outside the 30-day lock window", () => {
      // Force an old verification date to bypass the 30-day lock constraint
      const pastDate = new Date(
        Date.now() - 35 * 24 * 60 * 60 * 1000,
      ).toISOString();

      vi.mocked(diditMapper.map).mockReturnValueOnce({
        verification: { tier: IDTier.VERIFIED, verified_at: pastDate } as any,
        all_stages_passed: true,
        updated_stages: [DiditStage.ID_VERIFICATION],
        extracted_personal_data: {} as any,
        image_urls_to_hash: {},
        session_meta: {} as any,
        is_terminal: true,
      });

      // Simulate graduating to verified first
      return majikId
        .processWebhook({ vendor_data: majikId.id } as any, {} as any, "secret")
        .then(() => {
          expect(majikId.tier).toBe(IDTier.VERIFIED);

          // Now revoke should succeed
          majikId.revokeVerification("User requested data wipe");
          expect(majikId.tier).toBe(IDTier.UNVERIFIED);
          expect(majikId.isMutable).toBe(true);
        });
    });
  });
});
