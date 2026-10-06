// ── Errors ──────────────────────────────────────────────────────────────────
export * from "./core/errors.js";

// ── Schema enums ──────────────────────────────────────────────────────────────
export * from "./core/enums.js";

// ── Schema types ──────────────────────────────────────────────────────────────
export type * from "./core/schema.js";

// ── Didit webhook ─────────────────────────────────────────────────────
export * from "./core/didit/webhook.js";
export type * from "./core/didit/schema.js";

// ── Class-layer types ────────────────────────────────────────────────────────
export type * from "./core/types.js";

// ── Utilities (for advanced use) ───────────────────────────────────────────────
export * from "./core/utils.js";

// ── Mapper (for advanced use — build your own webhook handler) ────────────────
export { DiditWebhookMapperImpl, diditMapper } from "./core/didit/webhook.js";

// ──  Main SDK ───────────────────────────────────────────────
export * from "./majik-universal-id.js";
