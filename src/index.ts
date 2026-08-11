// ── Errors ──────────────────────────────────────────────────────────────────
export * from "./core/errors";

// ── Schema enums ──────────────────────────────────────────────────────────────
export * from "./core/enums";

// ── Schema types ──────────────────────────────────────────────────────────────
export type * from "./core/schema";

// ── Didit webhook ─────────────────────────────────────────────────────
export * from "./core/didit/webhook";

// ── Class-layer types ────────────────────────────────────────────────────────
export type * from "./core/types";

// ── Utilities (for advanced use) ───────────────────────────────────────────────
export * from "./core/utils";

// ── Mapper (for advanced use — build your own webhook handler) ────────────────
export { DiditWebhookMapperImpl, diditMapper } from "./core/didit/webhook";

// ──  Main SDK ───────────────────────────────────────────────
export * from "./majik-universal-id";
