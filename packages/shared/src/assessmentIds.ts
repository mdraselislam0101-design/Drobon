/**
 * Standalone assessment ID contract shared by assessment and scan guards.
 * Kept separate to avoid a runtime import cycle between their contracts.
 */
export const ASSESSMENT_ID_PATTERN = /^asm_[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
