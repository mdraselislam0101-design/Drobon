import { writePrivateJson } from '../lib/writePrivateJson.js';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import type { PaymentMethod } from '@drobon/shared';

/**
 * Runtime payment configuration (Phase 20) — the admin-controlled source of
 * truth for the PRO price and the manual-transfer destinations offered to
 * users.
 *
 * WHY THIS EXISTS: until Phase 20 the price/methods came from boot-time
 * environment variables. The phase requires authorized platform admins to
 * manage them at runtime with live reflection, historical integrity and an
 * audit trail — which needs a durable, mutable, server-authoritative store.
 * It follows the established single-document JSON store pattern (atomic
 * temp-file + rename writes, fail-fast on corruption, single writer).
 *
 * Semantics:
 * - While NO destinations have ever been configured, the store runs in the
 *   legacy seed mode: `MANUAL_TRANSFER` is offered with the boot-time
 *   instructions text (exactly the pre-Phase-20 behavior).
 * - Once an admin adds a destination, destinations are authoritative: only
 *   ENABLED destinations are offered; with none enabled, no manual payment
 *   can be created (fail closed).
 * - The engine-level method contract stays `MANUAL_TRANSFER`; destinations
 *   are the "where do I send the money" metadata, never a second method
 *   vocabulary.
 * - Price changes apply to NEW quotes/payments only. Historical payment
 *   records snapshot their own amount and are never rewritten.
 */

export interface PaymentDestinationRecord {
  methodId: string;
  method: PaymentMethod;
  displayName: string;
  accountNumber: string;
  instructions: string;
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
}

export type PaymentConfigAuditAction =
  | 'PAYMENT_CONFIG_PRICE_UPDATED'
  | 'PAYMENT_CONFIG_METHOD_ADDED'
  | 'PAYMENT_CONFIG_METHOD_UPDATED';

export interface PaymentConfigAuditRecord {
  entryId: string;
  at: string;
  actorId: string;
  action: PaymentConfigAuditAction;
  detail: string;
}

export interface PaymentConfigState {
  proPriceMinorUnits: number;
  currency: 'BDT';
  destinations: PaymentDestinationRecord[];
  updatedAt: string;
  audit: PaymentConfigAuditRecord[];
}

export type AddMethodResult =
  | { kind: 'CREATED' | 'REPLAY'; destination: PaymentDestinationRecord }
  | { kind: 'DUPLICATE_DISPLAY_NAME' };

export type UpdateMethodResult =
  | { kind: 'UPDATED'; state: PaymentConfigState }
  | { kind: 'NOT_FOUND' }
  | { kind: 'DUPLICATE_DISPLAY_NAME' };

export interface PaymentConfigStore {
  /** Live snapshot (clone). Reads never observe partial writes. */
  current(): PaymentConfigState;
  setPrice(actorId: string, proPriceMinorUnits: number, at: string): Promise<PaymentConfigState>;
  addMethod(
    actorId: string,
    input: { displayName: string; accountNumber: string; instructions: string },
    at: string,
    idempotencyKey: string,
  ): Promise<AddMethodResult>;
  updateMethod(
    actorId: string,
    methodId: string,
    patch: { displayName?: string; accountNumber?: string; instructions?: string; enabled?: boolean },
    at: string,
  ): Promise<UpdateMethodResult>;
}

export const PRICE_MIN_MINOR_UNITS = 1;
export const PRICE_MAX_MINOR_UNITS = 100_000_000;
export const MAX_DESTINATIONS = 32;
export const MAX_CONFIG_AUDIT_ENTRIES = 200;
const MAX_IDEMPOTENCY_KEYS = 1000;
const IDEMPOTENCY_KEY_PATTERN = /^[A-Za-z0-9_-]{8,128}$/;

/** Mask a transfer account number for audit records (never store it raw). */
export function maskAccountNumber(value: string): string {
  if (value.length <= 4) return '****';
  return `${value.slice(0, 2)}${'*'.repeat(Math.min(value.length - 4, 12))}${value.slice(-2)}`;
}

interface IdempotencyRecord {
  key: string;
  actorId: string;
  methodId: string;
  at: string;
}

interface StoreDocument {
  version: 1;
  proPriceMinorUnits: number;
  destinations: PaymentDestinationRecord[];
  audit: PaymentConfigAuditRecord[];
  idempotency: IdempotencyRecord[];
  updatedAt: string;
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && !Number.isNaN(Date.parse(value));
}

function isDestinationRecord(value: unknown): value is PaymentDestinationRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['methodId'] === 'string' && /^pmd_[0-9a-f-]{36}$/i.test(r['methodId']) &&
    r['method'] === 'MANUAL_TRANSFER' &&
    typeof r['displayName'] === 'string' && r['displayName'].length >= 1 && r['displayName'].length <= 80 &&
    typeof r['accountNumber'] === 'string' && r['accountNumber'].length >= 4 && r['accountNumber'].length <= 40 &&
    typeof r['instructions'] === 'string' && r['instructions'].length <= 300 &&
    typeof r['enabled'] === 'boolean' &&
    validTimestamp(r['createdAt']) && validTimestamp(r['updatedAt'])
  );
}

function isAuditRecord(value: unknown): value is PaymentConfigAuditRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['entryId'] === 'string' && /^pca_[0-9a-f-]{36}$/i.test(r['entryId']) &&
    validTimestamp(r['at']) &&
    typeof r['actorId'] === 'string' && r['actorId'].length > 0 &&
    (r['action'] === 'PAYMENT_CONFIG_PRICE_UPDATED' || r['action'] === 'PAYMENT_CONFIG_METHOD_ADDED' || r['action'] === 'PAYMENT_CONFIG_METHOD_UPDATED') &&
    typeof r['detail'] === 'string' && r['detail'].length > 0 && r['detail'].length <= 300
  );
}

function isIdempotencyRecord(value: unknown): value is IdempotencyRecord {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  return (
    typeof r['key'] === 'string' && typeof r['actorId'] === 'string' &&
    typeof r['methodId'] === 'string' && validTimestamp(r['at'])
  );
}

interface StoreInternals {
  state: PaymentConfigState;
  idempotency: IdempotencyRecord[];
}

function cloneState(state: PaymentConfigState): PaymentConfigState {
  return {
    ...state,
    destinations: state.destinations.map((destination) => ({ ...destination })),
    audit: state.audit.map((entry) => ({ ...entry })),
  };
}

function withAudit(state: PaymentConfigState, entry: Omit<PaymentConfigAuditRecord, 'entryId'>): PaymentConfigState {
  return { ...state, audit: [...state.audit, { entryId: `pca_${randomUUID()}`, ...entry }].slice(-MAX_CONFIG_AUDIT_ENTRIES) };
}

/**
 * Destination availability drives the user-facing method list. Empty list =
 * legacy seed mode (pre-Phase-20 behavior); otherwise at least one enabled
 * destination is required for manual payments to stay available.
 */
export function manualMethodsFromState(state: PaymentConfigState): PaymentMethod[] {
  if (state.destinations.length === 0) return ['MANUAL_TRANSFER'];
  return state.destinations.some((destination) => destination.enabled) ? ['MANUAL_TRANSFER'] : [];
}

function createStore(
  initial: StoreInternals,
  persist: (document: StoreDocument) => void,
): PaymentConfigStore {
  let { state, idempotency } = initial;
  let queue: Promise<unknown> = Promise.resolve();
  const exclusive = <T>(task: () => T): Promise<T> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run;
  };

  const commit = (nextState: PaymentConfigState, nextIdempotency: IdempotencyRecord[]): void => {
    persist({
      version: 1,
      proPriceMinorUnits: nextState.proPriceMinorUnits,
      destinations: nextState.destinations,
      audit: nextState.audit,
      idempotency: nextIdempotency,
      updatedAt: nextState.updatedAt,
    });
    state = nextState;
    idempotency = nextIdempotency;
  };

  return {
    current: () => cloneState(state),
    setPrice: (actorId, proPriceMinorUnits, at) => {
      if (!Number.isSafeInteger(proPriceMinorUnits) || proPriceMinorUnits < PRICE_MIN_MINOR_UNITS || proPriceMinorUnits > PRICE_MAX_MINOR_UNITS) {
        throw new Error('Payment config price is out of bounds.');
      }
      return exclusive(() => {
        const previous = state.proPriceMinorUnits;
        const nextState = withAudit(
          { ...state, proPriceMinorUnits, updatedAt: at },
          { at, actorId, action: 'PAYMENT_CONFIG_PRICE_UPDATED', detail: `PRO price changed from ${previous} to ${proPriceMinorUnits} minor units.` },
        );
        commit(nextState, idempotency);
        return cloneState(state);
      });
    },
    addMethod: (actorId, input, at, idempotencyKey) =>
      exclusive(() => {
        if (!IDEMPOTENCY_KEY_PATTERN.test(idempotencyKey)) throw new Error('Invalid idempotency key.');
        const scopedKey = `${actorId}:${idempotencyKey}`;
        const replay = idempotency.find((entry) => entry.key === scopedKey);
        if (replay !== undefined) {
          const existing = state.destinations.find((destination) => destination.methodId === replay.methodId);
          if (existing !== undefined) return { kind: 'REPLAY' as const, destination: { ...existing } };
        }
        const normalizedName = input.displayName.trim().toLowerCase();
        if (state.destinations.some((destination) => destination.displayName.trim().toLowerCase() === normalizedName)) {
          return { kind: 'DUPLICATE_DISPLAY_NAME' as const };
        }
        if (state.destinations.length >= MAX_DESTINATIONS) throw new Error('Payment destination capacity reached.');
        const destination: PaymentDestinationRecord = {
          methodId: `pmd_${randomUUID()}`,
          method: 'MANUAL_TRANSFER',
          displayName: input.displayName.trim(),
          accountNumber: input.accountNumber.trim(),
          instructions: input.instructions.trim(),
          enabled: true,
          createdAt: at,
          updatedAt: at,
        };
        let nextState: PaymentConfigState = { ...state, destinations: [...state.destinations, destination], updatedAt: at };
        nextState = withAudit(nextState, {
          at, actorId, action: 'PAYMENT_CONFIG_METHOD_ADDED',
          detail: `Added manual-transfer destination '${destination.displayName}' (account ${maskAccountNumber(destination.accountNumber)}).`,
        });
        commit(nextState, [...idempotency, { key: scopedKey, actorId, methodId: destination.methodId, at }].slice(-MAX_IDEMPOTENCY_KEYS));
        return { kind: 'CREATED' as const, destination: { ...destination } };
      }),
    updateMethod: (actorId, methodId, patch, at) =>
      exclusive(() => {
        const current = state.destinations.find((destination) => destination.methodId === methodId);
        if (current === undefined) return { kind: 'NOT_FOUND' as const };
        const nextName = (patch.displayName ?? current.displayName).trim().toLowerCase();
        if (state.destinations.some((destination) => destination.methodId !== methodId && destination.displayName.trim().toLowerCase() === nextName)) {
          return { kind: 'DUPLICATE_DISPLAY_NAME' as const };
        }
        const changes: string[] = [];
        if (patch.displayName !== undefined && patch.displayName.trim() !== current.displayName) changes.push('display name');
        if (patch.accountNumber !== undefined && patch.accountNumber.trim() !== current.accountNumber) changes.push(`account (${maskAccountNumber(patch.accountNumber.trim())})`);
        if (patch.instructions !== undefined && patch.instructions.trim() !== current.instructions) changes.push('instructions');
        if (patch.enabled !== undefined && patch.enabled !== current.enabled) changes.push(patch.enabled ? 'enabled' : 'disabled');
        const updated: PaymentDestinationRecord = {
          ...current,
          displayName: (patch.displayName ?? current.displayName).trim(),
          accountNumber: (patch.accountNumber ?? current.accountNumber).trim(),
          instructions: (patch.instructions ?? current.instructions).trim(),
          enabled: patch.enabled ?? current.enabled,
          updatedAt: at,
        };
        let nextState: PaymentConfigState = {
          ...state,
          destinations: state.destinations.map((destination) => (destination.methodId === methodId ? updated : destination)),
          updatedAt: at,
        };
        nextState = withAudit(nextState, {
          at, actorId, action: 'PAYMENT_CONFIG_METHOD_UPDATED',
          detail: changes.length === 0
            ? `Destination '${current.displayName}' updated with no field changes.`
            : `Destination '${current.displayName}' changed: ${changes.join(', ')}.`,
        });
        commit(nextState, idempotency);
        return { kind: 'UPDATED' as const, state: cloneState(state) };
      }),
  };
}

function documentToInternals(document: StoreDocument): StoreInternals {
  return {
    state: {
      proPriceMinorUnits: document.proPriceMinorUnits,
      currency: 'BDT',
      destinations: document.destinations.map((destination) => ({ ...destination })),
      updatedAt: document.updatedAt,
      audit: document.audit.map((entry) => ({ ...entry })),
    },
    idempotency: document.idempotency.map((entry) => ({ ...entry })),
  };
}

function seedDocument(seedPriceMinorUnits: number): StoreInternals {
  return documentToInternals({
    version: 1,
    proPriceMinorUnits: seedPriceMinorUnits,
    destinations: [],
    audit: [],
    idempotency: [],
    updatedAt: new Date(0).toISOString(),
  });
}

export function createMemoryPaymentConfigStore(seedPriceMinorUnits: number): PaymentConfigStore {
  return createStore(seedDocument(seedPriceMinorUnits), () => undefined);
}

export function createJsonFilePaymentConfigStore(path: string, seedPriceMinorUnits: number): PaymentConfigStore {
  const load = (): StoreInternals => {
    let raw: string;
    try {
      raw = readFileSync(path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return seedDocument(seedPriceMinorUnits);
      throw new Error(`Cannot read payment config store at ${path}: ${(error as NodeJS.ErrnoException).code ?? 'I/O error'}`);
    }
    let parsed: unknown;
    try { parsed = JSON.parse(raw) as unknown; } catch {
      throw new Error(`Payment config store at ${path} is not valid JSON — refusing to start with corrupt payment configuration.`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new Error(`Payment config store at ${path} has an unexpected shape — refusing to start.`);
    }
    const doc = parsed as Record<string, unknown>;
    if (
      doc['version'] !== 1 ||
      typeof doc['proPriceMinorUnits'] !== 'number' || !Number.isSafeInteger(doc['proPriceMinorUnits']) ||
      doc['proPriceMinorUnits'] < PRICE_MIN_MINOR_UNITS || doc['proPriceMinorUnits'] > PRICE_MAX_MINOR_UNITS ||
      !Array.isArray(doc['destinations']) || doc['destinations'].length > MAX_DESTINATIONS || !doc['destinations'].every(isDestinationRecord) ||
      !Array.isArray(doc['audit']) || doc['audit'].length > MAX_CONFIG_AUDIT_ENTRIES || !doc['audit'].every(isAuditRecord) ||
      !Array.isArray(doc['idempotency']) || doc['idempotency'].length > MAX_IDEMPOTENCY_KEYS || !doc['idempotency'].every(isIdempotencyRecord) ||
      !validTimestamp(doc['updatedAt'])
    ) {
      throw new Error(`Payment config store at ${path} has invalid records — refusing to start.`);
    }
    const seen = new Set<string>();
    for (const destination of doc['destinations'] as PaymentDestinationRecord[]) {
      if (seen.has(destination.methodId)) throw new Error(`Payment config store at ${path} contains duplicate destinations — refusing to start.`);
      seen.add(destination.methodId);
    }
    return documentToInternals({
      version: 1,
      proPriceMinorUnits: doc['proPriceMinorUnits'] as number,
      destinations: doc['destinations'] as PaymentDestinationRecord[],
      audit: doc['audit'] as PaymentConfigAuditRecord[],
      idempotency: doc['idempotency'] as IdempotencyRecord[],
      updatedAt: doc['updatedAt'] as string,
    });
  };

  const internals = load();
  return createStore(internals, (document) => {
    writePrivateJson(path, `${JSON.stringify(document, null, 2)}\n`);
  });
}
