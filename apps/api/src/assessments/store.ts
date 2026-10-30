import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import {
  ASSESSMENT_DECLARATIONS_MAX_COUNT,
  ASSESSMENT_ENGAGEMENTS_MAX_COUNT,
  ASSESSMENT_EVENTS_MAX_COUNT,
  ASSESSMENT_ID_PATTERN,
  ASSESSMENT_LIST_MAX_COUNT,
  ENGAGEMENT_ID_PATTERN,
  isAssessment,
  isAssessmentEngagement,
  isAssessmentScope,
  isSafeDastUrl,
  type Assessment,
  type AssessmentAuthorizationDeclaration,
  type AssessmentEngagement,
  type AssessmentEvent,
  type AssessmentScope,
  type AssessmentStatus,
} from '@drobon/shared';

const ASSESSMENTS_PER_PROJECT_MAX = ASSESSMENT_LIST_MAX_COUNT;
const ASSESSMENTS_TOTAL_MAX = 5_000;
const ASSESSMENT_DOCUMENT_MAX_BYTES = 24 * 1024 * 1024;

interface AssessmentRecord extends Assessment { ownerId: string }
interface StoreDocument { version: 1; assessments: AssessmentRecord[] }

export interface CreateAssessmentInput {
  ownerId: string;
  projectId: string;
  title: string;
  objectives: string[];
  scope: AssessmentScope;
  now: string;
}
export interface UpdateAssessmentInput {
  ownerId: string;
  projectId: string;
  assessmentId: string;
  title: string;
  objectives: string[];
  scope: AssessmentScope;
  now: string;
}
export interface AssessmentStore {
  create(input: CreateAssessmentInput): Promise<Assessment | { outcome: 'capacity-exceeded' }>;
  listByProject(ownerId: string, projectId: string): Promise<Assessment[]>;
  findByProjectAndId(ownerId: string, projectId: string, assessmentId: string): Promise<Assessment | undefined>;
  /** Linearizes linked scan creation against assessment completion/cancellation. */
  withActiveAssessment<T>(ownerId: string, projectId: string, assessmentId: string, action: (current: Assessment) => Promise<T>): Promise<{ outcome: 'ready'; value: T } | { outcome: 'not-found' } | { outcome: 'inactive' }>;
  update(input: UpdateAssessmentInput): Promise<{ outcome: 'updated' | 'not-found' | 'not-planned' | 'history-limit'; assessment?: Assessment }>;
  transition(input: { ownerId: string; projectId: string; assessmentId: string; status: AssessmentStatus; now: string }, guard?: (current: Assessment) => Promise<boolean>): Promise<{ outcome: 'updated' | 'unchanged' | 'not-found' | 'invalid-transition' | 'guard-rejected' | 'history-limit'; assessment?: Assessment }>;
  recordAuthorization(input: { ownerId: string; projectId: string; assessmentId: string; targetUrl: string; action: 'DECLARE' | 'WITHDRAW'; now: string }): Promise<{ outcome: 'updated' | 'unchanged' | 'not-found' | 'inactive' | 'not-declared' | 'declarations-limit' | 'history-limit'; assessment?: Assessment }>;
  /** Pump 17: append-only third-party engagement records (never edited/deleted). */
  recordEngagement(input: {
    ownerId: string; projectId: string; assessmentId: string; now: string;
    action: 'DECLARE' | 'WITHDRAW';
    engagement?: Omit<AssessmentEngagement, 'id' | 'declaredBy' | 'declaredAt' | 'state' | 'withdrawnAt'>;
    engagementId?: string;
  }): Promise<{ outcome: 'updated' | 'not-found' | 'inactive' | 'invalid' | 'not-declared' | 'engagements-limit' | 'history-limit'; assessment?: Assessment }>;
}

function publicRecord(record: AssessmentRecord): Assessment {
  const { ownerId: _ownerId, ...assessment } = record;
  return assessment;
}

function safeAssessment(record: AssessmentRecord): Assessment {
  return JSON.parse(JSON.stringify(publicRecord(record))) as Assessment;
}

function validRecord(record: AssessmentRecord): boolean {
  return isAssessment(publicRecord(record));
}

function makeEvent(type: AssessmentEvent['type'], at: string, extra: Partial<Pick<AssessmentEvent, 'status' | 'targetUrl'>> = {}): AssessmentEvent {
  return { id: `ase_${randomUUID()}`, type, at, ...extra };
}

function parseRecord(value: unknown): AssessmentRecord | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const record = value as Record<string, unknown>;
  if (typeof record['ownerId'] !== 'string' || record['ownerId'].length === 0) return undefined;
  const { ownerId, ...assessment } = record;
  if (!isAssessment(assessment)) return undefined;
  const history = assessment.history;
  if (history[0]?.type !== 'CREATED' || history[0].at !== assessment.createdAt) return undefined;
  const seenEventIds = new Set<string>();
  for (const event of history) {
    if (seenEventIds.has(event.id)) return undefined;
    seenEventIds.add(event.id);
  }
  const seenDeclarations = new Set<string>();
  for (const declaration of assessment.authorizationDeclarations) {
    if (!isSafeDastUrl(declaration.targetUrl)) return undefined;
    const key = `${declaration.targetUrl}:${declaration.declaredAt}:${declaration.state}`;
    if (seenDeclarations.has(key)) return undefined;
    seenDeclarations.add(key);
  }
  const engagements = assessment.engagements ?? [];
  const seenEngagementIds = new Set<string>();
  for (const engagement of engagements) {
    if (!isAssessmentEngagement(engagement) || seenEngagementIds.has(engagement.id)) return undefined;
    seenEngagementIds.add(engagement.id);
  }
  return { ...assessment, ownerId } as AssessmentRecord;
}

function readDocument(path: string): StoreDocument {
  let raw: string;
  try { raw = readFileSync(path, 'utf8'); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { version: 1, assessments: [] };
    throw new Error(`Cannot read assessment store at ${path}: ${String((error as NodeJS.ErrnoException).code ?? error)}`);
  }
  if (Buffer.byteLength(raw, 'utf8') > ASSESSMENT_DOCUMENT_MAX_BYTES) throw new Error(`Assessment store at ${path} exceeds its size limit — refusing to start.`);
  let parsed: unknown;
  try { parsed = JSON.parse(raw) as unknown; }
  catch { throw new Error(`Assessment store at ${path} is not valid JSON — refusing to start.`); }
  if (typeof parsed !== 'object' || parsed === null || (parsed as Record<string, unknown>)['version'] !== 1 || !Array.isArray((parsed as Record<string, unknown>)['assessments'])) {
    throw new Error(`Assessment store at ${path} has an unexpected shape — refusing to start.`);
  }
  const values = (parsed as { assessments: unknown[] }).assessments;
  if (values.length > ASSESSMENTS_TOTAL_MAX) throw new Error(`Assessment store at ${path} exceeds its record limit — refusing to start.`);
  const records: AssessmentRecord[] = [];
  const ids = new Set<string>();
  const projectCounts = new Map<string, number>();
  values.forEach((value, index) => {
    const record = parseRecord(value);
    if (record === undefined || ids.has(record.id)) throw new Error(`Assessment store at ${path} has an invalid or duplicate record at index ${index} — refusing to start.`);
    ids.add(record.id);
    const key = `${record.ownerId}:${record.projectId}`;
    const count = (projectCounts.get(key) ?? 0) + 1;
    if (count > ASSESSMENTS_PER_PROJECT_MAX) throw new Error(`Assessment store at ${path} exceeds the per-project record limit — refusing to start.`);
    projectCounts.set(key, count);
    records.push(record);
  });
  return { version: 1, assessments: records };
}

function createStore(initial: AssessmentRecord[], persistWith: (records: AssessmentRecord[]) => void): AssessmentStore {
  let queue: Promise<unknown> = Promise.resolve();
  const runExclusive = <T>(task: () => T | Promise<T>): Promise<Awaited<T>> => {
    const run = queue.then(task, task);
    queue = run.catch(() => undefined);
    return run as Promise<Awaited<T>>;
  };
  const byId = new Map(initial.map((record) => [record.id, record]));
  const find = (ownerId: string, projectId: string, id: string): AssessmentRecord | undefined => {
    const record = byId.get(id);
    return record?.ownerId === ownerId && record.projectId === projectId ? record : undefined;
  };
  const commit = (next: AssessmentRecord[], changed: AssessmentRecord): void => {
    persistWith(next);
    byId.set(changed.id, changed);
  };
  return {
    create: (input) => runExclusive(() => {
      const count = [...byId.values()].filter((record) => record.ownerId === input.ownerId && record.projectId === input.projectId).length;
      if (count >= ASSESSMENTS_PER_PROJECT_MAX || byId.size >= ASSESSMENTS_TOTAL_MAX) return { outcome: 'capacity-exceeded' };
      const id = `asm_${randomUUID()}`;
      const record: AssessmentRecord = {
        id, ownerId: input.ownerId, projectId: input.projectId, title: input.title,
        objectives: [...input.objectives], scope: JSON.parse(JSON.stringify(input.scope)) as AssessmentScope,
        status: 'PLANNED', createdAt: input.now, updatedAt: input.now,
        authorizationDeclarations: [], history: [makeEvent('CREATED', input.now)],
      };
      if (!validRecord(record)) throw new TypeError('Assessment input failed store validation.');
      const next = [...byId.values(), record];
      persistWith(next);
      byId.set(id, record);
      return safeAssessment(record);
    }),
    listByProject: (ownerId, projectId) => Promise.resolve([...byId.values()]
      .filter((record) => record.ownerId === ownerId && record.projectId === projectId)
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.id.localeCompare(b.id))
      .map(safeAssessment)),
    findByProjectAndId: (ownerId, projectId, id) => {
      if (!ASSESSMENT_ID_PATTERN.test(id)) return Promise.resolve(undefined);
      const record = find(ownerId, projectId, id);
      return Promise.resolve(record === undefined ? undefined : safeAssessment(record));
    },
    withActiveAssessment: (ownerId, projectId, id, action) => runExclusive(async () => {
      const current = find(ownerId, projectId, id);
      if (current === undefined) return { outcome: 'not-found' as const };
      if (current.status !== 'ACTIVE') return { outcome: 'inactive' as const };
      return { outcome: 'ready' as const, value: await action(safeAssessment(current)) };
    }),
    update: (input) => runExclusive(() => {
      const current = find(input.ownerId, input.projectId, input.assessmentId);
      if (current === undefined) return { outcome: 'not-found' };
      if (current.status !== 'PLANNED') return { outcome: 'not-planned' };
      if (current.history.length >= ASSESSMENT_EVENTS_MAX_COUNT) return { outcome: 'history-limit' };
      const updated: AssessmentRecord = {
        ...current, title: input.title, objectives: [...input.objectives],
        scope: JSON.parse(JSON.stringify(input.scope)) as AssessmentScope, updatedAt: input.now,
        history: [...current.history, makeEvent('DETAILS_UPDATED', input.now)],
      };
      if (!validRecord(updated) || !isAssessmentScope(updated.scope)) throw new TypeError('Assessment update failed store validation.');
      commit([...byId.values()].map((record) => record.id === updated.id ? updated : record), updated);
      return { outcome: 'updated', assessment: safeAssessment(updated) };
    }),
    transition: (input, guard) => runExclusive(async () => {
      const current = find(input.ownerId, input.projectId, input.assessmentId);
      if (current === undefined) return { outcome: 'not-found' };
      if (current.status === input.status) return { outcome: 'unchanged', assessment: safeAssessment(current) };
      const allowed = (current.status === 'PLANNED' && (input.status === 'ACTIVE' || input.status === 'CANCELLED')) ||
        (current.status === 'ACTIVE' && (input.status === 'COMPLETED' || input.status === 'CANCELLED'));
      if (!allowed) return { outcome: 'invalid-transition' };
      if (guard !== undefined && !(await guard(safeAssessment(current)))) return { outcome: 'guard-rejected' };
      if (current.history.length >= ASSESSMENT_EVENTS_MAX_COUNT) return { outcome: 'history-limit' };
      const updated: AssessmentRecord = { ...current, status: input.status, updatedAt: input.now,
        ...(input.status === 'ACTIVE' ? { startedAt: input.now } : {}),
        ...(input.status === 'COMPLETED' ? { completedAt: input.now } : {}),
        ...(input.status === 'CANCELLED' ? { cancelledAt: input.now } : {}),
        history: [...current.history, makeEvent('STATUS_CHANGED', input.now, { status: input.status })],
      };
      if (!validRecord(updated)) throw new TypeError('Assessment transition failed store validation.');
      commit([...byId.values()].map((record) => record.id === updated.id ? updated : record), updated);
      return { outcome: 'updated', assessment: safeAssessment(updated) };
    }),
    recordAuthorization: (input) => runExclusive(() => {
      const current = find(input.ownerId, input.projectId, input.assessmentId);
      if (current === undefined) return { outcome: 'not-found' };
      if (current.status !== 'PLANNED' && current.status !== 'ACTIVE') return { outcome: 'inactive' };
      if (!isSafeDastUrl(input.targetUrl)) return { outcome: 'not-found' };
      const previous = [...current.authorizationDeclarations].reverse().find((item) => item.targetUrl === input.targetUrl);
      if (input.action === 'DECLARE' && previous?.state === 'USER_DECLARED') return { outcome: 'unchanged', assessment: safeAssessment(current) };
      if (input.action === 'WITHDRAW' && previous?.state === 'WITHDRAWN') return { outcome: 'unchanged', assessment: safeAssessment(current) };
      if (input.action === 'WITHDRAW' && previous?.state !== 'USER_DECLARED') return { outcome: 'not-declared' };
      if (current.authorizationDeclarations.length >= ASSESSMENT_DECLARATIONS_MAX_COUNT) return { outcome: 'declarations-limit' };
      if (current.history.length >= ASSESSMENT_EVENTS_MAX_COUNT) return { outcome: 'history-limit' };
      const state = input.action === 'DECLARE' ? 'USER_DECLARED' as const : 'WITHDRAWN' as const;
      const updated: AssessmentRecord = { ...current, updatedAt: input.now,
        authorizationDeclarations: [...current.authorizationDeclarations, { targetUrl: input.targetUrl, state, declaredAt: input.now } satisfies AssessmentAuthorizationDeclaration],
        history: [...current.history, makeEvent(state === 'USER_DECLARED' ? 'AUTHORIZATION_DECLARED' : 'AUTHORIZATION_WITHDRAWN', input.now, { targetUrl: input.targetUrl })],
      };
      if (!validRecord(updated)) throw new TypeError('Authorization declaration failed store validation.');
      commit([...byId.values()].map((record) => record.id === updated.id ? updated : record), updated);
      return { outcome: 'updated', assessment: safeAssessment(updated) };
    }),
    recordEngagement: (input) => runExclusive(() => {
      const current = find(input.ownerId, input.projectId, input.assessmentId);
      if (current === undefined) return { outcome: 'not-found' };
      if (current.status !== 'PLANNED' && current.status !== 'ACTIVE') return { outcome: 'inactive' };
      const existing = current.engagements ?? [];
      if (current.history.length >= ASSESSMENT_EVENTS_MAX_COUNT) return { outcome: 'history-limit' };

      if (input.action === 'DECLARE') {
        const draft = input.engagement;
        if (draft === undefined) return { outcome: 'invalid' };
        if (existing.length >= ASSESSMENT_ENGAGEMENTS_MAX_COUNT) return { outcome: 'engagements-limit' };
        const candidate: AssessmentEngagement = {
          ...draft,
          id: `eng_${randomUUID()}`,
          inScopeHosts: [...draft.inScopeHosts],
          scopePaths: [...draft.scopePaths],
          allowedScanTypes: [...draft.allowedScanTypes],
          declaredBy: input.ownerId,
          declaredAt: input.now,
          state: 'DECLARED',
        };
        if (!isAssessmentEngagement(candidate) || !isSafeDastUrl(candidate.targetUrl)) return { outcome: 'invalid' };
        const updated: AssessmentRecord = { ...current, updatedAt: input.now,
          engagements: [...existing, candidate],
          history: [...current.history, makeEvent('AUTHORIZATION_DECLARED', input.now, { targetUrl: candidate.targetUrl })],
        };
        if (!validRecord(updated)) return { outcome: 'invalid' };
        commit([...byId.values()].map((record) => record.id === updated.id ? updated : record), updated);
        return { outcome: 'updated', assessment: safeAssessment(updated) };
      }

      if (input.engagementId === undefined || !ENGAGEMENT_ID_PATTERN.test(input.engagementId)) return { outcome: 'invalid' };
      const target = existing.find((item) => item.id === input.engagementId);
      if (target === undefined || target.state !== 'DECLARED') return { outcome: 'not-declared' };
      const withdrawn: AssessmentEngagement = { ...target, state: 'WITHDRAWN', withdrawnAt: input.now };
      if (!isAssessmentEngagement(withdrawn)) return { outcome: 'invalid' };
      const updated: AssessmentRecord = { ...current, updatedAt: input.now,
        engagements: existing.map((item) => item.id === target.id ? withdrawn : item),
        history: [...current.history, makeEvent('AUTHORIZATION_WITHDRAWN', input.now, { targetUrl: target.targetUrl })],
      };
      if (!validRecord(updated)) return { outcome: 'invalid' };
      commit([...byId.values()].map((record) => record.id === updated.id ? updated : record), updated);
      return { outcome: 'updated', assessment: safeAssessment(updated) };
    }),
  };
}

export function createJsonFileAssessmentStore(path: string): AssessmentStore {
  const document = readDocument(path);
  const persistWith = (assessments: AssessmentRecord[]): void => {
    const payload: StoreDocument = { version: 1, assessments };
    const serialized = `${JSON.stringify(payload, null, 2)}\n`;
    if (Buffer.byteLength(serialized, 'utf8') > ASSESSMENT_DOCUMENT_MAX_BYTES) throw new RangeError('Assessment store capacity has been reached.');
    mkdirSync(dirname(path), { recursive: true });
    const tempPath = join(dirname(path), `.${randomBytes(6).toString('hex')}.tmp`);
    writeFileSync(tempPath, serialized, { mode: 0o600 });
    renameSync(tempPath, path);
  };
  return createStore(document.assessments, persistWith);
}

export function createMemoryAssessmentStore(): AssessmentStore {
  return createStore([], () => undefined);
}
