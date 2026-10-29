import type { ApiConfig } from '../config.js';
import { badRequest, conflict, notFound, unauthorized, validationError } from '../errors.js';
import type { Route } from '../http.js';
import type { ProjectStore } from '../projects/store.js';
import type { ScanStore } from '../scans/store.js';
import { selectLatestAttempt } from '../reports/portfolio.js';
import { readJsonBody } from '../lib/body.js';
import * as v from '../lib/validate.js';
import type { Schema, ValidationIssue, ValidationResult } from '../lib/validate.js';
import { sendSuccess } from '../respond.js';
import {
  STUDENT_LESSON_ID_PATTERN,
  type StudentQuizFeedback,
} from '@drobon/shared';
import { findStudentLesson, studentLessonCatalogPublic } from '../student/lessons.js';
import type { DatasetService } from '../external/service.js';
import type { StudentStore } from '../student/store.js';

export interface StudentRouteDeps {
  config: ApiConfig;
  projects: ProjectStore;
  scans: ScanStore;
  student: StudentStore;
  now: () => number;
  dataset?: DatasetService;
}

/**
 * Student learning surface (Phase 22 Pump 2). Educational workflow over the
 * existing security core — UserType stays presentation-only and these routes
 * grant no privilege beyond reading internally authored lessons and
 * maintaining the caller's OWN progress:
 *
 * - `GET /api/v1/student/lessons` — the bounded, internally authored lesson
 *   catalog. Quiz answers never leave the server. Authentication required.
 * - `GET /api/v1/student/progress` — the caller's OWN progress only; there
 *   is no user parameter, so no cross-account read exists at all.
 * - `POST …/lessons/:lessonId/read` — idempotent self-acknowledgement.
 * - `POST …/lessons/:lessonId/quiz` — server-scored; the score is computed
 *   from the submitted answer indices, never accepted from the client.
 * - `POST …/lessons/:lessonId/practice/:stage` — server-verified practice:
 *   IDENTIFY requires a completed SAST scan in one of the caller's OWN
 *   projects whose persisted findings contain the lesson's target rule;
 *   FIX requires that finding's workflow to be NOT_OBSERVED_IN_LATEST_SCAN
 *   (the honest remediation-verification semantics). Another account's
 *   evidence never satisfies these checks because only owned projects are
 *   searched.
 *
 * Bounded in every dimension: 4 lessons, ≤3 tiny starter files, ≤200 quiz
 * attempts per lesson, ≤50 projects × latest 10 SAST scans per verification
 * lookup, 1 KiB body cap. No code execution, no datasets, no production data.
 */

const PRACTICE_STAGES = new Set(['IDENTIFY', 'FIX']);
const PROJECTS_SEARCH_MAX = 50;
const SCANS_PER_PROJECT_MAX = 10;

interface OwnedScanHit {
  projectId: string;
  scanId: string;
  fingerprint: string;
  completedAt: string;
}

/** Strict `(number | null)[]` schema with fixed length and option bounds. */
function quizAnswersSchema(length: number, optionCount: number): Schema<(number | null)[]> {
  return {
    parse(value: unknown, path?: string): ValidationResult<(number | null)[]> {
      const where = path ?? 'value';
      if (!Array.isArray(value) || value.length !== length) {
        return { ok: false, issues: [{ path: where, message: `Answers must be an array of exactly ${length} entries.` }] };
      }
      const out: (number | null)[] = [];
      const issues: ValidationIssue[] = [];
      value.forEach((entry, index) => {
        if (entry === null) { out.push(null); return; }
        if (typeof entry !== 'number' || !Number.isInteger(entry) || entry < 0 || entry >= optionCount) {
          issues.push({ path: `${where}[${index}]`, message: 'Each answer must be null or an option index.' });
          return;
        }
        out.push(entry);
      });
      return issues.length === 0 ? { ok: true, value: out } : { ok: false, issues };
    },
  };
}

export function createStudentRoutes(deps: StudentRouteDeps): Route[] {
  const { config, projects, scans, student, now } = deps;

  const rejectUnknownQueryParameters = (req: { url?: string | undefined }): void => {
    const url = new URL(req.url ?? '/', 'http://localhost');
    if ([...url.searchParams.keys()].length > 0) throw badRequest('Unsupported query parameter.');
  };

  const requireLesson = async (rawLessonId: unknown) => {
    if (typeof rawLessonId !== 'string' || rawLessonId.length > 64 || !STUDENT_LESSON_ID_PATTERN.test(rawLessonId)) {
      throw notFound('Lesson not found.');
    }
    if (deps.dataset?.configured) {
      try {
        const { getMergedLessons, findLessonInMerged } = await import('../external/lessonProvider.js');
        const merged = await getMergedLessons(deps.dataset);
        const lesson = findLessonInMerged(merged, rawLessonId);
        if (lesson !== undefined) return lesson;
      } catch { /* fail closed: optional path */ }
    }
    const lesson = findStudentLesson(rawLessonId);
    if (lesson === undefined) throw notFound('Lesson not found.');
    return lesson;
  };

  /** Latest completed SAST finding with the lesson's rule, across the caller's OWN projects only. */
  const findOwnRuleEvidence = async (actorId: string, ruleId: string): Promise<OwnedScanHit | undefined> => {
    const owned = await projects.listByOwner(actorId);
    const candidates = owned.slice(0, PROJECTS_SEARCH_MAX);
    let hit: OwnedScanHit | undefined;
    for (const project of candidates) {
      const projectScans = (await scans.listByProject(project.id))
        .filter((scan) => scan.scanType === 'SAST' && scan.status === 'COMPLETED')
        .sort((a, b) => (b.completedAt ?? '').localeCompare(a.completedAt ?? ''))
        .slice(0, SCANS_PER_PROJECT_MAX);
      for (const scan of projectScans) {
        const finding = scan.findings?.find((candidate) => candidate.ruleId === ruleId && candidate.scanner !== 'DAST');
        if (finding !== undefined && (hit === undefined || (scan.completedAt ?? '') > hit.completedAt)) {
          hit = { projectId: project.id, scanId: scan.id, fingerprint: finding.fingerprint, completedAt: scan.completedAt ?? '' };
        }
      }
    }
    return hit;
  };

  const routes: Route[] = [
    {
      method: 'GET',
      path: '/api/v1/student/lessons',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        if (ctx.user === undefined) throw unauthorized();
        rejectUnknownQueryParameters(req);
        if (deps.dataset?.configured) {
          try {
            const { getMergedLessons } = await import('../external/lessonProvider.js');
            const { studentLessonPublic } = await import('../student/lessons.js');
            const merged = await getMergedLessons(deps.dataset);
            sendSuccess(res, ctx, { lessons: merged.map(studentLessonPublic) });
            return;
          } catch { /* fail closed: optional path */ }
        }
        sendSuccess(res, ctx, { lessons: studentLessonCatalogPublic() });
      },
    },
    {
      method: 'GET',
      path: '/api/v1/student/progress',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        rejectUnknownQueryParameters(req);
        const lessons = await student.getProgress(actor.id);
        sendSuccess(res, ctx, { lessons });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/student/lessons/:lessonId/read',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        rejectUnknownQueryParameters(req);
        const lesson = await requireLesson(ctx.params['lessonId']);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) });
        const parsed = v.object({}).parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const lessons = await student.acknowledgeRead(actor.id, lesson.id, new Date(now()).toISOString());
        sendSuccess(res, ctx, { lessons: lessons.filter((entry) => entry.lessonId === lesson.id) });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/student/lessons/:lessonId/quiz',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        rejectUnknownQueryParameters(req);
        const lesson = await requireLesson(ctx.params['lessonId']);
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) });
        const answersSchema = v.object({ answers: quizAnswersSchema(lesson.quiz.length, Math.max(...lesson.quiz.map((question) => question.options.length))) });
        const parsedAnswers = answersSchema.parse(raw);
        if (!parsedAnswers.ok) throw validationError(parsedAnswers.issues);
        const answers = parsedAnswers.value.answers;
        let correct = 0;
        const feedback: StudentQuizFeedback[] = lesson.quiz.map((question, index) => {
          const chosen = answers[index] ?? null;
          const isCorrect = chosen === question.answerIndex;
          if (isCorrect) correct += 1;
          return { index, chosen, correctIndex: question.answerIndex, explanation: question.explanation };
        });
        const outcome = await student.recordQuiz(actor.id, lesson.id, correct, lesson.quiz.length, new Date(now()).toISOString());
        if (outcome.outcome === 'attempt-limit') throw conflict('The quiz attempt limit for this lesson has been reached.');
        const entry = outcome.progress.find((candidate) => candidate.lessonId === lesson.id)?.quiz;
        sendSuccess(res, ctx, { correctCount: correct, total: lesson.quiz.length, passed: entry?.passed ?? false, record: entry, feedback });
      },
    },
    {
      method: 'POST',
      path: '/api/v1/student/lessons/:lessonId/practice/:stage',
      requireAuth: true,
      handler: async (req, res, ctx): Promise<void> => {
        const actor = ctx.user;
        if (actor === undefined) throw unauthorized();
        rejectUnknownQueryParameters(req);
        const lesson = await requireLesson(ctx.params['lessonId']);
        const stage = ctx.params['stage'];
        if (typeof stage !== 'string' || !PRACTICE_STAGES.has(stage)) throw notFound('Practice stage not found.');
        const raw = await readJsonBody(req, { maxBytes: Math.min(config.bodyMaxBytes, 1024) });
        const parsed = v.object({}).parse(raw);
        if (!parsed.ok) throw validationError(parsed.issues);
        const at = new Date(now()).toISOString();

        if (stage === 'IDENTIFY') {
          const hit = await findOwnRuleEvidence(actor.id, lesson.practice.targetRuleId);
          if (hit === undefined) {
            throw conflict('No identification evidence yet: import the starter file into one of your own projects and complete a SAST scan first.');
          }
          const lessons = await student.recordIdentify(actor.id, lesson.id, hit.scanId, at);
          sendSuccess(res, ctx, { lessons: lessons.filter((entry) => entry.lessonId === lesson.id) });
          return;
        }

        // FIX: the finding's own workflow must say NOT_OBSERVED_IN_LATEST_SCAN —
        // the honest remediation-verification semantics of the existing engine.
        const hit = await findOwnRuleEvidence(actor.id, lesson.practice.targetRuleId);
        if (hit === undefined) {
          throw conflict('No identification evidence yet: complete the IDENTIFY stage first.');
        }
        const workflow = await scans.getFindingWorkflow(hit.projectId, hit.fingerprint);
        const latest = selectLatestAttempt(await scans.listByProject(hit.projectId), 'SAST');
        if (workflow?.verificationState !== 'NOT_OBSERVED_IN_LATEST_SCAN' || latest.kind !== 'SELECTED' ||
            latest.scan.id !== workflow.lastVerificationScanId || latest.scan.status !== 'COMPLETED' ||
            latest.scan.resultSummary === undefined || latest.scan.resultSummary.partial === true ||
            latest.scan.resultSummary.truncated === true || latest.scan.resultSummary.astSupplement?.status === 'PARTIAL' ||
            latest.scan.resultSummary.findingsTotal !== (latest.scan.findings ?? []).length) {
          throw conflict('Fix not verified yet: run a complete SAST scan with no reported coverage gaps; a partial or newer attempt does not verify absence.');
        }
        const lessons = await student.recordVerify(actor.id, lesson.id, workflow.lastVerificationScanId, at);
        sendSuccess(res, ctx, { lessons: lessons.filter((entry) => entry.lessonId === lesson.id) });
      },
    },
  ];
  return routes;
}
