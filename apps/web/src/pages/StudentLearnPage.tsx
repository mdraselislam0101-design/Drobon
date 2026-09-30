import { useCallback, useEffect, useState } from 'react';
import type {
  StudentLessonCatalogResponse,
  StudentLessonPublic,
  StudentProgressResponse,
  StudentQuizResultResponse,
} from '@drobon/shared';
import { ApiClientError } from '../api/client.js';
import { useApiClient } from '../api/context.js';
import { ErrorState } from '../components/ErrorState.js';
import { LoadingState } from '../components/LoadingState.js';

/**
 * Student learning path (Phase 22 Pump 2). Renders the internally authored
 * lesson catalog and the caller's OWN server-authoritative progress, and
 * drives the bounded LEARN → PRACTICE → VERIFY loop over the existing
 * security engines: the learner copies the synthetic starter file into their
 * OWN project, scans it with the ordinary SAST engine, applies the lesson's
 * fix, and re-scans. The server verifies identification and fix evidence from
 * completed-scan state — the browser can never claim completion by itself,
 * and nothing here executes learner code or grants any privilege beyond
 * reading educational content and one's own progress.
 */

interface LearnView {
  status: 'loading' | 'error';
  message: string;
  requestId?: string;
}

interface SelectedLesson {
  lesson: StudentLessonPublic;
  answers: Array<number | null>;
  quizResult?: StudentQuizResultResponse;
  notice?: string;
}

const dateLabel = (value: string): string => new Date(value).toLocaleString();

export function StudentLearnPage(): React.JSX.Element {
  const client = useApiClient();
  const [catalog, setCatalog] = useState<StudentLessonCatalogResponse | undefined>(undefined);
  const [progress, setProgress] = useState<StudentProgressResponse | undefined>(undefined);
  const [view, setView] = useState<LearnView>({ status: 'loading', message: 'Loading lessons…' });
  const [reloadToken, setReloadToken] = useState(0);
  const [selected, setSelected] = useState<SelectedLesson | undefined>(undefined);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setView({ status: 'loading', message: 'Loading lessons…' });
    void Promise.all([
      client.getStudentLessons(controller.signal),
      client.getStudentProgress(controller.signal),
    ]).then(([lessons, progressResponse]) => {
      if (controller.signal.aborted) return;
      setCatalog(lessons);
      setProgress(progressResponse);
      setView({ status: 'loading', message: 'ready' });
    }).catch((error: unknown) => {
      if (controller.signal.aborted) return;
      const message = error instanceof ApiClientError ? error.message : 'Learning path is unavailable right now.';
      setView({
        status: 'error',
        message,
        ...(error instanceof ApiClientError && error.requestId !== undefined ? { requestId: error.requestId } : {}),
      });
    });
    return () => {
      controller.abort();
    };
  }, [client, reloadToken]);

  const openLesson = useCallback((lesson: StudentLessonPublic): void => {
    setSelected({ lesson, answers: Array.from({ length: lesson.quiz.length }, () => null) });
  }, []);

  const refreshProgress = useCallback(async (): Promise<void> => {
    setProgress(await client.getStudentProgress());
  }, [client]);

  if (view.status === 'error') {
    return (
      <ErrorState
        title="Learning path unavailable."
        message={view.message}
        {...(view.requestId === undefined ? {} : { requestId: view.requestId })}
        onRetry={() => setReloadToken((token) => token + 1)}
      />
    );
  }

  if (catalog === undefined || progress === undefined) {
    return <LoadingState label="Loading lessons…" />;
  }

  const progressFor = (lessonId: string) => progress.lessons.find((entry) => entry.lessonId === lessonId);

  const markRead = async (lessonId: string): Promise<void> => {
    setBusy(true);
    try {
      await client.acknowledgeLessonRead(lessonId);
      await refreshProgress();
      setSelected((current) => (current === undefined ? current : { ...current, notice: 'Lesson marked as read.' }));
    } catch (error) {
      setSelected((current) => (current === undefined ? current : { ...current, notice: error instanceof ApiClientError ? error.message : 'Could not record read state.' }));
    } finally {
      setBusy(false);
    }
  };

  const submitQuiz = async (lessonId: string): Promise<void> => {
    setBusy(true);
    try {
      const result = await client.submitLessonQuiz(lessonId, selected?.answers ?? []);
      setSelected((current) => {
        if (current === undefined) return current;
        const next: SelectedLesson = { ...current, quizResult: result };
        delete next.notice;
        return next;
      });
      await refreshProgress();
    } catch (error) {
      setSelected((current) => (current === undefined ? current : { ...current, notice: error instanceof ApiClientError ? error.message : 'Quiz could not be scored.' }));
    } finally {
      setBusy(false);
    }
  };

  const verifyPractice = async (lessonId: string, stage: 'IDENTIFY' | 'FIX'): Promise<void> => {
    setBusy(true);
    try {
      await client.verifyLessonPractice(lessonId, stage);
      await refreshProgress();
      const entry = (await client.getStudentProgress()).lessons.find((item) => item.lessonId === lessonId);
      setSelected((current) => {
        if (current === undefined) return current;
        if (stage === 'IDENTIFY') {
          return { ...current, notice: 'Identification evidence recorded — the lesson rule was found in a completed scan of your project.' };
        }
        const suffix = entry?.practice?.verifiedAt === undefined ? '' : ` (verified ${dateLabel(entry.practice.verifiedAt)})`;
        return { ...current, notice: `Fix verified — the rule is no longer observed in your latest scan${suffix}.` };
      });
    } catch (error) {
      setSelected((current) => (current === undefined ? current : { ...current, notice: error instanceof ApiClientError ? error.message : 'Practice verification failed.' }));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section aria-labelledby="student-learn-heading" className="space-y-6">
      <header className="space-y-2">
        <h1 id="student-learn-heading" className="text-2xl font-semibold text-slate-100">Learning path</h1>
        <p className="max-w-3xl text-sm text-slate-400">
          Short, internally written lessons about the exact vulnerability classes the DROBON AEGIS SAST engine
          detects in real projects. Each lesson explains the pattern, the risk, and the safe fix, then has you
          practice it on the lesson&apos;s synthetic starter file inside your own project — scanned by the same
          engine your projects use. No exploit code, no external datasets, and no code execution: you stay in
          control of everything that runs.
        </p>
      </header>

      {selected === undefined ? (
        <ol className="space-y-3">
          {catalog.lessons.map((lesson, index) => {
            const entry = progressFor(lesson.id);
            return (
              <li key={lesson.id} className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="space-y-1">
                    <h2 className="text-base font-semibold text-slate-100">
                      {index + 1}. {lesson.title}
                    </h2>
                    <p className="max-w-2xl text-sm text-slate-400">{lesson.summary}</p>
                    <p className="text-xs text-slate-500">Practice rule: {lesson.practice.targetRuleId}</p>
                  </div>
                  <div className="flex flex-col items-end gap-2 text-xs">
                    {entry?.readAcknowledgedAt !== undefined && <span className="rounded bg-slate-800 px-2 py-1 text-slate-300">Read</span>}
                    {entry?.practice?.verifiedScanId !== undefined && <span className="rounded bg-emerald-900/60 px-2 py-1 text-emerald-300">Fix verified</span>}
                    {entry?.practice?.identifiedScanId !== undefined && entry?.practice?.verifiedScanId === undefined && (
                      <span className="rounded bg-amber-900/60 px-2 py-1 text-amber-300">Identified</span>
                    )}
                    {entry?.quiz?.passed === true && <span className="rounded bg-sky-900/60 px-2 py-1 text-sky-300">Quiz passed</span>}
                    {entry?.quiz !== undefined && entry.quiz.passed !== true && (
                      <span className="rounded bg-slate-800 px-2 py-1 text-slate-300">
                        Quiz best {entry.quiz.bestCorrect}/{entry.quiz.total} · {entry.quiz.attempts} {entry.quiz.attempts === 1 ? 'attempt' : 'attempts'}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => openLesson(lesson)}
                      className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:border-slate-500"
                    >
                      Open lesson
                    </button>
                  </div>
                </div>
              </li>
            );
          })}
        </ol>
      ) : (
        <article className="space-y-5 rounded-lg border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex items-start justify-between gap-3">
            <h2 className="text-xl font-semibold text-slate-100">{selected.lesson.title}</h2>
            <button
              type="button"
              onClick={() => setSelected(undefined)}
              className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-300 hover:border-slate-500"
            >
              Back to lessons
            </button>
          </div>

          <div className="space-y-2 text-sm text-slate-300">
            <h3 className="font-semibold text-slate-100">Concept</h3>
            <p className="whitespace-pre-line">{selected.lesson.concept}</p>
          </div>

          <div className="space-y-1 text-sm text-slate-300">
            <h3 className="font-semibold text-slate-100">Objectives</h3>
            <ul className="list-disc space-y-1 pl-5">
              {selected.lesson.objectives.map((objective) => <li key={objective}>{objective}</li>)}
            </ul>
          </div>

          <div className="space-y-2 rounded border border-slate-800 bg-slate-950/60 p-4 text-sm text-slate-300">
            <h3 className="font-semibold text-slate-100">Practice ({selected.lesson.practice.targetRuleId})</h3>
            <p>{selected.lesson.practice.instruction}</p>
            <ul className="space-y-1">
              {selected.lesson.practice.starterFiles.map((file) => (
                <li key={file.path}>
                  <code className="text-slate-400">{file.path}</code>
                  <pre className="mt-1 overflow-x-auto rounded bg-slate-950 p-2 text-xs text-slate-400">{file.content}</pre>
                </li>
              ))}
            </ul>
            <div className="flex flex-wrap gap-2 pt-1">
              <button
                type="button"
                disabled={busy}
                onClick={() => { void verifyPractice(selected.lesson.id, 'IDENTIFY'); }}
                className="rounded border border-slate-700 px-3 py-1.5 text-slate-100 hover:border-slate-500 disabled:opacity-50"
              >
                Verify identification (needs a completed scan)
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => { void verifyPractice(selected.lesson.id, 'FIX'); }}
                className="rounded border border-slate-700 px-3 py-1.5 text-slate-100 hover:border-slate-500 disabled:opacity-50"
              >
                Verify fix (needs a clean re-scan)
              </button>
            </div>
            <p className="text-xs text-slate-500">{selected.lesson.practice.fixInstruction}</p>
          </div>

          <div className="space-y-3 rounded border border-slate-800 bg-slate-950/60 p-4">
            <h3 className="font-semibold text-slate-100">Knowledge check</h3>
            {selected.lesson.quiz.map((question, questionIndex) => (
              <fieldset key={question.prompt} className="space-y-1.5">
                <legend className="text-sm text-slate-200">
                  {questionIndex + 1}. {question.prompt}
                </legend>
                {question.options.map((option, optionIndex) => (
                  <label key={option} className="flex items-center gap-2 text-sm text-slate-300">
                    <input
                      type="radio"
                      name={`quiz-${selected.lesson.id}-${questionIndex}`}
                      checked={selected.answers[questionIndex] === optionIndex}
                      onChange={() => setSelected((current) => {
                        if (current === undefined) return current;
                        const answers = [...current.answers];
                        answers[questionIndex] = optionIndex;
                        return { ...current, answers };
                      })}
                    />
                    <span>{option}</span>
                  </label>
                ))}
              </fieldset>
            ))}
            <button
              type="button"
              disabled={busy || selected.answers.some((answer) => answer === null)}
              onClick={() => { void submitQuiz(selected.lesson.id); }}
              className="rounded border border-slate-700 px-3 py-1.5 text-slate-100 hover:border-slate-500 disabled:opacity-50"
            >
              Submit answers
            </button>
            {selected.quizResult !== undefined && (
              <div className="space-y-2 text-sm">
                <p className={selected.quizResult.passed ? 'text-emerald-300' : 'text-amber-300'}>
                  Score: {selected.quizResult.correctCount}/{selected.quizResult.total}
                  {selected.quizResult.passed ? ' — passed.' : ' — review the explanations and try again.'}
                </p>
                <ul className="space-y-1 text-slate-300">
                  {selected.quizResult.feedback.map((item) => (
                    <li key={item.index}>
                      Q{item.index + 1}: {item.chosen === item.correctIndex ? 'Correct.' : `Incorrect — correct answer: ${selected.lesson.quiz[item.index]?.options[item.correctIndex]}.`} {item.explanation}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="button"
              disabled={busy}
              onClick={() => { void markRead(selected.lesson.id); }}
              className="rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-100 hover:border-slate-500 disabled:opacity-50"
            >
              Mark lesson as read
            </button>
            {selected.notice !== undefined && <p className="text-sm text-slate-400">{selected.notice}</p>}
          </div>
        </article>
      )}
    </section>
  );
}
