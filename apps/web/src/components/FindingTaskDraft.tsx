import { useState } from 'react';
import { findingScanner, type FindingDetailResponse } from '@drobon/shared';

/** A local copyable task draft, not an issue creation or account assignment. */
export function FindingTaskDraft({ detail }: { detail: FindingDetailResponse }): React.JSX.Element {
  const [assignee, setAssignee] = useState('');
  const [message, setMessage] = useState('');
  const finding = detail.finding;
  const clean = (value: string): string => Array.from(value, (char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127 || (code >= 0x202a && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) ? ' ' : char;
  }).join('').replace(/\s+/g, ' ').trim();
  const location = finding.scanner === 'DAST' ? `${finding.method} ${finding.endpoint}` : `${finding.file}:${finding.line}:${finding.column}`;
  const draft = [
    `Security review: ${clean(finding.title)}`,
    `Severity: ${finding.severity} | Scanner: ${findingScanner(finding) ?? 'unknown'} | Rule: ${finding.ruleId}`,
    `Suggested assignee (manual): ${clean(assignee) || 'unassigned'}`,
    `Project: ${clean(detail.project.name)} (${detail.project.id})`,
    `Scan: ${detail.scan.id} | Finding: ${finding.id}`,
    `Location: ${clean(location)}`,
    `Drobon workflow: ${detail.workflow?.state ?? 'not available'} | Verification: ${detail.workflow?.verificationState ?? 'not available'}`,
    '',
    'Review the finding and potential false positives in context. Add the approved remediation plan manually.',
    'After the change, rerun the same scanner in the authorized scope and review the new result; absence is not proof of a fix.',
    'Evidence, source code, notes and credentials are deliberately not included. Review this draft before sharing.',
  ].join('\n');

  const copy = async (): Promise<void> => {
    try {
      if (navigator.clipboard === undefined) throw new Error('Clipboard unavailable');
      await navigator.clipboard.writeText(draft);
      setMessage('Draft copied. No external issue was created or assigned.');
    } catch {
      setMessage('Clipboard unavailable. Select the draft and copy it manually.');
    }
  };

  return (
    <section className="workflow-guidance" aria-label="Manual task draft" data-testid="finding-task-draft">
      <h5>Prepare a manual security task</h5>
      <p className="muted">This is a local draft for a task tracker. It does not create a Jira issue, assign an account, send notifications, or synchronize status. Review what you share.</p>
      <label htmlFor={`task-assignee-${finding.id}`}>Suggested assignee (optional, text only)</label>
      <input id={`task-assignee-${finding.id}`} value={assignee} maxLength={80} onChange={(event) => { setAssignee(event.target.value); setMessage(''); }} />
      <label htmlFor={`task-draft-${finding.id}`}>Task draft (selectable, no evidence)</label>
      <textarea id={`task-draft-${finding.id}`} readOnly rows={10} value={draft} />
      <button type="button" className="button button-ghost" onClick={() => void copy()}>Copy task draft</button>
      {message !== '' && <p role="status">{message}</p>}
    </section>
  );
}
