import type { UserType } from '@drobon/shared';

const guidance: Record<UserType, string> = {
  STUDENT: 'Learn by comparing the parsed source or response with the reported source-to-sink candidate. A match is a review prompt, not a grade or proof of exploitation.',
  DEVELOPER: 'Prioritize SAST source flows, redacted secret context and package.json syntax coverage; review the location, fix safely, and rescan.',
  SECURITY_PROFESSIONAL: 'Review parser gaps, rule attribution and saved scan evidence alongside the assessment scope; validate findings before sharing a report.',
  PENTESTER: 'For an authorized target, review DAST response-script candidates alongside SAST source results. Obtain written permission and verify scope before any request.',
};

/** Presentation guidance only: user type never changes access or scan permissions. */
export function AstWorkflowGuide({ userType }: { userType: UserType | null }): React.JSX.Element {
  return (
    <aside className="form-alert" role="note" data-testid="ast-workflow-guide">
      <strong>AST-assisted workflow</strong>
      <p>{userType === null ? 'Choose a user type for tailored guidance, or review the same project-owned scans and their AST coverage here.' : guidance[userType]}</p>
      <p className="muted">User type changes guidance only—not engine permissions, project ownership, plan or coverage. Parsing never executes the analyzed code.</p>
    </aside>
  );
}
