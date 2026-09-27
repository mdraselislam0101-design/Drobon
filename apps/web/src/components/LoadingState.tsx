export function LoadingState({ label }: { label: string }): React.JSX.Element {
  return (
    <div className="state-card" role="status" aria-busy="true" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      <p>{label}</p>
    </div>
  );
}
