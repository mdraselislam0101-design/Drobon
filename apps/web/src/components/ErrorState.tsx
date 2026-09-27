export function ErrorState({
  title,
  message,
  requestId,
  onRetry,
}: {
  title: string;
  message: string;
  requestId?: string;
  onRetry?: () => void;
}): React.JSX.Element {
  return (
    <div className="state-card state-card-error" role="alert">
      <h2>{title}</h2>
      <p>{message}</p>
      {requestId !== undefined && requestId !== '' && (
        <p className="request-id">
          Reference: <code>{requestId}</code>
        </p>
      )}
      {onRetry !== undefined && (
        <button type="button" className="button" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}
