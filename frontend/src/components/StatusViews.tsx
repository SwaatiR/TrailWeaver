interface ErrorStateProps {
  title?: string;
  message: string;
  onRetry?: () => void;
}

export function PanelError({
  title = "Analysis unavailable",
  message,
  onRetry,
}: ErrorStateProps) {
  return (
    <div className="panel-state panel-state--error" role="alert">
      <span className="panel-state__mark" aria-hidden="true">!</span>
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
      </div>
      {onRetry ? (
        <button className="text-button" type="button" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}

export function PanelSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div
      className="skeleton-stack"
      role="status"
      aria-label="Loading analysis"
      aria-busy="true"
      aria-live="polite"
    >
      {Array.from({ length: rows }, (_, index) => (
        <span key={index} className="skeleton-line" aria-hidden="true" />
      ))}
    </div>
  );
}
