export interface EmptyStateCardProps {
  /** Card title — 14/600 uppercase-tracked ink-2, per brief §3. */
  title: string;
  /** One quiet sentence. Never a spinner farm (brief §3). */
  message: string;
}

/**
 * On-brand placeholder body for views not yet wired to a backend. Every
 * src/views/*.tsx uses this until its real content lands — swap the
 * <EmptyStateCard> out for real cards/charts without touching the page
 * shell (title + view-stack) around it.
 */
export function EmptyStateCard({ title, message }: EmptyStateCardProps) {
  return (
    <div className="card card-pad">
      <h2 className="card-title">{title}</h2>
      <p className="empty-state">{message}</p>
    </div>
  );
}
