/** Khung xương khi tải: giữ đúng bố cục để không bị nhảy layout. */
export function PageSkeleton({ rows = 5, title = true }: { rows?: number; title?: boolean }) {
  return (
    <div className="container-x py-12" role="status" aria-label="Đang tải">
      {title && <div className="skeleton h-9 w-64" />}
      <div className="skeleton mt-3 h-4 w-96 max-w-full" />
      <div className="mt-10 space-y-3">
        {Array.from({ length: rows }, (_, i) => <div key={i} className="skeleton h-16 w-full" style={{ animationDelay: `${i * 80}ms` }} />)}
      </div>
      <span className="sr-only">Đang tải nội dung…</span>
    </div>
  );
}

export function ReportSkeleton() {
  return (
    <div className="container-x py-12" role="status" aria-label="Đang tải báo cáo">
      <div className="skeleton h-4 w-24" /><div className="skeleton mt-3 h-9 w-72 max-w-full" />
      <div className="mt-10 grid gap-8 lg:grid-cols-[auto_1fr]">
        <div className="skeleton size-44 rounded-full" />
        <div className="space-y-3"><div className="skeleton h-4 w-full" /><div className="skeleton h-4 w-5/6" /><div className="skeleton h-24 w-full" /></div>
      </div>
      <div className="mt-10 space-y-3">{[0, 1, 2, 3].map((i) => <div key={i} className="skeleton h-14 w-full" />)}</div>
      <span className="sr-only">Đang tải báo cáo…</span>
    </div>
  );
}
