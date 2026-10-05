"use client";

/** Ranh giới lỗi: chỉ hiển thị thông điệp chung — không bao giờ lộ stack trace, biến môi trường hay chi tiết hạ tầng. */
export default function GlobalError({ reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return (
    <div className="container-x max-w-xl py-24 text-center" role="alert">
      <p className="mono text-sm text-faint">LỖI</p>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight">Đã xảy ra sự cố</h1>
      <p className="mx-auto mt-3 max-w-md text-muted">Chúng tôi không thể hiển thị trang này. Hãy thử lại; nếu lỗi tiếp diễn, vui lòng quay lại sau ít phút.</p>
      <button onClick={reset} className="btn-dark mt-8">Thử lại</button>
    </div>
  );
}
