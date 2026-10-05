import Link from "next/link";

export default function NotFound() {
  return (
    <div className="container-x max-w-xl py-24 text-center">
      <p className="mono text-sm text-faint">404</p>
      <h1 className="mt-3 text-3xl font-semibold tracking-tight">Không tìm thấy trang này</h1>
      <p className="mx-auto mt-3 max-w-md text-muted">Trang không tồn tại, đã bị xoá, hoặc bạn không có quyền xem nó.</p>
      <div className="term mx-auto mt-8 max-w-sm text-left"><div className="term-body"><span className="prompt">$</span> cd /trang-khong-ton-tai<br /><span className="text-crit">không tìm thấy đường dẫn</span><span className="cursor" /></div></div>
      <Link href="/" className="btn-dark mt-8">Về trang chủ</Link>
    </div>
  );
}
