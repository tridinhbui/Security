/** Chuyển trang: mỗi lần điều hướng, nội dung trượt nhẹ vào (transform + opacity). Tự tắt khi giảm chuyển động. */
export default function Template({ children }: { children: React.ReactNode }) {
  return <div className="page-enter">{children}</div>;
}
