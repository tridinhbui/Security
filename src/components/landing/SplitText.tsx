/**
 * Chữ vào từng từ (mỗi từ trượt lên khỏi mặt nạ). Thuần CSS, không cần JS; trình đọc màn hình đọc cả câu qua aria-label.
 * `lines` là danh sách dòng; mỗi dòng là danh sách đoạn {text, className}. Độ trễ tăng dần theo thứ tự từ.
 */
import { Fragment } from "react";

export interface Seg { text: string; className?: string }
export function SplitText({ lines, baseDelay = 120, step = 70 }: { lines: Seg[][]; baseDelay?: number; step?: number }) {
  let n = 0;
  const label = lines.map((l) => l.map((s) => s.text).join(" ")).join(" ");
  return (
    <span aria-label={label}>
      {lines.map((segs, li) => (
        <span key={li} aria-hidden className="block">
          {segs.flatMap((seg) => seg.text.split(" ").map((w) => ({ w, c: seg.className }))).map(({ w, c }, i) => (
            <Fragment key={i}>
              <span className="w-mask"><span className={`w-in ${c ?? ""}`} style={{ animationDelay: `${baseDelay + step * n++}ms` }}>{w}</span></span>{" "}
            </Fragment>
          ))}
        </span>
      ))}
    </span>
  );
}
