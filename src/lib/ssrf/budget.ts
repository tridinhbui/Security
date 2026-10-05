/** Giới hạn cứng cho một lượt quét (thuần TypeScript: dùng chung cho Worker và container). */

export type BudgetErrorCode = "request_budget" | "deadline" | "byte_budget";
export class BudgetError extends Error {
  constructor(public readonly code: BudgetErrorCode, message: string) {
    super(message);
    this.name = "BudgetError";
  }
}

/** Hard ceilings for one scan. Shared by every request the scan makes. */
export class ScanBudget {
  used = 0;
  bytes = 0;
  readonly deadline: number;
  constructor(
    readonly maxRequests = 20,
    readonly maxTotalBytes = 6 * 1024 * 1024,
    readonly maxDurationMs = 60_000,
    now = Date.now(),
  ) {
    this.deadline = now + maxDurationMs;
  }
  remainingMs() {
    return this.deadline - Date.now();
  }
  take() {
    if (this.remainingMs() <= 0) throw new BudgetError("deadline", "Đã hết thời gian quét tối đa.");
    if (this.used >= this.maxRequests) throw new BudgetError("request_budget", "Đã đạt giới hạn số request cho một lần quét.");
    if (this.bytes >= this.maxTotalBytes) throw new BudgetError("byte_budget", "Đã đạt giới hạn dung lượng tải cho một lần quét.");
    this.used++;
  }
  addBytes(n: number) {
    this.bytes += n;
  }
}
