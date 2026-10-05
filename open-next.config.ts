import { defineCloudflareConfig } from "@opennextjs/cloudflare";

/**
 * `npm run build` chạy `opennextjs-cloudflare build`, nên Cloudflare Workers Builds với cấu hình mặc định
 * (build: `npm run build`, deploy: `npx wrangler deploy`) tạo đủ thư mục `.open-next` trước khi deploy.
 * OpenNext cần một lệnh build Next riêng để khỏi gọi lại chính `npm run build` (vòng lặp vô hạn).
 */
export default {
  ...defineCloudflareConfig(), // không dùng incremental cache: mọi trang dữ liệu đều động theo người dùng
  buildCommand: "npx next build",
};
