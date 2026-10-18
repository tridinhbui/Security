/**
 * Phiên bản của BỘ LUẬT + CÁCH CHẤM ĐIỂM. TĂNG số này mỗi khi thêm/sửa luật, đổi mức độ nghiêm trọng hoặc đổi cách tính điểm.
 * Kết quả quét được dùng lại (bộ nhớ đệm) chỉ khi cùng phiên bản, nếu không người dùng sẽ nhận điểm cũ chấm theo luật cũ.
 */
export const ENGINE_VERSION = 10; // 10: gộp nguyên nhân gốc khi trừ điểm, trần điểm theo phạm vi thực tế, sửa 9 sai lệch độ chính xác (audit 2026-10-18)
