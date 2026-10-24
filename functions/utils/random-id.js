/**
 * 生成随机标识符。
 *
 * 文件 URL 是「未列出即可访问」的唯一屏障，而 Math.random() 不是密码学安全随机源
 * （V8 用 xorshift128+，观察若干输出后可以预测后续值）。这里统一改用
 * crypto.getRandomValues，并输出十六进制以保持 ID 可读、可安全用于 URL。
 */
export function randomToken(byteLength = 4) {
  const buf = new Uint8Array(byteLength);
  crypto.getRandomValues(buf);
  return Array.from(buf, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
