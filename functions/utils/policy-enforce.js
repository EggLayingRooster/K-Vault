/**
 * Per-token policy enforcement (requirement #10).
 * Shared by /api/v1/upload and /api/v1/import.
 */

function baseMime(mime) {
  return String(mime || '').split(';')[0].trim().toLowerCase();
}

/**
 * 归一化目录路径：统一分隔符、折叠 . 和 ..、去掉首尾斜杠。
 * 策略校验必须在归一化之后进行，否则 "allowed/../../etc" 会通过 startsWith('allowed')。
 */
function normalizePolicyFolder(value) {
  const raw = String(value || '').replace(/\\/g, '/');
  const parts = [];
  for (const piece of raw.split('/')) {
    const seg = piece.trim();
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      parts.pop();
      continue;
    }
    parts.push(seg);
  }
  return parts.join('/');
}

export function checkUploadPolicy(tokenRecord, { storage, mime, sizeBytes, folderPath, request }) {
  const policies = tokenRecord?.policies;
  if (!policies) return { ok: true };

  if (policies.allowedStorages?.length) {
    if (!storage || !policies.allowedStorages.includes(storage)) {
      return {
        ok: false,
        status: 403,
        code: 'POLICY_STORAGE_DENIED',
        message: `API Token policy only allows storage: ${policies.allowedStorages.join(', ')}.`,
      };
    }
  }

  if (policies.allowedMimeTypes?.length) {
    const normalized = baseMime(mime);
    if (!normalized || !policies.allowedMimeTypes.includes(normalized)) {
      return {
        ok: false,
        status: 403,
        code: 'POLICY_MIME_DENIED',
        message: `API Token policy only allows MIME types: ${policies.allowedMimeTypes.join(', ')}.`,
      };
    }
  }

  if (policies.maxFileSize && Number(sizeBytes) > policies.maxFileSize) {
    return {
      ok: false,
      status: 413,
      code: 'POLICY_SIZE_EXCEEDED',
      message: `API Token policy limits uploads to ${policies.maxFileSize} bytes.`,
    };
  }

  if (policies.folderPrefix) {
    const folder = normalizePolicyFolder(folderPath);
    const prefix = normalizePolicyFolder(policies.folderPrefix);
    // 必须按路径段匹配，否则前缀 "private" 会放行 "private2/"
    const withinPrefix = folder === prefix || folder.startsWith(`${prefix}/`);
    if (!withinPrefix) {
      return {
        ok: false,
        status: 403,
        code: 'POLICY_FOLDER_DENIED',
        message: `API Token policy restricts uploads to folder prefix "${prefix}/".`,
      };
    }
  }

  if (policies.allowedSourceHosts?.length) {
    const origin = String(request?.headers?.get('Origin') || request?.headers?.get('Referer') || '').trim();
    if (origin) {
      try {
        const host = new URL(origin).host.toLowerCase();
        if (!policies.allowedSourceHosts.includes(host)) {
          return {
            ok: false,
            status: 403,
            code: 'POLICY_SOURCE_DENIED',
            message: `API Token policy only allows source hosts: ${policies.allowedSourceHosts.join(', ')}.`,
          };
        }
      } catch {
        return { ok: false, status: 403, code: 'POLICY_SOURCE_DENIED', message: 'Invalid Origin/Referer header.' };
      }
    }
    // No Origin/Referer (server-to-server calls) -> allowed; browser clients
    // always send one of them on cross-origin requests.
  }

  return { ok: true };
}
