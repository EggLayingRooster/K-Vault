/**
 * Initialize chunked upload task.
 * POST /api/chunked-upload/init
 */
import { checkAuthentication, isAuthRequired } from '../../utils/auth.js';

const CHUNK_SIZE = 5 * 1024 * 1024;
const DEFAULT_MAX_FILE_SIZE = 100 * 1024 * 1024;
const TELEGRAM_WEB_UPLOAD_LIMIT = 20 * 1024 * 1024;

// Pages 版本原先硬编码 100MB，README 里写的 UPLOAD_MAX_SIZE 只对 Docker 版生效。
// 改用 R2 原生分片后，整体大小不再受单次请求体 100MB 限制（每片仍远小于该限制），
// 因此这里支持通过环境变量调整。
function resolveMaxFileSize(env) {
  const configured = parseInt(env?.UPLOAD_MAX_SIZE, 10);
  if (Number.isFinite(configured) && configured > 0) return configured;
  return DEFAULT_MAX_FILE_SIZE;
}

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    if (!env.img_url) {
      return jsonResponse({ error: 'KV binding img_url is required for chunk upload task state.' }, 500);
    }

    const isAdmin = isAuthRequired(env)
      ? (await checkAuthentication(context)).authenticated
      : true;

    if (!isAdmin) {
      // 访客不支持分片上传：无条件拒绝。
      // 原实现调用 checkGuestUpload(request, env, 0)，传入 size=0 使 GUEST_MAX_FILE_SIZE 校验失效，
      // 且 allowed 为 true 时访客仍会继续走分片流程，导致大小限制与每日次数限制双双被绕过。
      return jsonResponse({ error: '访客不支持分片上传，请使用普通上传' }, 403);
    }

    const body = await request.json();
    const { fileName, fileSize, fileType, totalChunks, storageMode } = body || {};
    const folderPath = normalizeFolderPath(body?.folderPath || body?.folder || '');
    const normalizedFileSize = Number(fileSize || 0);
    const normalizedTotalChunks = Number(totalChunks || 0);

    if (!fileName || !normalizedFileSize || !normalizedTotalChunks) {
      return jsonResponse({ error: '缺少必要参数' }, 400);
    }

    const validModes = ['telegram', 'r2', 's3', 'discord', 'huggingface', 'webdav', 'github'];
    const normalizedStorage = validModes.includes(storageMode) ? storageMode : 'telegram';

    const validation = validateChunkUpload(normalizedStorage, normalizedFileSize, resolveMaxFileSize(env));
    if (!validation.ok) {
      return jsonResponse({ error: validation.message, code: validation.code }, validation.status);
    }

    const uploadId = generateUploadId();

    const chunkBackend = resolveChunkBackend(env);

    // R2 原生分片上传：分片直接写进 R2，complete 时由 R2 在服务端拼接，
    // 不需要把整个文件读进内存。原来的做法峰值约为文件大小的 2 倍
    // （98MB 文件约 197MB），超过 Workers 128MB 内存上限，表现为
    // 进度到 100% 后 complete 返回非 JSON 错误页。
    let r2Multipart = null;
    if (
      normalizedStorage === 'r2' &&
      env.R2_BUCKET &&
      CHUNK_SIZE >= 5 * 1024 * 1024
    ) {
      try {
        const ext = getFileExtension(fileName);
        const objectKey = `r2_${Date.now()}_${uploadId.slice(0, 8)}.${ext}`;
        const multipart = await env.R2_BUCKET.createMultipartUpload(objectKey, {
          httpMetadata: { contentType: fileType || 'application/octet-stream' },
          customMetadata: { fileName, uploadTime: String(Date.now()) },
        });
        r2Multipart = {
          key: objectKey,
          uploadId: multipart.uploadId,
          parts: [],
        };
      } catch (error) {
        console.error('R2 multipart init failed, falling back to buffered chunks:', error);
        r2Multipart = null;
      }
    }

    // 大文件没拿到原生分片时记录一条日志，便于在 Pages Functions 日志里定位
    if (!r2Multipart && normalizedFileSize > 48 * 1024 * 1024) {
      console.warn(
        `[chunked-upload] 大文件未启用 R2 原生分片: storageMode=${normalizedStorage} hasR2Bucket=${Boolean(env.R2_BUCKET)} fileSize=${normalizedFileSize}`
      );
    }

    const uploadTask = {
      uploadId,
      fileName,
      fileSize: normalizedFileSize,
      fileType,
      totalChunks: normalizedTotalChunks,
      storageMode: normalizedStorage,
      folderPath,
      chunkBackend,
      r2Multipart,
      uploadedChunks: [],
      createdAt: Date.now(),
      status: 'pending',
    };

    await env.img_url.put(`upload:${uploadId}`, JSON.stringify(uploadTask), {
      expirationTtl: 3600,
    });

    return jsonResponse({
      success: true,
      uploadId,
      chunkSize: CHUNK_SIZE,
      chunkBackend,
      // 便于前端与排障确认这次是否走了 R2 原生分片
      multipart: Boolean(r2Multipart),
    });
  } catch (error) {
    console.error('Init upload error:', error);
    return jsonResponse({ error: error.message }, 500);
  }
}

/**
 * GET /api/chunked-upload/init?uploadId=xxx
 */
export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const uploadId = url.searchParams.get('uploadId');

  if (!uploadId) {
    return jsonResponse({ error: '缺少 uploadId' }, 400);
  }

  if (!env.img_url) {
    return jsonResponse({ error: 'KV binding img_url is required.' }, 500);
  }

  try {
    const taskData = await env.img_url.get(`upload:${uploadId}`, { type: 'json' });
    if (!taskData) {
      return jsonResponse({ error: '上传任务不存在或已过期' }, 404);
    }

    return jsonResponse({
      success: true,
      ...taskData,
    });
  } catch (error) {
    return jsonResponse({ error: error.message }, 500);
  }
}

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function resolveChunkBackend(env) {
  const mode = String(env.CHUNK_BACKEND || 'auto').toLowerCase();
  if (mode === 'kv') return 'kv';
  if (mode === 'r2') return env.R2_BUCKET ? 'r2' : 'kv';
  return env.R2_BUCKET ? 'r2' : 'kv';
}

function generateUploadId() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

function validateChunkUpload(storageMode, fileSize, maxFileSize = DEFAULT_MAX_FILE_SIZE) {
  if (fileSize > maxFileSize) {
    return {
      ok: false,
      status: 413,
      code: 'FILE_TOO_LARGE',
      message: `文件大小超过限制 (最大 ${Math.floor(maxFileSize / 1024 / 1024)}MB)`,
    };
  }

  if (storageMode === 'telegram' && fileSize > TELEGRAM_WEB_UPLOAD_LIMIT) {
    return {
      ok: false,
      status: 400,
      code: 'TELEGRAM_CHUNK_UNSUPPORTED',
      message: 'Cloudflare Pages 上的 Telegram 网页上传仅适合 20MB 以内文件。更大的文件请切换到 R2/S3/WebDAV/GitHub，或把文件直接发到 Telegram 后使用 Webhook 回链。',
    };
  }

  if (storageMode === 'discord' && fileSize > 25 * 1024 * 1024) {
    return {
      ok: false,
      status: 413,
      code: 'DISCORD_FILE_TOO_LARGE',
      message: 'Discord 默认上传上限按 25MB 处理；更大的文件请使用 R2/S3/WebDAV/GitHub。',
    };
  }

  if (storageMode === 'huggingface' && fileSize > 35 * 1024 * 1024) {
    return {
      ok: false,
      status: 413,
      code: 'HUGGINGFACE_FILE_TOO_LARGE',
      message: 'HuggingFace 普通上传链路建议控制在 35MB 以内；更大的文件请使用 LFS 或其他对象存储。',
    };
  }

  return { ok: true };
}

function normalizeFolderPath(value) {
  const raw = String(value || '').replace(/\\/g, '/').trim();
  const output = [];
  for (const part of raw.split('/')) {
    const piece = part.trim();
    if (!piece || piece === '.') continue;
    if (piece === '..') {
      output.pop();
      continue;
    }
    output.push(piece);
  }
  return output.join('/');
}

function getFileExtension(fileName) {
  const name = String(fileName || '');
  const ext = name.split('.').pop()?.toLowerCase();
  if (!ext || ext === name.toLowerCase()) return 'bin';
  return ext.replace(/[^a-z0-9]/g, '') || 'bin';
}
