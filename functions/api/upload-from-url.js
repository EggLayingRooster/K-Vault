import { createS3Client } from "../utils/s3client.js";
import { uploadToDiscord } from "../utils/discord.js";
import { hasHuggingFaceConfig, uploadToHuggingFace } from "../utils/huggingface.js";
import { hasWebDAVConfig, normalizeWebDAVPath, uploadToWebDAV } from "../utils/webdav.js";
import { hasGitHubConfig, normalizeGitHubStoragePath, uploadToGitHub } from "../utils/github.js";
import {
  buildTelegramDirectLink,
  buildTelegramBotApiUrl,
  createSignedTelegramFileId,
  getTelegramUploadMethodAndField,
  pickTelegramFileId,
  sendTelegramUploadNotice,
  shouldUseSignedTelegramLinks,
  shouldWriteTelegramMetadata,
} from "../utils/telegram.js";
import { checkAuthentication, isAuthRequired } from "../utils/auth.js";
import { checkGuestUpload } from "../utils/guest.js";
import { validateRemoteUrl, validateRedirectLocation, MAX_REDIRECTS } from "../utils/ssrf-guard.js";
import { randomToken } from "../utils/random-id.js";

const MAX_FILE_SIZE = 100 * 1024 * 1024;
const FETCH_TIMEOUT = 30000;
const MB = 1024 * 1024;

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // 鉴权：管理员，或已启用且未超限的访客
    const isAdmin = isAuthRequired(env)
      ? (await checkAuthentication(context)).authenticated
      : true;

    let maxBytes = MAX_FILE_SIZE;

    if (!isAdmin) {
      const guestCheck = await checkGuestUpload(request, env, 0);
      if (!guestCheck.allowed) {
        return jsonResponse({ error: guestCheck.reason || "未授权" }, guestCheck.status || 401);
      }
      const guestMax = parseInt(env.GUEST_MAX_FILE_SIZE, 10) || 5 * 1024 * 1024;
      maxBytes = Math.min(MAX_FILE_SIZE, guestMax);
    }

    const body = await request.json();
    const url = String(body?.url || "").trim();
    const storageMode = String(body?.storageMode || "telegram").toLowerCase();
    const folderPath = normalizeFolderPath(body?.folderPath || body?.folder || "");

    if (!url) {
      return jsonResponse({ error: "请输入 URL" }, 400);
    }

    // SSRF 校验：协议、主机名（含内网/元数据地址）、端口
    const urlCheck = validateRemoteUrl(url);
    if (!urlCheck.ok) {
      return jsonResponse({ error: urlCheck.message, code: urlCheck.code }, 400);
    }
    const parsedUrl = urlCheck.url;

    const fetched = await fetchRemote(url, maxBytes);
    if (!fetched.ok) {
      return jsonResponse({ error: fetched.error, code: fetched.code }, fetched.status || 502);
    }

    const arrayBuffer = fetched.arrayBuffer;
    const fileSize = arrayBuffer.byteLength;
    if (!fileSize) {
      return jsonResponse({ error: "Remote file is empty" }, 400);
    }
    if (fileSize > maxBytes) {
      return jsonResponse(
        { error: `文件过大（${formatSize(fileSize)}），最大允许 ${formatSize(maxBytes)}。` },
        413
      );
    }

    const storageValidation = validateStorageSize(storageMode, fileSize);
    if (!storageValidation.ok) {
      return jsonResponse({ error: storageValidation.message }, storageValidation.status);
    }

    const contentType = fetched.contentType || "application/octet-stream";
    const fileName = buildFileName(parsedUrl, contentType);
    const fileExtension = getFileExtension(fileName);

    if (storageMode === "r2") {
      if (!env.R2_BUCKET) {
        return jsonResponse({ error: "R2 未配置" }, 400);
      }
      return await uploadToR2(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    if (storageMode === "s3") {
      if (!env.S3_ENDPOINT || !env.S3_ACCESS_KEY_ID) {
        return jsonResponse({ error: "S3 未配置" }, 400);
      }
      return await uploadToS3(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    if (storageMode === "discord") {
      if (!env.DISCORD_WEBHOOK_URL && !env.DISCORD_BOT_TOKEN) {
        return jsonResponse({ error: "Discord 未配置" }, 400);
      }
      return await uploadToDiscordStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    if (storageMode === "huggingface") {
      if (!hasHuggingFaceConfig(env)) {
        return jsonResponse({ error: "HuggingFace 未配置" }, 400);
      }
      return await uploadToHFStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    if (storageMode === "webdav") {
      if (!hasWebDAVConfig(env)) {
        return jsonResponse({ error: "WebDAV 未配置" }, 400);
      }
      return await uploadToWebDAVStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    if (storageMode === "github") {
      if (!hasGitHubConfig(env)) {
        return jsonResponse({ error: "GitHub 未配置" }, 400);
      }
      return await uploadToGitHubStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath);
    }

    return await uploadToTelegram(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, new URL(request.url).origin, folderPath);
  } catch (error) {
    console.error("URL upload error:", error);
    return jsonResponse({ error: `服务器错误：${error.message}` }, 500);
  }
}

async function fetchRemote(url, maxBytes = MAX_FILE_SIZE) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT);

  try {
    let currentUrl = url;

    // 手动跟随重定向，每一跳都重新做 SSRF 校验
    for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
      const hopCheck = validateRemoteUrl(currentUrl);
      if (!hopCheck.ok) {
        return { ok: false, status: 400, code: hopCheck.code, error: hopCheck.message };
      }

      const response = await fetch(hopCheck.url.href, {
        signal: controller.signal,
        redirect: "manual",
        headers: {
          "User-Agent": "Mozilla/5.0 K-Vault URL Uploader",
          Accept: "image/*,video/*,audio/*,application/*,*/*",
        },
      });

      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("Location");
        if (!location) {
          return { ok: false, status: 502, error: "远程 URL 返回重定向，但缺少 Location 头。" };
        }
        const next = validateRedirectLocation(location, hopCheck.url.href);
        if (!next.ok) {
          return { ok: false, status: 400, code: next.code, error: next.message };
        }
        currentUrl = next.url.href;
        continue;
      }

      if (!response.ok) {
        return {
          ok: false,
          status: 502,
          error: `远程 URL 响应异常：${response.status} ${response.statusText}`,
        };
      }

      // 先用 Content-Length 预检，避免把超大文件读进内存
      const declaredLength = Number(response.headers.get("content-length") || 0);
      if (declaredLength && declaredLength > maxBytes) {
        return {
          ok: false,
          status: 413,
          code: "FILE_TOO_LARGE",
          error: `远程文件过大（${formatSize(declaredLength)}），最大允许 ${formatSize(maxBytes)}。`,
        };
      }

      const contentType = response.headers.get("content-type") || "application/octet-stream";
      const arrayBuffer = await readBodyWithLimit(response, maxBytes);
      if (!arrayBuffer.ok) {
        return { ok: false, status: arrayBuffer.status, code: arrayBuffer.code, error: arrayBuffer.error };
      }

      return {
        ok: true,
        contentType,
        arrayBuffer: arrayBuffer.data,
      };
    }

    return {
      ok: false,
      status: 400,
      code: "TOO_MANY_REDIRECTS",
      error: "远程 URL 重定向次数过多。",
    };
  } catch (error) {
    if (error.name === "AbortError") {
      return {
        ok: false,
        status: 408,
        error: "远程 URL 请求超时",
      };
    }

    return {
      ok: false,
      status: 502,
      error: `无法获取远程 URL：${error.message}`,
    };
  } finally {
    clearTimeout(timeout);
  }
}

// 流式读取并累计大小，超限立刻中断，不会把整个超大响应读进内存
async function readBodyWithLimit(response, maxBytes) {
  if (!response.body) {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > maxBytes) {
      return {
        ok: false,
        status: 413,
        code: "FILE_TOO_LARGE",
        error: `远程文件过大，最大允许 ${formatSize(maxBytes)}。`,
      };
    }
    return { ok: true, data: buffer };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;

  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch {}
        return {
          ok: false,
          status: 413,
          code: "FILE_TOO_LARGE",
          error: `远程文件过大，最大允许 ${formatSize(maxBytes)}。`,
        };
      }
      chunks.push(value);
    }
  } catch (error) {
    return { ok: false, status: 502, error: `读取远程内容失败：${error.message}` };
  }

  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return { ok: true, data: merged.buffer };
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function validateStorageSize(storageMode, fileSize) {
  const limits = {
    telegram: {
      maxBytes: 20 * MB,
      status: 413,
      message: "Cloudflare Pages 上的 Telegram URL 上传限制为 20MB。较大的文件请使用 R2、S3、WebDAV 或 GitHub。",
    },
    discord: {
      maxBytes: 25 * MB,
      status: 413,
      message: "Discord 上传上限受服务器加成影响，K-Vault 默认按 25MB 保守处理。",
    },
    huggingface: {
      maxBytes: 35 * MB,
      status: 413,
      message: "HuggingFace regular upload is capped at 35MB in K-Vault. Use another storage backend for larger files.",
    },
  };
  const limit = limits[storageMode];
  if (limit && fileSize > limit.maxBytes) {
    return { ok: false, status: limit.status, message: limit.message };
  }
  return { ok: true };
}

function normalizeFolderPath(value) {
  const raw = String(value || "").replace(/\\/g, "/").trim();
  const output = [];
  for (const part of raw.split("/")) {
    const piece = part.trim();
    if (!piece || piece === ".") continue;
    if (piece === "..") {
      output.pop();
      continue;
    }
    output.push(piece);
  }
  return output.join("/");
}

function joinStoragePath(folderPath, fileName) {
  const base = normalizeFolderPath(folderPath);
  if (!base) return fileName;
  return `${base}/${fileName}`;
}

function getFileExtension(fileName) {
  const ext = String(fileName || "")
    .split(".")
    .pop()
    ?.toLowerCase()
    ?.replace(/[^a-z0-9]/g, "");
  return ext || "bin";
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function getExtensionFromMimeType(mimeType) {
  const type = (mimeType || "").split(";")[0].trim().toLowerCase();
  const map = {
    "image/jpeg": "jpg",
    "image/jpg": "jpg",
    "image/png": "png",
    "image/gif": "gif",
    "image/webp": "webp",
    "image/bmp": "bmp",
    "image/svg+xml": "svg",
    "image/x-icon": "ico",
    "video/mp4": "mp4",
    "video/webm": "webm",
    "video/quicktime": "mov",
    "video/x-msvideo": "avi",
    "video/x-matroska": "mkv",
    "audio/mpeg": "mp3",
    "audio/wav": "wav",
    "audio/ogg": "ogg",
    "audio/flac": "flac",
    "audio/x-m4a": "m4a",
    "audio/mp4": "m4a",
    "application/pdf": "pdf",
    "application/zip": "zip",
    "application/x-rar-compressed": "rar",
    "application/x-7z-compressed": "7z",
    "text/plain": "txt",
    "application/json": "json",
  };
  return map[type] || "bin";
}

function buildFileName(parsedUrl, contentType) {
  let fileName = decodeURIComponent((parsedUrl.pathname.split("/").pop() || "").split("?")[0]);
  if (!fileName) {
    fileName = `url_${Date.now()}.${getExtensionFromMimeType(contentType)}`;
  }

  if (!fileName.includes(".")) {
    fileName = `${fileName}.${getExtensionFromMimeType(contentType)}`;
  }

  return fileName;
}

function randomId(prefix) {
  return `${prefix}_${Date.now()}_${randomToken(4)}`;
}

function appendCommonMetadata(metadata, folderPath) {
  if (!folderPath) return metadata;
  return {
    ...metadata,
    folderPath,
  };
}

async function uploadToTelegram(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, fallbackOrigin = "", folderPath = "") {
  const blob = new Blob([arrayBuffer], { type: contentType });
  const file = new File([blob], fileName, { type: contentType });

  const formData = new FormData();
  formData.append("chat_id", env.TG_Chat_ID);

  const { method: apiEndpoint, field } = getTelegramUploadMethodAndField(contentType);
  formData.append(field, file);

  const apiUrl = buildTelegramBotApiUrl(env, apiEndpoint);

  let response;
  try {
    response = await fetch(apiUrl, {
      method: "POST",
      body: formData,
    });
  } catch (error) {
    return jsonResponse({ error: `Telegram request failed: ${error.message}` }, 502);
  }

  const responseData = await response.json();

  if (!response.ok) {
    if (apiEndpoint === "sendAudio") {
      const docFormData = new FormData();
      docFormData.append("chat_id", env.TG_Chat_ID);
      docFormData.append("document", file);

      const docResponse = await fetch(buildTelegramBotApiUrl(env, "sendDocument"), {
        method: "POST",
        body: docFormData,
      });

      const docData = await docResponse.json();
      if (docResponse.ok) {
        return processTelegramSuccess(docData, fileName, fileExtension, contentType, fileSize, env, fallbackOrigin, folderPath);
      }
    }
    return jsonResponse({ error: responseData.description || "Telegram upload failed" }, 500);
  }

  return processTelegramSuccess(responseData, fileName, fileExtension, contentType, fileSize, env, fallbackOrigin, folderPath);
}

async function processTelegramSuccess(responseData, fileName, fileExtension, mimeType, fileSize, env, fallbackOrigin = "", folderPath = "") {
  const fileId = pickTelegramFileId(responseData);
  const messageId = responseData?.result?.message_id;

  if (!fileId) {
    return jsonResponse({ error: "Telegram 已接收文件，但未返回可用的文件 ID" }, 500);
  }

  const directId = await buildTelegramDirectId(fileId, fileExtension, fileName, mimeType, fileSize, messageId, env);

  if (env.img_url && shouldWriteTelegramMetadata(env)) {
    await env.img_url.put(`${fileId}.${fileExtension}`, "", {
      metadata: appendCommonMetadata(
        {
          TimeStamp: Date.now(),
          ListType: "None",
          Label: "None",
          liked: false,
          fileName,
          fileSize,
          storageType: "telegram",
          telegramFileId: fileId,
          telegramMessageId: messageId || undefined,
          signedLink: shouldUseSignedTelegramLinks(env),
        },
        folderPath
      ),
    });
  }

  const directLink = buildTelegramDirectLink(env, directId, fallbackOrigin);
  try {
    const noticeResult = await sendTelegramUploadNotice(
      {
        chatId: env.TG_Chat_ID,
        replyToMessageId: messageId || undefined,
        directLink,
        fileId,
        messageId,
        fileName,
        fileSize,
      },
      env
    );
    if (!noticeResult?.ok && !noticeResult?.skipped) {
      console.warn(
        "Telegram upload notice failed:",
        noticeResult?.data?.description || noticeResult?.error || "unknown error"
      );
    }
  } catch (error) {
    console.warn("Telegram upload notice error:", error.message);
  }

  return jsonResponse([{ src: `/file/${directId}` }]);
}

async function uploadToR2(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath = "") {
  try {
    const fileId = randomId("r2");
    const objectKey = `${fileId}.${fileExtension}`;

    await env.R2_BUCKET.put(objectKey, arrayBuffer, {
      httpMetadata: { contentType },
      customMetadata: { fileName, uploadTime: Date.now().toString() },
    });

    if (env.img_url) {
      await env.img_url.put(`r2:${objectKey}`, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "r2",
            r2Key: objectKey,
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/r2:${objectKey}` }]);
  } catch (error) {
    console.error("R2 upload error:", error);
    return jsonResponse({ error: `R2 upload failed: ${error.message}` }, 500);
  }
}

async function uploadToS3(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath = "") {
  try {
    const s3 = createS3Client(env);
    const fileId = randomId("s3");
    const objectKey = `${fileId}.${fileExtension}`;

    await s3.putObject(objectKey, arrayBuffer, {
      contentType,
      metadata: {
        "x-amz-meta-filename": fileName,
        "x-amz-meta-uploadtime": Date.now().toString(),
      },
    });

    if (env.img_url) {
      await env.img_url.put(`s3:${objectKey}`, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "s3",
            s3Key: objectKey,
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/s3:${objectKey}` }]);
  } catch (error) {
    console.error("S3 upload error:", error);
    return jsonResponse({ error: `S3 upload failed: ${error.message}` }, 500);
  }
}

async function uploadToDiscordStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath = "") {
  try {
    const result = await uploadToDiscord(arrayBuffer, fileName, contentType, env);

    if (!result.success) {
      return jsonResponse({ error: `Discord upload failed: ${result.error}` }, 500);
    }

    const fileId = randomId("discord");
    const kvKey = `discord:${fileId}.${fileExtension}`;

    if (env.img_url) {
      await env.img_url.put(kvKey, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "discord",
            discordChannelId: result.channelId,
            discordMessageId: result.messageId,
            discordAttachmentId: result.attachmentId,
            discordUploadMode: result.mode,
            discordSourceUrl: result.sourceUrl,
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/${kvKey}` }]);
  } catch (error) {
    console.error("Discord upload error:", error);
    return jsonResponse({ error: `Discord upload failed: ${error.message}` }, 500);
  }
}

async function uploadToHFStorage(arrayBuffer, fileName, fileExtension, _contentType, fileSize, env, folderPath = "") {
  try {
    const fileId = randomId("hf");
    const hfPath = joinStoragePath(folderPath, `${fileId}.${fileExtension}`);

    const result = await uploadToHuggingFace(arrayBuffer, hfPath, fileName, env);
    if (!result.success) {
      return jsonResponse({ error: `HuggingFace upload failed: ${result.error}` }, 500);
    }

    const kvKey = `hf:${fileId}.${fileExtension}`;

    if (env.img_url) {
      await env.img_url.put(kvKey, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "huggingface",
            hfPath,
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/${kvKey}` }]);
  } catch (error) {
    console.error("HuggingFace upload error:", error);
    return jsonResponse({ error: `HuggingFace upload failed: ${error.message}` }, 500);
  }
}

async function uploadToWebDAVStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath = "") {
  try {
    const fileId = randomId("wd");
    const publicId = `${fileId}.${fileExtension}`;
    const webdavPath = joinStoragePath(folderPath, publicId);

    const result = await uploadToWebDAV(arrayBuffer, webdavPath, contentType || "application/octet-stream", env);

    const kvKey = `webdav:${publicId}`;
    if (env.img_url) {
      await env.img_url.put(kvKey, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "webdav",
            webdavPath: normalizeWebDAVPath(result.path || webdavPath),
            webdavEtag: result.etag || undefined,
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/${kvKey}` }]);
  } catch (error) {
    console.error("WebDAV upload error:", error);
    return jsonResponse({ error: `WebDAV upload failed: ${error.message}` }, 500);
  }
}

async function uploadToGitHubStorage(arrayBuffer, fileName, fileExtension, contentType, fileSize, env, folderPath = "") {
  try {
    const fileId = randomId("github");
    const publicId = `${fileId}.${fileExtension}`;
    const githubStorageKey = joinStoragePath(folderPath, publicId);

    const result = await uploadToGitHub(
      arrayBuffer,
      normalizeGitHubStoragePath(githubStorageKey),
      fileName,
      contentType || "application/octet-stream",
      env
    );

    const kvKey = `github:${publicId}`;
    if (env.img_url) {
      await env.img_url.put(kvKey, "", {
        metadata: appendCommonMetadata(
          {
            TimeStamp: Date.now(),
            ListType: "None",
            Label: "None",
            liked: false,
            fileName,
            fileSize,
            storageType: "github",
            githubStorageKey: normalizeGitHubStoragePath(result.storagePath || githubStorageKey),
            ...(result.metadata || {}),
          },
          folderPath
        ),
      });
    }

    return jsonResponse([{ src: `/file/${kvKey}` }]);
  } catch (error) {
    console.error("GitHub upload error:", error);
    return jsonResponse({ error: `GitHub upload failed: ${error.message}` }, 500);
  }
}

async function buildTelegramDirectId(fileId, fileExtension, fileName, mimeType, fileSize, messageId, env) {
  if (!shouldUseSignedTelegramLinks(env)) {
    return `${fileId}.${fileExtension}`;
  }
  return createSignedTelegramFileId(
    {
      fileId,
      fileExtension,
      fileName,
      mimeType,
      fileSize,
      messageId,
    },
    env
  );
}
