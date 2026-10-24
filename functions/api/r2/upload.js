/**
 * R2 文件上传 API
 * 将文件直接存储到 Cloudflare R2
 */

import { createStorageManager, generateKey, getFileType } from '../../utils/storage.js';
import { checkAuthentication, isAuthRequired } from '../../utils/auth.js';
import { checkGuestUpload } from '../../utils/guest.js';
import { randomToken } from '../../utils/random-id.js';

const MAX_FILE_SIZE = 100 * 1024 * 1024;

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' }
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  
  // 检查 R2 是否可用
  if (!env.R2_BUCKET) {
    return new Response(JSON.stringify({
      error: 'R2 storage not configured'
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
  
  try {
    // 鉴权：管理员，或已启用且未超限的访客
    const isAdmin = isAuthRequired(env)
      ? (await checkAuthentication(context)).authenticated
      : true;

    let maxBytes = MAX_FILE_SIZE;

    if (!isAdmin) {
      const guestCheck = await checkGuestUpload(request, env, 0);
      if (!guestCheck.allowed) {
        return jsonResponse({ error: guestCheck.reason || '未授权' }, guestCheck.status || 401);
      }
      const guestMax = parseInt(env.GUEST_MAX_FILE_SIZE, 10) || 5 * 1024 * 1024;
      maxBytes = Math.min(MAX_FILE_SIZE, guestMax);
    }

    const formData = await request.formData();
    const file = formData.get('file');
    
    if (!file) {
      return jsonResponse({ error: 'No file provided' }, 400);
    }

    const declaredSize = Number(file.size || 0);
    if (declaredSize > maxBytes) {
      return jsonResponse({
        error: `文件过大，最大允许 ${Math.floor(maxBytes / 1024 / 1024)}MB`
      }, 413);
    }
    
    // 生成文件 ID
    const timestamp = Date.now();
    const randomStr = randomToken(4);
    const ext = file.name.split('.').pop() || '';
    const fileId = `${timestamp}_${randomStr}${ext ? '.' + ext : ''}`;
    
    // 获取文件内容
    const content = await file.arrayBuffer();

    if (content.byteLength > maxBytes) {
      return jsonResponse({
        error: `文件过大，最大允许 ${Math.floor(maxBytes / 1024 / 1024)}MB`
      }, 413);
    }
    
    // 存储到 R2
    await env.R2_BUCKET.put(fileId, content, {
      httpMetadata: {
        contentType: file.type || 'application/octet-stream'
      },
      customMetadata: {
        fileName: file.name,
        fileSize: String(file.size),
        uploadTime: String(timestamp),
        fileType: getFileType(file.name)
      }
    });
    
    // 同时在 KV 中存储元数据（用于管理和列表）
    if (env.img_url) {
      const key = generateKey(fileId, file.name);
      await env.img_url.put(key, '', {
        metadata: {
          fileName: file.name,
          fileSize: file.size,
          TimeStamp: timestamp,
          storage: 'r2',
          contentType: file.type || 'application/octet-stream'
        }
      });
    }
    
    // 返回成功响应
    return new Response(JSON.stringify([{
      src: `/file/${fileId}`,
      storage: 'r2'
    }]), {
      headers: { 'Content-Type': 'application/json' }
    });
    
  } catch (error) {
    console.error('R2 upload error:', error);
    return new Response(JSON.stringify({
      error: error.message || 'Upload failed'
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

/**
 * 获取 R2 文件
 */
export async function onRequestGet(context) {
  const { request, env } = context;
  
  if (!env.R2_BUCKET) {
    return new Response('R2 storage not configured', { status: 503 });
  }
  
  const url = new URL(request.url);
  const fileId = url.searchParams.get('id');
  
  if (!fileId) {
    return new Response('File ID required', { status: 400 });
  }
  
  try {
    const object = await env.R2_BUCKET.get(fileId);
    
    if (!object) {
      return new Response('File not found', { status: 404 });
    }
    
    const contentType = object.httpMetadata?.contentType || 'application/octet-stream';
    const headers = new Headers();
    headers.set('Content-Type', contentType);
    headers.set('Content-Length', object.size);
    headers.set('X-Content-Type-Options', 'nosniff');

    if (object.customMetadata?.fileName) {
      const encoded = encodeURIComponent(object.customMetadata.fileName);
      // HTML/SVG/JS 等主动内容强制下载，避免上传的文件在本站域名下执行脚本
      const isActiveContent = /^(text\/html|application\/xhtml\+xml|image\/svg\+xml|text\/xml|application\/xml|text\/javascript|application\/javascript)/i.test(contentType);
      const disposition = isActiveContent ? 'attachment' : 'inline';
      headers.set('Content-Disposition', `${disposition}; filename="${encoded}"; filename*=UTF-8''${encoded}`);
    }
    
    // 缓存控制
    headers.set('Cache-Control', 'public, max-age=31536000');
    
    return new Response(object.body, { headers });
    
  } catch (error) {
    console.error('R2 get error:', error);
    return new Response('Error retrieving file', { status: 500 });
  }
}
