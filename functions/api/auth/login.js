/**
 * 登录 API
 * POST /api/auth/login
 */
import { 
  createSession, 
  createSessionCookieHeader,
  isAuthRequired 
} from '../../utils/auth.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  try {
    // 如果没有配置认证，返回成功
    if (!isAuthRequired(env)) {
      return new Response(JSON.stringify({ 
        success: true, 
        message: '无需登录',
        authRequired: false 
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // KV 绑定缺失时给出可操作的提示，而不是 "Cannot read properties of undefined (reading 'put')"
    if (!env?.img_url) {
      return new Response(JSON.stringify({
        success: false,
        message: '服务端未绑定 KV 命名空间（变量名必须是 img_url），无法创建会话。请到 Cloudflare Pages 项目设置检查 KV 绑定，注意 Production 和 Preview 两个环境要分别绑定；本地调试请用 --kv=img_url 启动。'
      }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const body = await request.json();
    const username = String(body?.username ?? body?.user ?? '').trim();
    const password = String(body?.password ?? body?.pass ?? '');

    if (!username || password === '') {
      return new Response(JSON.stringify({
        success: false,
        message: 'Missing username or password.'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 验证凭据
    if (username === env.BASIC_USER && password === env.BASIC_PASS) {
      // 创建会话
      const sessionToken = await createSession(username, env);
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: '登录成功' 
      }), {
        headers: { 
          'Content-Type': 'application/json',
          'Set-Cookie': createSessionCookieHeader(sessionToken)
        }
      });
    }

    return new Response(JSON.stringify({ 
      success: false, 
      message: '用户名或密码错误' 
    }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (error) {
    console.error('Login error:', error);
    return new Response(JSON.stringify({ 
      success: false, 
      message: '登录失败：' + error.message 
    }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// 检查登录状态
export async function onRequestGet(context) {
  const { env } = context;
  
  return new Response(JSON.stringify({
    // 纵深防御：显式布尔化，防止上游返回非布尔值时把敏感值序列化出去
    authRequired: Boolean(isAuthRequired(env))
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}
