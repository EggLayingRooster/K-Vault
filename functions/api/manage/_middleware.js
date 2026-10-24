import { 
  checkAuthentication,
  isAuthRequired 
} from '../../utils/auth.js';

async function errorHandling(context) {
    try {
      return await context.next();
    } catch (err) {
      // 只写日志，不把堆栈返回给客户端（会暴露文件路径与内部结构）
      console.error('manage api error:', err);
      return new Response('Internal Server Error', {
        status: 500,
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store',
        },
      });
    }
  }

  function UnauthorizedException(reason) {
    return new Response(reason, {
        status: 401,
        statusText: 'Unauthorized',
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store',
          'Content-Length': reason.length,
        },
      });
  }
  
  function BadRequestException(reason) {
    return new Response(reason, {
        status: 400,
        statusText: 'Bad Request',
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store',
          'Content-Length': reason.length,
        },
      });
  }
  
  
  async function authentication(context) {
    // 检查 KV 是否绑定
    if (typeof context.env.img_url == "undefined" || context.env.img_url == null || context.env.img_url == "") {
        return new Response('Dashboard is disabled. Please bind a KV namespace to use this feature.', { status: 200 });
    }

    // 如果没有配置认证，直接放行
    if (!isAuthRequired(context.env)) {
        return context.next();
    }
    
    // 使用统一的认证检查（支持 Cookie session 和 Basic Auth）
    const authResult = await checkAuthentication(context);
    
    if (authResult.authenticated) {
        return context.next();
    }
    
    // 认证失败，返回 401
    return new Response('You need to login.', {
        status: 401,
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          'Cache-Control': 'no-store',
        },
    });
  }
  
  export const onRequest = [errorHandling, authentication];