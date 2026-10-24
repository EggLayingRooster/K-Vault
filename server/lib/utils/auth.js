const crypto = require('node:crypto');
const { run, get } = require('../../db');

const LEGACY_COOKIE_NAME = 'katelya_session';

function parseCookies(cookieHeader = '') {
  const result = {};
  if (!cookieHeader) return result;

  cookieHeader.split(';').forEach((chunk) => {
    const [rawName, ...rest] = chunk.trim().split('=');
    if (!rawName) return;
    const rawValue = rest.join('=');
    result[rawName] = decodeURIComponent(rawValue || '');
  });

  return result;
}

class AuthService {
  constructor(db, config) {
    this.db = db;
    this.config = config;
  }

  isAuthRequired() {
    return Boolean(this.config.basicUser && this.config.basicPass);
  }

  generateToken() {
    return crypto.randomBytes(32).toString('hex');
  }

  verifyBasicAuth(headerValue = '') {
    if (!headerValue || !headerValue.startsWith('Basic ')) return null;

    try {
      const encoded = headerValue.slice('Basic '.length).trim();
      const decoded = Buffer.from(encoded, 'base64').toString('utf8');
      const separator = decoded.indexOf(':');
      if (separator === -1) return null;
      const user = decoded.slice(0, separator);
      const pass = decoded.slice(separator + 1);

      if (user === this.config.basicUser && pass === this.config.basicPass) {
        return { authenticated: true, user, reason: 'basic-auth' };
      }
    } catch (error) {
      return null;
    }

    return null;
  }

  createSession(userName) {
    const now = Date.now();
    const expiresAt = now + this.config.sessionDurationMs;
    const token = this.generateToken();

    run(
      this.db,
      `INSERT INTO sessions(token, user_name, created_at, expires_at)
       VALUES (?, ?, ?, ?)` ,
      [token, userName, now, expiresAt]
    );

    return { token, expiresAt };
  }

  deleteSession(token) {
    if (!token) return;
    run(this.db, 'DELETE FROM sessions WHERE token = ?', [token]);
  }

  getSession(token) {
    if (!token) return null;
    const row = get(this.db, 'SELECT * FROM sessions WHERE token = ?', [token]);
    if (!row) return null;
    if (Date.now() > row.expires_at) {
      this.deleteSession(token);
      return null;
    }
    return row;
  }

  getSessionTokenFromRequest(request) {
    const cookies = parseCookies(request.headers.get('cookie') || '');
    return cookies[this.config.sessionCookieName] || cookies[LEGACY_COOKIE_NAME] || null;
  }

  // 仅在请求确实走 HTTPS 时加 Secure，避免局域网 HTTP 部署无法登录
  isSecureRequest(request) {
    if (!request) return false;
    try {
      const proto = request.headers.get('x-forwarded-proto');
      if (proto) return proto.split(',')[0].trim().toLowerCase() === 'https';
      return new URL(request.url).protocol === 'https:';
    } catch {
      return false;
    }
  }

  createSessionCookie(token, request) {
    const maxAge = Math.floor(this.config.sessionDurationMs / 1000);
    const secure = this.isSecureRequest(request) ? '; Secure' : '';
    return `${this.config.sessionCookieName}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=${maxAge}`;
  }

  createClearSessionCookies() {
    return [
      `${this.config.sessionCookieName}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
      `${LEGACY_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`,
    ];
  }

  checkAuthentication(request) {
    if (!this.isAuthRequired()) {
      return { authenticated: true, reason: 'no-auth-required', user: 'anonymous' };
    }

    const sessionToken = this.getSessionTokenFromRequest(request);
    const session = this.getSession(sessionToken);
    if (session) {
      return {
        authenticated: true,
        reason: 'session',
        token: sessionToken,
        user: session.user_name,
      };
    }

    const basicAuth = this.verifyBasicAuth(request.headers.get('authorization') || '');
    if (basicAuth) return basicAuth;

    return { authenticated: false, reason: 'unauthorized' };
  }
}

module.exports = {
  AuthService,
  parseCookies,
};
