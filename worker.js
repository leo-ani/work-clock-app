/* =============================================================================
 * work-clock Cloudflare Worker  ——  D1 版 v6.0.1 (Final)
 * -----------------------------------------------------------------------------
 * 环境变量 / 密钥：
 *   必需  SESSION_SECRET  随机密钥，≥32 字符且含大小写与符号
 *   可选  GITHUB_TOKEN    私有仓库 PAT（仅用于惰性迁移和备份）
 *   可选  GITHUB_REPO     owner/repo
 *   可选  GITHUB_BRANCH   默认 main
 *   可选  ALLOWED_ORIGINS 逗号分隔来源列表
 *
 * 绑定：
 *   必需  DB      D1 数据库
 *   可选  WC_KV   KV（用于读缓存 + 限流）
 * ========================================================================== */

export const SCHEMA_VERSION = 4;
export const APP_VERSION = 'V6.2-d1';
// 健康检查里回报的能力位，用来确认线上 worker 是否为新版
export const FEATURES = Object.freeze(['clearData', 'userDataUpsert', 'settingsV2', 'errorCodes', 'schemaProbe', 'legacyKdf']);

const DEFAULT_ORIGIN = 'https://leo-ani.github.io';
const DEFAULT_BRANCH = 'main';

const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const REFRESH_THRESHOLD_SECONDS = 3 * 24 * 60 * 60;

const USERNAME_RE = /^[A-Za-z0-9_-]{3,32}$/;
const HASH_RE = /^[a-f0-9]{64}$/i;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

const KDF_PBKDF2 = 'PBKDF2-SHA256';
const KDF_LEGACY = 'SHA256-LEGACY';
const PBKDF2_ITERATIONS = 600000;

/**
 * 生效的 PBKDF2 迭代次数：读环境变量 PASSWORD_ITERATIONS（100000 ~ 2000000），
 * 未配置时用 600000。原实现把这个变量晾在配置里、代码里硬编码 600000，
 * 改了配置也不生效 —— 属于"看起来能调、实际调不动"的死配置。
 */
export function resolveIterations(env) {
  const raw = Number(env && env.PASSWORD_ITERATIONS);
  if (!Number.isFinite(raw) || raw <= 0) return PBKDF2_ITERATIONS;
  return Math.min(2000000, Math.max(100000, Math.round(raw)));
}

const KV_CACHE_TTL_MS = 15000;
const KV_EXPIRE_SECONDS = 300;
const GITHUB_TIMEOUT_MS = 8000;
const MAX_RECORDS = 5000;
const MAX_PAYLOAD_BYTES = 512 * 1024;
const MAX_NOTE_LEN = 500;
const TOMBSTONE_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const RATE_RULES = Object.freeze({
  auth: { limit: 12, windowSec: 300 },
  authUser: { limit: 8, windowSec: 300 },
  read: { limit: 300, windowSec: 60 },
  write: { limit: 120, windowSec: 60 },
  register: { limit: 5, windowSec: 3600 },
});

const SHIFTS = ['day', 'early', 'mid', 'night'];
const TYPES = ['normal', 'weekend', 'holiday', 'daily'];
const LEAVES = ['none', 'sick', 'personal', 'paid', 'timeoff'];
const COMPENSATIONS = ['pay', 'timeoff'];
const DEDUCTION_KEYS = ['child', 'elder', 'loan', 'rent', 'edu', 'infant', 'medical', 'other'];
const INSURANCE_KEYS = ['pension', 'medical', 'unemployment', 'fund'];

/* ============ 1. 错误类型 ============ */
export class AppError extends Error {
  constructor(message, status = 500, code = 'INTERNAL_ERROR', detail = undefined, extra = undefined) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.detail = detail;
    this.extra = extra;
  }
}
export class GitHubError extends Error {
  constructor(message, status, info = {}) {
    super(message);
    this.name = 'GitHubError';
    this.status = status;
    this.info = info;
  }
}

/* ============ 2. 通用工具 ============ */
export function jsonResponse(data, status, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', ...extraHeaders },
  });
}
function clampNum(value, min, max, fallback = 0) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, n));
}
export function safeErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}
export function isValidDateKey(key) {
  if (typeof key !== 'string' || !DATE_RE.test(key)) return false;
  const [y, m, d] = key.split('-').map(Number);
  if (y < 1970 || y > 2100 || m < 1 || m > 12 || d < 1 || d > 31) return false;
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}
export function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---- base64 / base64url ---- */
export function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}
export function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
export function encodeBase64Utf8(str) { return bytesToBase64(new TextEncoder().encode(str)); }
export function decodeBase64Utf8(b64) { return new TextDecoder().decode(base64ToBytes(b64)); }
export function base64UrlEncode(bytes) {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
export function base64UrlDecode(str) {
  const normalized = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  return base64ToBytes(padded);
}

/* ---- 哈希 / HMAC ---- */
export async function sha256Hex(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
export async function userLogTag(username, secret) {
  if (!username) return '-';
  return (await sha256Hex(`${username}:${secret}`)).slice(0, 10);
}
export async function importHmacKey(secret, usages) {
  return crypto.subtle.importKey('raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, usages);
}
export async function hmacSign(message, secret) {
  const key = await importHmacKey(secret, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}
export async function hmacVerify(message, signature, secret) {
  const key = await importHmacKey(secret, ['verify']);
  return crypto.subtle.verify('HMAC', key, signature, new TextEncoder().encode(message));
}

/* ============ 3. 会话令牌 ============ */
export async function createSessionToken(username, secret, tv = 1) {
  const now = Math.floor(Date.now() / 1000);
  const payload = { u: username, iat: now, exp: now + SESSION_TTL_SECONDS, tv, v: 2 };
  const payloadPart = base64UrlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const signature = await hmacSign(payloadPart, secret);
  return `${payloadPart}.${base64UrlEncode(signature)}`;
}
export async function verifySessionToken(token, secret) {
  const [payloadPart, signaturePart, extra] = String(token || '').split('.');
  if (!payloadPart || !signaturePart || extra !== undefined) {
    throw new AppError('登录已失效，请重新登录', 401, 'BAD_SESSION');
  }
  let payload;
  try {
    const ok = await hmacVerify(payloadPart, base64UrlDecode(signaturePart), secret);
    if (!ok) throw new Error('bad signature');
    payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadPart)));
  } catch {
    throw new AppError('登录已失效，请重新登录', 401, 'BAD_SESSION');
  }
  const now = Math.floor(Date.now() / 1000);
  if (!payload || typeof payload.u !== 'string' || !Number.isFinite(payload.exp)) {
    throw new AppError('登录已失效，请重新登录', 401, 'BAD_SESSION');
  }
  if (payload.exp < now) throw new AppError('登录已过期，请重新登录', 401, 'SESSION_EXPIRED');
  return { username: payload.u, tv: Number(payload.tv) || 1, exp: payload.exp, iat: payload.iat };
}
export async function requireSession(request, expectedUsername, envOrSecret) {
  const secret = typeof envOrSecret === 'string' ? envOrSecret : envOrSecret.SESSION_SECRET;
  const auth = request.headers.get('Authorization') || '';
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) throw new AppError('登录已失效，请重新登录', 401, 'AUTH_REQUIRED');
  const session = await verifySessionToken(match[1].trim(), secret);
  if (expectedUsername && session.username !== expectedUsername) {
    throw new AppError('无权访问该用户数据', 403, 'SESSION_USER_MISMATCH');
  }
  // 会话撤销：token 里带 token_version，必须与库中当前值一致。
  // 否则改密码/强制下线后，旧 token 在 7 天有效期内仍可读写（原实现只签发、从不校验）。
  if (envOrSecret && typeof envOrSecret === 'object' && envOrSecret.DB) {
    const user = await d1GetUser(session.username, envOrSecret);
    if (!user) throw new AppError('账号不存在或已注销', 404, 'USER_NOT_FOUND');
    if ((Number(user.token_version) || 1) !== session.tv) {
      throw new AppError('登录已失效，请重新登录', 401, 'SESSION_REVOKED');
    }
  }
  return session;
}
async function maybeAttachRefreshToken(session, headers, env) {
  try {
    const now = Math.floor(Date.now() / 1000);
    const remaining = Number(session.exp) - now;
    if (remaining > 0 && remaining < REFRESH_THRESHOLD_SECONDS) {
      const newToken = await createSessionToken(session.username, env.SESSION_SECRET, session.tv);
      headers['X-Refresh-Token'] = newToken;
    }
  } catch (e) {
    console.warn(`refresh token failed: ${safeErrorMessage(e)}`);
  }
  return headers;
}

/* ============ 4. 数据 schema 与防污染校验 ============ */
export const DEFAULTS = Object.freeze({
  schemaVersion: SCHEMA_VERSION,
  settings: Object.freeze({
    mode: 'hourly', normalRate: 0, holidayRate: 0,
    baseSalary: 0, performance: 0,
    salaryDays: 21.75, salaryHours: 8,
    salaryFixedMode: 'daily',
    salaryRateNormal: 1, salaryRateOt: 1.5, salaryRateWeekend: 2, salaryRateHoliday: 3,
    salaryNormal: 0, salaryOt: 0, salaryWeekend: 0, salaryHoliday: 0, rule: 'fixed',
    taxSpecial: {},
    calcSalary: Object.freeze({ rate: 0, hours: 8, days: 21.75 }),
    taxUseCumulative: false,
    insuranceSalary: Object.freeze({ pension: 8, medical: 2, unemployment: 0.5, fund: 5 }),
  }),
  goal: 0,
  deductions: Object.freeze(
    DEDUCTION_KEYS.reduce((acc, k) => { acc[k] = Object.freeze({ on: false, val: 0 }); return acc; }, {})
  ),
  insurance: Object.freeze({ pension: 0, medical: 0, unemployment: 0, fund: 0 }),
  dataRev: 0,
});

export function normalizeRecord(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const now = Date.now();
  const rec = {
    shift: SHIFTS.includes(raw.shift) ? raw.shift : 'day',
    type: TYPES.includes(raw.type) ? raw.type : 'normal',
    leave: LEAVES.includes(raw.leave) ? raw.leave : 'none',
    normal: clampNum(raw.normal, 0, 24, 0),
    ot: clampNum(raw.ot, 0, 24, 0),
    compensation: COMPENSATIONS.includes(raw.compensation) ? raw.compensation : 'pay',
    deductHours: raw.deductHours === undefined || raw.deductHours === null ? 8 : clampNum(raw.deductHours, 0, 24, 8),
    note: typeof raw.note === 'string' ? raw.note.slice(0, MAX_NOTE_LEN) : '',
    updatedAt: clampNum(raw.updatedAt, 0, now + 86400000, 0),
  };
  if (rec.normal + rec.ot > 24) rec.ot = Math.round((24 - rec.normal) * 10) / 10;
  if (rec.leave !== 'none') { rec.normal = 0; rec.ot = 0; }
  return rec;
}

export function normalizeSettings(raw) {
  const out = { ...DEFAULTS.settings };
  if (!raw || typeof raw !== 'object') return out;
  if (raw.mode === 'salary' || raw.mode === 'hourly') out.mode = raw.mode;
  if (raw.salaryFixedMode === 'daily' || raw.salaryFixedMode === 'monthly') out.salaryFixedMode = raw.salaryFixedMode;
  
  out.normalRate = clampNum(raw.normalRate, 0, 10000, out.normalRate);
  out.holidayRate = clampNum(raw.holidayRate, 0, 10000, out.holidayRate);
  out.baseSalary = clampNum(raw.baseSalary, 0, 1000000, out.baseSalary);
  out.performance = clampNum(raw.performance, 0, 1000000, out.performance);
  
  out.salaryDays = clampNum(raw.salaryDays, 1, 31, out.salaryDays);
  out.salaryHours = clampNum(raw.salaryHours, 1, 24, out.salaryHours);
  
  out.salaryRateNormal = clampNum(raw.salaryRateNormal, 0, 10, out.salaryRateNormal);
  out.salaryRateOt = clampNum(raw.salaryRateOt, 0, 10, out.salaryRateOt);
  out.salaryRateWeekend = clampNum(raw.salaryRateWeekend, 0, 10, out.salaryRateWeekend);
  out.salaryRateHoliday = clampNum(raw.salaryRateHoliday, 0, 10, out.salaryRateHoliday);
  
  out.salaryNormal = clampNum(raw.salaryNormal, 0, 10000, out.salaryNormal);
  out.salaryOt = clampNum(raw.salaryOt, 0, 10000, out.salaryOt);
  out.salaryWeekend = clampNum(raw.salaryWeekend, 0, 10000, out.salaryWeekend);
  out.salaryHoliday = clampNum(raw.salaryHoliday, 0, 10000, out.salaryHoliday);
  
  if (raw.rule === 'fixed' || raw.rule === 'monthly') out.rule = raw.rule;

  // ---- 以下为"用户可设置、需要跟账号走"的字段 ----
  // 工资计算器（时薪/每日工时/月计薪天数）面板的输入
  out.calcSalary = {
    rate: clampNum(raw.calcSalary && raw.calcSalary.rate, 0, 10000, 0),
    hours: clampNum(raw.calcSalary && raw.calcSalary.hours, 1, 24, 8),
    days: clampNum(raw.calcSalary && raw.calcSalary.days, 1, 31, 21.75),
  };
  // 个税是否按年度累计预扣
  out.taxUseCumulative = raw.taxUseCumulative === true;
  // 月薪制下记住的五险一金比例（切回时恢复；时薪制一律用 0）
  const salaryDefaults = { pension: 8, medical: 2, unemployment: 0.5, fund: 5 };
  out.insuranceSalary = Object.assign({}, salaryDefaults);
  if (raw.insuranceSalary && typeof raw.insuranceSalary === 'object') {
    for (const key of INSURANCE_KEYS) {
      const v = raw.insuranceSalary[key];
      if (v !== undefined && v !== null) out.insuranceSalary[key] = clampNum(v, 0, 50, salaryDefaults[key]);
    }
  }

  out.taxSpecial = {};
  if (raw.taxSpecial && typeof raw.taxSpecial === 'object' && !Array.isArray(raw.taxSpecial)) {
    for (const [k, v] of Object.entries(raw.taxSpecial).slice(0, 32)) {
      if (typeof k === 'string' && k.length < 20) out.taxSpecial[k] = clampNum(v, 0, 100000, 0);
    }
  }
  return out;
}

export function normalizeDeductions(raw) {
  const out = {};
  const src = raw && typeof raw === 'object' ? raw : {};
  for (const key of DEDUCTION_KEYS) {
    const item = src[key];
    out[key] = {
      on: item && typeof item.on === 'boolean' ? item.on : false,
      val: clampNum(item?.val, 0, 100000, 0),
    };
  }
  return out;
}

export function normalizeInsurance(raw) {
  const out = { ...DEFAULTS.insurance };
  const src = raw && typeof raw === 'object' ? raw : {};
  const limits = { pension: 50, medical: 50, unemployment: 50, fund: 50 };
  for (const key of INSURANCE_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(src, key) || src[key] === undefined || src[key] === null) continue;
    out[key] = clampNum(src[key], 0, limits[key], out[key]);
  }
  return out;
}

export function normalizeDeleted(raw, now = Date.now()) {
  const out = {};
  const src = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  for (const [key, value] of Object.entries(src)) {
    if (!isValidDateKey(key)) continue;
    const at = Number(value);
    if (!Number.isFinite(at) || at <= 0) continue;
    if (now - at > TOMBSTONE_TTL_MS) continue;
    out[key] = at;
  }
  return out;
}

export function validateAndNormalizeUserData(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AppError('缺少或无效的数据', 400, 'BAD_DATA');
  }
  const records = {};
  const srcRecords = raw.records && typeof raw.records === 'object' && !Array.isArray(raw.records) ? raw.records : {};
  for (const [key, value] of Object.entries(srcRecords)) {
    if (!isValidDateKey(key)) continue;
    const rec = normalizeRecord(value);
    if (rec) records[key] = rec;
  }
  const count = Object.keys(records).length;
  if (count > MAX_RECORDS) {
    throw new AppError(`记录条数超限（${count} > ${MAX_RECORDS}）`, 413, 'TOO_MANY_RECORDS');
  }
  const settings = normalizeSettings(raw.settings);
  const deductions = normalizeDeductions(raw.deductions);
  const insurance = normalizeInsurance(raw.insurance);
  const goal = clampNum(raw.goal, 0, 1000, 0);
  const dataRev = clampNum(raw.dataRev, 0, Number.MAX_SAFE_INTEGER, 0);
  const deleted = normalizeDeleted(raw.deleted);
  const cleaned = {
    schemaVersion: SCHEMA_VERSION,
    records, settings, goal, deductions, insurance, dataRev, deleted,
  };
  const serialized = JSON.stringify(cleaned);
  if (serialized.length > MAX_PAYLOAD_BYTES) {
    throw new AppError('用户数据过大', 413, 'DATA_TOO_LARGE');
  }
  return { data: cleaned, serialized };
}

/* ============ 5. GitHub 客户端（惰性迁移） ============ */
export function normalizeRepo(value) {
  const repo = String(value || '')
    .trim()
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]*\/[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(repo)) {
    throw new AppError('GITHUB_REPO 格式错误', 500, 'BAD_GITHUB_REPO');
  }
  return repo;
}
export function isStrongSecret(secret) {
  if (typeof secret !== 'string' || secret.length < 32) return false;
  const classes = [/[a-z]/.test(secret), /[A-Z]/.test(secret), /[0-9]/.test(secret), /[^A-Za-z0-9]/.test(secret)].filter(Boolean).length;
  return classes >= 3;
}
export function assertServerConfig(env) {
  if (!env.DB) throw new AppError('服务端缺少 D1 绑定 DB', 500, 'MISSING_D1_BINDING');
  if (!isStrongSecret(String(env.SESSION_SECRET || ''))) {
    throw new AppError('服务端缺少有效的 SESSION_SECRET', 500, 'MISSING_SESSION_SECRET');
  }
}
export function createGitHubClient({ repo, branch, token, fetchImpl = fetch }) {
  const base = `https://api.github.com/repos/${repo}`;
  async function request(url, options = {}) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), GITHUB_TIMEOUT_MS);
    let res;
    try {
      res = await fetchImpl(url, {
        ...options, signal: ctrl.signal,
        headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'work-clock-worker', ...(options.headers || {}) },
      });
    } catch (e) {
      if (e?.name === 'AbortError') throw new GitHubError('GitHub 请求超时', 504, { message: 'timeout' });
      throw new GitHubError(`GitHub 网络错误: ${safeErrorMessage(e)}`, 502, { message: safeErrorMessage(e) });
    } finally { clearTimeout(timer); }
    const text = await res.text();
    let body = {};
    if (text) { try { body = JSON.parse(text); } catch { body = { message: text.slice(0, 500) }; } }
    if (!res.ok) throw new GitHubError(body.message || `HTTP ${res.status}`, res.status, { message: body.message || `HTTP ${res.status}` });
    return body;
  }
  function contentUrl(path) { return `${base}/contents/${path.split('/').map(encodeURIComponent).join('/')}`; }
  return {
    async readJson(path) {
      try {
        const result = await request(`${contentUrl(path)}?ref=${encodeURIComponent(branch)}`);
        if (!result || typeof result.content !== 'string') throw new AppError(`GitHub 文件格式异常: ${path}`, 500, 'GITHUB_BAD_CONTENT');
        const decoded = decodeBase64Utf8(result.content.replace(/\s/g, ''));
        return { content: JSON.parse(decoded), sha: result.sha };
      } catch (e) {
        if (e instanceof GitHubError && e.status === 404) return null;
        if (e instanceof SyntaxError) throw new AppError(`GitHub 中的 JSON 文件损坏`, 500, 'GITHUB_BAD_JSON');
        throw e;
      }
    },
  };
}

/* ============ 6. 限流 ============ */
export function clientIp(request) {
  return request.headers.get('CF-Connecting-IP') || request.headers.get('x-real-ip') || 'unknown';
}
// 进程内兜底计数：仅当既没有 KV、也没有 rate_limits 表时使用。
// 单个 isolate 内有效，多 isolate 会放宽限制，聊胜于无（原实现是完全没有限流）。
const MEM_BUCKETS = new Map();
function memoryRateLimit(bucket, key, rule) {
  const windowId = Math.floor(Date.now() / 1000 / rule.windowSec);
  const mapKey = `${bucket}:${key}:${windowId}`;
  const count = (MEM_BUCKETS.get(mapKey) || 0) + 1;
  if (MEM_BUCKETS.size > 20000) MEM_BUCKETS.clear();
  MEM_BUCKETS.set(mapKey, count);
  if (count > rule.limit) throw rateLimitError(rule);
}
function rateLimitError(rule) {
  const nowSec = Math.floor(Date.now() / 1000);
  const retryAfter = rule.windowSec - (nowSec % rule.windowSec);
  return new AppError('操作过于频繁，请稍后再试', 429, 'RATE_LIMITED', undefined, { retryAfter });
}

export async function enforceRateLimit(env, bucket, key, rule) {
  const windowId = Math.floor(Date.now() / 1000 / rule.windowSec);

  // 1) 首选 KV：最快，且跨 isolate 一致
  if (env.WC_KV) {
    const kvKey = `rl:${bucket}:${key}:${windowId}`;
    const current = Number(await env.WC_KV.get(kvKey)) || 0;
    if (current >= rule.limit) throw rateLimitError(rule);
    await env.WC_KV.put(kvKey, String(current + 1), { expirationTtl: rule.windowSec * 2 });
    return;
  }

  // 2) 无 KV：用 D1 计数表（多 isolate 也准确）。表缺失时自动退化到内存计数。
  if (env.DB) {
    try {
      const row = await env.DB.prepare(
        `INSERT INTO rate_limits (bucket, key, window_id, count) VALUES (?, ?, ?, 1)
         ON CONFLICT(bucket, key, window_id) DO UPDATE SET count = count + 1
         RETURNING count`
      ).bind(bucket, key, windowId).first();
      const count = Number(row && row.count) || 1;
      if (count > rule.limit) throw rateLimitError(rule);
      // 顺带清理过期窗口，避免计数表无限增长（低频触发即可）
      if (count === 1 && Math.random() < 0.02) {
        try { await env.DB.prepare('DELETE FROM rate_limits WHERE window_id < ?').bind(windowId - 10).run(); } catch (e) {}
      }
      return;
    } catch (e) {
      if (e instanceof AppError) throw e;
      // rate_limits 表不存在 -> 退化
    }
  }

  // 3) 最后兜底：进程内计数
  memoryRateLimit(bucket, key, rule);
}

/* ============ 7. KV 缓存辅助 ============ */
async function kvGet(env, key) {
  if (!env.WC_KV) return null;
  try { return await env.WC_KV.get(key, { type: 'json' }); } catch (e) { return null; }
}
async function kvPut(env, key, value, ttl) {
  if (!env.WC_KV) return;
  try { await env.WC_KV.put(key, JSON.stringify(value), { expirationTtl: ttl }); } catch (e) {}
}

/* ============ 8. 惰性迁移：从 GitHub 拉到 D1 ============ */
async function ensureUserMigrated(username, env) {
  const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
  if (existing) return true;

  // 已注销的账号不能被 GitHub 备份「复活」：注销时写入 deleted 标记，这里先拦截。
  // migrations 表可能不存在，因此单独 try，失败不影响正常迁移流程。
  try {
    const banned = await env.DB.prepare("SELECT 1 AS x FROM migrations WHERE username = ? AND source = 'deleted'").bind(username).first();
    if (banned) return false;
  } catch (e) { /* 表不存在则忽略 */ }
  if (env.WC_KV) {
    try { if (await env.WC_KV.get('ban:' + username)) return false; } catch (e) {}
  }

  if (!env.GITHUB_TOKEN || !env.GITHUB_REPO) return false;

  let github;
  try {
    const repo = normalizeRepo(env.GITHUB_REPO);
    const branch = (env.GITHUB_BRANCH || DEFAULT_BRANCH).trim();
    github = createGitHubClient({ repo, branch, token: String(env.GITHUB_TOKEN).trim() });
  } catch (e) { return false; }

  let profile, dataFile;
  try {
    profile = await github.readJson(`users/${username}/profile.json`);
    dataFile = await github.readJson(`users/${username}/data.json`);
  } catch (e) { return false; }

  if (!profile || !dataFile) return false;

  const now = new Date().toISOString();
  const profileContent = profile.content || {};
  const dataContent = dataFile.content || {};
  const records = dataContent.records && typeof dataContent.records === 'object' ? dataContent.records : {};
  const deleted = dataContent.deleted && typeof dataContent.deleted === 'object' ? dataContent.deleted : {};

  const statements = [];
  statements.push(env.DB.prepare(
    `INSERT OR IGNORE INTO users (username, hash, salt, kdf, iterations, token_version, migrated_from_github, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`
  // 关键：GitHub 时代(v4) 的 profile 没有 kdf 字段，其 hash 是单轮 SHA-256(salt+password)。
  // 原实现默认成 PBKDF2，迁移后这些账号的 hash 永远对不上 -> 老用户直接登不进来。
  // 没有 kdf 就按 LEGACY 处理，登录成功后再由客户端自动升级为 PBKDF2。
  ).bind(username, profileContent.hash || '', profileContent.salt || '', profileContent.kdf || KDF_LEGACY,
    clampNum(profileContent.iterations, 100000, 2000000, resolveIterations(env)), 1, profileContent.createdAt || now, now));

  statements.push(env.DB.prepare(
    `INSERT OR IGNORE INTO user_data (username, settings, goal, deductions, insurance, data_rev, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(username, JSON.stringify(dataContent.settings || {}), clampNum(dataContent.goal, 0, 1000, 0),
    JSON.stringify(dataContent.deductions || {}), JSON.stringify(dataContent.insurance || {}), 1, Date.now()));

  let recordCount = 0;
  for (const [dateKey, rec] of Object.entries(records)) {
    if (!isValidDateKey(dateKey)) continue;
    const n = normalizeRecord(rec);
    if (!n) continue;
    statements.push(env.DB.prepare(
      `INSERT OR REPLACE INTO records (username, date_key, shift, type, leave, normal, ot, compensation, deduct_hours, note, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(username, dateKey, n.shift, n.type, n.leave, n.normal, n.ot, n.compensation, n.deductHours, n.note, n.updatedAt));
    recordCount++;
  }

  const nowTs = Date.now();
  for (const [dateKey, ts] of Object.entries(deleted)) {
    if (!isValidDateKey(dateKey)) continue;
    const at = Number(ts);
    if (!Number.isFinite(at) || at <= 0 || nowTs - at > TOMBSTONE_TTL_MS) continue;
    statements.push(env.DB.prepare(
      `INSERT OR REPLACE INTO tombstones (username, date_key, deleted_at) VALUES (?, ?, ?)`
    ).bind(username, dateKey, at));
  }

  try {
    for (let i = 0; i < statements.length; i += 50) {
      await env.DB.batch(statements.slice(i, i + 50));
    }
    return true;
  } catch (e) { return false; }
}

/* ============ 9. D1 数据操作 ============ */
// 单批语句上限：超过后退化为分片（此时无法保证原子性，但保证能写入并留下日志）
const MAX_ATOMIC_STATEMENTS = 500;

async function runAtomic(db, statements) {
  if (!statements.length) return;
  if (statements.length <= MAX_ATOMIC_STATEMENTS) {
    await db.batch(statements);           // 原子
    return;
  }
  console.warn(`[d1] 单次写入 ${statements.length} 条语句，超过原子批上限 ${MAX_ATOMIC_STATEMENTS}，改为分片提交（非原子）`);
  for (let i = 0; i < statements.length; i += MAX_ATOMIC_STATEMENTS) {
    await db.batch(statements.slice(i, i + MAX_ATOMIC_STATEMENTS));
  }
}
async function d1GetUser(username, env) {
  return await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
}

async function d1GetUserData(username, env) {
  const [userData, recordsRes, tombstonesRes] = await Promise.all([
    env.DB.prepare('SELECT * FROM user_data WHERE username = ?').bind(username).first(),
    env.DB.prepare('SELECT * FROM records WHERE username = ?').bind(username).all(),
    env.DB.prepare('SELECT * FROM tombstones WHERE username = ?').bind(username).all(),
  ]);

  const records = {};
  if (recordsRes?.results) {
    for (const row of recordsRes.results) {
      records[row.date_key] = {
        shift: row.shift, type: row.type, leave: row.leave, normal: row.normal, ot: row.ot,
        compensation: row.compensation || 'pay', deductHours: row.deduct_hours ?? 8, note: row.note, updatedAt: row.updated_at,
      };
    }
  }

  const now = Date.now();
  const deleted = {};
  if (tombstonesRes?.results) {
    for (const row of tombstonesRes.results) {
      if (now - row.deleted_at <= TOMBSTONE_TTL_MS) deleted[row.date_key] = row.deleted_at;
    }
  }

  let settings = DEFAULTS.settings, goal = DEFAULTS.goal, deductions = {}, insurance = DEFAULTS.insurance, dataRev = 0;
  if (userData) {
    try { settings = normalizeSettings(JSON.parse(userData.settings || '{}')); } catch { settings = normalizeSettings({}); }
    goal = clampNum(userData.goal, 0, 1000, DEFAULTS.goal);
    try { deductions = normalizeDeductions(JSON.parse(userData.deductions || '{}')); } catch { deductions = normalizeDeductions({}); }
    try { insurance = normalizeInsurance(JSON.parse(userData.insurance || '{}')); } catch { insurance = normalizeInsurance({}); }
    dataRev = clampNum(userData.data_rev, 0, Number.MAX_SAFE_INTEGER, 0);
  } else { deductions = normalizeDeductions({}); }

  return { schemaVersion: SCHEMA_VERSION, records, settings, goal, deductions, insurance, dataRev, deleted };
}

async function d1RegisterUser(username, hash, salt, iterations, env) {
  const now = new Date().toISOString();
  const initialSettings = JSON.stringify(DEFAULTS.settings);
  const initialDeductions = JSON.stringify(normalizeDeductions({}));
  const initialInsurance = JSON.stringify(DEFAULTS.insurance);

  try {
    await env.DB.batch([
      env.DB.prepare(`INSERT INTO users (username, hash, salt, kdf, iterations, token_version, migrated_from_github, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?, ?)`)
        .bind(username, hash, salt, KDF_PBKDF2, clampNum(iterations, 100000, 2000000, PBKDF2_ITERATIONS), now, now),
      env.DB.prepare(`INSERT INTO user_data (username, settings, goal, deductions, insurance, data_rev, updated_at) VALUES (?, ?, ?, ?, ?, 1, ?)`)
        .bind(username, initialSettings, DEFAULTS.goal, initialDeductions, initialInsurance, Date.now()),
    ]);
  } catch (e) {
    if (/UNIQUE|PRIMARY/i.test(safeErrorMessage(e))) throw new AppError('用户名已存在', 409, 'USER_EXISTS');
    throw e;
  }
}

async function d1SetData(username, incoming, prefsTouched, env, presence = {}) {
  // 1. 查出所有墓碑（防止幽灵数据复活）
  const serverTombRes = await env.DB.prepare('SELECT * FROM tombstones WHERE username = ?').bind(username).all();
  const serverDeleted = {};
  if (serverTombRes?.results) {
    for (const row of serverTombRes.results) serverDeleted[row.date_key] = row.deleted_at;
  }

  const statements = [];
  
  // 2. 写入记录 (利用 UPSERT 极速合并，同时检查墓碑)
  for (const [dateKey, rec] of Object.entries(incoming.records || {})) {
    if (serverDeleted[dateKey] && serverDeleted[dateKey] >= rec.updatedAt) continue;

    statements.push(env.DB.prepare(
      `INSERT INTO records (username, date_key, shift, type, leave, normal, ot, compensation, deduct_hours, note, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(username, date_key) DO UPDATE SET
         shift = excluded.shift, type = excluded.type, leave = excluded.leave,
         normal = excluded.normal, ot = excluded.ot, compensation = excluded.compensation,
         deduct_hours = excluded.deduct_hours,
         note = excluded.note, updated_at = excluded.updated_at
       WHERE excluded.updated_at > records.updated_at`
    ).bind(username, dateKey, rec.shift, rec.type, rec.leave, rec.normal, rec.ot,
            rec.compensation, rec.deductHours ?? 8, (rec.note || '').slice(0, MAX_NOTE_LEN), rec.updatedAt || 0));
  }

  // 3. 写入墓碑
  const now = Date.now();
  const liveDeleted = {};
  for (const [dateKey, at] of Object.entries(incoming.deleted || {})) {
    if (!isValidDateKey(dateKey)) continue;
    if (now - Number(at) > TOMBSTONE_TTL_MS) continue;
    liveDeleted[dateKey] = at;
    
    // 根据墓碑删除记录
    statements.push(env.DB.prepare(
      `DELETE FROM records WHERE username = ? AND date_key = ? AND updated_at <= ?`
    ).bind(username, dateKey, at));
  }

  // 【核心修复】：合并写入墓碑，绝不清空现有墓碑
  for (const [dateKey, at] of Object.entries(liveDeleted)) {
    statements.push(env.DB.prepare(
      `INSERT INTO tombstones (username, date_key, deleted_at) VALUES (?, ?, ?)
       ON CONFLICT(username, date_key) DO UPDATE SET deleted_at = MAX(tombstones.deleted_at, excluded.deleted_at)`
    ).bind(username, dateKey, at));
  }

  // 记录比墓碑新 = 用户删完后重新记录了这一天，墓碑已无意义，顺手清理，
  // 否则它会跟着每次 getData 回传给所有设备，长期占据同步载荷。
  for (const [dateKey, rec] of Object.entries(incoming.records || {})) {
    const at = Number(serverDeleted[dateKey]) || 0;
    if (at > 0 && Number(rec.updatedAt) > at) {
      statements.push(env.DB.prepare('DELETE FROM tombstones WHERE username = ? AND date_key = ? AND deleted_at <= ?')
        .bind(username, dateKey, rec.updatedAt));
    }
  }

  // 4. 更新用户数据（原子自增 dataRev）
  if (prefsTouched) {
    // 只覆盖客户端本次真正提交的偏好字段。
    // 原实现无条件写入全部字段：客户端未携带 deductions / insurance 时，
    // 归一化会补成默认值并覆盖库中已存数据 -> 保存一次设置就把专项扣除、五险一金清零。
    const cur = await env.DB.prepare('SELECT settings, goal, deductions, insurance FROM user_data WHERE username = ?')
      .bind(username).first();
    const pres = presence || {};
    const nextSettings = pres.settings ? JSON.stringify(incoming.settings) : (cur?.settings ?? JSON.stringify(DEFAULTS.settings));
    const nextGoal = pres.goal ? incoming.goal : (cur?.goal ?? DEFAULTS.goal);
    const nextDeductions = pres.deductions ? JSON.stringify(incoming.deductions) : (cur?.deductions ?? '{}');
    const nextInsurance = pres.insurance ? JSON.stringify(incoming.insurance) : (cur?.insurance ?? '{}');
    // 用 UPSERT 而不是 UPDATE：user_data 行缺失时（例如老数据迁移、手工清过表），
    // UPDATE 会静默影响 0 行，表现为"设置怎么存都存不上"。
    statements.push(env.DB.prepare(
      `INSERT INTO user_data (username, settings, goal, deductions, insurance, data_rev, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, ?)
       ON CONFLICT(username) DO UPDATE SET
         settings = excluded.settings, goal = excluded.goal,
         deductions = excluded.deductions, insurance = excluded.insurance,
         data_rev = user_data.data_rev + 1, updated_at = excluded.updated_at`
    ).bind(username, nextSettings, nextGoal, nextDeductions, nextInsurance, Date.now()));
  } else {
    statements.push(env.DB.prepare(
      'UPDATE user_data SET data_rev = data_rev + 1, updated_at = ? WHERE username = ?'
    ).bind(Date.now(), username));
  }

  // 单批提交：D1 的 batch() 在单个事务里执行，全部成功或全部回滚。
  // 原实现按 50 条切片，中途失败会留下"记录已写、dataRev 未自增"这类半套状态。
  await runAtomic(env.DB, statements);

  const finalData = await d1GetUserData(username, env);
  return { data: finalData, droppedCount: 0, deduped: true };
}

/* ============ 10. 鉴权动作 ============ */
export function validateUsername(username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    throw new AppError('用户名需为 3-32 位，只能包含字母、数字、下划线和连字符', 400, 'BAD_USERNAME');
  }
}
export function validateHash(hash) {
  if (typeof hash !== 'string' || !HASH_RE.test(hash)) throw new AppError('密码哈希格式错误', 400, 'BAD_HASH');
}
export function validateSalt(salt) {
  if (typeof salt !== 'string' || salt.length < 22 || salt.length > 128 || !/^[A-Za-z0-9+/=_-]+$/.test(salt)) {
    throw new AppError('salt 格式错误', 400, 'BAD_SALT');
  }
}

export async function handleGetSalt({ username, env }) {
  validateUsername(username);
  let user = await d1GetUser(username, env);
  if (!user) {
    // 关键：老账号可能还躺在 GitHub 备份里，getSalt 必须先尝试迁移，
    // 否则会返回"伪 salt"，客户端算出的 hash 永远对不上 —— 首次登录必然失败。
    if (await ensureUserMigrated(username, env)) user = await d1GetUser(username, env);
  }
  if (user) return { salt: user.salt, kdf: user.kdf || KDF_LEGACY, iterations: Number(user.iterations) || 0 };
  const pseudo = await hmacSign(`pseudo-salt:${username}`, env.SESSION_SECRET);
  return { salt: base64UrlEncode(pseudo.subarray(0, 16)), kdf: KDF_PBKDF2, iterations: resolveIterations(env) };
}

export async function handleLogin({ username, hash, newHash, newSalt, env }) {
  validateUsername(username);
  validateHash(hash);
  await ensureUserMigrated(username, env);
  const user = await d1GetUser(username, env);
  if (!user) throw new AppError('用户名未注册，请先注册', 404, 'USER_NOT_FOUND');
  
  if (!constantTimeEqual(hash, user.hash)) throw new AppError('密码错误', 401, 'BAD_CREDENTIALS');

  // ALLOW_LEGACY_WRITES：是否允许登录时把旧密码格式自动升级为 PBKDF2。
  // 默认允许（升级本身是安全增强）；显式设为 "false" 可关闭。
  const allowUpgrade = String(env.ALLOW_LEGACY_WRITES === undefined ? 'true' : env.ALLOW_LEGACY_WRITES) !== 'false';
  if (allowUpgrade && user.kdf !== KDF_PBKDF2 && newHash && newSalt) {
    try {
      validateHash(newHash); validateSalt(newSalt);
      await env.DB.prepare(`UPDATE users SET hash = ?, salt = ?, kdf = ?, iterations = ?, updated_at = ? WHERE username = ?`)
        .bind(newHash, newSalt, KDF_PBKDF2, resolveIterations(env), new Date().toISOString(), username).run();
    } catch (e) { console.warn(`KDF upgrade failed: ${safeErrorMessage(e)}`); }
  }

  const token = await createSessionToken(username, env.SESSION_SECRET, Number(user.token_version) || 1);
  return { token, expiresIn: SESSION_TTL_SECONDS, createdAt: user.created_at || null };
}

export async function handleRegister({ username, hash, salt, iterations, env }) {
  validateUsername(username);
  validateHash(hash);
  validateSalt(salt);
  // 迭代次数一律由服务端配置决定，客户端自报的 iterations 不再生效。
  // 这样 PASSWORD_ITERATIONS 才是唯一真相（原实现里前端硬编码 600000，配置改了也没用），
  // 同时也避免有人注册一个只用 100000 轮的弱哈希账号。
  void iterations;
  await d1RegisterUser(username, hash, salt, resolveIterations(env), env);
  return { status: 201 };
}

export async function handleChangePassword({ username, oldHash, newHash, newSalt, env }) {
  validateHash(oldHash);
  validateHash(newHash);
  validateSalt(newSalt);
  const user = await d1GetUser(username, env);
  if (!user) throw new AppError('账号不存在或已注销', 404, 'USER_NOT_FOUND');
  if (!constantTimeEqual(oldHash, user.hash)) {
    throw new AppError('当前密码不正确', 401, 'BAD_CREDENTIALS');
  }
  if (constantTimeEqual(newHash, user.hash)) {
    throw new AppError('新密码不能与当前密码相同', 400, 'SAME_PASSWORD');
  }
  // token_version + 1：让所有旧 token 立刻失效（配合 requireSession 的校验）
  await env.DB.prepare(
    `UPDATE users SET hash = ?, salt = ?, kdf = ?, iterations = ?, token_version = token_version + 1, updated_at = ?
     WHERE username = ?`
  ).bind(newHash, newSalt, KDF_PBKDF2, resolveIterations(env), new Date().toISOString(), username).run();
  return { success: true, reauth: true };
}

/* ============ 11. 数据动作 ============ */
export async function handleGetData({ username, env }) {
  const userExists = await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first();
  if (!userExists) throw new AppError('账号不存在或已注销', 404, 'USER_NOT_FOUND');

  const kvKey = `data:${username}`;
  const cached = await kvGet(env, kvKey);
  if (cached?.data && cached._ts && Date.now() - cached._ts < KV_CACHE_TTL_MS) {
    return { data: cached.data, source: 'kv' };
  }

  await ensureUserMigrated(username, env);
  const data = await d1GetUserData(username, env);
  await kvPut(env, kvKey, { _ts: Date.now(), data }, KV_EXPIRE_SECONDS);
  return { data, source: 'd1', degraded: false };
}

export async function handleSetData({ username, incoming, settingsTouched = false, presence = {}, env }) {
  const userExists = await env.DB.prepare('SELECT 1 FROM users WHERE username = ?').bind(username).first();
  if (!userExists) throw new AppError('账号不存在或已注销', 404, 'USER_NOT_FOUND');

  const result = await d1SetData(username, incoming, settingsTouched === true, env, presence);
  
  if (env.WC_KV && result.data) {
    try { await env.WC_KV.put(`data:${username}`, JSON.stringify({ _ts: Date.now(), data: result.data }), { expirationTtl: KV_EXPIRE_SECONDS }); } catch (e) {}
  }
  return result;
}

/**
 * 清空某用户的全部打卡记录（云端同步删除）。
 * 为什么不复用 setData + 墓碑：清空 100+ 天需要 100+ 条墓碑，
 * 载荷大、容易超时，而且无法清掉"本地不知道、服务端却有"的残留记录。
 */
export async function handleClearData({ username, env }) {
  const statements = [
    env.DB.prepare('DELETE FROM records WHERE username = ?').bind(username),
    env.DB.prepare('DELETE FROM tombstones WHERE username = ?').bind(username),
  ];
  const cur = await env.DB.prepare('SELECT settings, data_rev FROM user_data WHERE username = ?').bind(username).first();
  if (cur) {
    // 同时把薪资/税费参数归零，否则清空后客户端一同步又把旧时薪、底薪带回来。
    // 保留 mode（时薪制/月薪制）与计薪天数、每日工时这类结构性参数。
    let settings = {};
    try { settings = JSON.parse(cur.settings || '{}'); } catch (e) { settings = {}; }
    settings.normalRate = 0;
    settings.holidayRate = 0;
    settings.baseSalary = 0;
    settings.performance = 0;
    settings.taxSpecial = {};
    settings.insuranceSalary = { pension: 0, medical: 0, unemployment: 0, fund: 0 };
    statements.push(env.DB.prepare(
      'UPDATE user_data SET settings = ?, insurance = ?, data_rev = data_rev + 1, updated_at = ? WHERE username = ?'
    ).bind(JSON.stringify(settings), JSON.stringify({ pension: 0, medical: 0, unemployment: 0, fund: 0 }), Date.now(), username));
  }
  await runAtomic(env.DB, statements);
  const data = await d1GetUserData(username, env);
  // KV 里可能还缓存着清空前的数据，必须失效
  if (env.WC_KV) {
    try { await env.WC_KV.delete('data:' + username); } catch (e) {}
  }
  return { data };
}

export async function handleDeleteUser({ username, env }) {
  // 逐表删除：原实现用一次 batch，只要其中一张表不存在（例如 migrations），
  // 整个 batch 回滚，表现为「注销账号」直接 500，账号永远删不掉。
  const failed = [];
  for (const table of ['records', 'tombstones', 'user_data', 'users']) {
    try {
      await env.DB.prepare(`DELETE FROM ${table} WHERE username = ?`).bind(username).run();
    } catch (e) {
      failed.push(table + ':' + safeErrorMessage(e));
    }
  }

  // 写入注销标记，阻止 GitHub 备份在下次登录时把账号复活。
  let marked = false;
  try {
    await env.DB.prepare("INSERT OR REPLACE INTO migrations (username, source) VALUES (?, 'deleted')").bind(username).run();
    marked = true;
  } catch (e) { /* migrations 表不存在 */ }
  if (env.WC_KV) {
    try {
      await env.WC_KV.put('ban:' + username, '1');
      await env.WC_KV.delete(`data:${username}`);
      await env.WC_KV.delete(`sha:${username}`);
      await env.WC_KV.delete(`hash:${username}`);
    } catch (e) {}
  }

  if (failed.length) {
    // 有表清理失败时明确报错，避免"看起来注销成功、实际数据仍在"
    throw new AppError('账号数据清理不完整，请稍后重试', 500, 'DELETE_INCOMPLETE', failed.join('; '));
  }
  return { success: true, banMarker: marked };
}

export async function handleHealth({ env }) {
  // config 原来写死为 'ok'，看不出 SESSION_SECRET 强度不足 / 缺 DB 绑定这类问题，
  // 这里改成真实体检：哪一项不满足直接列出来，便于部署后自查。
  const configErrors = [];
  if (!env.DB) configErrors.push('缺少 D1 绑定 DB');
  if (!isStrongSecret(String(env.SESSION_SECRET || ''))) {
    configErrors.push('SESSION_SECRET 缺失或强度不足（需 ≥32 位且含 3 类以上字符）');
  }
  if (env.GITHUB_TOKEN && !env.GITHUB_REPO) configErrors.push('配置了 GITHUB_TOKEN 但缺少 GITHUB_REPO');

  const deps = {
    config: configErrors.length ? 'error' : 'ok',
    d1: env.DB ? 'unknown' : 'missing',
    kv: env.WC_KV ? 'configured' : 'absent',
    github: env.GITHUB_TOKEN && env.GITHUB_REPO ? 'configured' : 'absent',
    iterations: resolveIterations(env),
    origins: String(env.ALLOWED_ORIGINS || DEFAULT_ORIGIN),
    version: APP_VERSION,
    features: FEATURES,
  };
  if (configErrors.length) deps.configErrors = configErrors;

  if (env.DB) {
    try {
      await env.DB.prepare('SELECT 1').first();
      deps.d1 = 'ok';
    } catch (e) {
      deps.d1 = 'error';
      deps.d1Error = safeErrorMessage(e);
    }
  }
  // 表是否建好：D1 连通但没跑 schema.sql 时，接口会返回 500（no such table），
  // 这里单独探一张表，把问题直接定位到"没建表"而不是含糊的 INTERNAL_ERROR。
  if (deps.d1 === 'ok') {
    try {
      await env.DB.prepare('SELECT 1 FROM users LIMIT 1').first();
      deps.schema = 'ok';
    } catch (e) {
      deps.schema = 'missing';
      deps.schemaError = safeErrorMessage(e);
    }
  }
  const healthy = deps.d1 === 'ok' && deps.schema === 'ok' && configErrors.length === 0;
  return { payload: { success: healthy, deps }, status: healthy ? 200 : 503 };
}

/* ============ 12. CORS / 安全响应头 ============ */
const SECURITY_HEADERS = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': 'geolocation=(), microphone=(), camera=(), payment=()',
});
export function getCorsHeaders(request, env) {
  const origin = request.headers.get('Origin');
  const configured = String(env.ALLOWED_ORIGINS || DEFAULT_ORIGIN).split(',').map((v) => v.trim()).filter(Boolean);
  const wildcard = configured.includes('*');
  const isBrowserRequest = Boolean(origin);
  const allowed = !isBrowserRequest || wildcard || configured.includes(origin);
  const headers = {
    ...SECURITY_HEADERS,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Expose-Headers': 'X-Refresh-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin, Access-Control-Request-Headers',
    'Cache-Control': 'no-store',
  };
  if (allowed && isBrowserRequest) headers['Access-Control-Allow-Origin'] = wildcard ? '*' : origin;
  return { allowed, headers, isBrowserRequest, wildcard };
}

/* ============ 13. 错误映射 ============ */
export function mapError(error) {
  if (error instanceof AppError) {
    return { status: error.status, code: error.code, message: error.message, clientDetail: error.detail, logDetail: error.detail, extra: error.extra };
  }
  if (error instanceof GitHubError) {
    return { status: 502, code: 'GITHUB_API_ERROR', message: 'GitHub API 请求失败', logDetail: `githubStatus=${error.status} ${error.message}` };
  }
  // 把常见的 D1 故障翻译成可执行的提示，避免前端只收到一句"服务器内部错误"。
  const msg = safeErrorMessage(error);
  if (/no such table/i.test(msg)) {
    return { status: 500, code: 'SCHEMA_MISSING', message: '数据库表未创建：请执行 schema.sql 后再试', logDetail: msg };
  }
  if (/no such column/i.test(msg)) {
    return { status: 500, code: 'SCHEMA_OUTDATED', message: '数据库表结构过期：请重新执行 schema.sql', logDetail: msg };
  }
  if (/D1_ERROR|SQLITE_|database is locked/i.test(msg)) {
    return { status: 500, code: 'D1_ERROR', message: '数据库繁忙或出错，请稍后重试', logDetail: msg };
  }
  // 把 D1 类错误的原文回给客户端一小段，方便不进 wrangler tail 也能定位（如 no such column）
  const clientDetail = /no such|SQLITE|D1_ERROR|constraint/i.test(msg) ? msg.slice(0, 240) : undefined;
  return { status: 500, code: 'INTERNAL_ERROR', message: '服务器内部错误', clientDetail, logDetail: msg };
}

/* ============ 14. 入口 ============ */
export default {
  async fetch(request, env) {
    const cors = getCorsHeaders(request, env);
    if (request.method === 'OPTIONS') {
      if (!cors.allowed) return jsonResponse({ error: '不允许的来源' }, 403, cors.headers);
      return new Response(null, { status: 204, headers: cors.headers });
    }
    if (!cors.allowed) return jsonResponse({ error: '不允许的来源' }, 403, cors.headers);
    if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405, cors.headers);

    let action = '-', username = '';
    try {
      let payload;
      try { payload = await request.json(); } catch { throw new AppError('请求体格式错误', 400, 'BAD_JSON'); }

      action = typeof payload?.action === 'string' ? payload.action : '';
      username = typeof payload?.username === 'string' ? payload.username : '';
      if (!action) throw new AppError('缺少 action', 400, 'MISSING_ACTION');

      const tag = await userLogTag(username, env.SESSION_SECRET || 'no-secret');
      console.log(`[${action}] user=${tag}`);

      if (action === 'health') {
        const { payload: body, status } = await handleHealth({ env });
        return jsonResponse(body, status, cors.headers);
      }

      assertServerConfig(env);

      const ip = clientIp(request);
      switch (action) {
        case 'getSalt': case 'login': case 'changePassword':
          await enforceRateLimit(env, 'auth', ip, RATE_RULES.auth);
          await enforceRateLimit(env, 'authu', `${ip}|${username}`, RATE_RULES.authUser);
          break;
        case 'register':
          await enforceRateLimit(env, 'reg', ip, RATE_RULES.register);
          break;
        case 'setData': case 'deleteUser': case 'clearData':
          await enforceRateLimit(env, 'write', ip, RATE_RULES.write);
          break;
        case 'getData':
          await enforceRateLimit(env, 'read', ip, RATE_RULES.read);
          break;
      }

      switch (action) {
        case 'getSalt': {
          const result = await handleGetSalt({ username, env });
          return jsonResponse({ success: true, ...result }, 200, cors.headers);
        }
        case 'register': {
          const { status } = await handleRegister({ username, hash: payload.hash, salt: payload.salt, iterations: payload.iterations, env });
          return jsonResponse({ success: true }, status, cors.headers);
        }
        case 'login': {
          const result = await handleLogin({ username, hash: payload.hash, newHash: payload.newHash, newSalt: payload.newSalt, env });
          const resp = { success: true, username, createdAt: result.createdAt, token: result.token, expiresIn: result.expiresIn };
          // 客户端带 withData 时，登录响应里直接带上用户数据：
          // 少一次往返（弱网下约省 200~800ms），失败则忽略、客户端会自行再拉。
          if (payload.withData === true) {
            try {
              const got = await handleGetData({ username, env });
              if (got && got.data) resp.data = got.data;
            } catch (e) { /* 忽略，客户端会回退到 getData */ }
          }
          return jsonResponse(resp, 200, cors.headers);
        }
        case 'getData': {
          const session = await requireSession(request, username, env);
          username = session.username;
          const { data, degraded } = await handleGetData({ username, env });
          const headers = await maybeAttachRefreshToken(session, { ...cors.headers }, env);
          return jsonResponse(degraded ? { ...data, _degraded: true } : data, 200, headers);
        }
        case 'setData': {
          const session = await requireSession(request, username, env);
          username = session.username;
          const rawData = payload.data && typeof payload.data === 'object' ? payload.data : {};
          const { data: incoming } = validateAndNormalizeUserData(rawData);
          // 记录客户端本次真正提交了哪些偏好字段（用于服务端局部合并）
          const presence = {
            settings: Object.prototype.hasOwnProperty.call(rawData, 'settings'),
            goal: Object.prototype.hasOwnProperty.call(rawData, 'goal'),
            deductions: Object.prototype.hasOwnProperty.call(rawData, 'deductions'),
            insurance: Object.prototype.hasOwnProperty.call(rawData, 'insurance'),
          };
          const result = await handleSetData({ username, incoming, settingsTouched: payload.settingsTouched === true, presence, env });
          const headers = await maybeAttachRefreshToken(session, { ...cors.headers }, env);
          return jsonResponse({ success: true, dataRev: result.data.dataRev, data: result.data, droppedCount: result.droppedCount || 0 }, 200, headers);
        }
        case 'changePassword': {
          const session = await requireSession(request, username, env);
          username = session.username;
          const result = await handleChangePassword({
            username, oldHash: payload.oldHash, newHash: payload.newHash, newSalt: payload.newSalt, env,
          });
          // 旧 token 已随 token_version 失效，响应里不再下发新 token，客户端应重新登录
          return jsonResponse({ success: true, reauth: result.reauth === true }, 200, cors.headers);
        }
        case 'clearData': {
          const session = await requireSession(request, username, env);
          username = session.username;
          const result = await handleClearData({ username, env });
          const headers = await maybeAttachRefreshToken(session, { ...cors.headers }, env);
          return jsonResponse({ success: true, data: result.data }, 200, headers);
        }
        case 'deleteUser': {
          const session = await requireSession(request, username, env);
          username = session.username;
          await handleDeleteUser({ username, env });
          return jsonResponse({ success: true }, 200, cors.headers);
        }
        default:
          throw new AppError('无效的 action', 400, 'INVALID_ACTION');
      }
    } catch (error) {
      const mapped = mapError(error);
      console.error(`request failed action=${action} code=${mapped.code} status=${mapped.status} message=${mapped.message}` + (mapped.logDetail ? ` detail=${mapped.logDetail}` : ''));
      const body = { error: mapped.message, code: mapped.code };
      if (mapped.clientDetail) body.detail = mapped.clientDetail;
      const headers = { ...cors.headers };
      if (mapped.extra?.retryAfter) headers['Retry-After'] = String(mapped.extra.retryAfter);
      return jsonResponse(body, mapped.status, headers);
    }
  },
};