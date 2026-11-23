// Cookie Sync 后端：Cloudflare Worker + D1
// 环境变量：UUID（路径前缀，Secret）、S_PW（登录密码，Secret）、URL_302（非法访问跳转地址，变量）
// D1 绑定变量名：cookie_sync_db。数据库表与索引由 ensureDb() 自动创建，无需手动执行 SQL。
// 源码仅使用 ASCII 与 UTF-8 中文字符串，页面脚本内不使用反斜杠正则，避免模板字符串转义问题。

const SESSION_COOKIE = 'cs_session';
const SESSION_TTL = 365 * 24 * 60 * 60; // 会话有效期 1 年（秒），同时用于令牌过期时间与 Cookie Max-Age
const SAMESITE = ['no_restriction', 'lax', 'strict', 'unspecified'];
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)*[a-z0-9-]{1,63}$/;
const NAME_RE = /^[^\x00-\x1f\x7f;=]{0,4096}$/; // 放宽：允许空名、中文与 RFC 7230 token 之外的字符；仅禁止控制字符、分号和等号
const VALUE_RE = /^[^\r\n;]{0,4096}$/;
const MAX_BATCH = 2000;
const UPSERT_SQL = 'INSERT INTO cookies (domain,name,value,path,secure,httpOnly,sameSite,expirationDate,comment,hostOnly,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?) ' +
  'ON CONFLICT(domain,name,path,comment) DO UPDATE SET value=excluded.value, secure=excluded.secure, httpOnly=excluded.httpOnly, sameSite=excluded.sameSite, expirationDate=excluded.expirationDate, hostOnly=excluded.hostOnly, updated_at=excluded.updated_at';
const enc = new TextEncoder();

// 每个 Worker 实例只执行一次建表；失败后清空缓存，下次请求重试。
let dbReady = null;

function ensureDb(env) {
  if (!dbReady) {
    dbReady = initDb(env.cookie_sync_db).catch((err) => {
      dbReady = null;
      throw err;
    });
  }
  return dbReady;
}

async function initDb(db) {
  await db.prepare(
    'CREATE TABLE IF NOT EXISTS cookies (' +
    'id INTEGER PRIMARY KEY AUTOINCREMENT,' +
    'domain TEXT NOT NULL,' +
    'name TEXT NOT NULL,' +
    "value TEXT NOT NULL DEFAULT ''," +
    "path TEXT NOT NULL DEFAULT '/'," +
    'secure INTEGER NOT NULL DEFAULT 0,' +
    'httpOnly INTEGER NOT NULL DEFAULT 0,' +
    "sameSite TEXT NOT NULL DEFAULT 'unspecified'," +
    'expirationDate REAL,' +
    "comment TEXT NOT NULL DEFAULT ''," +
    'hostOnly INTEGER NOT NULL DEFAULT 0,' +
    'updated_at INTEGER NOT NULL,' +
    'UNIQUE (domain, name, path, comment))'
  ).run();
  // 老版本表可能没有 hostOnly 列，补齐。
  const info = await db.prepare('PRAGMA table_info(cookies)').all();
  const cols = (info.results || []).map((c) => c.name);
  if (!cols.includes('hostOnly')) {
    await db.prepare('ALTER TABLE cookies ADD COLUMN hostOnly INTEGER NOT NULL DEFAULT 0').run();
  }
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_cookies_domain_comment ON cookies (domain, comment)').run();
  await db.prepare('CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies (domain)').run();
}

export default {
  async fetch(request, env) {
    try {
      return await route(request, env);
    } catch (err) {
      // 不记录请求体与 Cookie 内容。
      return json({ error: '服务器内部错误' }, 500);
    }
  },
};

async function route(request, env) {
  const uuid = (env.UUID || '').trim();
  if (!uuid) return json({ error: '未配置 UUID 环境变量' }, 500);
  const url = new URL(request.url);
  const p = trimSlash(url.pathname);
  const prefix = '/' + uuid;
  if (p !== prefix && !p.startsWith(prefix + '/')) return redirectOut(env);
  const sub = p.slice(prefix.length) || '/';
  const m = request.method;
  if (sub === '/' && (m === 'GET' || m === 'HEAD')) return html(PAGE);
  if (sub === '/login' && m === 'POST') return login(request, env, prefix);
  if (sub === '/logout' && m === 'POST') return logout(prefix);
  if (sub.startsWith('/api/')) return api(request, env, url, sub);
  return redirectOut(env);
}

function trimSlash(s) {
  let x = s;
  while (x.length > 1 && x.charAt(x.length - 1) === '/') x = x.slice(0, -1);
  return x;
}

function redirectOut(env) {
  return Response.redirect(env.URL_302 || 'https://www.google.com', 302);
}

function json(obj, status = 200, headers = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });
}

function html(body) {
  return new Response(body, {
    status: 200,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    },
  });
}

function safeEq(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const x = enc.encode(a), y = enc.encode(b);
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

async function sign(secret, msg) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const buf = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function makeToken(env) {
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  return exp + '.' + (await sign(env.S_PW, 'cs-session:' + exp));
}

async function validToken(env, token) {
  if (!env.S_PW || !token) return false;
  const parts = token.split('.');
  const exp = parts[0], sig = parts[1];
  if (!/^\d+$/.test(exp || '') || Number(exp) < Date.now() / 1000) return false;
  return safeEq(sig, await sign(env.S_PW, 'cs-session:' + exp));
}

function getCookie(request, name) {
  const h = request.headers.get('Cookie') || '';
  for (const part of h.split(';')) {
    const idx = part.indexOf('=');
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return '';
}

async function isAuthed(request, env) {
  if (!env.S_PW) return false;
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Bearer ') && safeEq(auth.slice(7).trim(), env.S_PW)) return true;
  if (safeEq(request.headers.get('X-Password') || '', env.S_PW)) return true;
  return validToken(env, getCookie(request, SESSION_COOKIE));
}

function sessionCookie(value, path, maxAge) {
  return SESSION_COOKIE + '=' + value + '; Path=' + path + '; Max-Age=' + maxAge + '; HttpOnly; Secure; SameSite=Strict';
}

async function login(request, env, prefix) {
  let pw = '';
  try {
    const body = await request.json();
    pw = String(body.password || '');
  } catch (e) {
    return json({ error: '请求格式错误' }, 400);
  }
  if (!env.S_PW || !safeEq(pw, env.S_PW)) {
    await new Promise((r) => setTimeout(r, 800));
    return json({ error: '密码错误' }, 401);
  }
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(await makeToken(env), prefix, SESSION_TTL) });
}

function logout(prefix) {
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', prefix, 0) });
}

function normDomain(d) {
  const x = String(d == null ? '' : d).trim().toLowerCase().replace(/^\.+/, '');
  return DOMAIN_RE.test(x) ? x : null;
}

function likeArg(s) {
  return '%' + String(s).replace(/[\\%_]/g, (c) => '\\' + c) + '%';
}

// 校验并规范化单条记录。前缀规则：
// __Host-：必须 secure、path=/、仅主机（不能带 domain 属性）；__Secure-：必须 secure；SameSite=None 必须 secure。
function validateRecord(r) {
  if (!r || typeof r !== 'object') return { ok: false, error: '记录格式错误' };
  const name = String(r.name == null ? '' : r.name);
  if (!NAME_RE.test(name)) return { ok: false, error: 'Cookie 名称不合法（不能包含控制字符、分号或等号，长度不超过 4096）：' + JSON.stringify(name).slice(0, 120) };
  const value = r.value == null ? '' : String(r.value);
  if (!VALUE_RE.test(value)) return { ok: false, error: 'Cookie 值不合法（不能包含换行或分号，长度不超过 4096）' };
  let path = r.path == null || r.path === '' ? '/' : String(r.path);
  if (!path.startsWith('/') || path.length > 512 || /[\r\n;]/.test(path)) return { ok: false, error: 'Cookie 路径不合法' };
  const sameSite = r.sameSite == null || r.sameSite === '' ? 'unspecified' : String(r.sameSite);
  if (!SAMESITE.includes(sameSite)) return { ok: false, error: 'SameSite 取值不合法' };
  let expirationDate = null;
  if (r.expirationDate != null && r.expirationDate !== '') {
    expirationDate = Number(r.expirationDate);
    if (!Number.isFinite(expirationDate) || expirationDate <= 0) return { ok: false, error: '过期时间不合法' };
    expirationDate = Math.floor(expirationDate);
  }
  let secure = !!r.secure;
  let hostOnly = !!r.hostOnly;
  const httpOnly = !!r.httpOnly;
  if (name.startsWith('__Host-')) { secure = true; path = '/'; hostOnly = true; }
  if (name.startsWith('__Secure-')) secure = true;
  if (sameSite === 'no_restriction') secure = true;
  return {
    ok: true, name, value, path, sameSite, expirationDate,
    secure: secure ? 1 : 0,
    httpOnly: httpOnly ? 1 : 0,
    hostOnly: hostOnly ? 1 : 0,
  };
}

async function readJson(request) {
  try { return await request.json(); } catch (e) { return null; }
}

function toApi(r) {
  return { ...r, secure: !!r.secure, httpOnly: !!r.httpOnly, hostOnly: !!r.hostOnly };
}

async function api(request, env, url, sub) {
  if (!(await isAuthed(request, env))) return json({ error: '未登录或密码错误' }, 401);
  if (!env.cookie_sync_db) return json({ error: '未绑定 D1 数据库（变量名应为 cookie_sync_db）' }, 500);
  await ensureDb(env);
  const db = env.cookie_sync_db;
  const m = request.method;

  if (sub === '/api/session' && m === 'GET') return json({ ok: true });

  if (sub === '/api/domains' && m === 'GET') {
    const { results } = await db.prepare('SELECT domain, comment, COUNT(*) AS count FROM cookies GROUP BY domain, comment ORDER BY domain, comment').all();
    return json({ domains: results });
  }

  if (sub === '/api/cookies' && m === 'GET') {
    const where = [];
    const args = [];
    const fuzzy = url.searchParams.get('fuzzy') === '1';
    const d = (url.searchParams.get('domain') || '').trim();
    const c = (url.searchParams.get('comment') || '').trim().slice(0, 200);
    const n = (url.searchParams.get('name') || '').trim().slice(0, 256);
    if (d) {
      if (fuzzy) {
        where.push("domain LIKE ? ESCAPE '\\'");
        args.push(likeArg(d.toLowerCase()));
      } else {
        const dom = normDomain(d);
        if (!dom) return json({ error: '域名格式不正确' }, 400);
        where.push('domain = ?');
        args.push(dom);
      }
    }
    if (c) {
      if (fuzzy) {
        where.push("comment LIKE ? ESCAPE '\\'");
        args.push(likeArg(c));
      } else {
        where.push('comment = ?');
        args.push(c);
      }
    }
    if (n) {
      where.push("name LIKE ? ESCAPE '\\'");
      args.push(likeArg(n));
    }
    const sql = 'SELECT id, domain, name, value, path, secure, httpOnly, sameSite, expirationDate, comment, hostOnly, updated_at FROM cookies' +
      (where.length ? ' WHERE ' + where.join(' AND ') : '') + ' ORDER BY domain, comment, name, path LIMIT 5000';
    const { results } = await db.prepare(sql).bind(...args).all();
    return json({ cookies: results.map(toApi) });
  }

  // 批量写入。body: { comment, replace?: boolean, records: [{ domain, hostOnly, name, value, path, secure, httpOnly, sameSite, expirationDate }] }
  // replace=true 时，先删除本次涉及的 (domain, comment) 下的旧记录，再写入，保证云端与浏览器一致。
  if (sub === '/api/cookies' && m === 'POST') {
    const body = await readJson(request);
    if (!body || typeof body !== 'object') return json({ error: '请求体不是合法 JSON' }, 400);
    const comment = typeof body.comment === 'string' ? body.comment.slice(0, 200) : '';
    const list = Array.isArray(body.records) ? body.records : [];
    if (!list.length) return json({ error: '没有可保存的记录' }, 400);
    if (list.length > MAX_BATCH) return json({ error: '单次最多保存 ' + MAX_BATCH + ' 条' }, 400);
    const now = Math.floor(Date.now() / 1000);
    const stmts = [];
    const domains = new Set();
    for (const raw of list) {
      const dom = normDomain(raw && raw.domain);
      if (!dom) return json({ error: '域名格式不正确：' + (raw && raw.domain) }, 400);
      const rec = validateRecord(raw);
      if (!rec.ok) return json({ error: rec.error }, 400);
      domains.add(dom);
      stmts.push(db.prepare(UPSERT_SQL).bind(dom, rec.name, rec.value, rec.path, rec.secure, rec.httpOnly, rec.sameSite, rec.expirationDate, comment, rec.hostOnly, now));
    }
    if (body.replace === true) {
      for (const dom of domains) {
        stmts.unshift(db.prepare('DELETE FROM cookies WHERE domain = ? AND comment = ?').bind(dom, comment));
      }
    }
    await db.batch(stmts);
    return json({ ok: true, saved: list.length });
  }

  // 批量删除。body: { ids: [number] }
  if (sub === '/api/cookies/batch-delete' && m === 'POST') {
    const body = await readJson(request);
    const ids = body && Array.isArray(body.ids) ? body.ids.map(Number) : [];
    if (!ids.length) return json({ error: '未选择任何记录' }, 400);
    if (ids.length > MAX_BATCH || ids.some((x) => !Number.isInteger(x) || x <= 0)) return json({ error: '记录编号不合法' }, 400);
    const stmts = ids.map((id) => db.prepare('DELETE FROM cookies WHERE id = ?').bind(id));
    const results = await db.batch(stmts);
    let deleted = 0;
    for (const r of results) deleted += (r.meta && r.meta.changes) || 0;
    return json({ ok: true, deleted });
  }

  const idMatch = sub.match(/^\/api\/cookies\/(\d+)$/);
  if (idMatch && m === 'PUT') {
    const body = await readJson(request);
    if (!body || typeof body !== 'object') return json({ error: '请求体不是合法 JSON' }, 400);
    const rec = validateRecord(body);
    if (!rec.ok) return json({ error: rec.error }, 400);
    const now = Math.floor(Date.now() / 1000);
    const r = await db.prepare('UPDATE cookies SET value=?, path=?, secure=?, httpOnly=?, sameSite=?, expirationDate=?, hostOnly=?, updated_at=? WHERE id=?')
      .bind(rec.value, rec.path, rec.secure, rec.httpOnly, rec.sameSite, rec.expirationDate, rec.hostOnly, now, Number(idMatch[1])).run();
    return json({ ok: true, updated: r.meta.changes });
  }

  if (sub === '/api/cookies' && m === 'DELETE') {
    const id = url.searchParams.get('id');
    if (id) {
      if (!/^\d+$/.test(id)) return json({ error: '记录编号不合法' }, 400);
      const r = await db.prepare('DELETE FROM cookies WHERE id = ?').bind(Number(id)).run();
      return json({ ok: true, deleted: r.meta.changes });
    }
    const dom = normDomain(url.searchParams.get('domain') || '');
    if (!dom) return json({ error: '域名格式不正确' }, 400);
    const c = url.searchParams.get('comment');
    const r = c === null
      ? await db.prepare('DELETE FROM cookies WHERE domain = ?').bind(dom).run()
      : await db.prepare('DELETE FROM cookies WHERE domain = ? AND comment = ?').bind(dom, c.slice(0, 200)).run();
    return json({ ok: true, deleted: r.meta.changes });
  }

  return json({ error: '接口不存在' }, 404);
}

const PAGE = `<!doctype html>
<html lang="zh-CN" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cookie 同步 · 管理面板</title>
<style>
:root{--bg:#0a0d12;--panel:#0f141c;--line:#1c2633;--fg:#c9d6e3;--mute:#6b7d90;--acc:#00ff88;--danger:#ff4d6d;--sel:#0d2a1e}
[data-theme=light]{--bg:#f4f7fa;--panel:#ffffff;--line:#d5dde6;--fg:#1a2430;--mute:#5b6b7c;--acc:#00a35c;--danger:#d62f4f;--sel:#e3f7ec}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:ui-monospace,Consolas,"Microsoft YaHei",monospace;font-size:13px}
header{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:12px 18px;border-bottom:1px solid var(--line);flex-wrap:wrap}
h1{font-size:16px;margin:0;color:var(--acc)}
button{font:inherit;background:transparent;color:var(--acc);border:1px solid var(--acc);padding:5px 10px;cursor:pointer;border-radius:4px}
button:hover{background:var(--acc);color:#000}
button.danger{color:var(--danger);border-color:var(--danger)}
button.danger:hover{background:var(--danger);color:#fff}
button:disabled{opacity:.45;cursor:default}
input,select{font:inherit;background:var(--panel);color:var(--fg);border:1px solid var(--line);padding:6px 8px;border-radius:4px;width:100%}
input:focus,select:focus{outline:1px solid var(--acc)}
input[type=checkbox]{width:auto;accent-color:var(--acc)}
.wrap{display:grid;grid-template-columns:230px 1fr;gap:16px;padding:16px}
@media(max-width:860px){.wrap{grid-template-columns:1fr}}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px;min-width:0}
.dom{display:block;width:100%;text-align:left;margin:4px 0;border-color:var(--line);color:var(--fg)}
.dom.on{border-color:var(--acc);color:var(--acc)}
.filters{display:grid;grid-template-columns:repeat(3,minmax(140px,1fr)) auto;gap:8px;margin-bottom:10px;align-items:center}
@media(max-width:860px){.filters{grid-template-columns:1fr}}
.bar{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px;align-items:center}
.muted{color:var(--mute)}
.msg{color:var(--mute);min-height:18px;margin:6px 0}
table{width:100%;border-collapse:collapse;font-size:12px}
th,td{padding:6px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;word-break:break-all}
th{color:var(--acc);font-weight:600;white-space:nowrap}
tr.picked td{background:var(--sel)}
.val{cursor:pointer;color:var(--mute)}
.hidden{display:none!important}
.login{max-width:360px;margin:12vh auto;display:grid;gap:10px;padding:0 16px}
.login h1{margin-bottom:6px}
dialog{background:var(--panel);color:var(--fg);border:1px solid var(--acc);border-radius:6px;width:min(560px,92vw)}
dialog::backdrop{background:rgba(0,0,0,.6)}
dialog.warn{border-color:var(--danger)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.grid2 label{display:grid;gap:4px;color:var(--mute)}
.chk{display:flex;align-items:center;gap:6px;color:var(--fg)}
.toast{position:fixed;right:16px;bottom:16px;background:var(--panel);border:1px solid var(--acc);color:var(--fg);padding:10px 14px;border-radius:6px;max-width:360px;z-index:9}
.toast.err{border-color:var(--danger)}
</style>
</head>
<body>
<div id="login" class="login hidden">
  <h1>&gt; COOKIE 同步 // 登录</h1>
  <input id="pw" type="password" placeholder="请输入密码 S_PW" autocomplete="current-password">
  <button id="loginBtn">登录</button>
  <div id="loginMsg" class="msg"></div>
</div>

<div id="app" class="hidden">
  <header>
    <h1>&gt; COOKIE 同步 管理面板</h1>
    <div>
      <button id="theme">切换浅色模式</button>
      <button id="logout" class="danger">退出登录</button>
    </div>
  </header>
  <div class="wrap">
    <aside class="card">
      <div class="muted" style="margin-bottom:6px">域名列表（点击筛选）</div>
      <button class="dom on" data-d="">全部域名</button>
      <div id="domains"></div>
    </aside>
    <main class="card">
      <div class="filters">
        <input id="fDomain" placeholder="按域名筛选，例如 bilibili">
        <input id="fComment" placeholder="按备注筛选，例如 主号">
        <input id="fName" placeholder="按 Cookie 名称筛选，例如 SESSDATA">
        <button id="clearF">清空筛选</button>
      </div>
      <div class="bar">
        <button id="selAll">全选</button>
        <button id="selInv">反选</button>
        <button id="selNone">取消选择</button>
        <button id="delSel" class="danger" disabled>删除选中</button>
        <button id="refresh">刷新</button>
        <button id="add">新增记录</button>
        <span id="status" class="muted"></span>
      </div>
      <div style="overflow:auto">
        <table>
          <thead><tr>
            <th><input type="checkbox" id="chkAll" title="全选 / 取消全选"></th>
            <th>域名</th><th>备注</th><th>名称</th><th>值（点击显示）</th><th>路径</th>
            <th>安全 Secure</th><th>仅主机</th><th>HttpOnly</th><th>SameSite</th><th>过期时间</th><th>更新时间</th><th>操作</th>
          </tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
    </main>
  </div>
</div>

<dialog id="dlg">
  <form id="form" class="grid2">
    <label>域名<input name="domain" required></label>
    <label>备注<input name="comment"></label>
    <label>名称<input name="name" required></label>
    <label>路径<input name="path" value="/"></label>
    <label style="grid-column:1/3">值<input name="value"></label>
    <label>SameSite
      <select name="sameSite">
        <option value="unspecified">未指定</option>
        <option value="no_restriction">None（需 Secure）</option>
        <option value="lax">Lax</option>
        <option value="strict">Strict</option>
      </select>
    </label>
    <label>过期时间（Unix 秒，留空为会话）<input name="expirationDate"></label>
    <label class="chk"><input type="checkbox" name="secure"> Secure</label>
    <label class="chk"><input type="checkbox" name="httpOnly"> HttpOnly</label>
    <label class="chk"><input type="checkbox" name="hostOnly"> 仅主机（不含子域）</label>
    <div style="grid-column:1/3;display:flex;gap:8px;justify-content:flex-end">
      <button type="button" id="cancelDlg">取消</button>
      <button type="submit">保存</button>
    </div>
  </form>
</dialog>

<dialog id="confirmDlg" class="warn">
  <div style="display:grid;gap:12px">
    <div id="confirmText"></div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button type="button" id="confirmNo">取消</button>
      <button type="button" id="confirmYes" class="danger">确认删除</button>
    </div>
  </div>
</dialog>

<div id="toast" class="toast hidden"></div>

<script>
var BASE = location.pathname;
while (BASE.length > 1 && BASE.charAt(BASE.length - 1) === '/') BASE = BASE.slice(0, -1);
var st = { rows: [], picked: {}, editId: null, pendingIds: [] };

function $(id) { return document.getElementById(id); }
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
    return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
  });
}
function fmt(sec) { return sec ? new Date(sec * 1000).toLocaleString('zh-CN') : '-'; }
function toast(text, bad) {
  var t = $('toast');
  t.textContent = text;
  t.className = 'toast' + (bad ? ' err' : '');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(function () { t.className = 'toast hidden'; }, 2600);
}
function showLogin() { $('app').classList.add('hidden'); $('login').classList.remove('hidden'); }
function showApp() { $('login').classList.add('hidden'); $('app').classList.remove('hidden'); refreshAll(); }

function api(method, path, body) {
  var opts = { method: method, headers: {}, credentials: 'same-origin' };
  if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
  return fetch(BASE + path, opts).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (d) {
      if (r.status === 401) { showLogin(); throw new Error('登录已失效，请重新登录'); }
      if (!r.ok) throw new Error(d.error || ('请求失败（HTTP ' + r.status + '）'));
      return d;
    });
  });
}

function loadDomains() {
  return api('GET', '/api/domains').then(function (d) {
    var m = {};
    d.domains.forEach(function (x) { m[x.domain] = (m[x.domain] || 0) + x.count; });
    var cur = $('fDomain').value.trim();
    var h = '';
    Object.keys(m).sort().forEach(function (k) {
      h += '<button class="dom' + (cur === k ? ' on' : '') + '" data-d="' + esc(k) + '">' + esc(k) + '（' + m[k] + '）</button>';
    });
    $('domains').innerHTML = h;
  });
}

function load() {
  var q = ['fuzzy=1'];
  var d = $('fDomain').value.trim(), c = $('fComment').value.trim(), n = $('fName').value.trim();
  if (d) q.push('domain=' + encodeURIComponent(d));
  if (c) q.push('comment=' + encodeURIComponent(c));
  if (n) q.push('name=' + encodeURIComponent(n));
  return api('GET', '/api/cookies?' + q.join('&')).then(function (r) {
    st.rows = r.cookies;
    render();
    $('status').textContent = '共 ' + r.cookies.length + ' 条，已选 ' + Object.keys(st.picked).length + ' 条';
  });
}

function render() {
  var h = '';
  st.rows.forEach(function (r, i) {
    var on = !!st.picked[r.id];
    h += '<tr class="' + (on ? 'picked' : '') + '">'
      + '<td><input type="checkbox" class="pick" data-id="' + r.id + '"' + (on ? ' checked' : '') + '></td>'
      + '<td>' + esc(r.domain) + '</td>'
      + '<td>' + esc(r.comment) + '</td>'
      + '<td>' + esc(r.name) + '</td>'
      + '<td><span class="val" data-i="' + i + '" data-shown="0">' + (r.value ? '******' : '') + '</span></td>'
      + '<td>' + esc(r.path) + '</td>'
      + '<td>' + (r.secure ? '是' : '否') + '</td>'
      + '<td>' + (r.hostOnly ? '是' : '否') + '</td>'
      + '<td>' + (r.httpOnly ? '是' : '否') + '</td>'
      + '<td>' + esc(r.sameSite) + '</td>'
      + '<td>' + (r.expirationDate ? esc(fmt(r.expirationDate)) : '会话') + '</td>'
      + '<td>' + esc(fmt(r.updated_at)) + '</td>'
      + '<td><button data-edit="' + i + '">编辑</button> <button class="danger" data-del="' + r.id + '">删除</button></td>'
      + '</tr>';
  });
  $('rows').innerHTML = h || '<tr><td colspan="13" class="muted">暂无记录</td></tr>';
  syncHeaderCheck();
  $('delSel').disabled = Object.keys(st.picked).length === 0;
}

function syncHeaderCheck() {
  var all = st.rows.length > 0 && st.rows.every(function (r) { return !!st.picked[r.id]; });
  $('chkAll').checked = all;
}

function refreshAll() {
  return loadDomains().then(load).catch(function (e) { $('status').textContent = e.message; });
}

function openEdit(r) {
  var f = $('form');
  st.editId = r ? r.id : null;
  f.domain.value = r ? r.domain : $('fDomain').value.trim();
  f.comment.value = r ? r.comment : $('fComment').value.trim();
  f.name.value = r ? r.name : '';
  f.path.value = r ? r.path : '/';
  f.value.value = r ? r.value : '';
  f.sameSite.value = r ? r.sameSite : 'unspecified';
  f.expirationDate.value = r && r.expirationDate ? Math.floor(r.expirationDate) : '';
  f.secure.checked = !!(r && r.secure);
  f.httpOnly.checked = !!(r && r.httpOnly);
  f.hostOnly.checked = !!(r && r.hostOnly);
  ['domain', 'comment', 'name'].forEach(function (k) { f[k].readOnly = !!r; });
  $('dlg').showModal();
}

$('form').onsubmit = function (e) {
  e.preventDefault();
  var f = this;
  var exp = f.expirationDate.value.trim();
  var rec = {
    domain: f.domain.value.trim(),
    name: f.name.value.trim(),
    value: f.value.value,
    path: f.path.value.trim() || '/',
    sameSite: f.sameSite.value,
    expirationDate: exp ? Number(exp) : null,
    secure: f.secure.checked,
    httpOnly: f.httpOnly.checked,
    hostOnly: f.hostOnly.checked
  };
  var p = st.editId
    ? api('PUT', '/api/cookies/' + st.editId, rec)
    : api('POST', '/api/cookies', { comment: f.comment.value.trim(), records: [rec] });
  p.then(function () { $('dlg').close(); toast('保存成功'); return refreshAll(); })
    .catch(function (err) { toast(err.message, true); });
};

$('cancelDlg').onclick = function () { $('dlg').close(); };
$('add').onclick = function () { openEdit(null); };
$('refresh').onclick = function () { refreshAll(); toast('已刷新'); };

$('rows').onclick = function (e) {
  var t = e.target;
  if (t.classList.contains('pick')) {
    var id = t.dataset.id;
    if (t.checked) st.picked[id] = true; else delete st.picked[id];
    return render();
  }
  if (t.dataset.edit !== undefined) return openEdit(st.rows[+t.dataset.edit]);
  if (t.dataset.del !== undefined) return askDelete([Number(t.dataset.del)], '确定删除这 1 条记录吗？此操作不可撤销。');
  if (t.classList.contains('val')) {
    var r = st.rows[+t.dataset.i];
    var shown = t.dataset.shown === '1';
    t.dataset.shown = shown ? '0' : '1';
    t.textContent = shown ? (r.value ? '******' : '') : r.value;
  }
};

$('chkAll').onchange = function () {
  var on = this.checked;
  st.rows.forEach(function (r) { if (on) st.picked[r.id] = true; else delete st.picked[r.id]; });
  render();
};
$('selAll').onclick = function () {
  st.rows.forEach(function (r) { st.picked[r.id] = true; });
  render();
};
$('selInv').onclick = function () {
  st.rows.forEach(function (r) {
    if (st.picked[r.id]) delete st.picked[r.id]; else st.picked[r.id] = true;
  });
  render();
};
$('selNone').onclick = function () { st.picked = {}; render(); };

function askDelete(ids, text) {
  st.pendingIds = ids;
  $('confirmText').textContent = text;
  $('confirmDlg').showModal();
}
$('delSel').onclick = function () {
  var ids = Object.keys(st.picked).map(Number);
  if (!ids.length) return toast('请先选择记录', true);
  askDelete(ids, '确定删除选中的 ' + ids.length + ' 条记录吗？此操作不可撤销。');
};
$('confirmNo').onclick = function () { $('confirmDlg').close(); };
$('confirmYes').onclick = function () {
  var ids = st.pendingIds;
  $('confirmDlg').close();
  var p = ids.length === 1
    ? api('DELETE', '/api/cookies?id=' + ids[0])
    : api('POST', '/api/cookies/batch-delete', { ids: ids });
  p.then(function (r) {
    ids.forEach(function (id) { delete st.picked[id]; });
    toast('已删除 ' + (r.deleted || 1) + ' 条记录');
    return refreshAll();
  }).catch(function (err) { toast(err.message, true); });
};

document.addEventListener('click', function (e) {
  var b = e.target.closest ? e.target.closest('button.dom') : null;
  if (!b) return;
  $('fDomain').value = b.dataset.d || '';
  load().then(loadDomains).catch(function (err) { toast(err.message, true); });
});

var timer = null;
function debounced() {
  clearTimeout(timer);
  timer = setTimeout(function () { load().catch(function (err) { toast(err.message, true); }); }, 250);
}
$('fDomain').oninput = debounced;
$('fComment').oninput = debounced;
$('fName').oninput = debounced;
$('clearF').onclick = function () {
  $('fDomain').value = ''; $('fComment').value = ''; $('fName').value = '';
  refreshAll();
};

function applyTheme(t) {
  document.documentElement.setAttribute('data-theme', t);
  $('theme').textContent = t === 'dark' ? '切换浅色模式' : '切换深色模式';
}
$('theme').onclick = function () {
  var t = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  try { localStorage.setItem('cs-theme', t); } catch (e) {}
  applyTheme(t);
};
applyTheme((function () { try { return localStorage.getItem('cs-theme') || 'dark'; } catch (e) { return 'dark'; } })());

$('loginBtn').onclick = function () {
  fetch(BASE + '/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: $('pw').value }),
    credentials: 'same-origin'
  }).then(function (r) {
    return r.json().catch(function () { return {}; }).then(function (d) {
      if (!r.ok) throw new Error(d.error || '登录失败');
      $('pw').value = '';
      $('loginMsg').textContent = '';
      showApp();
    });
  }).catch(function (err) { $('loginMsg').textContent = err.message; });
};
$('pw').onkeydown = function (e) { if (e.key === 'Enter') $('loginBtn').click(); };
$('logout').onclick = function () {
  fetch(BASE + '/logout', { method: 'POST', credentials: 'same-origin' }).finally(showLogin);
};

fetch(BASE + '/api/session', { credentials: 'same-origin' })
  .then(function (r) { if (r.ok) showApp(); else showLogin(); })
  .catch(showLogin);
</script>
</body>
</html>`;
