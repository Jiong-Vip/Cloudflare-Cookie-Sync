-- Cookie Sync D1 schema（与 worker.js 中 initDb() 保持一致）。
-- 新建数据库时执行即可；worker.js 首次请求也会自动执行同样的建表语句，通常无需手动执行。
-- 应用方式：npx wrangler d1 execute cookie_sync_db --remote --file=schema.sql
CREATE TABLE IF NOT EXISTS cookies (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  name TEXT NOT NULL,
  value TEXT NOT NULL DEFAULT '',
  path TEXT NOT NULL DEFAULT '/',
  secure INTEGER NOT NULL DEFAULT 0,
  httpOnly INTEGER NOT NULL DEFAULT 0,
  sameSite TEXT NOT NULL DEFAULT 'unspecified',
  expirationDate REAL,
  comment TEXT NOT NULL DEFAULT '',
  hostOnly INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  UNIQUE (domain, name, path, comment)
);
CREATE INDEX IF NOT EXISTS idx_cookies_domain_comment ON cookies (domain, comment);
CREATE INDEX IF NOT EXISTS idx_cookies_domain ON cookies (domain);
