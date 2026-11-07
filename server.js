'use strict';
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------- Ayarlar ----------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || '';
const SITE_URL = (process.env.SITE_URL || '').replace(/\/+$/, '');
const list = (v) => (v || '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim().replace(/\/+$/, '')).filter(Boolean);
const ADMINS = list(process.env.ADMIN_EMAILS);
const POSTERS = list(process.env.EVENT_POSTERS);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');

if (JWT_SECRET.length < 16) {
  console.error('XETA: JWT_SECRET teyin olunmayib (en azi 32 simvol olmalidir).');
  process.exit(1);
}

// ---------- Baza ----------
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'aztugram.db'));
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  code_hash TEXT,
  code_expires INTEGER,
  reset_hash TEXT,
  reset_expires INTEGER,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  author TEXT NOT NULL,
  category TEXT NOT NULL,
  text TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS likes (
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  PRIMARY KEY (post_id, user_id)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  author TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  date TEXT,
  location TEXT,
  created_at INTEGER NOT NULL
);
`);

// ---------- Email ----------
const mailer = process.env.SMTP_USER && process.env.SMTP_PASS
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
    })
  : null;

async function sendMail(to, subject, text) {
  if (!mailer) {
    console.log(`[EMAIL YOXDUR] ${to} | ${subject} | ${text}`);
    return false;
  }
  await mailer.sendMail({ from: `AZTUGRAM <${process.env.SMTP_USER}>`, to, subject, text });
  return true;
}

// ---------- Kompakt funksiyalar ----------
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const now = () => Date.now();
const isEmail = (s) => typeof s === 'string' && s.length <= 120 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s);
const clean = (s, max) => String(s || '').trim().slice(0, max);
const roleOf = (email) => (ADMINS.includes(email) ? 'admin' : POSTERS.includes(email) ? 'poster' : 'user');
const canPostEvents = (email) => ADMINS.includes(email) || POSTERS.includes(email);
const signToken = (u) => jwt.sign({ id: u.id, email: u.email, name: u.name }, JWT_SECRET, { expiresIn: '7d' });
const publicUser = (u) => ({
  id: u.id,
  name: u.name,
  email: u.email,
  role: roleOf(u.email),
  isAdmin: ADMINS.includes(u.email),
  canPostEvents: canPostEvents(u.email),
});
const fail = (res, code, msg, extra) => res.status(code).json({ error: msg, message: msg, ...(extra || {}) });

async function sendVerifyCode(user) {
  const code = String(crypto.randomInt(100000, 1000000));
  db.prepare('UPDATE users SET code_hash=?, code_expires=? WHERE id=?').run(sha(code), now() + 15 * 60 * 1000, user.id);
  return sendMail(user.email, 'AZTUGRAM təsdiq kodu', `Salam ${user.name},\n\nTəsdiq kodun: ${code}\nKod 15 dəqiqə etibarlıdır.`);
}

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(origin.replace(/\/+$/, ''))) return cb(null, true);
      return cb(null, false);
    },
  })
);
app.use(express.json({ limit: '10kb' }));

const generalLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Çox cəhd. Bir az sonra yenidən yoxla.', message: 'Çox cəhd. Bir az sonra yenidən yoxla.' },
});
app.use('/api', generalLimiter);

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : '';
  try {
    const p = jwt.verify(token, JWT_SECRET);
    const u = db.prepare('SELECT * FROM users WHERE id=?').get(p.id);
    if (!u) return fail(res, 401, 'Daxil ol.');
    req.user = u;
    next();
  } catch {
    return fail(res, 401, 'Daxil ol.');
  }
}
function optionalAuth(req, _res, next) {
  const h = req.headers.authorization || '';
  try {
    const p = jwt.verify(h.startsWith('Bearer ') ? h.slice(7) : '', JWT_SECRET);
    req.user = db.prepare('SELECT * FROM users WHERE id=?').get(p.id) || null;
  } catch {
    req.user = null;
  }
  next();
}

// ---------- Əsas ----------
// Sayt (frontend) fayllari
['index.html', 'robots.txt', 'sitemap.xml', 'googlebf696ea274b48d41.html'].forEach((f) => {
  app.get(f === 'index.html' ? ['/', '/index.html'] : '/' + f, (_req, res) => res.sendFile(require('path').join(__dirname, f)));
});
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// ---------- Qeydiyyat ----------
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const name = clean(req.body.name, 60);
    const email = clean(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    if (name.length < 2) return fail(res, 400, 'Ad ən azı 2 simvol olmalıdır.');
    if (!isEmail(email)) return fail(res, 400, 'Email düzgün deyil.');
    if (password.length < 6 || password.length > 100) return fail(res, 400, 'Şifrə 6-100 simvol olmalıdır.');

    const existing = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (existing && existing.verified) return fail(res, 409, 'Bu email artıq qeydiyyatdan keçib.');

    const hash = await bcrypt.hash(password, 10);
    let user;
    if (existing) {
      db.prepare('UPDATE users SET name=?, password_hash=? WHERE id=?').run(name, hash, existing.id);
      user = db.prepare('SELECT * FROM users WHERE id=?').get(existing.id);
    } else {
      const r = db.prepare('INSERT INTO users (name,email,password_hash,verified,created_at) VALUES (?,?,?,0,?)').run(name, email, hash, now());
      user = db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid);
    }

    let sent = false;
    try {
      sent = await sendVerifyCode(user);
    } catch (e) {
      console.error('Email xetasi:', e.message);
    }
    if (!sent) {
      // Email gonderile bilmirse, istifadeci bloklanmasin
      db.prepare('UPDATE users SET verified=1 WHERE id=?').run(user.id);
      user.verified = 1;
      return res.json({ ok: true, needsVerify: false, token: signToken(user), user: publicUser(user) });
    }
    res.json({ ok: true, needsVerify: true, email, message: 'Təsdiq kodu emailinə göndərildi.' });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Server xətası.');
  }
});

app.post('/api/verify', authLimiter, (req, res) => {
  const email = clean(req.body.email, 120).toLowerCase();
  const code = clean(req.body.code, 10);
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !u.code_hash || u.code_expires < now() || u.code_hash !== sha(code)) return fail(res, 400, 'Kod yanlışdır və ya vaxtı bitib.');
  db.prepare('UPDATE users SET verified=1, code_hash=NULL, code_expires=NULL WHERE id=?').run(u.id);
  u.verified = 1;
  res.json({ ok: true, token: signToken(u), user: publicUser(u) });
});

app.post('/api/resend', authLimiter, async (req, res) => {
  try {
    const email = clean(req.body.email, 120).toLowerCase();
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    if (u && !u.verified) await sendVerifyCode(u);
    res.json({ ok: true, message: 'Kod göndərildi.' });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Email göndərilə bilmədi.');
  }
});

// ---------- Giriş ----------
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const email = clean(req.body.email, 120).toLowerCase();
    const password = String(req.body.password || '');
    const u = db.prepare('SELECT * FROM users WHERE email=?').get(email);
    const ok = u && (await bcrypt.compare(password, u.password_hash));
    if (!ok) return fail(res, 401, 'Email və ya şifrə səhvdir.');
    if (!u.verified) {
      try {
        await sendVerifyCode(u);
      } catch (e) {
        console.error(e.message);
      }
      return fail(res, 403, 'Email təsdiqlənməyib. Yeni kod göndərildi.', { needsVerify: true, email });
    }
    res.json({ ok: true, token: signToken(u), user: publicUser(u) });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Server xətası.');
  }
});

app.get('/api/me', auth, (req, res) => res.json({ ok: true, user: publicUser(req.user) }));

// ---------- Şifrə yeniləmə ----------
app.post('/api/forgot', authLimiter, async (req, res) => {
  try {
    const email = clean(req.body.email, 120).toLowerCase();
    const u = isEmail(email) ? db.prepare('SELECT * FROM users WHERE email=?').get(email) : null;
    if (u) {
      const token = crypto.randomBytes(32).toString('hex');
      db.prepare('UPDATE users SET reset_hash=?, reset_expires=? WHERE id=?').run(sha(token), now() + 60 * 60 * 1000, u.id);
      const link = `${SITE_URL}/?reset=${token}`;
      try {
        await sendMail(u.email, 'AZTUGRAM şifrə yeniləmə', `Şifrəni yeniləmək üçün linkə bas (1 saat etibarlıdır, bir dəfə işləyir):\n\n${link}\n\nSən istəməmisənsə, bu emaili nəzərə alma.`);
      } catch (e) {
        console.error('Email xetasi:', e.message);
      }
    }
    res.json({ ok: true, message: 'Əgər bu email qeydiyyatdadırsa, link göndərildi.' });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Server xətası.');
  }
});

app.post('/api/reset', authLimiter, async (req, res) => {
  try {
    const token = clean(req.body.token, 200);
    const password = String(req.body.password || '');
    if (password.length < 6 || password.length > 100) return fail(res, 400, 'Şifrə 6-100 simvol olmalıdır.');
    const u = db.prepare('SELECT * FROM users WHERE reset_hash=?').get(sha(token));
    if (!token || !u || u.reset_expires < now()) return fail(res, 400, 'Link etibarsızdır və ya vaxtı bitib.');
    const hash = await bcrypt.hash(password, 10);
    db.prepare('UPDATE users SET password_hash=?, reset_hash=NULL, reset_expires=NULL, verified=1 WHERE id=?').run(hash, u.id);
    res.json({ ok: true, message: 'Şifrə yeniləndi. İndi daxil ola bilərsən.' });
  } catch (e) {
    console.error(e);
    fail(res, 500, 'Server xətası.');
  }
});

// ---------- Kampus divarı ----------
const CATEGORIES = ['sual', 'elan', 'tapinti', 'tovsiye'];
const normCat = (c) =>
  String(c || '')
    .toLowerCase()
    .replace(/ə/g, 'e').replace(/ı/g, 'i').replace(/ö/g, 'o').replace(/ü/g, 'u').replace(/ş/g, 's').replace(/ç/g, 'c').replace(/ğ/g, 'g');

app.get('/api/posts', optionalAuth, (req, res) => {
  const uid = req.user ? req.user.id : 0;
  const rows = db
    .prepare(
      `SELECT p.*, (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id) AS likes,
              (SELECT COUNT(*) FROM likes l WHERE l.post_id=p.id AND l.user_id=?) AS liked
       FROM posts p ORDER BY p.id DESC LIMIT 100`
    )
    .all(uid);
  const isAdmin = req.user && ADMINS.includes(req.user.email);
  res.json(
    rows.map((p) => ({
      id: p.id,
      author: p.author,
      category: p.category,
      text: p.text,
      createdAt: p.created_at,
      likes: p.likes,
      liked: !!p.liked,
      canDelete: !!req.user && (p.user_id === req.user.id || isAdmin),
    }))
  );
});

app.post('/api/posts', auth, (req, res) => {
  const text = clean(req.body.text, 1000);
  let category = normCat(req.body.category);
  if (!CATEGORIES.includes(category)) category = 'sual';
  if (text.length < 2) return fail(res, 400, 'Yazı çox qısadır.');
  const r = db.prepare('INSERT INTO posts (user_id,author,category,text,created_at) VALUES (?,?,?,?,?)').run(req.user.id, req.user.name, category, text, now());
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const p = db.prepare('SELECT * FROM posts WHERE id=?').get(Number(req.params.id));
  if (!p) return fail(res, 404, 'Tapılmadı.');
  if (p.user_id !== req.user.id && !ADMINS.includes(req.user.email)) return fail(res, 403, 'İcazə yoxdur.');
  db.prepare('DELETE FROM posts WHERE id=?').run(p.id);
  db.prepare('DELETE FROM likes WHERE post_id=?').run(p.id);
  res.json({ ok: true });
});

app.post('/api/posts/:id/like', auth, (req, res) => {
  const id = Number(req.params.id);
  if (!db.prepare('SELECT 1 FROM posts WHERE id=?').get(id)) return fail(res, 404, 'Tapılmadı.');
  const has = db.prepare('SELECT 1 FROM likes WHERE post_id=? AND user_id=?').get(id, req.user.id);
  if (has) db.prepare('DELETE FROM likes WHERE post_id=? AND user_id=?').run(id, req.user.id);
  else db.prepare('INSERT INTO likes (post_id,user_id) VALUES (?,?)').run(id, req.user.id);
  const count = db.prepare('SELECT COUNT(*) AS c FROM likes WHERE post_id=?').get(id).c;
  res.json({ ok: true, liked: !has, likes: count });
});

// ---------- Tədbirlər ----------
app.get('/api/events', optionalAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM events ORDER BY id DESC LIMIT 100').all();
  const isAdmin = req.user && ADMINS.includes(req.user.email);
  res.json(
    rows.map((e) => ({
      id: e.id,
      title: e.title,
      description: e.description,
      date: e.date,
      location: e.location,
      author: e.author,
      createdAt: e.created_at,
      canDelete: !!req.user && (e.user_id === req.user.id || isAdmin),
    }))
  );
});

app.post('/api/events', auth, (req, res) => {
  if (!canPostEvents(req.user.email)) return fail(res, 403, 'Tədbir paylaşmaq icazən yoxdur.');
  const title = clean(req.body.title, 120);
  if (title.length < 3) return fail(res, 400, 'Başlıq çox qısadır.');
  const r = db
    .prepare('INSERT INTO events (user_id,author,title,description,date,location,created_at) VALUES (?,?,?,?,?,?,?)')
    .run(req.user.id, req.user.name, title, clean(req.body.description, 1000), clean(req.body.date, 60), clean(req.body.location, 120), now());
  res.json({ ok: true, id: r.lastInsertRowid });
});

app.delete('/api/events/:id', auth, (req, res) => {
  const e = db.prepare('SELECT * FROM events WHERE id=?').get(Number(req.params.id));
  if (!e) return fail(res, 404, 'Tapılmadı.');
  if (e.user_id !== req.user.id && !ADMINS.includes(req.user.email)) return fail(res, 403, 'İcazə yoxdur.');
  db.prepare('DELETE FROM events WHERE id=?').run(e.id);
  res.json({ ok: true });
});

// ---------- Admin ----------
app.get('/api/admin/users', auth, (req, res) => {
  if (!ADMINS.includes(req.user.email)) return fail(res, 403, 'İcazə yoxdur.');
  const rows = db.prepare('SELECT id,name,email,verified,created_at FROM users ORDER BY id DESC').all();
  res.json(rows.map((u) => ({ id: u.id, name: u.name, email: u.email, verified: !!u.verified, createdAt: u.created_at })));
});
app.get('/api/users', auth, (req, res, next) => {
  req.url = '/api/admin/users';
  app.handle(req, res, next);
});

// ---------- Xəta tutucu ----------
app.use((req, res) => fail(res, 404, 'Tapılmadı.'));
app.use((err, _req, res, _next) => {
  console.error(err);
  fail(res, err.status || 500, err.status === 400 ? 'Sorğu düzgün deyil.' : 'Server xətası.');
});

app.listen(PORT, () => console.log(`AZTUGRAM API ${PORT} portunda işləyir`));
