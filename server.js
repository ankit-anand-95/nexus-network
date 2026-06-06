const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const validator = require('validator');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const JWT_SECRET = process.env.JWT_SECRET || 'nexus_dev_secret_change_in_prod';
const PORT = process.env.PORT || 3000;
const APP_URL = process.env.APP_URL || `http://localhost:${PORT}`;

// Email transporter — configure SMTP_* env vars to enable real emails
// Works with Gmail, Resend, SendGrid SMTP, Mailgun, etc.
let mailer = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
}
async function sendEmail(to, subject, html) {
  if (!mailer) {
    console.log(`[EMAIL] To: ${to} | Subject: ${subject}`);
    return false; // email not configured
  }
  try {
    await mailer.sendMail({
      from: process.env.SMTP_FROM || `Nexus <${process.env.SMTP_USER}>`,
      to, subject, html
    });
    return true;
  } catch(e) { console.error('Email error:', e.message); return false; }
}

// On Railway: uploads live on persistent volume; locally: public/uploads
const VOLUME = process.env.RAILWAY_VOLUME_MOUNT_PATH || null;
const uploadsDir = VOLUME
  ? path.join(VOLUME, 'uploads')
  : path.join(__dirname, 'public', 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });

// ── Security headers ──────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: false, // we load FA from CDN, keep flexible
  crossOriginEmbedderPolicy: false
}));

// ── Rate limiting ──────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,                   // 20 login/register attempts per IP per window
  message: { error: 'Too many attempts. Try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,  // 1 minute
  max: 300,             // 300 req/min per IP (5 req/sec, plenty for real users)
  message: { error: 'Too many requests. Slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => req.path === '/api/health' // don't rate-limit health checks
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10, // 10 uploads/min per IP
  message: { error: 'Upload limit reached. Try again in a minute.' }
});

app.use(cors());
app.use(express.json({ limit: '2mb' })); // cap payload size
app.use(express.static(path.join(__dirname, 'public')));
app.use('/api/auth', authLimiter);    // strict limit on login/register
app.use('/api/upload', uploadLimiter); // strict limit on uploads
app.use('/api', apiLimiter);           // general API limit
// Serve uploads from volume path when on Railway
if (VOLUME) app.use('/uploads', express.static(uploadsDir));

// Health check
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));


// Multer storage
const storage = multer.diskStorage({
  destination: uploadsDir,
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const ALLOWED_MIME = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const fileFilter = (req, file, cb) => {
  if (ALLOWED_MIME.includes(file.mimetype)) cb(null, true);
  else cb(new Error('Only JPEG, PNG, WebP and GIF images are allowed'), false);
};
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 }, fileFilter });

// Auth middleware
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    const u = db.prepare(`SELECT is_disabled, blocked_until FROM users WHERE id=?`).get(req.user.id);
    if (u?.is_disabled) return res.status(403).json({ error: 'Account disabled', code: 'DISABLED' });
    if (u?.blocked_until && new Date(u.blocked_until) > new Date()) return res.status(403).json({ error: 'Account suspended until ' + u.blocked_until, code: 'BLOCKED', until: u.blocked_until });
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
};
// Feed new-posts check — lightweight, just returns count of posts newer than given timestamp
app.get('/api/posts/new-count', auth, (req, res) => {
  const since = req.query.since;
  if (!since) return res.json({ count: 0 });
  const DEMO_EMAIL = process.env.DEMO_EMAIL || 'ankit@example.com';
  const me = db.prepare(`SELECT email FROM users WHERE id=?`).get(req.user.id);
  const isDemo = me?.email === DEMO_EMAIL;
  const feedFilter = isDemo
    ? `WHERE p.is_published=1 AND p.created_at > ?`
    : `WHERE p.is_published=1 AND p.created_at > ? AND (p.author_id=? OR p.author_id IN (
        SELECT CASE WHEN requester_id=? THEN addressee_id ELSE requester_id END
        FROM connections WHERE (requester_id=? OR addressee_id=?) AND status='accepted'
      ))`;
  const params = isDemo ? [since] : [since, req.user.id, req.user.id, req.user.id, req.user.id];
  const row = db.prepare(`SELECT COUNT(*) as n FROM posts p ${feedFilter}`).get(...params);
  res.json({ count: row?.n || 0 });
});

// Notification helper
function createNotif(userId, actorId, type, refId, content) {
  if (userId === actorId) return;
  db.prepare(`INSERT INTO notifications (user_id, actor_id, type, reference_id, content) VALUES (?, ?, ?, ?, ?)`)
    .run(userId, actorId, type, refId, content);
  io.to(`user_${userId}`).emit('notification', { type, content });
}

// Slot key comparison — handles both UTC (old "...Z") and local bare strings (new "YYYY-MM-DDTHH:mm:ss")
// Treats bare strings as IST (+05:30) since that's what the slot picker generates on the user's device
function _sameSlot(k1, k2) {
  if (!k1 || !k2) return false;
  if (k1 === k2) return true;
  const toMs = k => {
    if (k.endsWith('Z') || k.includes('+')) return new Date(k).getTime();
    return new Date(k + '+05:30').getTime(); // bare string → assume IST
  };
  try { return toMs(k1) === toMs(k2); } catch(e) { return false; }
}

// ─── AUTH ────────────────────────────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { name, email, password, headline, location } = req.body;
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare(`INSERT INTO users (name, email, password, headline, location) VALUES (?, ?, ?, ?, ?)`)
      .run(name, email, hash, headline || '', location || '');
    const user = db.prepare(`SELECT id, name, email, headline, location, avatar_url, banner_url, about, current_position, connections_count, is_dark_mode FROM users WHERE id = ?`).get(info.lastInsertRowid);
    const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user });
  } catch (e) {
    res.status(400).json({ error: 'Email already exists' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(email);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '7d' });
  const { password: _, ...safe } = user;
  res.json({ token, user: safe });
});

// ─── SEARCH ──────────────────────────────────────────────────────────────────

app.get('/api/search', auth, (req, res) => {
  const q = (req.query.q || '').trim();
  if (!q) return res.json({ users: [], posts: [] });
  const like = `%${q}%`;
  const uid = req.user.id;

  const users = db.prepare(`
    SELECT u.id, u.name, u.headline, u.avatar_url, u.current_position, u.location,
      c.status AS connection_status,
      -- degree: 1st if connected, 2nd if friend-of-friend
      CASE
        WHEN c.status='accepted' THEN '1st'
        WHEN EXISTS (
          SELECT 1 FROM connections c1
          JOIN connections c2 ON (
            CASE WHEN c1.requester_id=? THEN c1.addressee_id ELSE c1.requester_id END =
            CASE WHEN c2.requester_id=u.id THEN c2.addressee_id ELSE c2.requester_id END
          )
          WHERE (c1.requester_id=? OR c1.addressee_id=?) AND c1.status='accepted'
          AND (c2.requester_id=u.id OR c2.addressee_id=u.id) AND c2.status='accepted'
        ) THEN '2nd'
        ELSE '3rd'
      END AS degree
    FROM users u
    LEFT JOIN connections c ON (
      (c.requester_id=? AND c.addressee_id=u.id) OR
      (c.addressee_id=? AND c.requester_id=u.id)
    )
    WHERE u.id != ? AND (
      u.name LIKE ? OR u.headline LIKE ? OR
      u.current_position LIKE ? OR u.location LIKE ?
    )
    ORDER BY
      CASE WHEN c.status='accepted' THEN 0 ELSE 1 END,
      u.connections_count DESC
    LIMIT 20
  `).all(uid, uid, uid, uid, uid, uid, like, like, like, like);

  const posts = db.prepare(`
    SELECT p.id, p.content, p.created_at, p.likes_count, p.comments_count,
      CASE WHEN p.is_anonymous=1 THEN 'Anonymous' ELSE u.name END AS author_name,
      CASE WHEN p.is_anonymous=1 THEN NULL ELSE u.avatar_url END AS author_avatar,
      CASE WHEN p.is_anonymous=1 THEN NULL ELSE u.id END AS author_id
    FROM posts p LEFT JOIN users u ON p.author_id=u.id
    WHERE p.is_published=1 AND p.content LIKE ?
    ORDER BY p.created_at DESC LIMIT 10
  `).all(like);

  res.json({ users, posts });
});

// ─── USERS ───────────────────────────────────────────────────────────────────

app.get('/api/users/me', auth, (req, res) => {
  const user = db.prepare(`SELECT id, name, email, headline, location, about, avatar_url, banner_url, current_position, connections_count, is_dark_mode, created_at FROM users WHERE id = ?`).get(req.user.id);
  const experiences = db.prepare(`SELECT * FROM experiences WHERE user_id = ? ORDER BY is_current DESC, start_date DESC`).all(req.user.id);
  const education = db.prepare(`SELECT * FROM education WHERE user_id = ?`).all(req.user.id);
  const skills = db.prepare(`SELECT name FROM user_skills WHERE user_id = ?`).all(req.user.id).map(s => s.name);
  res.json({ ...user, experiences, education, skills });
});

app.put('/api/users/me', auth, (req, res) => {
  const rawBody = req.body;
  const name = sanitize(rawBody.name, 100);
  const headline = sanitize(rawBody.headline, 220);
  const location = sanitize(rawBody.location, 100);
  const about = sanitizeRich(rawBody.about, 2000);
  const current_position = sanitize(rawBody.current_position, 220);
  const is_dark_mode = rawBody.is_dark_mode;
  // Only update fields that were explicitly provided (non-empty strings)
  const noe = v => (v === '' || v == null) ? null : v;
  db.prepare(`UPDATE users SET name=COALESCE(?,name), headline=COALESCE(?,headline), location=COALESCE(?,location), about=COALESCE(?,about), current_position=COALESCE(?,current_position), is_dark_mode=COALESCE(?,is_dark_mode) WHERE id=?`)
    .run(noe(name), noe(headline), noe(location), noe(about), noe(current_position), is_dark_mode ?? null, req.user.id);
  res.json({ ok: true });
});

app.get('/api/users/:id', auth, (req, res) => {
  const user = db.prepare(`SELECT id, name, headline, location, about, avatar_url, banner_url, current_position, connections_count, created_at FROM users WHERE id = ?`).get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  const experiences = db.prepare(`SELECT * FROM experiences WHERE user_id = ? ORDER BY is_current DESC, start_date DESC`).all(req.params.id);
  const education = db.prepare(`SELECT * FROM education WHERE user_id = ?`).all(req.params.id);
  const skills = db.prepare(`SELECT name FROM user_skills WHERE user_id = ?`).all(req.params.id).map(s => s.name);
  const conn = db.prepare(`SELECT status FROM connections WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)`).get(req.user.id, req.params.id, req.params.id, req.user.id);
  res.json({ ...user, experiences, education, skills, connectionStatus: conn?.status || null });
});

// File upload
app.post('/api/upload', auth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file' });
  const url = `/uploads/${req.file.filename}`;
  const type = req.body.type;
  if (type === 'avatar') db.prepare(`UPDATE users SET avatar_url=? WHERE id=?`).run(url, req.user.id);
  if (type === 'banner') db.prepare(`UPDATE users SET banner_url=? WHERE id=?`).run(url, req.user.id);
  res.json({ url });
});

// Experience
app.post('/api/users/me/experience', auth, (req, res) => {
  const { company, role, start_date, end_date, is_current, description } = req.body;
  const info = db.prepare(`INSERT INTO experiences (user_id, company, role, start_date, end_date, is_current, description) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, company, role, start_date || '', end_date || '', is_current ? 1 : 0, description || '');
  if (is_current) db.prepare(`UPDATE users SET current_position=? WHERE id=?`).run(`${role} at ${company}`, req.user.id);
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/users/me/experience/:id', auth, (req, res) => {
  db.prepare(`DELETE FROM experiences WHERE id=? AND user_id=?`).run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// Education
app.post('/api/users/me/education', auth, (req, res) => {
  const { school, degree, start_year, end_year } = req.body;
  const info = db.prepare(`INSERT INTO education (user_id, school, degree, start_year, end_year) VALUES (?, ?, ?, ?, ?)`)
    .run(req.user.id, school, degree, start_year, end_year);
  res.json({ id: info.lastInsertRowid });
});

app.delete('/api/users/me/education/:id', auth, (req, res) => {
  db.prepare(`DELETE FROM education WHERE id=? AND user_id=?`).run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// Skills
app.post('/api/users/me/skills', auth, (req, res) => {
  const { name } = req.body;
  try {
    db.prepare(`INSERT INTO user_skills (user_id, name) VALUES (?, ?)`).run(req.user.id, name);
    res.json({ ok: true });
  } catch { res.json({ ok: true }); }
});

app.delete('/api/users/me/skills/:name', auth, (req, res) => {
  db.prepare(`DELETE FROM user_skills WHERE user_id=? AND name=?`).run(req.user.id, decodeURIComponent(req.params.name));
  res.json({ ok: true });
});

// ─── POSTS ───────────────────────────────────────────────────────────────────

app.get('/api/posts', auth, (req, res) => {
  const page = parseInt(req.query.page) || 1;
  const limit = 20;
  const offset = (page - 1) * limit;
  const DEMO_EMAIL = process.env.DEMO_EMAIL || 'ankit@example.com';
  const me = db.prepare(`SELECT email FROM users WHERE id=?`).get(req.user.id);
  const isDemo = me?.email === DEMO_EMAIL;

  // Non-demo users only see posts from themselves + their connections
  // Demo user sees everything (useful for testing seed data)
  const feedFilter = isDemo
    ? `WHERE p.is_published = 1`
    : `WHERE p.is_published = 1 AND (
        p.author_id = ? OR
        p.author_id IN (
          SELECT CASE WHEN requester_id=? THEN addressee_id ELSE requester_id END
          FROM connections WHERE (requester_id=? OR addressee_id=?) AND status='accepted'
        )
      )`;
  const feedParams = isDemo
    ? [req.user.id, limit, offset]
    : [req.user.id, req.user.id, req.user.id, req.user.id, req.user.id, limit, offset];

  const sort = req.query.sort === 'new' ? 'new' : 'top';
  // Use JOINed counts for ORDER BY — avoids correlated subqueries per row
  const orderBy = sort === 'top'
    ? 'reaction_count DESC, comment_count DESC, p.created_at DESC'
    : 'p.created_at DESC';
  const posts = db.prepare(`
    SELECT p.*,
      CASE WHEN p.is_anonymous = 1 THEN 'Anonymous' ELSE u.name END as author_name,
      CASE WHEN p.is_anonymous = 1 THEN '' ELSE u.avatar_url END as author_avatar,
      CASE WHEN p.is_anonymous = 1 THEN '' ELSE u.headline END as author_headline,
      EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) as liked,
      COUNT(DISTINCT pr.id) as reaction_count,
      COUNT(DISTINCT cm.id) as comment_count
    FROM posts p
    LEFT JOIN users u ON p.author_id = u.id
    LEFT JOIN post_reactions pr ON pr.post_id = p.id
    LEFT JOIN comments cm ON cm.post_id = p.id
    ${feedFilter}
    GROUP BY p.id
    ORDER BY ${orderBy}
    LIMIT ? OFFSET ?
  `).all(...feedParams);

  if (!posts.length) { res.json([]); return; }

  // ── Bulk fetch — 3 queries total regardless of post count ──
  const ids = posts.map(p => p.id);
  const ph = ids.map(() => '?').join(',');

  // All reactions grouped by post
  const allReactions = db.prepare(
    `SELECT post_id, reaction_type, COUNT(*) as count FROM post_reactions WHERE post_id IN (${ph}) GROUP BY post_id, reaction_type`
  ).all(...ids);
  const reactMap = {};
  allReactions.forEach(r => { (reactMap[r.post_id] = reactMap[r.post_id] || []).push(r); });

  // My reaction per post
  const myReactions = db.prepare(
    `SELECT post_id, reaction_type FROM post_reactions WHERE post_id IN (${ph}) AND user_id=?`
  ).all(...ids, req.user.id);
  const myReactMap = {};
  myReactions.forEach(r => { myReactMap[r.post_id] = r.reaction_type; });

  // Top 2 comments per post — one query, slice in JS
  const allComments = db.prepare(`
    SELECT c.post_id, c.id, c.content, c.created_at, c.author_id,
      u.name as author_name, u.avatar_url as author_avatar
    FROM comments c JOIN users u ON c.author_id=u.id
    WHERE c.post_id IN (${ph})
    ORDER BY c.post_id, c.created_at DESC
  `).all(...ids);
  const commentMap = {};
  allComments.forEach(c => {
    if (!commentMap[c.post_id]) commentMap[c.post_id] = [];
    if (commentMap[c.post_id].length < 2) commentMap[c.post_id].push(c);
  });

  const result = posts.map(p => {
    const post = { ...p, is_mine: p.author_id === req.user.id };
    if (p.is_poll) {
      post.poll_options = db.prepare(`SELECT * FROM poll_options WHERE post_id=?`).all(p.id);
      const vote = db.prepare(`SELECT option_id FROM poll_votes WHERE post_id=? AND user_id=?`).get(p.id, req.user.id);
      post.user_vote = vote?.option_id || null;
    }
    post.reactions = reactMap[p.id] || [];
    post.my_reaction = myReactMap[p.id] || null;
    post.top_comments = commentMap[p.id] || [];
    if (p.is_anonymous && p.author_id !== req.user.id) post.author_id = null;
    return post;
  });
  res.json(result);
});

app.post('/api/posts', auth, (req, res) => {
  const { content, image_url, is_anonymous, is_poll, poll_options, scheduled_at } = req.body;
  const isPublished = scheduled_at ? 0 : 1;
  const info = db.prepare(`INSERT INTO posts (author_id, content, image_url, is_anonymous, is_poll, scheduled_at, is_published) VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, content, image_url || '', is_anonymous ? 1 : 0, is_poll ? 1 : 0, scheduled_at || null, isPublished);

  if (is_poll && poll_options?.length) {
    const stmt = db.prepare(`INSERT INTO poll_options (post_id, option_text) VALUES (?, ?)`);
    poll_options.forEach(opt => stmt.run(info.lastInsertRowid, opt));
  }
  // Return the full post so frontend can render it immediately
  const newPost = db.prepare(`
    SELECT p.*,
      CASE WHEN p.is_anonymous=1 THEN 'Anonymous' ELSE u.name END as author_name,
      CASE WHEN p.is_anonymous=1 THEN NULL ELSE u.avatar_url END as author_avatar,
      CASE WHEN p.is_anonymous=1 THEN NULL ELSE u.headline END as author_headline,
      CASE WHEN p.is_anonymous=1 THEN NULL ELSE u.id END as author_id,
      0 as liked, 0 as likes_count, 0 as comments_count
    FROM posts p LEFT JOIN users u ON p.author_id = u.id
    WHERE p.id = ?
  `).get(info.lastInsertRowid);
  if (is_poll && poll_options?.length) {
    newPost.poll_options = db.prepare(`SELECT * FROM poll_options WHERE post_id=?`).all(info.lastInsertRowid);
  }
  if (newPost) { newPost.is_mine = true; newPost.reactions = []; newPost.my_reaction = null; }
  res.json(newPost || { id: info.lastInsertRowid });
  // Broadcast new post — strip is_mine so receivers don't think it's theirs
  if (newPost && isPublished) io.emit('new_post', { ...newPost, is_mine: false });
});

app.delete('/api/posts/:id', auth, (req, res) => {
  const r = db.prepare(`DELETE FROM posts WHERE id=? AND author_id=?`).run(req.params.id, req.user.id);
  if (r.changes > 0) io.emit('post_deleted', { postId: Number(req.params.id) });
  res.json({ ok: true });
});

app.patch('/api/posts/:id', auth, (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  const r = db.prepare(`UPDATE posts SET content=? WHERE id=? AND author_id=?`).run(content.trim(), req.params.id, req.user.id);
  if (!r.changes) return res.status(403).json({ error: 'Not found or not yours' });
  io.emit('post_edited', { postId: Number(req.params.id), content: content.trim() });
  res.json({ ok: true });
});

// Like toggle — accepts both POST and DELETE from client
function toggleLike(req, res) {
  const postId = req.params.id;
  const existing = db.prepare(`SELECT id FROM likes WHERE post_id=? AND user_id=?`).get(postId, req.user.id);
  if (existing) {
    db.prepare(`DELETE FROM likes WHERE post_id=? AND user_id=?`).run(postId, req.user.id);
    db.prepare(`UPDATE posts SET likes_count = MAX(0, likes_count-1) WHERE id=?`).run(postId);
  } else {
    db.prepare(`INSERT INTO likes (post_id, user_id) VALUES (?, ?)`).run(postId, req.user.id);
    db.prepare(`UPDATE posts SET likes_count = likes_count+1 WHERE id=?`).run(postId);
    const post = db.prepare(`SELECT author_id FROM posts WHERE id=?`).get(postId);
    if (post && post.author_id !== req.user.id) {
      const actor = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
      if (actor) createNotif(post.author_id, req.user.id, 'like', postId, `${actor.name} liked your post`);
    }
  }
  const updated = db.prepare(`SELECT likes_count FROM posts WHERE id=?`).get(postId);
  const result = { liked: !existing, likes_count: updated?.likes_count ?? 0 };
  // Broadcast updated like count to all users
  io.emit('post_liked', { postId: Number(postId), likes_count: result.likes_count });
  res.json(result);
}
app.post('/api/posts/:id/like', auth, toggleLike);
app.delete('/api/posts/:id/like', auth, toggleLike);

// ── REACTIONS ────────────────────────────────────────────────────────────────
const VALID_REACTIONS = ['like','love','insightful','celebrate','support'];
app.post('/api/posts/:id/react', auth, (req, res) => {
  const { reaction } = req.body;
  if (!VALID_REACTIONS.includes(reaction)) return res.status(400).json({ error: 'Invalid reaction' });
  const postId = req.params.id;
  const existing = db.prepare(`SELECT reaction_type FROM post_reactions WHERE post_id=? AND user_id=?`).get(postId, req.user.id);
  if (existing) {
    if (existing.reaction_type === reaction) {
      db.prepare(`DELETE FROM post_reactions WHERE post_id=? AND user_id=?`).run(postId, req.user.id);
    } else {
      db.prepare(`UPDATE post_reactions SET reaction_type=? WHERE post_id=? AND user_id=?`).run(reaction, postId, req.user.id);
    }
  } else {
    db.prepare(`INSERT INTO post_reactions (post_id, user_id, reaction_type) VALUES (?,?,?)`).run(postId, req.user.id, reaction);
  }
  const reactions = db.prepare(`SELECT reaction_type, COUNT(*) as count FROM post_reactions WHERE post_id=? GROUP BY reaction_type`).all(postId);
  const my_reaction = db.prepare(`SELECT reaction_type FROM post_reactions WHERE post_id=? AND user_id=?`).get(postId, req.user.id)?.reaction_type || null;
  io.emit('post_reacted', { postId: Number(postId), reactions, my_reaction_by: req.user.id, my_reaction });
  // Notify post author that their post got engagement (post impressions update)
  const reactedPost = db.prepare(`SELECT author_id FROM posts WHERE id=?`).get(postId);
  if (reactedPost?.author_id && reactedPost.author_id !== req.user.id) {
    _analyticsCache.delete(reactedPost.author_id);
    io.to(`user_${reactedPost.author_id}`).emit('analytics_update', { type: 'post_reaction' });
  }
  res.json({ reactions, my_reaction });
});

// ── CONTENT FLAGS / MODERATION ────────────────────────────────────────────────
app.post('/api/flag', auth, (req, res) => {
  const { content_type, content_id, reason } = req.body; // content_type: 'post'|'message'|'comment'
  if (!content_type || !content_id) return res.status(400).json({ error: 'Missing fields' });
  try {
    db.prepare(`INSERT INTO content_flags (content_type, content_id, reporter_id, reason) VALUES (?,?,?,?)`).run(content_type, content_id, req.user.id, reason || 'inappropriate');
  } catch { return res.json({ ok: true }); } // ignore duplicate flag
  // Count flags on this content item
  const flagCount = db.prepare(`SELECT COUNT(*) as n FROM content_flags WHERE content_type=? AND content_id=?`).get(content_type, content_id)?.n || 0;
  if (flagCount >= 3) {
    // Find who authored this content
    let authorId = null;
    if (content_type === 'post') { const p = db.prepare(`SELECT author_id FROM posts WHERE id=?`).get(content_id); authorId = p?.author_id; }
    else if (content_type === 'message') { const m = db.prepare(`SELECT sender_id FROM messages WHERE id=?`).get(content_id); authorId = m?.sender_id; }
    else if (content_type === 'comment') { const c = db.prepare(`SELECT author_id FROM comments WHERE id=?`).get(content_id); authorId = c?.author_id; }
    if (authorId && authorId !== req.user.id) {
      const warningCount = db.prepare(`SELECT warnings FROM users WHERE id=?`).get(authorId)?.warnings || 0;
      const newWarnings = warningCount + 1;
      if (newWarnings >= 5) {
        // Permanent disable
        db.prepare(`UPDATE users SET is_disabled=1 WHERE id=?`).run(authorId);
        io.to(`user_${authorId}`).emit('account_action', { type: 'disabled', message: 'Your account has been permanently disabled due to repeated violations.' });
      } else if (newWarnings >= 3) {
        // 24h block
        const until = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
        db.prepare(`UPDATE users SET blocked_until=?, warnings=? WHERE id=?`).run(until, newWarnings, authorId);
        io.to(`user_${authorId}`).emit('account_action', { type: 'blocked', until, message: `Your account has been suspended for 24 hours due to policy violations. (Warning ${newWarnings}/5)` });
      } else {
        // Warning
        db.prepare(`UPDATE users SET warnings=? WHERE id=?`).run(newWarnings, authorId);
        io.to(`user_${authorId}`).emit('account_action', { type: 'warning', message: `Warning ${newWarnings}/5: Content you posted was flagged as inappropriate. Repeated violations will result in suspension.` });
      }
    }
  }
  res.json({ ok: true });
});

app.post('/api/posts/:id/comments', auth, (req, res) => {
  const content = sanitize(req.body.content, 1000);
  const postId = req.params.id;
  if (!content) return res.status(400).json({ error: 'Comment cannot be empty' });
  const info = db.prepare(`INSERT INTO comments (post_id, author_id, content) VALUES (?, ?, ?)`).run(postId, req.user.id, content);
  db.prepare(`UPDATE posts SET comments_count = comments_count+1 WHERE id=?`).run(postId);
  const post = db.prepare(`SELECT author_id FROM posts WHERE id=?`).get(postId);
  const actor = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
  if (post && post.author_id !== req.user.id && actor) {
    createNotif(post.author_id, req.user.id, 'comment', postId, `${actor.name} commented on your post`);
    // Invalidate and push analytics update to post author
    _analyticsCache.delete(post.author_id);
    io.to(`user_${post.author_id}`).emit('analytics_update', { type: 'comment' });
  }
  const newCount = db.prepare(`SELECT comments_count FROM posts WHERE id=?`).get(postId)?.comments_count ?? 0;
  // Broadcast updated comment count to all users
  io.emit('post_commented', { postId: Number(postId), comments_count: newCount });
  res.json({ id: info.lastInsertRowid });
});

app.get('/api/posts/:id/comments', auth, (req, res) => {
  const comments = db.prepare(`
    SELECT c.*, u.name as author_name, u.avatar_url as author_avatar
    FROM comments c JOIN users u ON c.author_id=u.id
    WHERE c.post_id=? ORDER BY c.created_at ASC
  `).all(req.params.id);
  res.json(comments);
});

app.post('/api/posts/:id/poll/:optionId/vote', auth, (req, res) => {
  const { id: postId, optionId } = req.params;
  const existing = db.prepare(`SELECT option_id FROM poll_votes WHERE post_id=? AND user_id=?`).get(postId, req.user.id);
  if (existing) return res.status(400).json({ error: 'Already voted' });
  db.prepare(`INSERT INTO poll_votes (post_id, option_id, user_id) VALUES (?, ?, ?)`).run(postId, optionId, req.user.id);
  db.prepare(`UPDATE poll_options SET votes_count = votes_count+1 WHERE id=?`).run(optionId);
  const options = db.prepare(`SELECT * FROM poll_options WHERE post_id=?`).all(postId);
  // Broadcast poll update to all users
  io.emit('poll_voted', { postId: Number(postId), options });
  res.json({ options });
});

// ─── CONNECTIONS ─────────────────────────────────────────────────────────────

app.get('/api/connections', auth, (req, res) => {
  const conns = db.prepare(`
    SELECT u.id, u.name, u.headline, u.avatar_url, u.current_position
    FROM connections c
    JOIN users u ON (CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END) = u.id
    WHERE (c.requester_id=? OR c.addressee_id=?) AND c.status='accepted'
  `).all(req.user.id, req.user.id, req.user.id);
  res.json(conns);
});

app.get('/api/connections/requests', auth, (req, res) => {
  const reqs = db.prepare(`
    SELECT c.id as connection_id, u.id, u.name, u.headline, u.avatar_url, c.created_at
    FROM connections c JOIN users u ON c.requester_id = u.id
    WHERE c.addressee_id=? AND c.status='pending'
  `).all(req.user.id);
  res.json(reqs);
});

app.get('/api/connections/suggestions', auth, (req, res) => {
  const uid = req.user.id;
  // Show 2nd-degree (friends-of-friends) first, then everyone else not yet connected
  const suggestions = db.prepare(`
    SELECT u.id, u.name, u.headline, u.avatar_url, u.current_position,
      COUNT(DISTINCT bridge.mid) AS mutual_count,
      CASE WHEN COUNT(DISTINCT bridge.mid) > 0 THEN '2nd' ELSE '3rd' END AS degree
    FROM users u
    LEFT JOIN (
      SELECT CASE WHEN c1.requester_id=? THEN c1.addressee_id ELSE c1.requester_id END AS mid
      FROM connections c1
      WHERE (c1.requester_id=? OR c1.addressee_id=?) AND c1.status='accepted'
    ) AS myconn ON 1=1
    LEFT JOIN connections bridge2 ON bridge2.status='accepted' AND (
      (bridge2.requester_id = myconn.mid AND bridge2.addressee_id = u.id) OR
      (bridge2.addressee_id = myconn.mid AND bridge2.requester_id = u.id)
    )
    LEFT JOIN connections bridge ON bridge.status='accepted' AND (
      (bridge.requester_id = myconn.mid AND bridge.addressee_id = u.id) OR
      (bridge.addressee_id = myconn.mid AND bridge.requester_id = u.id)
    )
    WHERE u.id != ?
    AND u.id NOT IN (
      SELECT CASE WHEN requester_id=? THEN addressee_id ELSE requester_id END
      FROM connections WHERE (requester_id=? OR addressee_id=?) AND status IN ('accepted','pending')
    )
    GROUP BY u.id
    ORDER BY mutual_count DESC, RANDOM()
    LIMIT 20
  `).all(uid, uid, uid, uid, uid, uid, uid);
  res.json(suggestions);
});

app.post('/api/connections/:id', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  try {
    db.prepare(`INSERT INTO connections (requester_id, addressee_id) VALUES (?, ?)`).run(req.user.id, targetId);
    const actor = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
    createNotif(targetId, req.user.id, 'connection_request', req.user.id, `${actor.name} sent you a connection request`);
    res.json({ ok: true });
  } catch { res.status(400).json({ error: 'Already exists' }); }
});

app.put('/api/connections/:id', auth, (req, res) => {
  const { action } = req.body; // accept | decline
  const conn = db.prepare(`SELECT * FROM connections WHERE id=? AND addressee_id=?`).get(req.params.id, req.user.id);
  if (!conn) return res.status(404).json({ error: 'Not found' });
  if (action === 'accept') {
    db.prepare(`UPDATE connections SET status='accepted' WHERE id=?`).run(req.params.id);
    db.prepare(`UPDATE users SET connections_count=connections_count+1 WHERE id=? OR id=?`).run(conn.requester_id, conn.addressee_id);
    const actor = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
    createNotif(conn.requester_id, req.user.id, 'connection_accepted', req.user.id, `${actor.name} accepted your connection request`);
  } else {
    db.prepare(`DELETE FROM connections WHERE id=?`).run(req.params.id);
  }
  res.json({ ok: true });
});

app.delete('/api/connections/:id', auth, (req, res) => {
  db.prepare(`DELETE FROM connections WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)`).run(req.user.id, req.params.id, req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── MESSAGES ────────────────────────────────────────────────────────────────

app.get('/api/messages/threads', auth, (req, res) => {
  const uid = req.user.id;
  // MAX(id) per conversation pair guarantees the most recent message
  const threads = db.prepare(`
    SELECT
      u.id, u.name, u.avatar_url, u.headline,
      m.content as last_message, m.created_at,
      (SELECT COUNT(*) FROM messages x WHERE x.sender_id=u.id AND x.receiver_id=? AND x.is_read=0) as unread_count
    FROM messages m
    JOIN users u ON u.id = IIF(m.sender_id=?, m.receiver_id, m.sender_id)
    WHERE m.id IN (
      SELECT MAX(id) FROM messages
      WHERE sender_id=? OR receiver_id=?
      GROUP BY IIF(sender_id < receiver_id,
                   CAST(sender_id AS TEXT) || '_' || CAST(receiver_id AS TEXT),
                   CAST(receiver_id AS TEXT) || '_' || CAST(sender_id AS TEXT))
    )
    ORDER BY m.created_at DESC
  `).all(uid, uid, uid, uid);
  res.json(threads);
});

app.get('/api/messages/:userId', auth, (req, res) => {
  const otherId = req.params.userId;
  db.prepare(`UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=?`).run(otherId, req.user.id);
  const msgs = db.prepare(`
    SELECT m.*, u.name as sender_name, u.avatar_url as sender_avatar
    FROM messages m JOIN users u ON m.sender_id=u.id
    WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
    ORDER BY m.created_at ASC LIMIT 100
  `).all(req.user.id, otherId, otherId, req.user.id);
  res.json(msgs);
});

app.post('/api/messages/:userId', auth, (req, res) => {
  const { content } = req.body;
  const receiverId = req.params.userId;
  const info = db.prepare(`INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)`).run(req.user.id, receiverId, content);
  const sender = db.prepare(`SELECT name, avatar_url FROM users WHERE id=?`).get(req.user.id);
  const msg = { id: info.lastInsertRowid, sender_id: req.user.id, receiver_id: receiverId, content, sender_name: sender.name, sender_avatar: sender.avatar_url, created_at: new Date().toISOString(), is_read: 0 };
  const room = [req.user.id, receiverId].sort().join('-');
  io.to(room).emit('message', msg);
  // Also emit to receiver's personal room in case they haven't joined the chat room yet (new conversation)
  io.to(`user_${receiverId}`).emit('message', msg);
  res.json(msg);
});

app.patch('/api/messages/:id', auth, (req, res) => {
  const { content } = req.body;
  if (!content?.trim()) return res.status(400).json({ error: 'Content required' });
  const msg = db.prepare(`SELECT * FROM messages WHERE id=? AND sender_id=?`).get(req.params.id, req.user.id);
  if (!msg) return res.status(403).json({ error: 'Not found or not yours' });
  db.prepare(`UPDATE messages SET content=?, is_edited=1 WHERE id=?`).run(content.trim(), req.params.id);
  // Broadcast edit to both sides
  const room = [msg.sender_id, msg.receiver_id].sort().join('-');
  io.to(room).emit('message_edited', { id: Number(req.params.id), content: content.trim() });
  io.to(`user_${msg.receiver_id}`).emit('message_edited', { id: Number(req.params.id), content: content.trim() });
  res.json({ ok: true });
});

// ─── NOTIFICATIONS ───────────────────────────────────────────────────────────

app.get('/api/notifications', auth, (req, res) => {
  const notifs = db.prepare(`
    SELECT n.*, u.name as actor_name, u.avatar_url as actor_avatar
    FROM notifications n
    LEFT JOIN users u ON n.actor_id = u.id
    WHERE n.user_id=? ORDER BY n.created_at DESC LIMIT 50
  `).all(req.user.id);
  res.json(notifs);
});

app.get('/api/notifications/badges', auth, (req, res) => {
  const unread_notifications = db.prepare(`SELECT COUNT(*) as n FROM notifications WHERE user_id=? AND is_read=0`).get(req.user.id)?.n || 0;
  const unread_messages = db.prepare(`SELECT COUNT(*) as n FROM messages WHERE receiver_id=? AND is_read=0`).get(req.user.id)?.n || 0;
  const pending_connections = db.prepare(`SELECT COUNT(*) as n FROM connections WHERE addressee_id=? AND status='pending'`).get(req.user.id)?.n || 0;
  res.json({ unread_notifications, unread_messages, pending_connections });
});

app.put('/api/notifications/read-all', auth, (req, res) => {
  db.prepare(`UPDATE notifications SET is_read=1 WHERE user_id=?`).run(req.user.id);
  res.json({ ok: true });
});

app.put('/api/notifications/:id/read', auth, (req, res) => {
  db.prepare(`UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?`).run(req.params.id, req.user.id);
  res.json({ ok: true });
});

// ─── SALARY BOARD ────────────────────────────────────────────────────────────

app.get('/api/salary', auth, (req, res) => {
  const { company, role, city } = req.query;
  let query = `SELECT s.*, CASE WHEN s.is_anonymous=1 THEN 'Anonymous' ELSE u.name END as submitted_by FROM salary_entries s JOIN users u ON s.user_id=u.id WHERE 1=1`;
  const params = [];
  if (company) { query += ` AND s.company LIKE ?`; params.push(`%${company}%`); }
  if (role) { query += ` AND s.role LIKE ?`; params.push(`%${role}%`); }
  if (city) { query += ` AND s.city LIKE ?`; params.push(`%${city}%`); }
  query += ` ORDER BY s.created_at DESC LIMIT 50`;
  res.json(db.prepare(query).all(...params));
});

app.get('/api/salary/stats', auth, (req, res) => {
  const stats = db.prepare(`
    SELECT company, role,
      ROUND(AVG(salary_lpa), 1) as avg_salary,
      MIN(salary_lpa) as min_salary,
      MAX(salary_lpa) as max_salary,
      COUNT(*) as sample_count
    FROM salary_entries
    GROUP BY company, role
    HAVING sample_count >= 1
    ORDER BY avg_salary DESC LIMIT 30
  `).all();
  res.json(stats);
});

app.post('/api/salary', auth, (req, res) => {
  const { company, role, salary_lpa, experience_years, city, tech_stack, is_anonymous } = req.body;
  db.prepare(`INSERT INTO salary_entries (user_id, company, role, salary_lpa, experience_years, city, tech_stack, is_anonymous) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, company, role, salary_lpa, experience_years || 0, city || '', tech_stack || '', is_anonymous !== false ? 1 : 0);
  res.json({ ok: true });
});

app.patch('/api/salary/:id', auth, (req, res) => {
  const entry = db.prepare('SELECT * FROM salary_entries WHERE id=?').get(req.params.id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  if (entry.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  const { company, role, salary_lpa, experience_years, city, tech_stack, is_anonymous } = req.body;
  db.prepare('UPDATE salary_entries SET company=?,role=?,salary_lpa=?,experience_years=?,city=?,tech_stack=?,is_anonymous=? WHERE id=?')
    .run(company||entry.company, role||entry.role, salary_lpa||entry.salary_lpa, experience_years??entry.experience_years, city??entry.city, tech_stack??entry.tech_stack, is_anonymous!==undefined?+(is_anonymous):entry.is_anonymous, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/salary/:id', auth, (req, res) => {
  const entry = db.prepare('SELECT * FROM salary_entries WHERE id=?').get(req.params.id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  if (entry.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  db.prepare('DELETE FROM salary_entries WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ─── COMPANY REVIEWS ─────────────────────────────────────────────────────────

app.get('/api/reviews', auth, (req, res) => {
  const { company } = req.query;
  let query = `SELECT r.*, CASE WHEN r.is_anonymous=1 THEN 'Anonymous' ELSE u.name END as reviewer FROM company_reviews r JOIN users u ON r.user_id=u.id WHERE 1=1`;
  const params = [];
  if (company) { query += ` AND r.company LIKE ?`; params.push(`%${company}%`); }
  query += ` ORDER BY r.created_at DESC LIMIT 50`;
  res.json(db.prepare(query).all(...params));
});

app.get('/api/reviews/companies', auth, (req, res) => {
  const companies = db.prepare(`
    SELECT company,
      ROUND(AVG(overall_rating), 1) as avg_rating,
      ROUND(AVG(work_life_balance), 1) as avg_wlb,
      ROUND(AVG(culture), 1) as avg_culture,
      ROUND(AVG(salary_rating), 1) as avg_salary_rating,
      ROUND(AVG(growth), 1) as avg_growth,
      COUNT(*) as review_count,
      SUM(would_recommend) * 100 / COUNT(*) as recommend_pct
    FROM company_reviews
    GROUP BY company
    ORDER BY avg_rating DESC, review_count DESC LIMIT 30
  `).all();
  res.json(companies);
});

app.post('/api/reviews', auth, (req, res) => {
  const { company, overall_rating, title, pros, cons, work_life_balance, culture, salary_rating, growth, would_recommend, is_anonymous } = req.body;
  db.prepare(`INSERT INTO company_reviews (user_id, company, overall_rating, title, pros, cons, work_life_balance, culture, salary_rating, growth, would_recommend, is_anonymous) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(req.user.id, company, overall_rating, title || '', pros || '', cons || '', work_life_balance || 3, culture || 3, salary_rating || 3, growth || 3, would_recommend ? 1 : 0, is_anonymous !== false ? 1 : 0);
  res.json({ ok: true });
});

app.patch('/api/reviews/:id', auth, (req, res) => {
  const entry = db.prepare('SELECT * FROM company_reviews WHERE id=?').get(req.params.id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  if (entry.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  const { company, overall_rating, title, pros, cons, work_life_balance, culture, would_recommend, is_anonymous } = req.body;
  db.prepare('UPDATE company_reviews SET company=?,overall_rating=?,title=?,pros=?,cons=?,work_life_balance=?,culture=?,would_recommend=?,is_anonymous=? WHERE id=?')
    .run(company||entry.company, overall_rating||entry.overall_rating, title??entry.title, pros??entry.pros, cons??entry.cons, work_life_balance??entry.work_life_balance, culture??entry.culture, would_recommend!==undefined?+(would_recommend):entry.would_recommend, is_anonymous!==undefined?+(is_anonymous):entry.is_anonymous, req.params.id);
  res.json({ ok: true });
});
app.delete('/api/reviews/:id', auth, (req, res) => {
  const entry = db.prepare('SELECT * FROM company_reviews WHERE id=?').get(req.params.id);
  if (!entry) return res.status(404).json({ error: 'Not found' });
  if (entry.user_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  db.prepare('DELETE FROM company_reviews WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});

// ─── EXPERT / MOCK INTERVIEWS ─────────────────────────────────────────────────

// ── MENTOR SESSIONS (multi-session per mentor) ────────────────────────────
app.get('/api/mentor-sessions/mine', auth, (req, res) => {
  const sessions = db.prepare(`SELECT * FROM mentor_sessions WHERE user_id=? AND is_active=1 ORDER BY created_at DESC`).all(req.user.id);
  res.json(sessions.map(s => ({ ...s, availability_slots: JSON.parse(s.availability_slots || '[]') })));
});

app.post('/api/mentor-sessions', auth, (req, res) => {
  const { title, expertise, price_per_session, meeting_link, bio, availability_slots } = req.body;
  if (!title || !expertise) return res.status(400).json({ error: 'Title and expertise required' });
  const info = db.prepare(`INSERT INTO mentor_sessions (user_id, title, expertise, price_per_session, meeting_link, bio, availability_slots) VALUES (?,?,?,?,?,?,?)`)
    .run(req.user.id, title, expertise, price_per_session || 500, meeting_link || '', bio || '', JSON.stringify(availability_slots || []));
  // Ensure expert_profiles row exists (for rating tracking)
  const ep = db.prepare(`SELECT id FROM expert_profiles WHERE user_id=?`).get(req.user.id);
  if (!ep) db.prepare(`INSERT INTO expert_profiles (user_id, bio, expertise, price_per_session, meeting_link, availability_slots) VALUES (?,?,?,?,?,?)`)
    .run(req.user.id, bio || '', JSON.stringify([expertise]), price_per_session || 500, meeting_link || '', '[]');
  // Notify all clients a new session is available
  io.emit('experts_updated', { expertId: req.user.id });
  res.json({ id: info.lastInsertRowid, ok: true });
});

app.put('/api/mentor-sessions/:id', auth, (req, res) => {
  const ms = db.prepare(`SELECT * FROM mentor_sessions WHERE id=? AND user_id=?`).get(req.params.id, req.user.id);
  if (!ms) return res.status(404).json({ error: 'Not found' });
  const { title, expertise, price_per_session, meeting_link, bio, availability_slots } = req.body;
  const newSlots = availability_slots ?? JSON.parse(ms.availability_slots || '[]');
  db.prepare(`UPDATE mentor_sessions SET title=?, expertise=?, price_per_session=?, meeting_link=?, bio=?, availability_slots=? WHERE id=?`)
    .run(title ?? ms.title, expertise ?? ms.expertise, price_per_session ?? ms.price_per_session, meeting_link ?? ms.meeting_link, bio ?? ms.bio, JSON.stringify(newSlots), ms.id);
  // Broadcast slot change so all clients update immediately
  io.emit('mentor_slot_booked', { expertId: ms.user_id, sessionId: ms.id, slots: newSlots });
  io.emit('experts_updated', { expertId: ms.user_id });
  res.json({ ok: true });
});

app.delete('/api/mentor-sessions/:id', auth, (req, res) => {
  const ms = db.prepare(`SELECT id, user_id FROM mentor_sessions WHERE id=? AND user_id=?`).get(req.params.id, req.user.id);
  if (!ms) return res.status(404).json({ error: 'Not found' });
  db.prepare(`UPDATE mentor_sessions SET is_active=0 WHERE id=?`).run(ms.id);
  // Notify all clients to refresh experts list
  io.emit('experts_updated', { expertId: ms.user_id });
  res.json({ ok: true });
});

app.post('/api/mentor-sessions/:id/book-slot', auth, (req, res) => {
  const { slotKey } = req.body;
  if (!slotKey) return res.status(400).json({ error: 'slotKey is required' });
  // node:sqlite has no .transaction() — use explicit BEGIN/COMMIT/ROLLBACK
  let ms, slots, slot, sessionInfo;
  try {
    db.exec('BEGIN IMMEDIATE');
    try {
      ms = db.prepare('SELECT * FROM mentor_sessions WHERE id=? AND is_active=1').get(req.params.id);
      if (!ms) { db.exec('ROLLBACK'); return res.status(404).json({ error: 'Session not found' }); }
      if (ms.user_id === req.user.id) { db.exec('ROLLBACK'); return res.status(400).json({ error: 'Cannot book your own session' }); }
      slots = JSON.parse(ms.availability_slots || '[]');
      slot = slots.find(s => s.key === slotKey);
      if (!slot) { db.exec('ROLLBACK'); return res.status(404).json({ error: 'Slot not found' }); }
      if (slot.booked) { db.exec('ROLLBACK'); return res.status(409).json({ error: 'This slot was just booked by someone else. Please choose another.' }); }
      slot.booked = true; slot.booked_by = req.user.id;
      db.prepare('UPDATE mentor_sessions SET availability_slots=? WHERE id=?').run(JSON.stringify(slots), ms.id);
      sessionInfo = db.prepare('INSERT INTO interview_sessions (expert_id, learner_id, topic, session_type, scheduled_at, duration_minutes, meeting_link, price, slot_key, status, mentor_session_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(ms.user_id, req.user.id, ms.title, 'Mentorship', slotKey, 60, ms.meeting_link || '', ms.price_per_session || 500, slotKey, 'pending', ms.id);
      db.exec('COMMIT');
    } catch(innerE) {
      try { db.exec('ROLLBACK'); } catch(_) {}
      console.error('[book-slot] error:', innerE.message);
      return res.status(500).json({ error: 'Booking failed, please try again' });
    }
    const actor = db.prepare('SELECT name FROM users WHERE id=?').get(req.user.id);
    createNotif(ms.user_id, req.user.id, 'session_booked', sessionInfo.lastInsertRowid, actor.name + ' requested a "' + ms.title + '" session — please accept or decline');
    io.emit('mentor_slot_booked', { expertId: ms.user_id, sessionId: ms.id, slots });
    res.json({ ok: true, meeting_link: ms.meeting_link, session_id: sessionInfo.lastInsertRowid });
  } catch(e) {
    console.error('[book-slot] outer error:', e.message);
    return res.status(500).json({ error: 'Booking failed, please try again' });
  }
});

// ── EXPERTS (union of mentor_sessions + legacy expert_profiles) ──────────
app.get('/api/experts', auth, (req, res) => {
  // New sessions from mentor_sessions table
  const newSessions = db.prepare(`
    SELECT ms.id, ms.user_id, ms.title, ms.expertise, ms.price_per_session,
      ms.meeting_link, ms.bio, ms.availability_slots,
      u.name, u.headline, u.avatar_url, u.location,
      COALESCE(ep.rating, 0) as rating, COALESCE(ep.rating_count, 0) as rating_count,
      COALESCE(ep.total_sessions, 0) as total_sessions,
      'new' as source
    FROM mentor_sessions ms
    JOIN users u ON ms.user_id = u.id
    LEFT JOIN expert_profiles ep ON ep.user_id = ms.user_id
    WHERE ms.is_active=1
  `).all();

  // Legacy sessions from expert_profiles (only if user has no mentor_sessions)
  const legacySessions = db.prepare(`
    SELECT ep.id, ep.user_id, 'Mentorship Session' as title,
      ep.expertise, ep.price_per_session, ep.meeting_link, ep.bio,
      ep.availability_slots, u.name, u.headline, u.avatar_url, u.location,
      ep.rating, ep.rating_count, ep.total_sessions,
      'legacy' as source
    FROM expert_profiles ep
    JOIN users u ON ep.user_id = u.id
    WHERE ep.is_available=1
      AND ep.user_id NOT IN (SELECT user_id FROM mentor_sessions WHERE is_active=1)
  `).all();

  const all = [...newSessions, ...legacySessions]
    .map(s => ({
      ...s,
      expertise: typeof s.expertise === 'string' && s.expertise.startsWith('[')
        ? JSON.parse(s.expertise) : s.expertise,
      availability_slots: JSON.parse(s.availability_slots || '[]')
    }))
    .filter(s => s.availability_slots.some(sl => !sl.booked))
    .sort((a,b) => b.rating - a.rating);
  res.json(all);
});

app.get('/api/experts/me', auth, (req, res) => {
  // Check if user is a mentor (has any active mentor_sessions OR expert_profiles)
  const hasMs = db.prepare(`SELECT id FROM mentor_sessions WHERE user_id=? AND is_active=1 LIMIT 1`).get(req.user.id);
  const ep = db.prepare(`SELECT * FROM expert_profiles WHERE user_id=?`).get(req.user.id);
  if (!hasMs && !ep) return res.json(null);
  if (ep) return res.json({ ...ep, expertise: JSON.parse(ep.expertise || '[]'), session_types: JSON.parse(ep.session_types || '[]'), availability_slots: JSON.parse(ep.availability_slots || '[]') });
  return res.json({ user_id: req.user.id });
});

app.post('/api/experts/me', auth, (req, res) => {
  const { bio, expertise, session_types, price_per_session, meeting_link, availability_slots } = req.body;
  const existing = db.prepare(`SELECT id FROM expert_profiles WHERE user_id=?`).get(req.user.id);
  if (existing) {
    db.prepare(`UPDATE expert_profiles SET bio=?, expertise=?, session_types=?, price_per_session=?, meeting_link=?, availability_slots=? WHERE user_id=?`)
      .run(bio, JSON.stringify(expertise || []), JSON.stringify(session_types || []), price_per_session || 500, meeting_link || '', JSON.stringify(availability_slots || []), req.user.id);
  } else {
    db.prepare(`INSERT INTO expert_profiles (user_id, bio, expertise, session_types, price_per_session, meeting_link, availability_slots) VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(req.user.id, bio, JSON.stringify(expertise || []), JSON.stringify(session_types || []), price_per_session || 500, meeting_link || '', JSON.stringify(availability_slots || []));
  }
  res.json({ ok: true });
});

app.get('/api/sessions', auth, (req, res) => {
  const role = req.query.role; // 'expert' or 'learner'
  let query;
  if (role === 'expert') {
    query = `SELECT s.*, u.name as learner_name, u.avatar_url as learner_avatar FROM interview_sessions s JOIN users u ON s.learner_id=u.id WHERE s.expert_id=? ORDER BY s.scheduled_at DESC`;
  } else {
    query = `SELECT s.*, u.name as expert_name, u.avatar_url as expert_avatar FROM interview_sessions s JOIN users u ON s.expert_id=u.id WHERE s.learner_id=? ORDER BY s.scheduled_at DESC`;
  }
  res.json(db.prepare(query).all(req.user.id));
});

app.post('/api/sessions', auth, (req, res) => {
  const { expert_id, topic, session_type, scheduled_at, duration_minutes, learner_notes } = req.body;
  const expert = db.prepare(`SELECT price_per_session FROM expert_profiles WHERE user_id=?`).get(expert_id);
  const meetLink = `https://meet.jit.si/LinkedInPro-${Date.now()}`;
  const info = db.prepare(`INSERT INTO interview_sessions (expert_id, learner_id, topic, session_type, scheduled_at, duration_minutes, learner_notes, meeting_link, price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(expert_id, req.user.id, topic, session_type || 'Mock Interview', scheduled_at, duration_minutes || 60, learner_notes || '', meetLink, expert?.price_per_session || 500);
  const actor = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
  createNotif(expert_id, req.user.id, 'session_booked', info.lastInsertRowid, `${actor.name} booked a session with you`);
  res.json({ id: info.lastInsertRowid, meeting_link: meetLink });
});

app.put('/api/sessions/:id', auth, (req, res) => {
  const { status, feedback, rating } = req.body;
  const session = db.prepare(`SELECT * FROM interview_sessions WHERE id=?`).get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Not found' });
  const isExpert = session.expert_id === req.user.id;
  const isLearner = session.learner_id === req.user.id;
  if (!isExpert && !isLearner) return res.status(403).json({ error: 'Forbidden' });
  db.prepare(`UPDATE interview_sessions SET status=COALESCE(?,status), feedback=COALESCE(?,feedback), rating=COALESCE(?,rating) WHERE id=?`)
    .run(status||null, feedback||null, rating||null, req.params.id);
  const expertUser = db.prepare(`SELECT name FROM users WHERE id=?`).get(session.expert_id);
  const learnerUser = db.prepare(`SELECT name FROM users WHERE id=?`).get(session.learner_id);
  const _releaseSlot = () => {
    if (!session.slot_key) return;
    // Restore slot in mentor_sessions (new system) — use _sameSlot for timezone-tolerant matching
    const msId = session.mentor_session_id;
    if (msId) {
      const ms = db.prepare(`SELECT availability_slots FROM mentor_sessions WHERE id=?`).get(msId);
      if (ms) {
        const slots = JSON.parse(ms.availability_slots || '[]');
        const s = slots.find(x => _sameSlot(x.key, session.slot_key));
        if (s) { s.booked = false; delete s.booked_by; }
        db.prepare(`UPDATE mentor_sessions SET availability_slots=? WHERE id=?`).run(JSON.stringify(slots), msId);
        io.emit('mentor_slot_booked', { expertId: session.expert_id, sessionId: msId, slots });
      }
    } else {
      // No mentor_session_id: scan ALL mentor_sessions for this expert and release the matching slot
      const allMs = db.prepare(`SELECT id, availability_slots FROM mentor_sessions WHERE user_id=? AND is_active=1`).all(session.expert_id);
      allMs.forEach(ms => {
        const slots = JSON.parse(ms.availability_slots || '[]');
        const s = slots.find(x => _sameSlot(x.key, session.slot_key));
        if (s) {
          s.booked = false; delete s.booked_by;
          db.prepare(`UPDATE mentor_sessions SET availability_slots=? WHERE id=?`).run(JSON.stringify(slots), ms.id);
          io.emit('mentor_slot_booked', { expertId: session.expert_id, sessionId: ms.id, slots });
        }
      });
    }
    // Also restore in expert_profiles (legacy)
    const ep = db.prepare(`SELECT availability_slots FROM expert_profiles WHERE user_id=?`).get(session.expert_id);
    if (ep) {
      const slots = JSON.parse(ep.availability_slots || '[]');
      const s = slots.find(x => _sameSlot(x.key, session.slot_key));
      if (s) { s.booked = false; delete s.booked_by; }
      db.prepare(`UPDATE expert_profiles SET availability_slots=? WHERE user_id=?`).run(JSON.stringify(slots), session.expert_id);
    }
  };
  if (status === 'confirmed') {
    createNotif(session.learner_id, session.expert_id, 'session_confirmed', session.id, `${expertUser.name} accepted your session booking ✅`);
    io.to(`user_${session.learner_id}`).emit('session_update', { sessionId: session.id, status: 'confirmed' });
  } else if (status === 'cancelled') {
    _releaseSlot();
    const sessionMeta = { title: session.topic, scheduledAt: session.scheduled_at, expertName: expertUser?.name, learnerName: learnerUser?.name };
    if (isExpert) {
      createNotif(session.learner_id, session.expert_id, 'session_declined', session.id, `${expertUser.name} declined your "${session.topic}" session request`);
      io.to(`user_${session.learner_id}`).emit('session_update', { sessionId: session.id, status: 'cancelled', meta: sessionMeta, cancelledBy: 'expert' });
    } else {
      createNotif(session.expert_id, session.learner_id, 'session_cancelled', session.id, `${learnerUser.name} cancelled their "${session.topic}" session`);
      io.to(`user_${session.expert_id}`).emit('session_update', { sessionId: session.id, status: 'cancelled', meta: sessionMeta, cancelledBy: 'learner' });
    }
  }
  if (status === 'completed' && rating) {
    const ep = db.prepare(`SELECT rating, rating_count, total_sessions FROM expert_profiles WHERE user_id=?`).get(session.expert_id);
    const newCount = (ep.rating_count||0) + 1;
    const newRating = ((ep.rating||0) * (ep.rating_count||0) + rating) / newCount;
    db.prepare(`UPDATE expert_profiles SET rating=?, rating_count=?, total_sessions=total_sessions+1 WHERE user_id=?`).run(newRating.toFixed(1), newCount, session.expert_id);
  }
  res.json({ ok: true });
});

// Learner cancels a session
app.delete('/api/sessions/:id', auth, (req, res) => {
  const session = db.prepare(`SELECT * FROM interview_sessions WHERE id=?`).get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Not found' });
  if (session.learner_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  if (session.status === 'completed') return res.status(400).json({ error: 'Cannot cancel a completed session' });
  // Release slot — use _sameSlot for timezone-tolerant matching
  if (session.slot_key) {
    const msId = session.mentor_session_id;
    if (msId) {
      const ms = db.prepare(`SELECT availability_slots FROM mentor_sessions WHERE id=?`).get(msId);
      if (ms) {
        const slots = JSON.parse(ms.availability_slots || '[]');
        const s = slots.find(x => _sameSlot(x.key, session.slot_key));
        if (s) { s.booked = false; delete s.booked_by; }
        db.prepare(`UPDATE mentor_sessions SET availability_slots=? WHERE id=?`).run(JSON.stringify(slots), msId);
        io.emit('mentor_slot_booked', { expertId: session.expert_id, sessionId: msId, slots });
      }
    } else {
      // No mentor_session_id: scan all mentor_sessions for this expert
      const allMs = db.prepare(`SELECT id, availability_slots FROM mentor_sessions WHERE user_id=? AND is_active=1`).all(session.expert_id);
      allMs.forEach(ms => {
        const slots = JSON.parse(ms.availability_slots || '[]');
        const s = slots.find(x => _sameSlot(x.key, session.slot_key));
        if (s) {
          s.booked = false; delete s.booked_by;
          db.prepare(`UPDATE mentor_sessions SET availability_slots=? WHERE id=?`).run(JSON.stringify(slots), ms.id);
          io.emit('mentor_slot_booked', { expertId: session.expert_id, sessionId: ms.id, slots });
        }
      });
    }
    // Also release from expert_profiles (legacy)
    const ep = db.prepare(`SELECT availability_slots FROM expert_profiles WHERE user_id=?`).get(session.expert_id);
    if (ep) {
      const slots = JSON.parse(ep.availability_slots || '[]');
      const s = slots.find(x => _sameSlot(x.key, session.slot_key));
      if (s) { s.booked = false; delete s.booked_by; }
      db.prepare(`UPDATE expert_profiles SET availability_slots=? WHERE user_id=?`).run(JSON.stringify(slots), session.expert_id);
    }
  }
  db.prepare(`UPDATE interview_sessions SET status='cancelled' WHERE id=?`).run(session.id);
  const learner = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
  const expertUser = db.prepare(`SELECT name FROM users WHERE id=?`).get(session.expert_id);
  const sessionMeta = { title: session.topic, scheduledAt: session.scheduled_at, expertName: expertUser?.name, learnerName: learner?.name };
  createNotif(session.expert_id, req.user.id, 'session_cancelled', session.id, `${learner.name} cancelled their "${session.topic}" session`);
  io.to(`user_${session.expert_id}`).emit('session_update', { sessionId: session.id, status: 'cancelled', meta: sessionMeta, cancelledBy: 'learner' });
  res.json({ ok: true, meta: sessionMeta });
});

// Learner reschedules a session
app.patch('/api/sessions/:id/reschedule', auth, (req, res) => {
  const { new_slot_key } = req.body;
  const session = db.prepare(`SELECT * FROM interview_sessions WHERE id=?`).get(req.params.id);
  if (!session) return res.status(404).json({ error: 'Not found' });
  if (session.learner_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  if (['completed','cancelled'].includes(session.status)) return res.status(400).json({ error: 'Cannot reschedule this session' });
  const ep = db.prepare(`SELECT * FROM expert_profiles WHERE user_id=?`).get(session.expert_id);
  if (!ep) return res.status(404).json({ error: 'Expert not found' });
  const slots = JSON.parse(ep.availability_slots || '[]');
  const newSlot = slots.find(s => s.key === new_slot_key);
  if (!newSlot) return res.status(404).json({ error: 'Slot not found' });
  if (newSlot.booked) return res.status(400).json({ error: 'That slot is already booked' });
  // Release old slot
  if (session.slot_key) {
    const old = slots.find(s => s.key === session.slot_key);
    if (old) { old.booked = false; delete old.booked_by; }
  }
  // Reserve new slot
  newSlot.booked = true; newSlot.booked_by = req.user.id;
  db.prepare(`UPDATE expert_profiles SET availability_slots=? WHERE user_id=?`).run(JSON.stringify(slots), session.expert_id);
  db.prepare(`UPDATE interview_sessions SET scheduled_at=?, slot_key=?, status='pending' WHERE id=?`).run(new_slot_key, new_slot_key, session.id);
  const learner = db.prepare(`SELECT name FROM users WHERE id=?`).get(req.user.id);
  const _sd = new Date(new_slot_key);
  const _months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
  const _days = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];
  const readableSlot = `${_days[_sd.getUTCDay()]}, ${_sd.getUTCDate()} ${_months[_sd.getUTCMonth()]} at ${String(_sd.getUTCHours()).padStart(2,'0')}:${String(_sd.getUTCMinutes()).padStart(2,'0')}`;
  createNotif(session.expert_id, req.user.id, 'session_rescheduled', session.id, `${learner.name} rescheduled their session to ${readableSlot} — please confirm`);
  io.emit('mentor_slot_booked', { expertId: session.expert_id, slots });
  res.json({ ok: true });
});

// ─── JOBS ─────────────────────────────────────────────────────────────────────

app.get('/api/jobs', auth, (req, res) => {
  const { search, type } = req.query;
  let query = `SELECT j.*, u.name as poster_name, u.avatar_url as poster_avatar FROM jobs j JOIN users u ON j.poster_id=u.id WHERE j.is_active=1`;
  const params = [];
  if (search) { query += ` AND (j.title LIKE ? OR j.company LIKE ? OR j.description LIKE ?)`; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }
  if (type) { query += ` AND j.job_type=?`; params.push(type); }
  query += ` ORDER BY j.created_at DESC LIMIT 50`;
  const jobs = db.prepare(query).all(...params);
  const withApplied = jobs.map(j => ({
    ...j,
    applied: !!db.prepare(`SELECT 1 FROM job_applications WHERE job_id=? AND applicant_id=?`).get(j.id, req.user.id)
  }));
  res.json(withApplied);
});

app.post('/api/jobs', auth, (req, res) => {
  const { title, company, location, job_type, salary_range, description, requirements } = req.body;
  const info = db.prepare(`INSERT INTO jobs (poster_id, title, company, location, job_type, salary_range, description, requirements) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(req.user.id, title, company, location, job_type||'Full-time', salary_range, description, requirements);
  const poster = db.prepare(`SELECT name, avatar_url FROM users WHERE id=?`).get(req.user.id);
  res.json({ id: info.lastInsertRowid, title, company, location, job_type, salary_range, description, requirements, poster_name: poster.name, poster_avatar: poster.avatar_url, applications_count: 0 });
});

app.post('/api/jobs/:id/apply', auth, (req, res) => {
  const { cover_letter } = req.body;
  try {
    db.prepare(`INSERT INTO job_applications (job_id, applicant_id, cover_letter) VALUES (?, ?, ?)`).run(req.params.id, req.user.id, cover_letter||'');
    db.prepare(`UPDATE jobs SET applications_count=applications_count+1 WHERE id=?`).run(req.params.id);
    res.json({ ok: true });
  } catch { res.status(400).json({ error: 'Already applied' }); }
});

app.patch('/api/jobs/:id', auth, (req, res) => {
  const job = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Not found' });
  if (job.poster_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  const { title, company, location, job_type, salary_range, description, requirements } = req.body;
  db.prepare('UPDATE jobs SET title=COALESCE(?,title), company=COALESCE(?,company), location=COALESCE(?,location), job_type=COALESCE(?,job_type), salary_range=COALESCE(?,salary_range), description=COALESCE(?,description), requirements=COALESCE(?,requirements) WHERE id=?')
    .run(title||null, company||null, location||null, job_type||null, salary_range||null, description||null, requirements||null, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/jobs/:id', auth, (req, res) => {
  const job = db.prepare('SELECT * FROM jobs WHERE id=?').get(req.params.id);
  if (!job) return res.status(404).json({ error: 'Not found' });
  if (job.poster_id !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
  db.prepare('UPDATE jobs SET is_active=0 WHERE id=?').run(req.params.id);
  res.json({ ok: true });
});



app.post('/api/auth/reset-by-email', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password || password.length < 6) return res.status(400).json({ error: 'Email and password (min 6 chars) required' });
  const user = db.prepare('SELECT id FROM users WHERE email=?').get(email);
  if (!user) return res.status(400).json({ error: 'No account found with that email' });
  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password=? WHERE id=?').run(hash, user.id);
  res.json({ ok: true });
});

// ── FORGOT PASSWORD (token-based, legacy) ─────────────────────────────────────
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  const user = db.prepare('SELECT id, name FROM users WHERE email=?').get(email);
  if (!user) return res.json({ ok: true }); // don't reveal if email exists
  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 60 * 60 * 1000).toISOString();
  db.prepare('INSERT OR REPLACE INTO password_resets (user_id, token, expires_at) VALUES (?,?,?)').run(user.id, token, expires);
  const resetUrl = `${APP_URL}/reset-password?token=${token}`;
  await sendEmail(email, 'Reset your Nexus password', `<p>Hi ${user.name},</p><p><a href="${resetUrl}">Click here to reset your password</a></p><p>This link expires in 1 hour.</p>`);
  res.json({ ok: true, message: 'If that email exists, a reset link was sent.' });
});

app.get('/api/auth/reset-password/:token', (req, res) => {
  const row = db.prepare('SELECT * FROM password_resets WHERE token=?').get(req.params.token);
  if (!row || new Date(row.expires_at + 'Z') < new Date()) return res.status(400).json({ error: 'Reset link expired or invalid.' });
  res.json({ ok: true });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password || password.length < 6) return res.status(400).json({ error: 'Token and password (min 6 chars) required' });
  const row = db.prepare('SELECT * FROM password_resets WHERE token=?').get(token);
  if (!row || new Date(row.expires_at + 'Z') < new Date()) return res.status(400).json({ error: 'Reset link expired. Request a new one.' });
  const hash = await bcrypt.hash(password, 10);
  db.prepare('UPDATE users SET password=? WHERE id=?').run(hash, row.user_id);
  db.prepare('DELETE FROM password_resets WHERE user_id=?').run(row.user_id);
  res.json({ ok: true, message: 'Password updated successfully.' });
});

// SOCKET.IO
const onlineUsers = new Map();

io.on('connection', socket => {
  socket.on('authenticate', token => {
    try {
      const { id } = jwt.verify(token, JWT_SECRET);
      socket.userId = id;
      socket.join(`user_${id}`);
      const partners = db.prepare('SELECT DISTINCT CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END as partner_id FROM messages WHERE sender_id=? OR receiver_id=?').all(id, id, id);
      partners.forEach(({ partner_id }) => socket.join([id, partner_id].sort().join('-')));
      if (!onlineUsers.has(id)) onlineUsers.set(id, new Set());
      onlineUsers.get(id).add(socket.id);
      partners.forEach(({ partner_id }) => io.to(`user_${partner_id}`).emit('user_online', { userId: id }));
      const onlineNow = partners.map(p => p.partner_id).filter(pid => onlineUsers.has(pid) && onlineUsers.get(pid).size > 0);
      socket.emit('online_users', onlineNow);
    } catch {}
  });
  socket.on('join_chat', otherId => {
    if (!socket.userId) return;
    socket.join([socket.userId, otherId].sort().join('-'));
  });
  socket.on('typing', ({ to }) => {
    if (!socket.userId) return;
    socket.to([socket.userId, to].sort().join('-')).emit('typing', { from: socket.userId });
  });
  socket.on('stop_typing', ({ to }) => {
    if (!socket.userId) return;
    socket.to([socket.userId, to].sort().join('-')).emit('stop_typing', { from: socket.userId });
  });
  socket.on('mark_read', ({ from }) => {
    if (!socket.userId || !from) return;
    db.prepare('UPDATE messages SET is_read=1 WHERE sender_id=? AND receiver_id=? AND is_read=0').run(from, socket.userId);
    io.to(`user_${from}`).emit('read_receipt', { by: socket.userId });
  });
  socket.on('get_presence', ({ userId }) => {
    const online = onlineUsers.has(userId) && onlineUsers.get(userId).size > 0;
    socket.emit(online ? 'user_online' : 'user_offline', { userId });
  });
  socket.on('disconnect', () => {
    if (!socket.userId) return;
    const sockets = onlineUsers.get(socket.userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(socket.userId);
        const partners = db.prepare('SELECT DISTINCT CASE WHEN sender_id=? THEN receiver_id ELSE sender_id END as partner_id FROM messages WHERE sender_id=? OR receiver_id=?').all(socket.userId, socket.userId, socket.userId);
        partners.forEach(({ partner_id }) => io.to(`user_${partner_id}`).emit('user_offline', { userId: socket.userId }));
      }
    }
  });
});

server.listen(PORT, () => console.log(`Nexus running on port ${PORT}`))
// ── ANALYTICS ─────────────────────────────────────────────────────────────
const _analyticsCache = new Map();
app.get('/api/analytics/me', auth, (req, res) => {
  const uid = req.user.id;
  const hit = _analyticsCache.get(uid);
  if (hit && Date.now() - hit.ts < 60000) return res.json(hit.data);
  const views = db.prepare('SELECT COUNT(*) as c FROM profile_views WHERE profile_id=? AND viewed_at > datetime("now","-30 days")').get(uid);
  // Single query: count reactions and comments for all user posts at once
  const row = db.prepare(`
    SELECT
      COUNT(DISTINCT pr.id) as rx_count,
      COUNT(DISTINCT c.id)  as cm_count,
      COUNT(DISTINCT p.id)  as post_count
    FROM posts p
    LEFT JOIN post_reactions pr ON pr.post_id = p.id
    LEFT JOIN comments c ON c.post_id = p.id
    WHERE p.author_id = ?
  `).get(uid);
  const impressions = (row?.rx_count || 0) * 8 + (row?.cm_count || 0) * 12 + (row?.post_count || 0) * 5;
  const data = { profile_views: views?.c || 0, post_impressions: impressions };
  _analyticsCache.set(uid, { data, ts: Date.now() });
  res.json(data);
});

// ── PROFILE VIEW TRACKING ─────────────────────────────────────────────────
app.post('/api/users/:id/view', auth, (req, res) => {
  const profileId = parseInt(req.params.id);
  if (profileId === req.user.id) return res.json({ ok: true });
  try {
    db.prepare('INSERT INTO profile_views (profile_id, viewer_id) VALUES (?, ?)').run(profileId, req.user.id);
    // Invalidate server-side analytics cache for the profile owner
    _analyticsCache.delete(profileId);
    // Push real-time notification to the profile owner
    io.to(`user_${profileId}`).emit('analytics_update', { type: 'profile_view' });
  } catch(e) {}
  res.json({ ok: true });
});

// ── FOLLOWERS ─────────────────────────────────────────────────────────────
app.get('/api/users/:id/follow', auth, (req, res) => {
  const row = db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id, req.params.id);
  res.json({ following: !!row });
});
app.post('/api/users/:id/follow', auth, (req, res) => {
  const targetId = parseInt(req.params.id);
  if (targetId === req.user.id) return res.status(400).json({ error: 'Cannot follow yourself' });
  const existing = db.prepare('SELECT id FROM follows WHERE follower_id=? AND following_id=?').get(req.user.id, targetId);
  if (existing) {
    db.prepare('DELETE FROM follows WHERE follower_id=? AND following_id=?').run(req.user.id, targetId);
    res.json({ following: false });
  } else {
    db.prepare('INSERT OR IGNORE INTO follows (follower_id, following_id) VALUES (?,?)').run(req.user.id, targetId);
    const actor = db.prepare('SELECT name FROM users WHERE id=?').get(req.user.id);
    if (actor) createNotif(targetId, req.user.id, 'follow', 0, `${actor.name} started following you`);
    res.json({ following: true });
  }
});
app.get('/api/users/:id/followers', auth, (req, res) => {
  const rows = db.prepare('SELECT u.id, u.name, u.headline, u.avatar_url FROM follows f JOIN users u ON f.follower_id=u.id WHERE f.following_id=? LIMIT 50').all(req.params.id);
  res.json(rows);
});
app.get('/api/users/:id/following', auth, (req, res) => {
  const rows = db.prepare('SELECT u.id, u.name, u.headline, u.avatar_url FROM follows f JOIN users u ON f.following_id=u.id WHERE f.follower_id=? LIMIT 50').all(req.params.id);
  res.json(rows);
});

// ── SAVED POSTS ───────────────────────────────────────────────────────────
app.post('/api/posts/:id/save', auth, (req, res) => {
  const postId = parseInt(req.params.id);
  const existing = db.prepare('SELECT id FROM saved_posts WHERE user_id=? AND post_id=?').get(req.user.id, postId);
  if (existing) {
    db.prepare('DELETE FROM saved_posts WHERE user_id=? AND post_id=?').run(req.user.id, postId);
    res.json({ saved: false });
  } else {
    db.prepare('INSERT OR IGNORE INTO follows (follower_id, following_id) VALUES (?,?)').run(req.user.id, targetId);
    const actor = db.prepare('SELECT name FROM users WHERE id=?').get(req.user.id);
    if (actor) createNotif(targetId, req.user.id, 'follow', 0, `${actor.name} started following you`);
    res.json({ following: true });
  }
});
app.get('/api/users/:id/followers', auth, (req, res) => {
  const rows = db.prepare('SELECT u.id, u.name, u.headline, u.avatar_url FROM follows f JOIN users u ON f.follower_id=u.id WHERE f.following_id=? LIMIT 50').all(req.params.id);
  res.json(rows);
});
app.get('/api/users/:id/following', auth, (req, res) => {
  const rows = db.prepare('SELECT u.id, u.name, u.headline, u.avatar_url FROM follows f JOIN users u ON f.following_id=u.id WHERE f.follower_id=? LIMIT 50').all(req.params.id);
  res.json(rows);
});

// ── SAVED POSTS ───────────────────────────────────────────────────────────
app.post('/api/posts/:id/save', auth, (req, res) => {
  const postId = parseInt(req.params.id);
  const existing = db.prepare('SELECT id FROM saved_posts WHERE user_id=? AND post_id=?').get(req.user.id, postId);
  if (existing) {
    db.prepare('DELETE FROM saved_posts WHERE user_id=? AND post_id=?').run(req.user.id, postId);
    res.json({ saved: false });
  } else {
    db.prepare('INSERT OR IGNORE INTO saved_posts (user_id, post_id) VALUES (?,?)').run(req.user.id, postId);
    res.json({ saved: true });
  }
});
app.get('/api/posts/saved', auth, (req, res) => {
  const uid = req.user.id;
  const rows = db.prepare(`
    SELECT p.*, u.name as author_name, u.avatar_url as author_avatar, u.headline as author_headline,
      CASE WHEN p.is_anonymous=1 AND p.author_id!=? THEN NULL ELSE p.author_id END as author_id,
      (p.author_id=? OR p.is_anonymous=0) as show_author,
      (p.author_id=?) as is_mine,
      (SELECT COUNT(*) FROM likes WHERE post_id=p.id) as likes_count,
      (SELECT COUNT(*) FROM comments WHERE post_id=p.id) as comments_count,
      1 as is_saved
    FROM saved_posts sp JOIN posts p ON sp.post_id=p.id LEFT JOIN users u ON p.author_id=u.id
    WHERE sp.user_id=? AND p.is_published=1
    ORDER BY sp.created_at DESC LIMIT 50
  `).all(uid, uid, uid, uid);
  res.json(rows.map(p => ({ ...p, reactions: [], my_reaction: null, is_saved: true })));
});

// ── TRENDING TOPICS ───────────────────────────────────────────────────────
let _trendingCache = null, _trendingTs = 0;
app.get('/api/trending', auth, (req, res) => {
  // Serve from cache if < 5 minutes old
  if (_trendingCache && Date.now() - _trendingTs < 5 * 60 * 1000) {
    return res.json(_trendingCache);
  }
  const topPosts = db.prepare(`
    SELECT p.id, p.content, u.name as author_name, u.avatar_url as author_avatar,
      COUNT(pr.id) as reaction_count, COUNT(DISTINCT c.id) as comment_count
    FROM posts p
    LEFT JOIN users u ON p.author_id=u.id
    LEFT JOIN post_reactions pr ON pr.post_id=p.id
    LEFT JOIN comments c ON c.post_id=p.id
    WHERE p.is_published=1 AND p.is_anonymous=0
      AND p.created_at > datetime('now','-7 days')
    GROUP BY p.id
    ORDER BY reaction_count DESC, comment_count DESC
    LIMIT 5
  `).all();
  const tagRows = db.prepare(`
    SELECT content FROM posts
    WHERE is_published=1 AND created_at > datetime('now','-7 days')
    AND content LIKE '%#%'
    LIMIT 500
  `).all();
  const tagCount = {};
  tagRows.forEach(p => {
    const tags = (p.content || '').match(/#[\w]+/g) || [];
    tags.forEach(t => { tagCount[t.toLowerCase()] = (tagCount[t.toLowerCase()] || 0) + 1; });
  });
  const trending_tags = Object.entries(tagCount).sort((a,b)=>b[1]-a[1]).slice(0,8).map(([tag, count]) => ({ tag, count }));
  _trendingCache = { top_posts: topPosts, trending_tags };
  _trendingTs = Date.now();
  res.json(_trendingCache);
});
