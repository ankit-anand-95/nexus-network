# Nexus Network — Comprehensive Technical Documentation

> Full technical reference: architecture, features, system design decisions, performance tradeoffs, and code-level implementation details.

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Tech Stack](#2-tech-stack)
3. [High-Level Architecture](#3-high-level-architecture)
4. [Database Design](#4-database-design)
5. [Backend — API Layer](#5-backend--api-layer)
6. [Real-Time Layer (Socket.io)](#6-real-time-layer-socketio)
7. [Frontend Architecture (SPA)](#7-frontend-architecture-spa)
8. [Feature Implementations](#8-feature-implementations)
9. [Performance Engineering](#9-performance-engineering)
10. [Security Implementation](#10-security-implementation)
11. [System Design Decisions & Tradeoffs](#11-system-design-decisions--tradeoffs)
12. [Deployment (Railway)](#12-deployment-railway)

---

## 1. Project Overview

Nexus is a full-stack professional networking platform (LinkedIn-like) built as a single deployable Node.js application. It includes a social feed, messaging, job board, salary transparency board, company reviews, a peer mentorship/booking system, and real-time notifications — all in one codebase.

**Design goal:** Ship a feature-rich platform with zero external services (no Redis, no separate job queue, no CDN required) that runs on a single Railway dyno with a persistent volume.

---

## 2. Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Runtime | Node.js 22 | Built-in SQLite (`node:sqlite`) — no npm driver needed |
| Web framework | Express 4 | Mature, minimal, low overhead |
| Real-time | Socket.io 4 | WebSocket with automatic polling fallback |
| Database | SQLite (WAL mode) | Zero-setup, file-based, persistent on Railway volume |
| Auth | JWT (jsonwebtoken) | Stateless; no session store needed |
| Password hashing | bcryptjs | Safe bcrypt in pure JS (no native bindings) |
| Security headers | helmet | One-line hardened HTTP headers |
| Rate limiting | express-rate-limit | In-process; no Redis needed at this scale |
| Input validation | validator.js | Email, URL, string sanitization |
| File uploads | multer | Disk storage, MIME whitelist, 5 MB cap |
| Email | nodemailer | Optional SMTP; gracefully disabled if not configured |
| Frontend | Vanilla JS SPA | Zero framework, zero build step, instant deploy |

---

## 3. High-Level Architecture

```
Browser
  │
  │  HTTP (REST + static files)
  │  WebSocket (Socket.io)
  ▼
Express Server  (server.js — single process)
  ├── Middleware stack: helmet → CORS → JSON parser → rate limiters → static
  ├── Auth middleware (JWT verify + account status check)
  ├── REST API routes (~60 endpoints)
  ├── Socket.io server (same HTTP server, shared port)
  └── Background timers (auto-cancel pending bookings every 30s)
  │
  ▼
SQLite (WAL mode)  ←── db.js bootstraps schema + migrations + indexes
  │
  ▼
Railway Persistent Volume  /data/nexus.db  +  /data/uploads/
```

**Single-process, single-file design.** Everything — web server, WebSocket server, background jobs, file serving — runs in one Node.js process. This keeps operational complexity near zero and is appropriate for a platform in early/growth stage.

---

## 4. Database Design

### 4.1 Engine Choice: SQLite in WAL Mode

```javascript
// db.js
db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');
```

**WAL (Write-Ahead Logging):** Readers don't block writers and vice-versa. Critical for a web app where multiple requests hit the DB concurrently. Default journal mode (DELETE) would serialize all reads and writes.

**Foreign keys ON:** Referential integrity enforced at the DB level — cascading deletes ensure no orphan rows (e.g., when a post is deleted, its comments, reactions, and saves are automatically removed).

**Tradeoff:** SQLite is single-writer. Under extremely high write concurrency it would bottleneck. For the current scale (hobby/startup) it handles thousands of requests/day with ease. Migration path to PostgreSQL would need prepared statements rewritten (SQLite uses `?` placeholders; Postgres uses `$1, $2`).

### 4.2 Schema Overview

**20 tables** covering all domain entities:

```
users               — core profile, auth, moderation fields
experiences         — work history (CASCADE → users)
education           — education history (CASCADE → users)
user_skills         — skill tags (CASCADE → users)
posts               — feed posts, anonymous flag, poll flag, scheduled flag
poll_options        — poll choices (CASCADE → posts)
poll_votes          — one vote per user per post (UNIQUE constraint)
likes               — post likes (UNIQUE constraint prevents duplicates)
post_reactions      — 5-type reactions: like/love/insightful/celebrate/support
comments            — post comments (CASCADE → posts)
connections         — directed graph: requester → addressee, status: pending/accepted
messages            — DMs between users, read flag, edit flag
notifications       — in-app notifications with actor, type, reference
salary_entries      — anonymous salary submissions
company_reviews     — multi-dimension ratings (overall, WLB, culture, growth, salary)
expert_profiles     — legacy mentor profile (one per user)
mentor_sessions     — new multi-session mentor listings with JSON slot state
interview_sessions  — bookings linking learner ↔ expert with status lifecycle
jobs                — job postings with applications count
job_applications    — applicant ↔ job, UNIQUE prevents duplicate apply
saved_posts         — bookmarked posts per user
follows             — follower graph (separate from connections)
profile_views       — who viewed whose profile, with date deduplication
post_views          — impression tracking (UNIQUE: one view per viewer per post)
password_resets     — token-based reset (legacy, token expires in 1 hour)
content_flags       — abuse reports with UNIQUE(content_type, content_id, reporter_id)
```

### 4.3 Key Schema Decisions

**`connections` table — directed graph, not symmetric:**
```sql
CREATE TABLE connections (
  requester_id INTEGER,
  addressee_id INTEGER,
  status TEXT DEFAULT 'pending',
  UNIQUE(requester_id, addressee_id)
)
```
One row represents the connection. `status` transitions: `pending` → `accepted`. Queries must check both directions: `(requester_id=? OR addressee_id=?)`. The UNIQUE constraint is on the directed pair — you can't send two requests to the same person.

**`connections_count` denormalized counter on `users`:**
Instead of `SELECT COUNT(*) FROM connections WHERE ...` on every profile load, a counter is maintained:
- Incremented on `PUT /api/connections/:id` (accept)
- Decremented on `DELETE /api/connections/:id` (only if status was `accepted`)
- `MAX(0, count-1)` prevents going negative

**`welcome_for_user_id` on posts:**
```sql
ALTER TABLE posts ADD COLUMN welcome_for_user_id INTEGER DEFAULT NULL
```
The system bot posts a welcome post that's only visible to the new user. Feed query includes `p.welcome_for_user_id = ?` so it shows up in that user's feed but not anyone else's.

**`availability_slots` stored as JSON in `mentor_sessions`:**
```sql
availability_slots TEXT DEFAULT '[]'
```
Slots are a JSON array stored in a TEXT column. Each slot object has: `key` (ISO timestamp), `booked` (bool), `booked_by` (user id), `pending` (bool), `pending_by`, `pending_until` (epoch ms for auto-cancel timeout). This avoids a separate slots table and complex joins for a feature with variable slot counts.

**Tradeoff:** JSON in SQLite means you can't query individual slot properties with SQL indexes. The full array must be fetched and parsed in JS. Acceptable because a mentor typically has 10–50 slots, not thousands.

### 4.4 Migrations Strategy

Migrations are run on every server startup:

```javascript
const migrations = [
  `ALTER TABLE users ADD COLUMN warnings INTEGER DEFAULT 0`,
  `ALTER TABLE posts ADD COLUMN welcome_for_user_id INTEGER DEFAULT NULL`,
  `ALTER TABLE users ADD COLUMN nx_template TEXT DEFAULT NULL`,
  // ...
];
migrations.forEach(sql => {
  try { db.exec(sql); } catch(e) { /* column already exists — safe to ignore */ }
});
```

**Pattern:** Every `ALTER TABLE ADD COLUMN` is idempotent — it fails silently if the column already exists. This means new columns can be added to an existing production database without a separate migration tool or downtime.

**Tradeoff:** No rollback. Columns added this way can't be removed via migration (SQLite doesn't support `DROP COLUMN` in older versions). Acceptable at this scale — unused columns just sit there.

### 4.5 Indexes

15 indexes covering all hot query paths:

```sql
-- Feed query
CREATE INDEX idx_posts_published_created ON posts(is_published, created_at DESC)
CREATE INDEX idx_posts_author ON posts(author_id)

-- Connection graph traversal
CREATE INDEX idx_connections_requester ON connections(requester_id, status)
CREATE INDEX idx_connections_addressee ON connections(addressee_id, status)

-- Reactions (grouped per post)
CREATE INDEX idx_post_reactions_post ON post_reactions(post_id, reaction_type)
CREATE INDEX idx_post_reactions_user ON post_reactions(post_id, user_id)

-- Comments
CREATE INDEX idx_comments_post ON comments(post_id, created_at DESC)

-- Messages (thread query)
CREATE INDEX idx_messages_thread ON messages(sender_id, receiver_id, created_at DESC)

-- Notifications
CREATE INDEX idx_notifications_user ON notifications(user_id, created_at DESC)

-- Analytics
CREATE INDEX idx_profile_views_profile ON profile_views(profile_id, viewed_at DESC)
CREATE INDEX idx_post_views_post ON post_views(post_id)
CREATE INDEX idx_post_views_viewer ON post_views(viewer_id)
```

All index creations use `IF NOT EXISTS` and are wrapped in try/catch, so they're safe to re-run on every boot.

### 4.6 Self-Healing Slot Sync

A startup IIFE in `db.js` reconciles mentor slot state against the `interview_sessions` table:

```javascript
(function healSlots() {
  // For every slot in every mentor_sessions row:
  // Query interview_sessions to find confirmed/pending sessions
  // Fix any mismatch between JSON slot flags and DB reality
})();
```

**Why:** If the server crashed mid-booking, a slot could be marked `booked: true` in JSON but have no confirmed session in the DB. This healer fixes it on next boot, making the system self-correcting without manual intervention.

---

## 5. Backend — API Layer

### 5.1 Middleware Stack (applied in order)

```javascript
app.use(helmet({ contentSecurityPolicy: false }))  // security headers
app.use(cors())                                     // cross-origin
app.use(express.json({ limit: '2mb' }))            // body parsing with size cap
app.use(express.static('public'))                   // serve frontend
app.use('/api/auth', authLimiter)                   // 20 req / 15min per IP
app.use('/api/upload', uploadLimiter)               // 10 uploads / min per IP
app.use('/api', apiLimiter)                         // 300 req / min per IP
```

Rate limiters cascade — `/api/auth` routes get both the auth limiter and the general API limiter.

### 5.2 Auth Middleware

```javascript
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  req.user = jwt.verify(token, JWT_SECRET);
  // Always re-check account status on every request:
  const u = db.prepare('SELECT is_disabled, blocked_until FROM users WHERE id=?').get(req.user.id);
  if (u?.is_disabled) return res.status(403).json({ error: 'Account disabled', code: 'DISABLED' });
  if (u?.blocked_until && new Date(u.blocked_until) > new Date())
    return res.status(403).json({ error: 'Account suspended until ...' });
  next();
};
```

**Key design:** Account status is checked on *every authenticated request*, not just login. This means a banned user is immediately locked out — their existing JWT becomes unusable within one request. No token blacklist or session store needed.

### 5.3 Complete API Surface

| Domain | Endpoints |
|---|---|
| Auth | `POST /register`, `POST /login`, `POST /forgot-password`, `GET/POST /reset-password/:token` |
| Users | `GET/PUT /me`, `GET /:id`, `GET /:id/follow`, `POST /:id/follow`, `GET /:id/followers`, `GET /:id/following`, `POST /:id/view` |
| Profile | `POST/DELETE /me/experience/:id`, `POST/DELETE /me/education/:id`, `POST/DELETE /me/skills/:name` |
| Posts | `GET /posts` (feed, paginated, sorted), `POST /posts`, `DELETE /:id`, `PATCH /:id`, `GET /posts/new-count`, `GET /posts/saved`, `POST /:id/save`, `POST /posts/viewed` |
| Reactions | `POST/DELETE /:id/like`, `POST /:id/react` |
| Comments | `POST /:id/comments`, `GET /:id/comments` (paginated with cursor) |
| Polls | `POST /:id/poll/:optionId/vote` |
| Connections | `GET /connections`, `GET /connections/requests`, `GET /connections/suggestions`, `POST /:id`, `PUT /:id`, `DELETE /:id` |
| Messages | `GET /messages/threads`, `GET /messages/:userId` (paginated), `POST /messages/:userId`, `PATCH /messages/:id` |
| Notifications | `GET /notifications`, `GET /notifications/badges`, `PUT /notifications/read-all`, `PUT /notifications/:id/read` |
| Search | `GET /search?q=` |
| Salary | `GET /salary`, `GET /salary/stats`, `POST /salary`, `PATCH /:id`, `DELETE /:id` |
| Reviews | `GET /reviews`, `GET /reviews/companies`, `POST /reviews`, `PATCH /:id`, `DELETE /:id` |
| Mentors | `GET /experts`, `GET /experts/me`, `POST /experts/me`, `GET/POST/PUT/DELETE /mentor-sessions`, `POST /mentor-sessions/:id/book-slot` |
| Sessions | `GET /sessions`, `POST /sessions`, `PUT/DELETE /:id`, `PATCH /:id/reschedule` |
| Jobs | `GET /jobs`, `POST /jobs`, `POST /:id/apply`, `GET /jobs/my-applications`, `PATCH /:id`, `DELETE /:id` |
| Analytics | `GET /analytics/me` |
| Upload | `POST /upload` |
| Health | `GET /health` |

### 5.4 Feed Query — The Most Complex Endpoint

`GET /api/posts` serves the social feed. It demonstrates the core performance pattern used throughout:

```javascript
// Step 1: One query to fetch paginated post rows (20 per page)
// Uses LEFT JOINs for reaction_count and comment_count to avoid N+1
const posts = db.prepare(`
  SELECT p.*,
    EXISTS(SELECT 1 FROM likes WHERE post_id=p.id AND user_id=?) as liked,
    COUNT(DISTINCT pr.id) as reaction_count,
    COUNT(DISTINCT cm.id) as comment_count
  FROM posts p
  LEFT JOIN users u ON p.author_id = u.id
  LEFT JOIN post_reactions pr ON pr.post_id = p.id
  LEFT JOIN comments cm ON cm.post_id = p.id
  WHERE p.is_published = 1 AND (
    p.welcome_for_user_id = ? OR
    p.author_id = ? OR
    p.author_id IN (SELECT ... FROM connections WHERE ... AND status='accepted')
  )
  GROUP BY p.id
  ORDER BY reaction_count DESC, comment_count DESC, p.created_at DESC
  LIMIT 20 OFFSET ?
`).all(...params);

// Step 2: Bulk fetch reactions for all 20 posts — ONE query
const allReactions = db.prepare(
  `SELECT post_id, reaction_type, COUNT(*) as count
   FROM post_reactions WHERE post_id IN (${placeholders})
   GROUP BY post_id, reaction_type`
).all(...ids);

// Step 3: Bulk fetch my reactions — ONE query
const myReactions = db.prepare(
  `SELECT post_id, reaction_type FROM post_reactions
   WHERE post_id IN (${placeholders}) AND user_id=?`
).all(...ids, userId);

// Step 4: Bulk fetch top 2 comments per post — ONE query
const allComments = db.prepare(`
  SELECT c.post_id, ... FROM comments c JOIN users u ON c.author_id=u.id
  WHERE c.post_id IN (${placeholders})
  ORDER BY c.post_id, c.created_at DESC
`).all(...ids);
// Slice in JS to get max 2 per post — avoids ROW_NUMBER() window function

// Total: 4 queries for any page size, regardless of N posts
```

**N+1 pattern avoided:** Without this bulk approach, rendering 20 posts with reactions and comments would require 20×3 = 60 queries.

### 5.5 Connection Suggestions — Graph Traversal in SQL

```sql
SELECT u.id, u.name, ...,
  COUNT(DISTINCT myconn.mid) AS mutual_count,
  CASE WHEN COUNT(DISTINCT myconn.mid) > 0 THEN '2nd' ELSE '3rd' END AS degree
FROM users u
LEFT JOIN (
  -- My direct connections
  SELECT CASE WHEN requester_id=? THEN addressee_id ELSE requester_id END AS mid
  FROM connections WHERE (requester_id=? OR addressee_id=?) AND status='accepted'
) AS myconn ON 1=1
LEFT JOIN connections bridge ON bridge.status='accepted' AND (
  (bridge.requester_id = myconn.mid AND bridge.addressee_id = u.id) OR
  (bridge.addressee_id = myconn.mid AND bridge.requester_id = u.id)
)
WHERE u.id != ?
  AND u.email != '__nexus_system__@nexus.internal'
  AND u.id NOT IN (-- already connected or pending)
GROUP BY u.id
ORDER BY mutual_count DESC, RANDOM()
LIMIT 20
```

This does a 2-hop graph traversal in pure SQL: my connections → their connections → suggestions. Sorted by mutual count descending (so people with more mutual friends appear first, like LinkedIn's "2nd degree").

### 5.6 Sanitize Helper

```javascript
function sanitize(str, maxLen = 5000) {
  if (typeof str !== 'string') return '';
  return validator.escape(str.trim()).slice(0, maxLen);
}
```

All user-generated text (post content, chat messages, review text) passes through this before storage. `validator.escape()` converts `<`, `>`, `&`, `"`, `'` to HTML entities, preventing stored XSS. Length cap prevents database bloat attacks.

---

## 6. Real-Time Layer (Socket.io)

### 6.1 Room Model

```javascript
// On connect: join a personal room named after the user
socket.on('join', (userId) => {
  socket.join(`user_${userId}`);
});

// On open chat: join a shared conversation room
socket.on('join_chat', ({ with: otherId }) => {
  const room = [userId, otherId].sort().join('_');
  socket.join(room);
});
```

**Two room types:**
- `user_{id}` — personal room for notifications, connection updates, analytics
- `{id1}_{id2}` (sorted) — chat room shared by both participants for real-time messaging

### 6.2 Events Emitted by Server

| Event | Payload | Scope |
|---|---|---|
| `new_post` | full post object | broadcast (all) |
| `post_deleted` | `{ postId }` | broadcast |
| `post_edited` | `{ postId, content }` | broadcast |
| `post_liked` | `{ postId, likes_count }` | broadcast |
| `post_reacted` | `{ postId, reactions, my_reaction_by }` | broadcast |
| `post_commented` | `{ postId, comments_count }` | broadcast |
| `poll_voted` | `{ postId, options }` | broadcast |
| `message` | full message object | chat room + personal |
| `notification` | `{ type, content }` | personal room |
| `connection_update` | `{ type, with }` | personal room |
| `session_update` | `{ sessionId, status }` | personal room |
| `account_action` | `{ type, message }` | personal room |
| `analytics_update` | `{ type }` | personal room |
| `mentor_slot_booked` | `{ expertId, slots }` | broadcast |

### 6.3 Client-Side Socket Handling

```javascript
function initSocket() {
  socket = io({
    reconnection: true,
    reconnectionAttempts: Infinity,
    reconnectionDelay: 1000,
    reconnectionDelayMax: 8000,
    timeout: 10000
  });
  socket.emit('join', me.id);

  socket.on('new_post', post => {
    // Show "New posts available" banner instead of auto-inserting
    // User clicks to load — avoids jarring feed jumps
    window._pendingNewPosts = (window._pendingNewPosts || 0) + 1;
    showNewPostsBanner(window._pendingNewPosts);
  });

  socket.on('message', msg => {
    // If chat is open to that user, append; otherwise update badge
    if (window._chatWith == msg.sender_id || window._chatWith == msg.receiver_id) {
      appendChatMessage(msg);
      playMsgSound();
    } else {
      updateMsgBadge(+1);
    }
  });
}
```

**Reconnection strategy:** Exponential backoff from 1s to 8s max, infinite retries. Mobile devices disconnect frequently (screen lock, background app) — infinite reconnection ensures the app comes back online without a page refresh.

### 6.4 CORS Scoping

```javascript
const io = new Server(server, {
  cors: { origin: process.env.APP_URL || '*', methods: ['GET','POST'] }
});
```

Production sets `APP_URL` in Railway env vars, locking WebSocket CORS to the production domain. Local dev uses `*`.

---

## 7. Frontend Architecture (SPA)

### 7.1 Zero-Framework SPA Design

The entire frontend is one HTML file (`public/index.html`, ~3,300 lines). It's a Single-Page Application built with:

- **Vanilla JS** — no React, Vue, Angular, or any framework
- **No build step** — the file is served directly as static HTML
- **No npm frontend dependencies** — Font Awesome and Socket.io loaded from CDN/server

**Why vanilla JS:** Zero build pipeline means zero CI/CD complexity. Deploy is `git push`. No transpilation, no webpack, no node_modules for frontend. The file loads in one HTTP request.

**Tradeoff:** As the app grows, a single 3,300-line file becomes harder to maintain. Framework components would help structure. But for a solo/small-team project this is significantly faster to iterate.

### 7.2 Page Routing

```javascript
// All navigation goes through a single go() function
function go(page, data = {}) {
  curPage = page;
  document.getElementById('pr').innerHTML = ''; // clear page region
  // Switch on page name to call the right render function
  if (page === 'home') renderFeed();
  else if (page === 'network') renderNetwork();
  else if (page === 'messages') renderMessages();
  else if (page === 'jobs') renderJobs();
  // etc.
}
```

No URL routing library. Pages are identified by a string key. Browser history is not updated (no `pushState`) — navigating with back button returns to the OS, not the previous Nexus page.

**Tradeoff:** No deep linking. Users can't bookmark specific pages or share URLs to specific profiles. Acceptable for v1.

### 7.3 Client-Side API Cache

```javascript
const _apiCache = new Map();

// Two TTL tiers:
const _LONG_CACHE = ['/api/connections/suggestions', '/api/jobs', '/api/users/me'];
const _LONG_TTL = 120000;   // 2 minutes for stable data
const _SHORT_TTL = 30000;   // 30 seconds for everything else

async function api(path, opts = {}) {
  const isGet = !opts.method || opts.method === 'GET';
  if (isGet) {
    const hit = _apiCache.get(path);
    if (hit && Date.now() - hit.ts < _apiTTL(path)) return hit.data; // cache hit
  }
  const r = await fetch(path, opts);
  const data = await r.json().catch(() => ({}));
  if (isGet && r.ok) _apiCache.set(path, { data, ts: Date.now() }); // store
  return data;
}
```

**Cache invalidation on mutations:**
```javascript
async function likePost(id) {
  await api(`/api/posts/${id}/like`, { method: 'POST' });
  apiInvalidate('/api/posts');  // flush feed cache
  apiInvalidate('/api/notifications/badges'); // flush badge cache
}
```

Every write operation calls `apiInvalidate(prefix)` with the affected prefix. This purges all cached entries whose key starts with that string.

**Why this matters:** Without the cache, navigating away from the feed and back would fire a full feed HTTP request. With 30s TTL, repeat navigation within half a minute is instant. Critical for mobile where latency is high.

### 7.4 Boot Sequence

```javascript
// Registered FIRST — fires regardless of everything else
setTimeout(function() {
  var l = document.getElementById('nxload');
  if (l) { l.style.opacity = '0'; setTimeout(() => l.remove(), 350); }
}, 5000);

// Main boot IIFE
(async () => {
  // Apply saved theme from localStorage before API call
  const saved = localStorage.getItem('nx-template');
  if (saved) document.body.classList.add(saved);

  const saved = localStorage.getItem('nxtoken');
  if (saved) {
    token = saved;
    try {
      // Race: API call vs 7-second timeout
      me = await Promise.race([
        api('/api/users/me'),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 7000))
      ]);
      if (me?.id) { go('home'); initSocket(); } // logged in
      else { renderAF('login'); }                // token invalid
    } catch(e) { renderAF('login'); }            // timeout or error
  } else {
    renderAF('login'); // first visit
  }
  // Remove splash
  setTimeout(() => { /* fade nxload */ }, 350);
})();
```

**Key design decisions:**
- The 5-second emergency splash kill is registered *before* any other code, so even a script error below it can't prevent the page from becoming usable
- Theme is applied from `localStorage` synchronously before any API call — no flash of unstyled content
- The `Promise.race` with a 7-second timeout ensures the app never hangs indefinitely waiting for a slow/dead server

### 7.5 Skeleton Loaders

```javascript
function renderSkeleton(count = 3) {
  return Array(count).fill(0).map(() => `
    <div class="post-card skeleton">
      <div class="sk-av"></div>
      <div class="sk-line w70"></div>
      <div class="sk-line w50"></div>
      <div class="sk-block"></div>
    </div>
  `).join('');
}
```

Feed, trending sidebar, and People You May Know all render skeleton cards immediately, then replace with real data when the API responds. Users see structure before content, making the app feel faster than it is (perceived performance > actual latency).

### 7.6 Template Themes

8 visual themes (Default, Executive, Slate, Parchment, Arctic, Carbon, Graphite, Crimson) implemented purely via CSS custom properties:

```css
body.tmpl-executive {
  --bg: #0a0f1e;
  --surface: #0f1729;
  --primary: #d4af37;
  --text: #e8e0d0;
  /* ... */
}
```

The active template class on `<body>` cascades to every UI component. Switching themes is one `classList` operation.

**Cross-device sync:** The selected template is saved to the `nx_template` column on the `users` table via `PUT /api/users/me`. On next login on any device, the template is restored from the server response.

```javascript
function setTemplate(t) {
  document.body.classList.remove(..._templates);
  if (t) document.body.classList.add(t);
  localStorage.setItem('nx-template', t || '');
  // Sync to DB
  if (token) api('/api/users/me', { method: 'PUT', body: JSON.stringify({ nx_template: t || '' }) }).catch(() => {});
}
```

---

## 8. Feature Implementations

### 8.1 Social Feed

**Feed filtering logic:**
- New users see an empty feed (not global discover mode)
- Welcome post from Nexus Community is shown to the new user only (`welcome_for_user_id` filter)
- Regular users see: their own posts + posts from accepted connections
- Demo account sees all posts (for showcase purposes, set via `DEMO_EMAIL` env var)

**Feed sorting:**
- "Top" (default): `ORDER BY reaction_count DESC, comment_count DESC, created_at DESC`
- "New": `ORDER BY created_at DESC`

**Sort mode stored client-side:**
```javascript
let _feedSort = localStorage.getItem('nx-sort') || 'top';
```

**New posts polling:**
```javascript
// Every 60 seconds, check for new posts since last load
setInterval(async () => {
  const r = await api(`/api/posts/new-count?since=${lastFeedTs}`);
  if (r.count > 0) showNewPostsBanner(r.count);
}, 60000);
```

The `new-count` endpoint is a lightweight COUNT query — it doesn't fetch actual post data, just a number. This is far cheaper than polling the full feed endpoint.

### 8.2 Post Types

**Text post:** Plain content, optional image attachment.

**Anonymous post:** `is_anonymous: 1` stored in DB. The server replaces author info with `'Anonymous'` / empty avatar for all users except the author. The author still sees it as their own post (`is_mine: true`).

**Poll post:** Creates rows in `poll_options`. Voting calls `POST /api/posts/:id/poll/:optionId/vote` which uses `INSERT OR REPLACE` to allow vote-changing. Results broadcast via `poll_voted` Socket event.

**Scheduled post:** `scheduled_at` datetime stored, `is_published: 0`. A background check on every feed load finds and publishes overdue scheduled posts:
```javascript
db.prepare(`UPDATE posts SET is_published=1, scheduled_at=NULL WHERE is_published=0 AND scheduled_at <= datetime('now')`).run();
```

### 8.3 Reactions System

5 reaction types: 👍 Like, ❤️ Love, 💡 Insightful, 🎉 Celebrate, 🤝 Support

```javascript
// POST /api/posts/:id/react
// Toggle logic: same reaction type = remove; different = replace
const existing = db.prepare('SELECT id, reaction_type FROM post_reactions WHERE post_id=? AND user_id=?').get(postId, userId);
if (existing?.reaction_type === reaction_type) {
  db.prepare('DELETE FROM post_reactions WHERE id=?').run(existing.id);
} else {
  db.prepare('INSERT OR REPLACE INTO post_reactions (post_id, user_id, reaction_type) VALUES (?,?,?)').run(postId, userId, reaction_type);
}
// Broadcast updated reaction counts to all clients
io.emit('post_reacted', { postId, reactions, my_reaction_by: userId, my_reaction });
```

The `UNIQUE(post_id, user_id)` constraint with `INSERT OR REPLACE` ensures one reaction per user per post at the DB level.

### 8.4 Messaging

**Thread list:** Shows last message per conversation with unread badge:
```sql
SELECT m.*, sender.name, receiver.name,
  CASE WHEN m.sender_id=? THEN m.receiver_id ELSE m.sender_id END as other_id
FROM messages m
JOIN (
  -- Latest message per thread
  SELECT MAX(id) as id FROM messages WHERE sender_id=? OR receiver_id=?
  GROUP BY CASE WHEN sender_id<receiver_id THEN sender_id||'_'||receiver_id ELSE receiver_id||'_'||sender_id END
) latest ON m.id = latest.id
ORDER BY m.created_at DESC
```

**Pagination:** Messages paginate with a cursor (before-ID), not offset:
```javascript
// GET /api/messages/:userId?before=123
const PAGE_SIZE = 50;
const before = req.query.before ? parseInt(req.query.before) : null;
const whereClause = before ? 'WHERE thread condition AND m.id < ?' : 'WHERE thread condition';
```

**Cursor-based vs offset pagination:** Offset pagination (`LIMIT 50 OFFSET 100`) is unstable — if new messages arrive while paginating, rows shift and you get duplicates. Cursor-based (`WHERE id < last_seen_id`) is stable.

**Real-time delivery:**
```javascript
// Send to the chat room (if both users have it open) AND to receiver's personal room
io.to(room).emit('message', msg);
io.to(`user_${receiverId}`).emit('message', msg);
```

Sending to both ensures the message appears in the open chat window AND updates the thread list badge for users who don't have that specific chat open.

### 8.5 Notification System

**Badge endpoint (lightweight):**
```javascript
// GET /api/notifications/badges
res.json({
  notifications: unreadNotifCount,
  messages: unreadMsgCount,
  connections: pendingConnectionCount
});
```

This endpoint is polled every 30 seconds and on specific mutations. It returns only three numbers — far cheaper than fetching full notification lists.

**Badge cache bypass:**
```javascript
async function pollBadges() {
  apiInvalidate('/api/notifications/badges'); // always bypass cache
  const r = await api('/api/notifications/badges');
  updateBadgeUI(r);
}
```

Badges are always fetched fresh (cache invalidated before call) because stale badge counts are misleading to users.

### 8.6 Connection Graph

**People You May Know:**
- 2nd-degree connections shown first (friends of friends, ranked by mutual count)
- Mutual count displayed instead of degree badge (cleaner UX)
- System bot excluded from suggestions via `u.email != '__nexus_system__@nexus.internal'`

**Connection state machine:**
```
[none] → send request → [pending] → accept → [connected]
                                  → decline → [none]
[connected] → remove → [none]
```

**Badge accuracy:** After accept/decline, `apiInvalidate('/api/notifications/badges')` is called before `pollBadges()`, ensuring the Network tab badge updates instantly rather than waiting for the 30s poll interval.

### 8.7 Salary Board

Anonymous salary submissions with multi-dimension filtering. Stats endpoint:
```sql
SELECT company, role, AVG(salary_lpa) as avg_salary, COUNT(*) as count,
  MIN(salary_lpa) as min_sal, MAX(salary_lpa) as max_sal
FROM salary_entries
GROUP BY company, role
ORDER BY count DESC, avg_salary DESC
```

**Input validation:**
```javascript
const salNum = parseFloat(salary_lpa);
if (isNaN(salNum) || salNum <= 0 || salNum > 10000) {
  return res.status(400).json({ error: 'Valid salary (0–10000 LPA) required' });
}
```

### 8.8 Mentorship / Session Booking

The most complex feature. Two data stores used together:

**`mentor_sessions` table:** The mentor's offering (title, expertise, price, meeting link, JSON availability slots).

**`interview_sessions` table:** Individual bookings (learner, expert, status lifecycle: pending → confirmed/cancelled).

**Booking flow:**
1. Learner clicks a time slot → `POST /api/mentor-sessions/:id/book-slot`
2. Slot marked `pending: true, pending_until: now + 5 minutes` in JSON
3. `interview_session` row created with `status: 'pending'`
4. Socket event `mentor_slot_booked` sent to all clients (mentor sees slot as pending)
5. Mentor accepts → `PUT /api/sessions/:id` with `{ action: 'accept' }` → status → `confirmed`
6. If mentor doesn't respond in 5 minutes → background interval auto-cancels

**Auto-cancel timer:**
```javascript
setInterval(() => {
  const now = Date.now();
  // For every active mentor with pending slots:
  msList.forEach(ms => {
    slots.forEach(s => {
      if (s.pending && s.pending_until && now > s.pending_until) {
        // Cancel the session, notify learner, clear slot
      }
    });
  });
}, 30000); // check every 30s
```

**Self-healing:** On startup, `healSlots()` in db.js reconciles JSON slot state against the DB, fixing any inconsistency from crashes.

### 8.9 Jobs

**My Applications tab:**
```javascript
// GET /api/jobs/my-applications
const apps = db.prepare(`
  SELECT ja.id as application_id, ja.cover_letter, ja.created_at as applied_at,
    j.id as job_id, j.title, j.company, j.status as job_status,
    u.name as poster_name
  FROM job_applications ja
  JOIN jobs j ON ja.job_id = j.id
  JOIN users u ON j.poster_id = u.id
  WHERE ja.applicant_id = ?
  ORDER BY ja.created_at DESC
`).all(req.user.id);
```

**Role-based UI:** The job poster sees Edit/Close buttons instead of "Easy Apply". This is determined client-side by comparing `job.poster_id === me.id`.

### 8.10 Analytics

```javascript
// GET /api/analytics/me — 2 queries
const views = db.prepare(
  "SELECT COUNT(DISTINCT viewer_id) as c FROM profile_views WHERE profile_id=? AND viewed_at > datetime('now','-30 days')"
).get(uid);

const impressions = db.prepare(
  "SELECT COUNT(pv.id) as c FROM post_views pv JOIN posts p ON pv.post_id=p.id WHERE p.author_id=? AND pv.viewed_at > datetime('now','-30 days')"
).get(uid);
```

**Post view tracking — batched:**
```javascript
// Client collects visible post IDs for 800ms, then sends one batch request
function _sendVisiblePostViews() {
  const pids = [...document.querySelectorAll('.post-card[data-pid]')]
    .filter(el => { /* check if in viewport */ })
    .map(el => parseInt(el.dataset.pid));
  if (pids.length) api('/api/posts/viewed', { method: 'POST', body: JSON.stringify({ post_ids: pids }) });
}
```

Instead of firing one HTTP request per post impression, the client batches all visible post IDs into a single call. The server does `INSERT OR IGNORE` for each — the `UNIQUE(post_id, viewer_id)` constraint ensures each post counts once per viewer.

### 8.11 Nexus Community System Bot

A special system user that sends welcome messages on registration:

```javascript
// server.js — runs at startup
const NEXUS_BOT_EMAIL = '__nexus_system__@nexus.internal';
(function ensureSystemUser() {
  let bot = db.prepare('SELECT id FROM users WHERE email=?').get(NEXUS_BOT_EMAIL);
  if (!bot) { /* create it */ }
  NEXUS_BOT_ID = bot.id;
})();

// On register — fire-and-forget after response sent
if (NEXUS_BOT_ID) {
  db.prepare('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?,?,?)').run(NEXUS_BOT_ID, user.id, welcomeMsg);
  db.prepare('INSERT INTO posts (author_id, content, is_published, welcome_for_user_id) VALUES (?,?,1,?)').run(NEXUS_BOT_ID, welcomePost, user.id);
}
```

The bot is excluded from all user-facing queries:
```sql
WHERE u.email != '__nexus_system__@nexus.internal'
```
This appears in search, connection suggestions, and People You May Know queries.

### 8.12 Content Moderation

**User reporting:** `POST /api/flag` with `{ content_type, content_id, reason }`. `UNIQUE(content_type, content_id, reporter_id)` prevents repeat reports from same user.

**Auto-escalation by warning count:**
```javascript
const newWarnings = warnings + 1;
if (newWarnings >= 5) {
  db.prepare('UPDATE users SET is_disabled=1 WHERE id=?').run(authorId);
  io.to(`user_${authorId}`).emit('account_action', { type: 'disabled', message: '...' });
} else if (newWarnings >= 3) {
  // Block for 24 hours
  db.prepare('UPDATE users SET blocked_until=?, warnings=? WHERE id=?').run(until, newWarnings, authorId);
  io.to(`user_${authorId}`).emit('account_action', { type: 'blocked', until, message: '...' });
} else {
  io.to(`user_${authorId}`).emit('account_action', { type: 'warning', message: `Warning ${newWarnings}/5...` });
}
```

Moderation actions are delivered to the user in real time via Socket — they don't need to refresh.

---

## 9. Performance Engineering

### 9.1 Bulk Queries — N+1 Elimination

Every list endpoint follows the same pattern:
1. Fetch the primary list (one query)
2. Collect all IDs into an array
3. One `IN (?,?,...)` query per related entity type
4. Merge in JS with a Map/object

This caps database queries per request regardless of page size. Feed: 4 queries. Thread list: 2 queries. Mentor listing: 2 queries.

### 9.2 Client-Side Cache with Two TTL Tiers

| Path | TTL | Reason |
|---|---|---|
| `/api/connections/suggestions` | 2 min | Computationally expensive graph query |
| `/api/jobs` | 2 min | Rarely changes within minutes |
| `/api/users/me` | 2 min | User profile doesn't change constantly |
| Everything else | 30 sec | Fresh enough, still reduces redundant calls |

### 9.3 Notification Badge Polling vs Push

Badges are updated by two mechanisms:
- **Push (primary):** Socket events trigger immediate badge updates (e.g., a new message increments the chat badge instantly)
- **Poll (fallback):** Every 30 seconds, `pollBadges()` fetches current counts. This catches cases where the WebSocket was disconnected

```javascript
window._badgeTimer = setInterval(pollBadges, 30000);
```

The polling interval always bypasses cache (`apiInvalidate` called first) to ensure freshness.

### 9.4 Post View Debouncing

The IntersectionObserver-like client implementation:
```javascript
let _viewTimer = null;
function observePosts() {
  window.addEventListener('scroll', () => {
    clearTimeout(_viewTimer);
    _viewTimer = setTimeout(_sendVisiblePostViews, 800); // 800ms debounce
  }, { passive: true });
}
```

Scroll events fire hundreds of times per second. Without debouncing, every scroll would trigger a DOM query + API call. The 800ms debounce means one batch call fires after the user stops scrolling.

### 9.5 SQLite WAL Concurrency

WAL mode allows concurrent reads while a write is in progress. For a web server handling simultaneous requests:
- `GET /api/posts` (read) and `POST /api/posts/:id/like` (write) can execute concurrently
- Without WAL, the read would block until the write commits

### 9.6 Socket.io Backpressure

Feed updates use a "soft notification" pattern instead of auto-inserting posts:
```javascript
socket.on('new_post', post => {
  window._pendingNewPosts = (window._pendingNewPosts || 0) + 1;
  showNewPostsBanner(window._pendingNewPosts);
  // Does NOT immediately modify the DOM
});
```

Auto-inserting posts into the feed DOM as they arrive would cause jarring layout shifts (especially on mobile). The banner lets the user choose when to reload. Clicking the banner calls `renderFeed()` which fetches fresh data.

### 9.7 Lazy AudioContext

```javascript
let _ac = null;
function _getAC() {
  if (_ac) return _ac;
  try {
    _ac = typeof AudioContext !== 'undefined' ? new AudioContext() : null;
  } catch(e) { _ac = null; }
  return _ac;
}
```

`AudioContext` is only instantiated on first sound playback, not at module load time. This:
- Avoids "AudioContext was not allowed to start" browser warnings
- Doesn't block script execution on environments where AudioContext fails
- Doesn't consume audio resources until actually needed

### 9.8 Emergency Splash Kill

```javascript
// First thing in the main script
setTimeout(function() {
  var l = document.getElementById('nxload');
  if (l) { l.style.opacity = '0'; setTimeout(function() { l.remove(); }, 350); }
}, 5000);
```

This is registered before any other code. Even if a JavaScript error occurs later in the 3,300-line script, this timer is already in the event loop and will fire at 5 seconds, ensuring the loading screen never hangs forever.

---

## 10. Security Implementation

### 10.1 Password Security

```javascript
// Registration
const hash = await bcrypt.hash(password, 10); // bcrypt cost factor 10
// Login
const ok = await bcrypt.compare(password, user.password);
```

bcrypt with cost factor 10 — approximately 100ms per hash, making brute force impractical. Passwords are never stored in plain text or reversibly encrypted.

**Password strength rules (client-side + server enforced):**
- Minimum 8 characters
- At least one number
- At least one special character

### 10.2 JWT Tokens

- 7-day expiry
- `JWT_SECRET` from environment variable (must be set in production)
- Verified on every request via `auth` middleware
- Account status re-checked on every request (banned user can't use existing token)

### 10.3 Rate Limiting

| Route | Limit | Window |
|---|---|---|
| `/api/auth/*` | 20 requests | 15 minutes |
| `/api/upload` | 10 requests | 1 minute |
| `/api/*` (general) | 300 requests | 1 minute |
| `/api/health` | unlimited | — |

Limits are per-IP, enforced in-process. No Redis required.

### 10.4 Input Sanitization

- All user text: `validator.escape()` before storage → XSS safe
- Length caps: posts 5000 chars, messages 2000 chars
- File uploads: MIME type whitelist (JPEG, PNG, WebP, GIF only), 5 MB size cap
- Salary: validated as a number in 0–10,000 range
- JSON body: `express.json({ limit: '2mb' })` prevents payload attacks

### 10.5 Security Headers (Helmet)

Helmet adds: `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Referrer-Policy`, `Strict-Transport-Security`, and more. `contentSecurityPolicy` disabled to allow Font Awesome CDN.

### 10.6 CORS

Socket.io CORS locked to `APP_URL` env var in production. REST CORS uses `cors()` middleware (permissive — acceptable since the API is auth-protected).

### 10.7 Removed Insecure Endpoint

The original `POST /api/auth/reset-by-email` endpoint exposed user data. It was removed:
```javascript
// REMOVED: insecure reset-by-email that could enumerate accounts
// app.post('/api/auth/reset-by-email', ...) — deleted
```

The remaining password reset flow uses opaque random tokens.

### 10.8 Account Moderation

Disabled accounts receive `{ code: 'DISABLED' }` on every API call. The client handles this:
```javascript
if (r.code === 'DISABLED') { logout(); toast('Your account has been disabled.'); }
```

---

## 11. System Design Decisions & Tradeoffs

### 11.1 SQLite vs PostgreSQL

| | SQLite | PostgreSQL |
|---|---|---|
| Setup | Zero (built into Node 22) | Separate server, connection pool |
| Write concurrency | Single writer (WAL helps) | Full concurrent writes |
| Railway cost | Free (file on volume) | $5+/month managed |
| Migration | Alter table in-process | Migration tools, schema versions |
| Read performance | Excellent (local file, no network) | Good (network hop) |
| Scale ceiling | ~10K writes/day easily | Millions |

**Decision:** SQLite is appropriate for this stage. The WAL mode handles the typical web app read-heavy workload. Migration to Postgres is possible but would require rewriting placeholder syntax (`?` → `$1`) and removing `node:sqlite` for `pg`.

### 11.2 Monolith vs Microservices

Everything (web server, socket server, jobs, file serving) runs in one process. This is intentional:
- Zero inter-service latency
- Simple deployment (one Railway service)
- Shared DB connection — no connection pool overhead
- Trivial local development (`node server.js`)

**When to split:** If the background booking auto-cancel timer starts interfering with request latency, extract it to a separate worker. If file uploads need more storage, add S3. If the DB becomes a bottleneck, migrate to Postgres with a read replica.

### 11.3 In-Process Rate Limiting vs Redis

`express-rate-limit` defaults to in-memory storage. This means:
- Rate limit state is NOT shared across multiple instances
- If Railway runs two dynos, a user could make 2×300 = 600 API requests/minute

**Current decision:** Single dyno, so in-process is fine. If scaling to multiple dynos, switch to `rate-limit-redis` store.

### 11.4 JSON Slots vs Slots Table

Mentor availability slots stored as a JSON array in a TEXT column vs a normalized `mentor_slots` table:

| JSON column | Separate table |
|---|---|
| One row fetch per mentor | Join required |
| No SQL query per slot | Index per slot possible |
| Complex queries impossible | Can query by date range |
| Atomic update | Transaction needed |

**Decision:** JSON is fine because slots are always loaded/saved as a complete set per mentor (never queried individually by SQL). The self-healing function on startup handles consistency.

### 11.5 Real-Time Feed vs Polling

New post notifications use a hybrid: WebSocket push for the notification (instant), but the actual feed data is fetched via REST when the user clicks the banner.

**Why not push the full post via WebSocket?**
- Posts include reactions, comments, author info — fetching all this for each incoming post would be expensive server-side
- The server would need to format posts identically to the REST feed endpoint
- Users may not want to receive every post (their timeline would jump)

**Tradeoff:** There's a 1–2 second delay between clicking the banner and seeing new posts (REST roundtrip). Acceptable UX.

### 11.6 Authentication: JWT vs Sessions

| JWT | Sessions |
|---|---|
| Stateless — no DB lookup per request | Stateful — session store lookup |
| Can't invalidate individual tokens | Instant logout possible |
| Account ban requires API check on every call | Session deletion = immediate lockout |

**Decision:** JWT with a per-request account status DB check. This combines stateless tokens with instant ban enforcement. The DB check is one indexed query (`SELECT is_disabled, blocked_until WHERE id=?`) — negligible cost.

### 11.7 Single HTML File vs Multi-File Frontend

The entire frontend is `public/index.html`. Alternatives:
- Split into multiple JS/CSS files (better caching per file)
- Use a framework with component files
- Build system producing hashed output

**Decision:** Single file eliminates all build tooling, makes deployment trivial (git push = done), and keeps the development loop fast. For a 3,300-line file, the gzip'd transfer is under 40 KB — one HTTP request, cached by the browser.

---

## 12. Deployment (Railway)

### 12.1 Infrastructure

- **Platform:** Railway.app
- **Service:** Single Node.js service
- **Database:** SQLite on a Railway persistent volume (mounted at `RAILWAY_VOLUME_MOUNT_PATH`)
- **File storage:** User uploads on the same persistent volume at `/data/uploads/`
- **Start command:** `node server.js`

### 12.2 Environment Variables

| Variable | Purpose | Required |
|---|---|---|
| `JWT_SECRET` | Token signing key | **Yes** |
| `PORT` | Server port (Railway sets automatically) | Auto |
| `RAILWAY_VOLUME_MOUNT_PATH` | Path where volume is mounted | Auto |
| `APP_URL` | Production URL (for Socket.io CORS) | Recommended |
| `DEMO_EMAIL` | Email of demo account (sees all posts) | Optional |
| `SMTP_HOST/USER/PASS/PORT/SECURE/FROM` | Email config | Optional |
| `DB_PATH` | Override DB file path | Optional |
| `CLEAR_SESSIONS` | One-time booking data reset | One-time |

### 12.3 Data Persistence

```javascript
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
const DB_PATH = path.join(DATA_DIR, 'nexus.db');
const uploadsDir = VOLUME ? path.join(VOLUME, 'uploads') : path.join(__dirname, 'public', 'uploads');
```

On Railway, both the SQLite database file and uploaded images live on the persistent volume. This survives service restarts and redeployments. Without a volume, data would be lost on every deploy.

### 12.4 Zero-Downtime Consideration

Railway restarts the service on every push. During restart (~5–15 seconds), new connections fail. The client's Socket.io reconnection logic handles this:
```javascript
socket = io({ reconnection: true, reconnectionAttempts: Infinity, reconnectionDelay: 1000, reconnectionDelayMax: 8000 });
```

After the server comes back up, all clients automatically reconnect within 1–8 seconds.

### 12.5 Schema Migration on Deploy

No migration runner needed. Every `ALTER TABLE ADD COLUMN` in the `migrations` array runs at startup and silently succeeds if the column already exists. New columns appear in production the moment the server restarts after a deploy.

---

## Summary: Key Design Principles

1. **Minimal dependencies:** Node 22 built-in SQLite, no frontend framework, no Redis, no separate job queue.
2. **N+1 elimination everywhere:** All list endpoints use bulk queries with `IN (...)` clauses, never per-row queries.
3. **Cache at the right layer:** Client-side API cache with two TTL tiers. Server-side: SQLite is already an in-process cache.
4. **Real-time for UX, REST for data:** Socket events signal that data changed; REST fetches the actual data. Keeps socket payloads small.
5. **Idempotent startup:** Migrations, index creation, system user bootstrap, and slot healing all run on every startup and are safe to re-run.
6. **Fail safe:** Emergency splash kill registered first; auth timeout via Promise.race; account status checked per-request; auto-cancel for stuck bookings.
7. **Single deployable unit:** One `git push` updates the entire platform — backend, frontend, schema, and static assets.
