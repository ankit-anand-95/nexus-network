// Uses Node.js built-in SQLite (node:sqlite) — available in Node v22+
// No npm package needed, no compilation required!
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

// On Railway: DB lives on the persistent volume at /data/nexus.db
// Locally: lives next to this file as nexus.db
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || __dirname;
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'nexus.db');

const db = new DatabaseSync(DB_PATH);

db.exec('PRAGMA journal_mode = WAL');
db.exec('PRAGMA foreign_keys = ON');

const tables = [
`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  headline TEXT DEFAULT '',
  location TEXT DEFAULT '',
  about TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  banner_url TEXT DEFAULT '',
  current_position TEXT DEFAULT '',
  connections_count INTEGER DEFAULT 0,
  is_dark_mode INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)`,
`CREATE TABLE IF NOT EXISTS experiences (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  company TEXT NOT NULL,
  role TEXT NOT NULL,
  start_date TEXT DEFAULT '',
  end_date TEXT DEFAULT '',
  is_current INTEGER DEFAULT 0,
  description TEXT DEFAULT '',
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS education (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  school TEXT NOT NULL,
  degree TEXT NOT NULL,
  start_year INTEGER,
  end_year INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS user_skills (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  name TEXT NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  author_id INTEGER,
  content TEXT NOT NULL,
  image_url TEXT DEFAULT '',
  is_anonymous INTEGER DEFAULT 0,
  is_poll INTEGER DEFAULT 0,
  scheduled_at DATETIME DEFAULT NULL,
  is_published INTEGER DEFAULT 1,
  likes_count INTEGER DEFAULT 0,
  comments_count INTEGER DEFAULT 0,
  shares_count INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (author_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS poll_options (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  option_text TEXT NOT NULL,
  votes_count INTEGER DEFAULT 0,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS poll_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  option_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  UNIQUE(post_id, user_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS likes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  UNIQUE(post_id, user_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS comments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  author_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (author_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  requester_id INTEGER NOT NULL,
  addressee_id INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(requester_id, addressee_id),
  FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (addressee_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL,
  receiver_id INTEGER NOT NULL,
  content TEXT NOT NULL,
  is_read INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (sender_id) REFERENCES users(id),
  FOREIGN KEY (receiver_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS notifications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  actor_id INTEGER,
  type TEXT NOT NULL,
  reference_id INTEGER DEFAULT NULL,
  content TEXT NOT NULL,
  is_read INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS salary_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  company TEXT NOT NULL,
  role TEXT NOT NULL,
  salary_lpa REAL NOT NULL,
  experience_years INTEGER DEFAULT 0,
  city TEXT DEFAULT '',
  tech_stack TEXT DEFAULT '',
  is_anonymous INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS company_reviews (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  company TEXT NOT NULL,
  overall_rating INTEGER NOT NULL CHECK(overall_rating BETWEEN 1 AND 5),
  title TEXT DEFAULT '',
  pros TEXT DEFAULT '',
  cons TEXT DEFAULT '',
  work_life_balance INTEGER DEFAULT 3,
  culture INTEGER DEFAULT 3,
  salary_rating INTEGER DEFAULT 3,
  growth INTEGER DEFAULT 3,
  would_recommend INTEGER DEFAULT 1,
  is_anonymous INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS expert_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER UNIQUE NOT NULL,
  bio TEXT DEFAULT '',
  expertise TEXT DEFAULT '[]',
  session_types TEXT DEFAULT '["Mock Interview","Career Guidance","Code Review","Resume Review"]',
  price_per_session INTEGER DEFAULT 500,
  rating REAL DEFAULT 0,
  rating_count INTEGER DEFAULT 0,
  total_sessions INTEGER DEFAULT 0,
  is_available INTEGER DEFAULT 1,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS interview_sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  expert_id INTEGER NOT NULL,
  learner_id INTEGER NOT NULL,
  topic TEXT NOT NULL,
  session_type TEXT DEFAULT 'Mock Interview',
  scheduled_at DATETIME NOT NULL,
  duration_minutes INTEGER DEFAULT 60,
  status TEXT DEFAULT 'pending',
  meeting_link TEXT DEFAULT '',
  learner_notes TEXT DEFAULT '',
  feedback TEXT DEFAULT '',
  rating INTEGER DEFAULT NULL,
  price INTEGER DEFAULT 500,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (expert_id) REFERENCES users(id),
  FOREIGN KEY (learner_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  poster_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  company TEXT NOT NULL,
  location TEXT DEFAULT '',
  job_type TEXT DEFAULT 'Full-time',
  salary_range TEXT DEFAULT '',
  description TEXT DEFAULT '',
  requirements TEXT DEFAULT '',
  is_active INTEGER DEFAULT 1,
  applications_count INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (poster_id) REFERENCES users(id)
)`,
`CREATE TABLE IF NOT EXISTS job_applications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id INTEGER NOT NULL,
  applicant_id INTEGER NOT NULL,
  status TEXT DEFAULT 'applied',
  cover_letter TEXT DEFAULT '',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(job_id, applicant_id),
  FOREIGN KEY (job_id) REFERENCES jobs(id) ON DELETE CASCADE,
  FOREIGN KEY (applicant_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  token TEXT NOT NULL UNIQUE,
  expires_at DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`
];

tables.forEach(sql => db.exec(sql));

// Migrations — safe to run multiple times (try/catch for "duplicate column" errors)
const extraTables = [
`CREATE TABLE IF NOT EXISTS post_reactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  post_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  reaction_type TEXT NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(post_id, user_id),
  FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)`,
`CREATE TABLE IF NOT EXISTS content_flags (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  content_type TEXT NOT NULL,
  content_id INTEGER NOT NULL,
  reporter_id INTEGER NOT NULL,
  reason TEXT DEFAULT 'inappropriate',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(content_type, content_id, reporter_id),
  FOREIGN KEY (reporter_id) REFERENCES users(id) ON DELETE CASCADE
)`
];

const newTables = [
  `CREATE TABLE IF NOT EXISTS mentor_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL DEFAULT 'Mentorship Session',
    expertise TEXT NOT NULL DEFAULT '',
    price_per_session INTEGER DEFAULT 500,
    meeting_link TEXT DEFAULT '',
    bio TEXT DEFAULT '',
    availability_slots TEXT DEFAULT '[]',
    is_active INTEGER DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS saved_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    post_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, post_id),
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL,
    following_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(following_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS profile_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    viewer_id INTEGER,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(profile_id) REFERENCES users(id) ON DELETE CASCADE
  )`,
  `CREATE TABLE IF NOT EXISTS post_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    viewer_id INTEGER NOT NULL,
    viewed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(post_id, viewer_id),
    FOREIGN KEY(post_id) REFERENCES posts(id) ON DELETE CASCADE
  )`
];
[...extraTables, ...newTables].forEach(sql => db.exec(sql));

const migrations = [
  `ALTER TABLE expert_profiles ADD COLUMN meeting_link TEXT DEFAULT ''`,
  `ALTER TABLE expert_profiles ADD COLUMN availability_slots TEXT DEFAULT '[]'`,
  `ALTER TABLE messages ADD COLUMN is_edited INTEGER DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN warnings INTEGER DEFAULT 0`,
  `ALTER TABLE users ADD COLUMN blocked_until DATETIME DEFAULT NULL`,
  `ALTER TABLE users ADD COLUMN is_disabled INTEGER DEFAULT 0`,
  `ALTER TABLE interview_sessions ADD COLUMN slot_key TEXT DEFAULT ''`,
  `ALTER TABLE interview_sessions ADD COLUMN mentor_session_id INTEGER DEFAULT NULL`,
];
migrations.forEach(sql => { try { db.exec(sql); } catch(e) { /* column already exists */ } });

// ── INDEXES ── (safe to re-run — IF NOT EXISTS)
const indexes = [
  `CREATE INDEX IF NOT EXISTS idx_posts_published_created ON posts(is_published, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_id)`,
  `CREATE INDEX IF NOT EXISTS idx_connections_requester ON connections(requester_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_connections_addressee ON connections(addressee_id, status)`,
  `CREATE INDEX IF NOT EXISTS idx_post_reactions_post ON post_reactions(post_id, reaction_type)`,
  `CREATE INDEX IF NOT EXISTS idx_post_reactions_user ON post_reactions(post_id, user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_messages_thread ON messages(sender_id, receiver_id, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, created_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_likes_post_user ON likes(post_id, user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_saved_posts_user ON saved_posts(user_id)`,
  `CREATE INDEX IF NOT EXISTS idx_profile_views_profile ON profile_views(profile_id, viewed_at DESC)`,
  `CREATE INDEX IF NOT EXISTS idx_post_views_post ON post_views(post_id)`,
  `CREATE INDEX IF NOT EXISTS idx_post_views_viewer ON post_views(viewer_id)`,
];
indexes.forEach(sql => { try { db.exec(sql); } catch(e) {} });

// ── ONE-TIME DATA RESET ── Set CLEAR_SESSIONS=1 in Railway env vars, deploy once, then remove it
if (process.env.CLEAR_SESSIONS === '1') {
  console.log('[db] CLEAR_SESSIONS=1 — wiping interview_sessions and resetting all booked slots...');
  db.exec(`DELETE FROM interview_sessions`);
  // Unmark all booked slots in mentor_sessions
  const msList = db.prepare(`SELECT id, availability_slots FROM mentor_sessions`).all();
  msList.forEach(ms => {
    const slots = JSON.parse(ms.availability_slots || '[]').map(s => ({ ...s, booked: false, booked_by: undefined }));
    db.prepare(`UPDATE mentor_sessions SET availability_slots=? WHERE id=?`).run(JSON.stringify(slots), ms.id);
  });
  // Unmark all booked slots in expert_profiles
  const epList = db.prepare(`SELECT user_id, availability_slots FROM expert_profiles`).all();
  epList.forEach(ep => {
    const slots = JSON.parse(ep.availability_slots || '[]').map(s => ({ ...s, booked: false, booked_by: undefined }));
    db.prepare(`UPDATE expert_profiles SET availability_slots=? WHERE user_id=?`).run(JSON.stringify(slots), ep.user_id);
  });
  console.log('[db] Reset complete — remove CLEAR_SESSIONS from Railway env vars now');
}

// ── SELF-HEALING SLOT SYNC — runs on every startup, no env var needed.
// Cross-references interview_sessions against slot flags. Uses expert_id+slot_key
// so legacy sessions (mentor_session_id=NULL) are also matched. Idempotent.
(function healSlots() {
  try {
    let fixed = 0;
    // ── mentor_sessions ──────────────────────────────────────────────────
    const msList = db.prepare('SELECT id, user_id, availability_slots FROM mentor_sessions').all();
    msList.forEach(ms => {
      const slots = JSON.parse(ms.availability_slots || '[]');
      let changed = false;
      slots.forEach(s => {
        // Query by expert_id+slot_key — covers both new (mentor_session_id set) and legacy (NULL)
        const confirmed = db.prepare(`SELECT id, learner_id FROM interview_sessions WHERE expert_id=? AND slot_key=? AND status='confirmed' LIMIT 1`).get(ms.user_id, s.key);
        const pending   = db.prepare(`SELECT id FROM interview_sessions WHERE expert_id=? AND slot_key=? AND status='pending' LIMIT 1`).get(ms.user_id, s.key);
        const shouldBeBooked  = !!confirmed;
        const shouldBePending = !confirmed && !!pending;
        if (s.booked !== shouldBeBooked || !!s.pending !== shouldBePending) {
          s.booked = shouldBeBooked;
          if (shouldBeBooked) { s.booked_by = confirmed.learner_id; }
          else { delete s.booked_by; }
          if (shouldBePending) { s.pending = true; }
          else { delete s.pending; delete s.pending_by; delete s.pending_until; }
          changed = true; fixed++;
        }
      });
      if (changed) db.prepare('UPDATE mentor_sessions SET availability_slots=? WHERE id=?').run(JSON.stringify(slots), ms.id);
    });
    // ── expert_profiles (legacy) ──────────────────────────────────────────
    const epList = db.prepare('SELECT user_id, availability_slots FROM expert_profiles').all();
    epList.forEach(ep => {
      const slots = JSON.parse(ep.availability_slots || '[]');
      let changed = false;
      slots.forEach(s => {
        const active = db.prepare(`SELECT id FROM interview_sessions WHERE expert_id=? AND slot_key=? AND status IN ('pending','confirmed') LIMIT 1`).get(ep.user_id, s.key);
        const shouldBeBooked = !!(db.prepare(`SELECT id FROM interview_sessions WHERE expert_id=? AND slot_key=? AND status='confirmed' LIMIT 1`).get(ep.user_id, s.key));
        if (s.booked !== shouldBeBooked) {
          s.booked = shouldBeBooked;
          if (!shouldBeBooked) { delete s.booked_by; delete s.pending; delete s.pending_by; delete s.pending_until; }
          changed = true; fixed++;
        }
      });
      if (changed) db.prepare('UPDATE expert_profiles SET availability_slots=? WHERE user_id=?').run(JSON.stringify(slots), ep.user_id);
    });
    if (fixed > 0) console.log('[db] Self-heal: corrected ' + fixed + ' stale slot(s)');
  } catch(e) { console.error('[db] Self-heal error:', e.message); }
})();

module.exports = db;
