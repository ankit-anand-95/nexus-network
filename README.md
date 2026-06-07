# Nexus — Professional Network Platform

**Nexus** is a full-stack professional networking platform built for modern teams and communities. It goes beyond traditional networking apps by combining a real-time social feed, transparent salary and review data, peer mentorship booking, and anonymous community features — all in one unified experience.

🌐 **Live:** [nexus-network-production.up.railway.app](https://nexus-network-production.up.railway.app)

---

## Why Nexus

Professional networking tools today are either walled gardens or limited in transparency. Nexus is designed around three principles:

- **Transparency** — salary data and company reviews are community-owned, not gatekept
- **Real-time everything** — connections, messages, notifications, and feed updates are live, not polled
- **Community-first** — anonymous posting and peer mentorship create psychological safety alongside professional identity

---

## Platform Features

### Identity & Profile
- Secure registration and login with JWT — sessions persist across devices
- Rich profile: headline, bio, current position, location, skills, experience, education
- Avatar and banner image upload
- Profile analytics — who viewed your profile and post impression counts over 30 days
- Real-time presence indicators (online / away)

### Social Feed
- Create text posts, poll posts, and scheduled posts (write now, publish later)
- Anonymous posting — post ideas without revealing identity
- 5-type reactions: Like, Insightful, Celebrate, Support, Funny — with long-press on mobile
- Comments and nested interactions
- Feed sorting — Top (by engagement) and New, with eventual consistency (re-sorts live after reactions)
- Saved posts — bookmark any post and revisit from your profile
- Trending hashtags sidebar — server-cached, updates with activity
- Post impressions tracked per unique viewer

### Network & Connections
- Connection requests with 1st / 2nd / 3rd degree visibility
- Mutual connection counts on suggestions
- People You May Know — suggested by mutual connections and shared skills
- Follow without connecting
- Real-time connection updates via socket events — no page refresh needed

### Messaging
- Real-time 1:1 chat powered by Socket.io
- Typing indicators and read receipts
- Unread message badge — synced across all open tabs and devices simultaneously
- Message search within threads
- Emoji picker in chat

### Notifications
- Real-time bell notifications for connections, reactions, comments, and session events
- Per-type icons and relative timestamps
- Unread badge synced in real time

### Jobs
- Post jobs with role, location, company, and description
- Search and filter job listings
- One-click apply flow
- Job posters see Edit and Close controls on their own listings

### Salary Transparency Board
- Community-driven salary sharing by role, company, city, and tech stack
- Filter and browse entries anonymously or attributed
- Edit and delete your own submissions
- Instant UI update on add / edit / delete — no refresh needed

### Company Reviews
- Rate companies on overall score, work-life balance, culture, and growth
- Pros / cons format with recommendation flag
- Anonymous or attributed submission
- Edit and delete your own reviews

### Mentorship & Booking
- Experts list their available time slots and session details
- Learners browse and book 1:1 sessions
- Automatic Jitsi Meet video link generated on confirmation
- Full accept / decline / reschedule flow with socket notifications
- Mentors manage active bookings from a dedicated dashboard

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT (Browser)                      │
│                                                             │
│   Vanilla JS SPA (index.html ~3300 lines)                   │
│   ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│   │  Page Router│  │  API Cache   │  │  Socket Client   │  │
│   │  (go/render)│  │  (30s TTL)   │  │  (Socket.io)     │  │
│   └─────────────┘  └──────────────┘  └──────────────────┘  │
└────────────────────────────┬────────────────────────────────┘
                             │  HTTP + WebSocket
┌────────────────────────────▼────────────────────────────────┐
│                     SERVER (Node.js 22)                      │
│                                                             │
│   Express REST API                  Socket.io               │
│   ┌──────────────────────┐   ┌─────────────────────────┐   │
│   │  /api/users          │   │  Rooms: user_${id}       │   │
│   │  /api/posts          │   │  Events:                 │   │
│   │  /api/messages       │   │  - new_message           │   │
│   │  /api/connections    │   │  - notification          │   │
│   │  /api/jobs           │   │  - post_reacted          │   │
│   │  /api/salary         │   │  - connection_update     │   │
│   │  /api/reviews        │   │  - badge_sync            │   │
│   │  /api/experts        │   │  - typing / presence     │   │
│   │  /api/analytics      │   └─────────────────────────┘   │
│   └──────────────────────┘                                  │
│                                                             │
│   Middleware: JWT auth · multer uploads · trending cache    │
└────────────────────────────┬────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────┐
│                    SQLite (WAL mode)                         │
│                                                             │
│   20+ tables: users · posts · comments · reactions          │
│   messages · connections · notifications · jobs             │
│   salary_entries · company_reviews · skills                 │
│   expert_profiles · mentor_sessions · bookings              │
│   post_views · profile_views · saved_posts · polls          │
└─────────────────────────────────────────────────────────────┘
```

### Key Technical Decisions

**Single-file frontend** — The entire UI is a ~3300-line vanilla JS SPA with zero framework dependencies and zero build step. Pages are rendered by JavaScript functions that write into a single `#pr` content div. This makes deployment trivial and load time near-instant.

**Client-side API cache** — A `Map`-based cache with 30-second TTL sits in front of every GET request. Mutations (POST/PUT/DELETE) call `apiInvalidate(prefix)` to clear affected keys before re-rendering, giving immediate feedback without stale data.

**Socket.io room-per-user** — Every authenticated user joins a `user_${id}` room on connect. The server targets events to specific users via `io.to('user_X').emit(...)`, enabling cross-device badge sync, read receipts, and real-time connection updates with no polling.

**SQLite in WAL mode** — Write-Ahead Logging allows concurrent reads during writes. Uses Node.js 22's built-in `node:sqlite` module — no external ORM, no connection pool, no separate database process. The database file travels with the app on Railway's persistent volume.

**Eventual consistency on feed** — The feed re-sorts by engagement score after reactions land via sockets, with a 2-second debounce. Users see the sort shift naturally without a page reload.

**Server-side view tracking** — Post impressions are recorded when the feed is fetched (`GET /api/posts`), not by client-side IntersectionObserver. This is reliable across all devices, including those that block JavaScript events.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 22 |
| HTTP framework | Express 4 |
| Real-time | Socket.io |
| Database | SQLite · `node:sqlite` (built-in) · WAL mode |
| Auth | JWT (`jsonwebtoken`) · `bcryptjs` |
| File uploads | `multer` |
| Video calls | Jitsi Meet (auto-generated room URLs) |
| Audio feedback | Web Audio API (no external files) |
| Frontend | Vanilla JS · no framework · no build step |
| Hosting | Railway · persistent volume for DB and uploads |

---

## Local Setup

```bash
git clone <repo-url>
cd linkedin-pro
npm install
node seed.js        # seed demo users and content
npm start           # http://localhost:3000
```

Requires Node.js 22+ (for `node:sqlite`).

---

## File Structure

```
nexus/
├── server.js          # Express REST API + Socket.io (~1700 lines)
├── db.js              # SQLite schema — 20+ tables, indexes, WAL setup
├── seed.js            # Demo content seeder
├── package.json
├── railway.toml       # Railway deployment config
├── nexus.db           # SQLite database (created on first run)
└── public/
    ├── index.html     # Full SPA — all pages, styles, and JS (~3300 lines)
    └── uploads/       # User-uploaded avatars and banners
```
