# Nexus 🚀

A full-stack LinkedIn clone built with Node.js, SQLite, Socket.io, and vanilla JS — plus features LinkedIn doesn't have.

Live: [nexus-network-production.up.railway.app](https://nexus-network-production.up.railway.app)

---

## Features

### Core LinkedIn features
- Auth — register, login, JWT with auto-login
- Feed — posts, rich reactions (Like / Insightful / Celebrate / Support / Funny), comments, shares
- Profile — headline, bio, experience, education, skills, avatar, banner image
- Network — connection requests, degrees (1st/2nd/3rd), mutual connections, People You May Know suggestions
- Real-time messaging — Socket.io chat with read receipts, typing indicators, unread badge sync across devices
- Notifications — bell with badge, real-time delivery, per-type icons
- Jobs — post, search/filter, Easy Apply, job poster sees Edit/Close controls
- Dark mode — system preference detected, toggleable, persists

### Extra features LinkedIn doesn't have
- **Anonymous posting** — post without revealing identity; anonymous avatar shown
- **Poll posts** — create multi-option polls directly in the feed
- **Scheduled posts** — write now, auto-publish at a chosen time
- **Salary Transparency Board** — share & browse real salaries by company/role/city/stack
- **Glassdoor-style Company Reviews** — rate WLB, culture, recommend; edit/delete own entries
- **Topmate-style Mentorship Booking** — browse experts, book sessions, auto-Jitsi meeting link, accept/decline/reschedule flow
- **Post reactions with emoji picker** — 5 reaction types, long-press on mobile, hover on desktop
- **Profile analytics** — profile views (30d) and post impressions tracked in real time
- **Saved posts** — bookmark any post and view saved list
- **Trending hashtags** — server-cached trending topics in right sidebar

### UX / technical highlights
- Full responsive design — dedicated mobile layout with bottom nav, tablet and desktop layouts
- Skeleton loaders — no blank flash on page load
- Client-side API cache (30 s TTL) with targeted invalidation — instant UI updates without stale data
- Eventual consistency for feed sort — re-sorts after reactions without full reload
- Recent search history — dropdown on search focus with clear/remove per item
- Custom in-app confirm dialogs — no native browser popups
- Web Audio API notification sounds — distinct tones for messages vs notifications
- Real-time presence indicators (green dot / Away)
- Cross-device badge sync — message/notification counts stay in sync across tabs and devices
- Post impression tracking — server-side view recording per unique user

---

## Setup

```bash
cd linkedin-pro
npm install
node seed.js      # populate demo data
npm start         # http://localhost:3000
```

## Demo Accounts

| Email | Password |
|---|---|
| ankit@example.com | password |
| priya@example.com | password |
| rahul@example.com | password |
| sneha@example.com | password |
| arjun@example.com | password |

---

## Tech Stack

| Layer | Tech |
|---|---|
| Runtime | Node.js 22 |
| API | Express 4 |
| Real-time | Socket.io |
| Database | SQLite via `node:sqlite` (built-in, WAL mode) |
| Auth | JWT + bcryptjs |
| File uploads | multer |
| Video calls | Jitsi Meet (auto-generated room links) |
| Frontend | Vanilla JS SPA — zero frameworks, zero build step |
| Hosting | Railway (persistent volume for DB + uploads) |

## File Structure

```
nexus/
├── server.js        # Express REST API + Socket.io handlers (~1700 lines)
├── db.js            # SQLite schema — 20+ tables, indexes, WAL setup
├── seed.js          # Demo users, posts, jobs, salaries, reviews
├── package.json
├── railway.toml     # Railway deploy config
├── nexus.db         # Created on first run
└── public/
    ├── index.html   # Full SPA frontend (~3300 lines)
    └── uploads/     # User-uploaded avatars and banners
```
