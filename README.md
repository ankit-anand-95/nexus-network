# LinkedIn Pro 🚀

A full-stack LinkedIn clone with SQLite persistence + features LinkedIn doesn't have.

## Features

### LinkedIn features
- Auth (register / login / JWT)
- Feed with posts, likes, comments, shares
- Profile with experience, education, skills, avatar, banner
- Network — connections, pending requests, suggestions
- Real-time messaging (Socket.io)
- Notifications
- Jobs — post, search, easy apply
- Dark mode

### Extra features LinkedIn doesn't have
- **Anonymous posting** — post without revealing your identity
- **Poll posts** — create multi-option polls in the feed
- **Scheduled posts** — write now, publish later
- **Salary Transparency Board** — share & browse salaries by company/role/city
- **Glassdoor-style Company Reviews** — rate WLB, culture, salary, growth
- **Topmate-style Mock Interview Booking** — book sessions with mentors, auto Jitsi link

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

## Tech Stack

- **Backend**: Node.js, Express, Socket.io
- **Database**: SQLite (better-sqlite3) — zero setup, file-based
- **Auth**: JWT + bcryptjs
- **File uploads**: multer
- **Video calls**: Jitsi Meet (auto-generated links)
- **Frontend**: Vanilla JS SPA — no framework, no build step

## File Structure

```
linkedin-pro/
├── server.js        # Express API + Socket.io
├── db.js            # SQLite schema (18 tables)
├── seed.js          # Demo data
├── package.json
├── linkedin.db      # Created on first run
└── public/
    ├── index.html   # Full SPA frontend
    └── uploads/     # User-uploaded images
```
