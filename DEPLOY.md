# Nexus — Production Deployment Guide

## Option A: Railway (Easiest, Free Tier Available)

### 1. Push to GitHub
```bash
cd C:\Users\Ankit\Documents\Project\linkedin-pro
git init
git add .
git commit -m "initial commit"
# Create a repo at github.com, then:
git remote add origin https://github.com/YOUR_USERNAME/nexus.git
git push -u origin main
```

### 2. Deploy on Railway
1. Go to https://railway.app → **New Project** → **Deploy from GitHub repo**
2. Select your `nexus` repo
3. Railway auto-detects Node.js and runs `npm start`
4. Go to **Variables** tab and add:
   ```
   JWT_SECRET=<generate with: node -e "console.log(require('crypto').randomBytes(64).toString('hex'))">
   NODE_ENV=production
   DEMO_EMAIL=ankit@example.com
   PORT=3000
   ```
5. Go to **Settings** → **Domains** → **Generate Domain** (free `.railway.app` URL)
6. For custom domain: add your domain there and point DNS as instructed

**Cost:** Free tier = 500 hours/month (enough for testing). $5/month Hobby plan for always-on.

---

## Option B: DigitalOcean VPS (Best for Production, $6/month)

### 1. Create a Droplet
- Go to https://digitalocean.com → Create → Droplet
- Choose: **Ubuntu 22.04**, **Basic**, **$6/mo** (1 vCPU, 1GB RAM)
- Add your SSH key
- Note the IP address (e.g. `157.245.10.20`)

### 2. Buy a Domain
- https://namecheap.com (search for a `.com` or `.in` domain, ~₹800/year)
- Set DNS A record: `@` → your Droplet IP, `www` → your Droplet IP
- DNS propagates in 5–30 minutes

### 3. Server Setup (SSH into your Droplet)
```bash
ssh root@YOUR_DROPLET_IP

# Install Node 22
curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
apt-get install -y nodejs

# Install nginx + certbot
apt install -y nginx certbot python3-certbot-nginx

# Install PM2
npm install -g pm2

# Clone your repo
mkdir -p /var/www
cd /var/www
git clone https://github.com/YOUR_USERNAME/nexus.git
cd nexus
npm install

# Create .env
cat > .env << 'EOF'
NODE_ENV=production
PORT=3000
JWT_SECRET=PASTE_YOUR_64_CHAR_SECRET_HERE
DEMO_EMAIL=ankit@example.com
EOF

# Create logs dir
mkdir -p logs

# Start with PM2
pm2 start ecosystem.config.js --env production
pm2 save
pm2 startup  # follow the printed command to auto-start on reboot
```

### 4. Configure nginx
```bash
# Copy the nginx config
cp /var/www/nexus/nginx.conf /etc/nginx/sites-available/nexus

# Edit domain name in the config
nano /etc/nginx/sites-available/nexus
# Replace yournexus.com with your actual domain

# Enable site
ln -s /etc/nginx/sites-available/nexus /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

### 5. SSL Certificate (Free, auto-renews)
```bash
certbot --nginx -d yourdomain.com -d www.yourdomain.com
# Follow prompts, choose option 2 (redirect HTTP to HTTPS)
```

Your app is now live at `https://yourdomain.com` 🎉

---

## Architecture (High Throughput Design)

```
Users (browser)
     │
     ▼
  Cloudflare (CDN + DDoS protection — free)
     │
     ▼
  nginx (reverse proxy, SSL termination, static file cache)
     │
     ├──/uploads/*  ──► Serve directly (no Node hit)
     ├──/socket.io  ──► Node (WebSocket upgrade)
     └──/api, /     ──► Node via PM2
                              │
                         SQLite (WAL mode)
                         (handles ~10k reads/sec,
                          500 writes/sec — fine for
                          tens of thousands of users)
```

**Cloudflare (free tier):**
1. Sign up at https://cloudflare.com
2. Add your domain, follow DNS migration steps
3. Enable **Proxy** (orange cloud) on DNS records
4. Free DDoS protection, global CDN, and analytics

---

## Keeping Seed/Demo Data Private

- Set `DEMO_EMAIL=ankit@example.com` in your `.env`
- Only that account sees all posts in the feed (including seed data)
- All other users only see posts from their own connections (real LinkedIn behaviour)
- Seed users still exist and can be used for demos — real users won't see their posts until they connect

---

## Generating a Secure JWT Secret
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```
Paste the output as `JWT_SECRET` in your `.env`.

---

## Updating the App After Changes
```bash
# On your VPS:
cd /var/www/nexus
git pull
npm install  # if package.json changed
pm2 restart nexus
```

---

## Monitoring
```bash
pm2 status          # check if app is running
pm2 logs nexus      # live logs
pm2 monit           # CPU/memory dashboard
```
