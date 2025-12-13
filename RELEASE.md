# JellyLooter v3.0.0 Release Notes

**Release Date:** December 2024

This is a major release introducing poster overlays, Pro features, enhanced security, and performance improvements.

---

## 🆕 New Features

### ⭐ Poster Overlays (NEW!)
- **Rating badges** - IMDB/TMDB ratings displayed on posters (e.g., ⭐ 8.5)
- **Quality badges** - Resolution (4K, 1080p, 720p), HDR, Dolby Vision, Atmos
- **Content ratings** - PG-13, R, TV-MA displayed on posters
- **Toggleable** - Enable/disable in Settings → Advanced Settings

### ⌨️ Keyboard Shortcuts
- Press `?` anytime to see all shortcuts
- Quick tabs: `1` Browse, `2` Sync, `3` Settings
- Downloads: `P` pause/resume, `D` download selected, `Ctrl+A` select all
- Navigation: `/` focus search, `Esc` clear selection, `R` refresh

### 📊 Download Statistics Widget
- Real-time download speed display
- Total downloaded tracker
- Today's download count
- Queue status at a glance

### 📦 Collection/Playlist Support
- "Download All" button on collections and playlists
- One-click to queue all movies/episodes in a collection
- Automatic recursive resolution of nested items

### 💾 Backup & Restore
- **Export config** - Download settings as JSON (API keys masked)
- **Import config** - Restore settings, preserves existing API keys
- Found in Settings → Advanced Settings → Backup & Restore

### 🏥 Health Check Endpoint
- Access at `/health` or `/api/health` (no auth required)
- Perfect for Docker healthchecks and monitoring
- Returns: version, uptime, queue status, disk space, server health

### Licensing System
- **Free tier:** 2 remote servers, 1 local server, 2 concurrent downloads
- **Trial:** 14 days of full Pro features (user-activated)
- **Pro ($10 lifetime):** Unlimited everything, no ads

### Pro Features
- Unlimited remote and local servers
- **10 concurrent downloads** (vs 2 for free)
- **🔄 Download resume** - Interrupted downloads can be resumed
- Notifications (Discord, Telegram, 80+ services via Apprise)
- **GPU Transcoding** - NVIDIA NVENC, Intel QuickSync, AMD VAAPI
- **Transcode Presets** - H.264, H.265, Mobile, 4K Optimized, Custom
- Download scheduling (only during off-peak hours)
- Bandwidth scheduling (full speed nights, throttled days)
- **Custom themes** - 14 presets (including seasonal) + custom colors
- ***arr integration** - Sonarr/Radarr folder naming
- **Multiple local servers** for duplicate detection
- Analytics dashboard
- No ads/banners

### UI Improvements
- Single-click to select shows/folders
- Double-click to navigate into folders
- Interaction hints below filter bar
- Hover tooltips on all items
- Mobile: Downloads & Stats in hamburger menu
- License banner for free users
- Movie downloads now use folder with year (e.g., "Inception (2010)/")
- Transcoding status shown in download queue
- Collapsible panels (click header to collapse)
- Automatic subtitle download (SRT, ASS, VTT)

---

## 🔒 Security Hardening

- **bcrypt password hashing** - Secure password storage
- **Rate limiting** - 5 login attempts per minute
- **Path traversal protection** - Blocks directory escape attacks
- **Input validation** - URL and API key format checking
- **Security headers** - X-Frame-Options, X-Content-Type-Options, CSP
- **Session timeout** - Configurable auto-logout
- **Reverse proxy support** - X-Forwarded-* headers
- **API keys encrypted at rest** - Sensitive data protected
- **Backup license system** - License recovery from library folders

---

## ⚡ Performance Improvements

- **Config caching** - Reduced disk reads
- **2-second polling** - Down from 1 second
- **Ring buffer logging** - Max 500 entries, prevents memory bloat
- **Delta updates** - Only sync changed data
- **Deque for history** - Efficient fixed-size collections
- ***arr cache** - Background refresh of Sonarr/Radarr folder names

---

## 🐛 Bug Fixes

- Fixed folder names not showing in browser
- Fixed mobile bottom sheet issues
- Improved poster image display
- Fixed download panel button tooltips

---

## 📦 Installation

### Docker
```bash
docker pull ghcr.io/friendlymedia/jellylooter:3.0.0
```

### Upgrade from v2.x
1. Pull the new image
2. Restart the container
3. Your config will be migrated automatically
4. If using username/password auth on remote servers, re-test connections

---

## ⚠️ Breaking Changes

None - v3.0.0 is backward compatible with v2.x configs.

---

## 📋 Dependencies

New dependencies in v3.0.0:
- bcrypt (password hashing)
- flask-limiter (rate limiting)
- flask-wtf (CSRF protection)
- apprise (notifications - Pro)
- gevent (async support)
- ffmpeg (transcoding - Pro, included in Docker image)

---

## 🙏 Support

- **Pro License:** [lightwave43.gumroad.com/l/rmtmrr](https://lightwave43.gumroad.com/l/rmtmrr)
- **Donations:** [Ko-fi](https://ko-fi.com/jellyloot)

Thank you for using JellyLooter!
