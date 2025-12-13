# JellyLooter v3.0.0

**Sync media from remote Jellyfin/Emby servers to your local storage.**

Built by Friendly Media — because your friends' Jellyfin libraries aren't going to backup themselves.

![JellyLooter Banner](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/banner.png)

---

## Screenshots

| Browse Library | Download Queue | Settings |
|----------------|----------------|----------|
| ![Browse](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/browse.png) | ![Queue](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/queue.png) | ![Settings](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/settings.png) |

| Rating Overlays | Quality Badges | Pro Features |
|-----------------|----------------|--------------|
| ![Ratings](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/ratings.png) | ![Quality](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/quality.png) | ![Pro](https://raw.githubusercontent.com/friendlymedia/jellylooter/main/screenshots/pro.png) |

---

## What's New in v3.0.0

This is a major release with Pro features, security hardening, and UI enhancements.

### ⭐ Poster Overlays (NEW!)
- **Rating badges** - IMDB/TMDB ratings displayed on posters
- **Quality badges** - 4K, 1080p, 720p, HDR, Dolby Vision, Atmos
- **Content ratings** - PG-13, R, TV-MA displayed on posters
- **Toggleable** - Enable/disable in Advanced Settings

### ⌨️ Keyboard Shortcuts
- Press `?` to see all shortcuts
- Quick navigation (1, 2, 3 for tabs)
- Download controls (P=pause, D=download, Ctrl+A=select all)

### 📊 Download Statistics
- Real-time download speed display
- Total downloaded tracker
- Queue status at a glance

### 📦 Collection/Playlist Support
- "Download All" button on collections and playlists
- Automatically fetches all movies/episodes
- One-click batch download

### 💾 Backup & Restore
- Export configuration to JSON
- Import settings (API keys masked for security)
- Health check endpoint (`/health`) for Docker monitoring

### 🔄 Download Resume (Pro)
- Interrupted downloads can be resumed
- Partial files saved automatically
- Resume from where you left off

### 🎨 Visual Enhancements
- GPU transcoding support (NVENC, QuickSync, VAAPI)
- Custom themes (14 presets including seasonal)
- Movie folder naming with year (e.g., "Inception (2010)/")

### 🔗 *arr Integration
- Sonarr/Radarr folder naming support
- Use exact folder names from your *arr apps
- Auto-refresh cache for folder lookups

---

## Free vs Pro

| Feature | Free | Pro ($10 lifetime) |
|---------|------|--------------------|
| Remote servers | 2 | Unlimited |
| Local servers | 1 | Unlimited |
| Concurrent downloads | 2 | 10 |
| Auto-sync mappings | 1 | Unlimited |
| Items per page | 100 | Unlimited |
| Rating overlays | ✅ | ✅ |
| Quality badges | ✅ | ✅ |
| Download history | ✅ | ✅ |
| Keyboard shortcuts | ✅ | ✅ |
| Download statistics | ✅ | ✅ |
| Collection download | ✅ | ✅ |
| Config backup/restore | ✅ | ✅ |
| Health check endpoint | ✅ | ✅ |
| Download resume | ❌ | ✅ |
| Notifications | ❌ | ✅ Discord, Telegram, 80+ |
| Custom themes | ❌ | ✅ 14 presets + custom |
| GPU transcoding | ❌ | ✅ NVENC, QuickSync, VAAPI |
| Download scheduling | ❌ | ✅ |
| *arr integration | ❌ | ✅ |
| Analytics | ❌ | ✅ |
| Ads/banner | Yes | None |

**Get Pro:** [lightwave43.gumroad.com/l/rmtmrr](https://lightwave43.gumroad.com/l/rmtmrr)

---

## Compatibility

| Platform | Version | Status |
|----------|---------|--------|
| Unraid | 7.0+ / 7.2.2 | ✅ Tested |
| Docker | Linux/macOS/Windows | ✅ Tested |
| Jellyfin | 10.8+ | ✅ Supported |
| Emby | 4.7+ | ✅ Supported |

---

## Quick Start

### Docker Run

```bash
docker run -d \
  --name jellylooter \
  -p 5000:5000 \
  -v /path/to/config:/config \
  -v /path/to/media:/storage \
  ghcr.io/friendlymedia/jellylooter:latest
```

### Docker Compose

```yaml
version: "3"
services:
  jellylooter:
    image: ghcr.io/friendlymedia/jellylooter:latest
    container_name: jellylooter
    ports:
      - "5000:5000"
    volumes:
      - ./config:/config
      - /mnt/media:/storage
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:5000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Windows Docker Desktop

```powershell
docker run -d `
  --name jellylooter `
  -p 5000:5000 `
  -v C:\JellyLooter\config:/config `
  -v D:\Media:/storage `
  ghcr.io/friendlymedia/jellylooter:latest
```

### Unraid

1. Install from Community Applications (search "JellyLooter")
2. Or manually add using the included `jellylooter.xml` template
3. Configure paths and optional GPU passthrough for transcoding

---

## Health Check Endpoint

JellyLooter provides a `/health` endpoint for monitoring:

```bash
curl http://localhost:5000/health
```

Returns JSON with status, disk space, queue info, and server connectivity. Returns HTTP 200 if healthy, 503 if unhealthy (e.g., disk < 1GB free).

---

## Features

### Core Features (Free)
- 📺 Browse remote Jellyfin/Emby libraries
- ⬇️ Download movies, shows, seasons, episodes
- 📝 Automatic subtitle download (SRT, ASS, VTT)
- 🔍 Duplicate detection with local server
- ⭐ Rating overlays (IMDB/TMDB/Rotten Tomatoes)
- 📊 Quality badges (4K, HDR, Dolby Vision, Atmos)
- 📦 Collection/Playlist batch download
- ⌨️ Keyboard shortcuts (press ? for help)
- 📈 Download statistics widget
- 💾 Config backup & restore
- 🌐 Multi-language UI (English, Spanish, German)
- 🌙 Dark/Light theme
- ⏸️ Download queue with pause/resume
- 📈 Progress tracking with ETA
- 📜 Download history

### Pro Features ($10 lifetime)
- 🖥️ **Unlimited servers** - Connect to all your friends
- 🔄 **Download resume** - Resume interrupted downloads from where you left off
- 🔔 **Notifications** - Discord, Telegram, Email, and 80+ services via Apprise
- 🎬 **GPU Transcoding** - NVENC (NVIDIA), QuickSync (Intel), VAAPI (AMD/Intel)
- ⏰ **Download scheduling** - Only download during off-peak hours
- 📉 **Bandwidth scheduling** - Full speed at night, throttled during day
- 🎨 **Custom themes** - 14 presets (seasonal, platform) or custom colors
- 📁 **\*arr integration** - Sonarr/Radarr folder naming
- 📊 **Analytics dashboard** - Download stats and graphs
- ⬇️ **10 concurrent downloads** - vs 2 for free tier
- ✨ **No ads** - Clean, distraction-free UI

---

## Security

v3.0.0 includes significant security improvements:

- ✅ bcrypt password hashing
- ✅ Rate limiting (5 login attempts/minute)
- ✅ Path traversal protection
- ✅ Input validation
- ✅ Security headers (X-Frame-Options, CSP)
- ✅ Session timeout (configurable)
- ✅ Reverse proxy support (X-Forwarded-* headers)

### Reverse Proxy Setup

If exposing JellyLooter externally:

1. Enable "Trust X-Forwarded headers" in Security Settings
2. Add your proxy IP to "Trusted proxy IPs"
3. Use strong passwords
4. Consider using Cloudflare or similar for additional protection

---

## Configuration

Access the web UI at `http://your-server:5000`

### First Run
1. (Optional) Enable authentication in Settings → Security
2. Add a remote server (your friend's Jellyfin/Emby)
3. Test the connection before saving
4. Configure local server for duplicate detection
5. Start browsing and downloading!

### Settings Overview

| Setting | Description |
|---------|-------------|
| Remote Servers | Jellyfin/Emby servers to download from |
| Local Server | Your Jellyfin for duplicate detection |
| Speed Limit | Throttle download speed (0 = unlimited) |
| Max Downloads | Concurrent download threads |
| Show Ratings | Toggle rating overlays on posters |
| Show Quality | Toggle quality badges (4K, HDR, etc.) |

---

## Support

- **Buy Pro License:** [lightwave43.gumroad.com/l/rmtmrr](https://lightwave43.gumroad.com/l/rmtmrr)
- **GitHub:** [Issues & Discussions](https://github.com/friendlymedia/jellylooter)

---

## ⚠️ Legal Disclaimer

**JellyLooter is designed for legitimate personal use only.**

This software is intended to help users sync and backup media they have legal access to, such as:
- Content you own or have purchased
- Media shared by friends/family with their permission
- Content from servers you are authorized to access

**We do not support, condone, or encourage:**
- Piracy or illegal downloading of copyrighted content
- Circumventing DRM or copy protection
- Distributing copyrighted material without authorization
- Any use that violates copyright laws in your jurisdiction

**You are solely responsible** for ensuring your use of this software complies with all applicable laws and the terms of service of any media servers you access. The developers assume no liability for misuse of this software.

By using JellyLooter, you agree to use it only for lawful purposes.

---

## License

MIT License - Free to use, modify, and distribute.

Pro features require a valid license key.
