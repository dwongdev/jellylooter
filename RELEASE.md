# JellyLooter v3.2.0 Release Notes

**Release Date:** January 2025

This release adds external API integration for apps like NZB360 and Organizr, customizable dashboard layouts, per-server download workers, and enhanced statistics tracking.

---

## 🆕 New Features

### 🔌 External API Integration
- **API key authentication** - Generate secure API keys for external access
- **Full queue control** - Add, remove, pause, resume downloads via REST API
- **Server browsing** - Browse and search remote servers via API
- **Statistics endpoint** - Get download and transcode statistics
- **Built-in documentation** - API docs available at `/api/v1/docs`

**Compatible Apps:**
- **NZB360** - Use Custom Downloader with API key
- **Organizr** - Add status widget to dashboard
- **Home Assistant** - Create sensors from `/api/v1/status`
- **Custom scripts** - Automate downloads with curl/Python

### 📊 Dashboard Layouts
Choose from 6 layouts to customize how you browse media:

| Layout | Description |
|--------|-------------|
| **Classic** | Large posters with ratings, quality badges, and full details |
| **Compact** | Smaller posters with tighter spacing - fits 2x more items |
| **Cards** | Horizontal cards showing poster + title + year |
| **List** | Vertical list with small thumbnails - fastest browsing |
| **Minimal** | Posters only, hover for details - maximum density |
| **Large Posters** | Oversized artwork focus |

### ⚙️ Tabbed Settings UI
Redesigned settings page replaces collapsible dropdowns with organized tabs:
- **General** - Appearance, language, layout, display options, timezone
- **Servers** - Remote servers, local server, API integration  
- **Downloads** - Speed limits, retry settings, folder naming, metadata APIs
- **Security** - Authentication, reverse proxy settings
- **Pro** - Notifications, transcoding, resource limits, scheduling, *arr integration, themes

### ⚡ Resource Limits (Pro)
Control system resource usage to prevent overloading:

| Setting | Options | Effect |
|---------|---------|--------|
| **CPU Threads** | Auto, 1-16 | Limit FFmpeg threads during transcoding |
| **CPU Priority** | Low, Normal, High | Process scheduling via nice |
| **I/O Priority** | Idle, Low, Normal | Disk priority via ionice |
| **Memory Buffer** | 8-256 MB | Download buffer size |

**Recommended presets:**
- **NAS/Low-power:** Low CPU, Idle I/O, 16 MB buffer
- **Shared systems:** Normal CPU, Low I/O, 32 MB buffer
- **Dedicated server:** High CPU, Normal I/O, 256 MB buffer

### 📡 Per-Server Workers (Pro)
Download from multiple Jellyfin servers simultaneously:
- Each server gets its own dedicated worker pool
- Downloads from Server A don't block Server B
- Configure 1-10 workers per server (matches concurrent download limit)
- Total concurrent downloads = servers × workers per server

### 📈 Enhanced Download Statistics
- **Persistent tracking** - Stats survive container restarts
- **Per-server breakdown** - See downloads by server
- **Session vs total** - Track current session and all-time totals
- **Reset button** - Clear stats from the UI

### 💾 Transcode Savings Widget
- Shows space saved when transcoding is enabled
- Displays in main stats area (not hidden in Pro Settings)
- Shows files transcoded, space saved, and average reduction %

---

## 📡 API Endpoints

### Authentication
All API endpoints require an API key via:
- Header: `X-Api-Key: your_key`
- Query param: `?apikey=your_key`

### Endpoints

```
Status & Queue
GET  /api/v1/status              - Queue status, speeds, disk space
GET  /api/v1/queue               - Get download queue
POST /api/v1/queue/add           - Add item (body: server_id, item_id)
DELETE /api/v1/queue/{task_id}   - Cancel download
POST /api/v1/queue/pause         - Pause all downloads
POST /api/v1/queue/resume        - Resume downloads
POST /api/v1/queue/clear         - Clear pending queue

Servers & Browsing
GET  /api/v1/servers             - List configured servers
GET  /api/v1/servers/{id}/browse - Browse library (params: parent_id, limit)
GET  /api/v1/servers/{id}/search - Search library (params: q, limit)

History & Stats
GET  /api/v1/history             - Download history (params: limit, offset)
GET  /api/v1/stats               - Download and transcode statistics

Documentation
GET  /api/v1/docs                - API documentation (no auth required)
```

---

## 🐛 Bug Fixes

- **Fixed basic logs not showing activity** - Log patterns now account for timestamp prefixes
- **Fixed download stats not persisting** - Statistics now save to disk and survive restarts
- **Fixed transcode stats display** - Properly shows space saved percentage in API
- Fixed Sonarr series_provider_ids not being passed correctly to API
- Fixed series IDs falling back to episode IDs incorrectly
- Improved TVDB/IMDB lookup for Sonarr auto-add

---

## ⚙️ Configuration

### Enable API Access
1. Go to **Settings** → **API Integration**
2. Toggle **Enable API Access**
3. Click **Generate New Key**
4. Copy the key - it cannot be retrieved later!

### NZB360 Setup
1. Open NZB360 → Settings → Downloaders
2. Add Custom Downloader
3. Enter: `http://your-server:5000`
4. Add header: `X-Api-Key: your_key`

### Home Assistant Example
```yaml
sensor:
  - platform: rest
    name: JellyLooter Status
    resource: http://jellylooter:5000/api/v1/status
    headers:
      X-Api-Key: your_key_here
    value_template: "{{ value_json.status }}"
    json_attributes:
      - queue
      - speed
      - disk
```

---

## 📦 Installation

### Docker
```bash
docker pull ghcr.io/jlightner86/jellylooter:3.2.0
```

### Upgrade from v3.1.x
1. Pull the new image
2. Restart the container
3. Your config will be migrated automatically
4. Generate an API key in Settings if you want external access

---

## ⚙️ New Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| `api_enabled` | `false` | Enable API access |
| `api_key` | `` | Generated API key (encrypted) |
| `dashboard_layout` | `classic` | Dashboard layout style |
| `resource_limits_enabled` | `false` | Enable resource limiting |
| `cpu_limit_threads` | `0` | FFmpeg threads (0=auto) |
| `cpu_priority` | `normal` | Process priority (low/normal/high) |
| `io_priority` | `normal` | I/O priority (idle/low/normal) |
| `memory_buffer_mb` | `64` | Download buffer size |
| `per_server_workers` | `false` | Enable per-server download workers |
| `per_server_worker_count` | `2` | Workers per server (1-10) |

---

## 📋 Full Changelog

### New Features
- 🔌 External API integration with API key authentication
- 📡 Full REST API for queue, servers, history, and stats
- 📊 6 dashboard layout options (classic, compact, cards, list, minimal, large posters)
- 📖 Built-in API documentation endpoint
- ⚡ Resource limits - CPU threads, priority, I/O priority, memory buffer
- 📡 Per-server workers - download from multiple servers simultaneously (Pro)
- 📈 Enhanced download statistics with persistent tracking
- 💾 Transcode savings widget in main UI
- 🔒 API security: encryption at rest, brute force protection, one-time key display

### Bug Fixes
- Fixed basic logs not showing download activity (timestamp-aware patterns)
- Fixed download stats not persisting across restarts
- Fixed transcode stats percentage calculation in API
- Fixed Sonarr series_provider_ids being overwritten
- Fixed episode IDs incorrectly used for Sonarr lookups

### Improvements
- Added SeriesId to Fields request for better episode handling
- Enhanced logging for series provider ID resolution
- API keys encrypted in config file
- Rate limiting for API authentication (10 failed attempts = 5 min lockout)
- Download stats now include per-server breakdown
- Reset stats button in UI

---

## 🙏 Credits

- **[nwithan8](https://github.com/nwithan8)** - Fixed jellylooter.xml for Unraid Community Apps compatibility

---

## 🔗 Links

- **GitHub:** [github.com/jlightner86/jellylooter](https://github.com/jlightner86/jellylooter)
- **Pro License:** [lightwave43.gumroad.com/l/rmtmrr](https://lightwave43.gumroad.com/l/rmtmrr)
- **API Docs:** `/api/v1/docs` (on your JellyLooter instance)

Thank you for using JellyLooter!
