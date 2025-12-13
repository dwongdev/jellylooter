# JellyLooter Roadmap

## Current Version: 2.4.1

---

## v2.4.2 - Quick Fixes (Current)

| Fix | Description |
|-----|-------------|
| Folder names visible | Show titles on folder items |
| Single-click to select | Works on folders and media |
| Double-click to navigate | Enter folders |
| Select All includes folders | Can select entire shows |

---

## v3.0.0 - The Big One

### Licensing System

**Tiers:**
| Tier | Price | Duration | Features |
|------|-------|----------|----------|
| Free | $0 | Forever | 2 remote, 1 local, 1 sync, ads |
| Trial | $0 | 14 days (user-activated) | All Pro features |
| Pro | $10 | Lifetime | Unlimited everything, no ads |

**Gumroad Integration:**
| Feature | Description |
|---------|-------------|
| License key purchase | Via Gumroad storefront |
| Hybrid validation | Online verify when possible, offline fallback |
| Instant delivery | Key emailed automatically |

**Banner System:**
| Tier | Banner |
|------|--------|
| Free | Ko-fi/Gumroad support banner (bottom of page) |
| Trial | "Pro Trial: X days left - Buy $10" |
| Pro | None - clean UI |

---

### Free Features (everyone)

| Feature | Description |
|---------|-------------|
| 2 remote servers | Connect to friends' libraries |
| 1 local server | For duplicate detection |
| 1 auto-sync mapping | Basic automation |
| Download history | Track completed downloads |
| Search/filter | Find items in current view |
| 100 items per page max | |
| Folder names visible | Titles shown on folders |
| Single-click select | Works on shows/folders too |
| Double-click to navigate | Enter folders |
| Hover tooltips on posters | Show title on hover |
| Keyboard shortcuts | Space=select, Enter=download, arrows=navigate |
| "What's New" indicators | Highlight new content since last visit |
| Remember last location | Per server |
| Stop after current downloads | Finish queue gracefully |
| Interaction hints | Help text: "Single-click to select • Double-click to open folders" |

---

### Pro Features ($10 lifetime)

**Unlimited:**
| Feature | Description |
|---------|-------------|
| Unlimited remote servers | Connect to as many as you want |
| Unlimited local servers | Multiple Jellyfin/Emby instances |
| Unlimited auto-sync mappings | Full automation |
| Unlimited items per page | No pagination limits |

**Media Processing:**
| Feature | Description |
|---------|-------------|
| Transcode on download | Convert during download |
| H.265 preset | Smaller files, same quality |
| Mobile-friendly preset | 720p, lower bitrate |
| Custom transcode | Pick codec, resolution, bitrate |
| Smart sync | Only download if better quality than local |
| Exclude patterns | Skip "Sample" files, specific codecs |

**Automation:**
| Feature | Description |
|---------|-------------|
| Download scheduling | Only download between X-Y hours |
| Bandwidth scheduling | Full speed nights, throttled days |
| Download priorities | Prioritize certain shows/movies |
| *arr integration | Sonarr, Radarr, Lidarr |

**Notifications:**
| Feature | Description |
|---------|-------------|
| Discord webhook | Notify on download complete |
| Telegram bot | Push notifications |
| Apprise | 80+ notification services |

**Customization:**
| Feature | Description |
|---------|-------------|
| Custom themes | Color picker for accent, background, text |
| Pre-built themes | Plex orange, Emby green, Netflix red |
| No ads/banners | Clean UI |

**Analytics:**
| Feature | Description |
|---------|-------------|
| Download stats | Total downloaded, by server, by month |
| Storage dashboard | Visual breakdown of disk usage |
| Speed graphs | Historical download speed chart |

**Advanced:**
| Feature | Description |
|---------|-------------|
| Import/Export config | Backup and restore settings |
| API access | REST API for automation |

---

### Performance Optimization

**Problems to fix:**
| Issue | Cause |
|-------|-------|
| UI freezes during downloads | Blocking I/O on main thread |
| Sluggish response | Status polling too heavy |
| High CPU usage | Inefficient loops, no caching |
| Memory bloat | Holding too much in memory |

**Optimizations:**
| Area | Current | Optimized |
|------|---------|-----------|
| Status polling | Every 1 second, full data | Every 2-3 sec, delta updates only |
| Download workers | May block Flask thread | Separate process (multiprocessing) |
| File I/O | Synchronous | Async with threading |
| Config loading | Read from disk every request | Cache in memory, reload on change |
| Local cache | Full scan on rebuild | Incremental updates |
| Logging | Unbounded list | Ring buffer (last 500 entries) |
| Frontend | Re-render everything | Only update changed DOM elements |

---

### Security Hardening

| Priority | Fix | Description |
|----------|-----|-------------|
| 1 | Path traversal protection | Block `../../` attacks |
| 2 | Rate limiting on login | 5 attempts per minute |
| 3 | Input validation | URL format, API key format |
| 4 | Security headers | X-Frame-Options, CSP, etc. |
| 5 | CSRF protection | Protect forms from cross-site attacks |
| 6 | Session hardening | Secure, HttpOnly, SameSite cookies |
| 7 | Password hashing | bcrypt (never plain text) |
| 8 | Session timeout | Configurable auto-logout |
| 9 | Trusted proxy support | X-Forwarded-* headers |
| 10 | Force HTTPS option | For reverse proxy setups |

**Security Settings UI:**
```
┌─────────────────────────────────────┐
│ Security Settings                   │
├─────────────────────────────────────┤
│ ☑ Enable authentication             │
│                                     │
│ Username: [admin            ]       │
│ Password: [••••••••••••••••]        │
│                                     │
│ Session timeout: [30 mins   ▼]      │
│                                     │
│ ☑ Force HTTPS (reverse proxy)       │
│ ☑ Trust X-Forwarded headers         │
│ Trusted proxy IPs: [172.17.0.0/16]  │
└─────────────────────────────────────┘
```

---

### UI/UX Improvements

| Feature | Description |
|---------|-------------|
| Faster UI | No sluggishness during downloads |
| Mobile hamburger menu | Downloads & Stats moved here |
| Remove bottom sheet | Cleaner mobile experience |
| Better error messages | Clear, actionable |
| Interaction hints | "Single-click to select • Double-click to open folders" |
| Folder hover tooltip | "Double-click to open" |

---

### Integrations

| Service | Purpose |
|---------|---------|
| Gumroad | License key purchase & verification |
| Sonarr | TV show management (Pro) |
| Radarr | Movie management (Pro) |
| Lidarr | Music management (Pro) |
| Apprise | 80+ notification services (Pro) |
| FFmpeg | Transcoding (Pro) |

---

## v4.0.0 - Future Ideas

| Feature | Description |
|---------|-------------|
| Multi-user | Separate accounts with permissions |
| Mobile app | PWA or native app |
| Plex support | Add Plex as source/destination |
| Cloud storage | Download to S3, Google Drive, etc. |

---

## Technical Notes

### License Key System
- Gumroad handles key generation and purchase
- Hybrid validation: online when possible, offline fallback
- Keys stored in config.json
- Format validation works offline

### Platforms
| Platform | Use |
|----------|-----|
| Gumroad | License sales (10% fee) |
| Ko-fi | Tips/donations (0% fee) |
| GitHub | Source code, issues, releases |

### Testing Options (for later)
- Local Docker testing (no Unraid needed)
- Dev mode flag (`--dev`) for mock data
- Automated pytest suite for security
- Mock Jellyfin server for API testing

---

## Development Notes

- All development/testing done locally on Unraid before public release
- Ko-fi link: https://ko-fi.com/jellyloot
- Gumroad: TBD
- No priority support offered - documentation and community only

---

*Last updated: December 2024*
