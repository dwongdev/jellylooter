# JellyLooter v3.1.0 - Pre-Release Testing Checklist

## 🆕 New in v3.1.0

### Folder Naming Formats
- [ ] Settings dropdown shows 6 format options
- [ ] Live preview updates when format selected
- [ ] Movie preview shows: `Movie Name (2024) {imdb-tt1234567}`
- [ ] TV preview shows: `Show Name {imdb-tt1234567} {tvdb-12345}`
- [ ] **Standard format**: No IDs appended
- [ ] **IDs (Space)**: `tt1234567 12345`
- [ ] **IDs (Braces)**: `{imdb-tt1234567} {tvdb-12345}`
- [ ] **IDs (Brackets)**: `[imdb-tt1234567] [tvdb-12345]`
- [ ] **TMDB Only**: `{tmdb-12345}`
- [ ] **IMDB Only**: `tt1234567`
- [ ] Episodes use **series IDs**, not episode IDs
- [ ] All episodes of same series go in ONE folder

### External Metadata APIs
- [ ] TMDB API key field saves (encrypted)
- [ ] TVDB API key field saves (encrypted)
- [ ] OMDb API key field saves (encrypted)
- [ ] "Get free key" links work
- [ ] Lookup timing toggle works ("On Browse" vs "On Download")
- [ ] API fallback chain works: TMDB → TVDB → OMDb
- [ ] Log shows: `✅ TMDB lookup success: Show Name -> IMDB:tt1234567`
- [ ] Log shows: `⚠️ TMDB: No results for 'Unknown Show'`
- [ ] Log shows: `❌ No metadata API keys configured`
- [ ] Pro: Metadata caching works (cache hit message in logs)
- [ ] Free: No caching (always hits API)

### Activity Log Views
- [ ] Dropdown shows "Basic" and "Advanced" options
- [ ] Basic view shows only download activity
- [ ] Advanced view shows all logs (metadata, cache, debug)
- [ ] History button (📜) toggles to history view
- [ ] Rebuild Cache button (🔄) works
- [ ] Buttons are icon-only (no text overflow)

### Transcoding (Pro)
- [ ] Settings appear in Pro Features section
- [ ] "Enable transcoding" toggle saves
- [ ] Encoder dropdown works (Software, NVENC, QSV, VAAPI)
- [ ] Preset dropdown works (Original, H.264, H.265, Mobile, 4K)
- [ ] **Test mode**: Click "O" in "COMING SOON" 5x reveals panel
- [ ] Test mode toggle enables transcoding for testing
- [ ] Log shows: `🎬 [TRANSCODE PRO] Processing: file.mkv`
- [ ] Log shows: `✅ [TRANSCODE] Success: file_transcoded.mkv`
- [ ] Original file replaced with transcoded file
- [ ] Hardware encoder fallback to software works

### Download Statistics
- [ ] Total Downloaded shows correct value
- [ ] Today's count shows correct value
- [ ] Stats persist across container restarts
- [ ] Stats DON'T reset to 0 during active downloads
- [ ] Speed updates in real-time

### Multi-Local Server (Cache)
- [ ] Rebuild Cache scans all configured local servers
- [ ] Log shows: `Scanning ServerName...`
- [ ] Log shows: `Scanned X items from ServerName`
- [ ] Cache properly clears old data before rebuild
- [ ] Deleted files no longer show as "owned"

---

## 🔧 Environment Setup

- [ ] Build Docker image successfully
- [ ] Container starts without errors
- [ ] Web UI loads at http://localhost:5000
- [ ] No Python errors in container logs

---

## 🔐 Security Testing

### Authentication
- [ ] App works with auth disabled (no login required)
- [ ] Can enable authentication in settings
- [ ] Setup page appears on first run with auth enabled
- [ ] Can create username/password
- [ ] Login works with correct credentials
- [ ] Login fails with wrong password
- [ ] Rate limiting works (block after 5 failed attempts in 1 minute)
- [ ] Session timeout works (configurable)
- [ ] Logout clears session
- [ ] "Remember me" works (token stored, auto-login)

### Password Security
- [ ] Passwords are hashed (not plain text in auth.json)
- [ ] bcrypt hash format (starts with $2) if bcrypt available
- [ ] Legacy SHA256 passwords still work after upgrade

### Path Traversal
- [ ] Cannot browse outside /storage or /mnt directories
- [ ] `../` in path is blocked
- [ ] Error logged when traversal attempted

### Input Validation
- [ ] Invalid URL format rejected (no http/https)
- [ ] Short API key rejected
- [ ] Long API key rejected
- [ ] Invalid characters in API key rejected

### Security Headers
- [ ] X-Content-Type-Options: nosniff present
- [ ] X-Frame-Options: SAMEORIGIN present
- [ ] X-XSS-Protection present

### Reverse Proxy Support
- [ ] Force HTTPS option saves
- [ ] Trust proxy headers option saves
- [ ] Trusted proxy IPs setting saves

---

## 📜 Licensing System

### Free Tier
- [ ] Default tier is "free"
- [ ] License banner appears at bottom
- [ ] Ko-fi and Gumroad links work
- [ ] Can only add 2 remote servers (3rd blocked)
- [ ] Can only add 1 local server
- [ ] Can only add 1 sync mapping
- [ ] Items per page capped at 100

### Trial Activation
- [ ] "Start Trial" button works
- [ ] Trial lasts 14 days
- [ ] Trial banner shows days remaining
- [ ] Pro features unlocked during trial
- [ ] Cannot re-activate trial after expiration
- [ ] Reverts to free when trial expires

### Pro License
- [ ] "Enter License Key" button works
- [ ] Invalid key format rejected
- [ ] Valid key activates Pro
- [ ] Pro badge appears in settings
- [ ] License banner hidden for Pro users
- [ ] All limits removed for Pro
- [ ] Gumroad API verification works (if online)
- [ ] Offline fallback works (format check only)

### API Endpoints
- [ ] GET /api/license returns correct tier info
- [ ] POST /api/license/activate works
- [ ] POST /api/license/trial works
- [ ] POST /api/license/deactivate works

---

## 📡 Remote Server Management

### Adding Servers
- [ ] "Add Remote Server" button opens modal
- [ ] Modal translations work (all 3 languages)
- [ ] Can add server with API key
- [ ] Can add server with username/password
- [ ] "Test Connection" works before saving
- [ ] Warning hint displayed ("Test before adding")
- [ ] Server appears in list after adding
- [ ] Server appears in dropdown
- [ ] Free tier: blocked after 2 servers

### Editing/Removing Servers
- [ ] Can remove server from list
- [ ] Removed server disappears from dropdown

### Connection Testing
- [ ] Valid server shows success
- [ ] Invalid URL shows error
- [ ] Wrong API key shows error
- [ ] Wrong username/password shows error
- [ ] Timeout handled gracefully

---

## 🏠 Local Server Management

### Single Local Server
- [ ] "Configure Local Server" button works
- [ ] Can save local server URL and API key
- [ ] Can use username/password auth instead
- [ ] Test connection works
- [ ] Cache rebuild starts
- [ ] Scan progress shown
- [ ] Cache count updates
- [ ] Duplicate detection works (items grayed out with ✓)

### Multi-Local Server (Pro)
- [ ] "Add Local Server" shows for Pro users
- [ ] Can add multiple local servers
- [ ] Each server appears in list
- [ ] Can remove individual servers
- [ ] Rebuild Cache scans ALL servers
- [ ] Log shows each server being scanned
- [ ] Combined cache includes all servers' items
- [ ] Free tier: limited to 1 local server

---

## 📂 Remote Browser

### Navigation
- [ ] Libraries load after selecting server
- [ ] Can click into library (folder)
- [ ] Breadcrumb path updates
- [ ] Can navigate back via breadcrumb
- [ ] Home button returns to root

### Selection
- [ ] **Single-click selects item** (folders AND media)
- [ ] **Double-click opens folders**
- [ ] Ctrl+click multi-select
- [ ] Right-click selects
- [ ] Selection count updates
- [ ] "Select All" selects everything on page (including folders)
- [ ] "Clear" clears selection

### Display
- [ ] Folder names visible (gradient overlay)
- [ ] Poster images load
- [ ] Placeholder icons for items without images
- [ ] Hover tooltip shows item name
- [ ] Folder tooltip says "double-click to open"
- [ ] **Interaction hints visible** below filter bar

### Filter/Search
- [ ] Filter box works
- [ ] Typing filters items
- [ ] Clear filter shows all

### Pagination
- [ ] Items per page dropdown works
- [ ] Page numbers display
- [ ] Can navigate pages
- [ ] Free tier: max 100 items enforced
- [ ] Pro: 200 items per page works

---

## ⬇️ Downloads

### Queue Management
- [ ] "Download Selected" starts downloads
- [ ] Download path modal appears
- [ ] Can browse for destination
- [ ] Quick path buttons work (from mappings)
- [ ] Downloads appear in queue
- [ ] Progress bar updates
- [ ] Speed displayed
- [ ] ETA displayed
- [ ] Pause button works
- [ ] Resume button works
- [ ] Cancel individual download works
- [ ] Cancel All works
- [ ] **Stop After Current works**

### Download History
- [ ] History panel accessible
- [ ] Completed downloads appear in history
- [ ] Timestamp shown
- [ ] History limited to 1000 items (deque)

### Browser Tab Title
- [ ] Title shows download count: "JellyLooter (3 ⬇)"
- [ ] Title clears when downloads complete

---

## ⚡ Performance

### Config Caching
- [ ] Config loads from cache (no disk read every request)
- [ ] Cache invalidates when config saved
- [ ] Performance feels snappy

### Status Polling
- [ ] Polling interval is 2 seconds (not 1)
- [ ] UI updates without lag

### Log Buffer
- [ ] Logs don't grow unbounded
- [ ] Oldest logs removed (ring buffer)

---

## 📱 Mobile

### Hamburger Menu
- [ ] Hamburger button visible on mobile
- [ ] Menu slides out on tap
- [ ] **Downloads option in menu** with badge
- [ ] **Stats shown in menu**
- [ ] Theme toggle in menu
- [ ] Other links work (Changelog, Help, etc.)
- [ ] Logout works from menu

### Mobile Modals
- [ ] Downloads modal opens from menu
- [ ] Activity log modal opens from menu
- [ ] Pause/Resume buttons in mobile modal
- [ ] Queue syncs with desktop queue

### Responsive Layout
- [ ] Grid adjusts to screen width
- [ ] No horizontal scroll
- [ ] Posters display correctly
- [ ] Selection bar usable

---

## ⌨️ Keyboard Shortcuts

- [ ] **Space** - toggles selection on focused item
- [ ] **Enter** - triggers download of selected
- [ ] **Ctrl+A** - select all
- [ ] **Escape** - clear selection
- [ ] **/** - focus search box
- [ ] Shortcuts disabled when typing in input

---

## ⭐ Pro Features

### Notifications (Pro)
- [ ] Notification URLs save
- [ ] Toggle for complete/error notifications
- [ ] Apprise sends notification on download complete
- [ ] Apprise sends notification on download error
- [ ] Feature disabled for free tier

### Transcoding (Pro)
- [ ] Transcode toggle saves in settings
- [ ] Preset selection works (Original, H.264, H.265, Mobile, 4K)
- [ ] Encoder selection works (Software, NVENC, QSV, VAAPI)
- [ ] **With Pro + enabled**: Transcode runs automatically
- [ ] **Test mode**: Transcode runs when test mode enabled
- [ ] Log shows transcode check: `test_mode=False, enabled=True, feature=True, preset=h265`
- [ ] Log shows processing: `🎬 [TRANSCODE PRO] Processing: filename.mkv`
- [ ] H.265 transcode runs after download
- [ ] Mobile preset outputs 720p
- [ ] Original file removed after transcode
- [ ] Savings percentage logged: `saved 45.2%`
- [ ] Hardware encoder errors fall back to software
- [ ] Feature disabled for free tier

### Scheduling (Pro)
- [ ] Download schedule toggle saves
- [ ] Start/end time fields work
- [ ] Downloads blocked outside schedule
- [ ] Bandwidth schedule toggle saves
- [ ] Day/night limits respected
- [ ] Feature disabled for free tier

### *arr Integration (Pro)
- [ ] Sonarr URL/key saves
- [ ] Radarr URL/key saves
- [ ] "Test Sonarr" button works
- [ ] "Test Radarr" button works
- [ ] Library scan triggered after download
- [ ] Feature disabled for free tier

### Analytics (Pro)
- [ ] GET /api/analytics returns data
- [ ] Total downloads shown
- [ ] Total size shown
- [ ] By-date grouping works
- [ ] Feature disabled for free tier

---

## 🔒 Security Settings UI

- [ ] Security settings section toggles open/closed
- [ ] Auth enabled checkbox saves
- [ ] Session timeout saves
- [ ] Force HTTPS saves
- [ ] Trust proxy saves
- [ ] Trusted IPs saves
- [ ] "Save Security Settings" works

---

## ⭐ Pro Settings UI

- [ ] Pro settings section toggles open/closed
- [ ] License status box shows correct tier
- [ ] Pro badge shown for Pro users
- [ ] Sections disabled for free tier (with lock overlay)
- [ ] Sections enabled for trial/pro
- [ ] All form values load from config
- [ ] "Save Pro Settings" saves all values

---

## 🌐 Translations

- [ ] English loads correctly
- [ ] Spanish loads correctly
- [ ] German loads correctly
- [ ] Language selector saves preference
- [ ] Page refreshes after language change
- [ ] All modal text translated
- [ ] All settings text translated

---

## 🎨 Themes

- [ ] Dark theme (default) works
- [ ] Light theme works
- [ ] Toggle in header works
- [ ] Toggle in settings works
- [ ] Theme persists across refresh
- [ ] License banner readable in both themes

---

## 📝 Logging

### Activity Log
- [ ] Activity log updates in real-time
- [ ] Log lines color-coded (success=green, error=red)
- [ ] **Basic view**: Only shows download activity (⬇️ ✓ ✗)
- [ ] **Advanced view**: Shows all logs (metadata, cache, transcode, debug)
- [ ] View selector dropdown works
- [ ] View preference persists during session
- [ ] History button (📜) toggles to download history
- [ ] Rebuild Cache button (🔄) works
- [ ] Buttons fit in panel header (no overflow)

---

## 🔄 Auto-Sync

- [ ] Sync time saves
- [ ] Mappings can be added
- [ ] Mappings respect tier limits
- [ ] Manual "Sync Now" works
- [ ] Scheduled sync runs at configured time

---

## 📋 Miscellaneous

- [ ] Version number shows "3.0.0"
- [ ] Changelog page loads
- [ ] Help page loads
- [ ] Ko-fi link works
- [ ] Gumroad link works

---

## 🐛 Error Handling

- [ ] Connection errors show clear message
- [ ] Disk full handled gracefully
- [ ] Invalid JSON doesn't crash app
- [ ] Missing config file creates default
- [ ] Corrupted cache file recreated

---

## 📦 Docker

- [ ] Image builds successfully
- [ ] FFmpeg available in container
- [ ] bcrypt module loads
- [ ] flask-limiter loads
- [ ] apprise loads
- [ ] Volume mounts work (/config, /storage)
- [ ] Port 5000 accessible

---

## 🔙 Upgrade Path

- [ ] v2.x config migrates successfully
- [ ] Old password hashes still work
- [ ] Servers preserved after upgrade
- [ ] Mappings preserved after upgrade
- [ ] No data loss

---

## 📱 Browser Compatibility

- [ ] Chrome (desktop)
- [ ] Firefox (desktop)
- [ ] Safari (desktop)
- [ ] Chrome (Android)
- [ ] Safari (iOS)
- [ ] Edge

---

## ⌨️ Keyboard Shortcuts

- [ ] Press `?` opens shortcuts modal
- [ ] Press `Esc` closes modal
- [ ] Press `1` switches to Browse tab
- [ ] Press `2` switches to Sync tab
- [ ] Press `3` switches to Settings tab
- [ ] Press `/` focuses search box
- [ ] Press `P` pauses/resumes downloads
- [ ] Press `D` downloads selected items
- [ ] Press `Space` toggles selection on hovered item
- [ ] Press `Ctrl+A` selects all items on page
- [ ] Press `R` refreshes current view
- [ ] Press `Enter` downloads selected items
- [ ] Shortcuts don't fire when typing in input fields

---

## 📊 Download Statistics Widget

- [ ] Widget appears in right column above download queue
- [ ] Shows current download speed
- [ ] Shows items in queue count
- [ ] Shows today's download count
- [ ] Shows total downloaded (GB)
- [ ] Speed updates in real-time during downloads
- [ ] Stats persist correctly after page reload

---

## 📦 Collection/Playlist Support

- [ ] "Download All" button appears on BoxSet items
- [ ] "Download All" button appears on Playlist items
- [ ] Clicking button shows path picker modal
- [ ] All items in collection are queued
- [ ] Nested items (series→seasons→episodes) are resolved
- [ ] Download order preference is respected
- [ ] Toast shows count of queued items

---

## 💾 Backup & Restore

### Export
- [ ] Export Config button in Advanced Settings
- [ ] Downloads JSON file with timestamp in filename
- [ ] API keys are masked (***MASKED***)
- [ ] Server passwords are masked
- [ ] Notification URLs are masked
- [ ] Export metadata includes version and timestamp

### Import
- [ ] Import Config file picker works
- [ ] Confirmation dialog shows export info
- [ ] Settings are restored correctly
- [ ] Existing API keys are preserved (not overwritten with masked)
- [ ] Page reloads after successful import
- [ ] Invalid JSON shows error toast
- [ ] Success message displayed

---

## 🏥 Health Check Endpoint

- [ ] GET /health returns JSON
- [ ] GET /api/health returns same JSON
- [ ] No authentication required
- [ ] Returns status: "healthy" or "unhealthy"
- [ ] Returns version number
- [ ] Returns uptime_seconds
- [ ] Returns queue info (active, pending, workers, paused)
- [ ] Returns disk info (path, free_bytes, free_human)
- [ ] Returns server connectivity status
- [ ] Returns cache info
- [ ] Returns license tier
- [ ] Returns 200 when healthy
- [ ] Returns 503 when unhealthy (disk < 1GB)
- [ ] Works in Docker healthcheck

---

## 🔄 Download Resume (Pro)

- [ ] Downloads save as .partial files during progress
- [ ] Partial state saved every 30 seconds
- [ ] Interrupted download creates resumable entry
- [ ] Restarting container shows resumable downloads (Pro only)
- [ ] Resume continues from correct byte offset
- [ ] Range header sent to server
- [ ] 206 Partial Content handled correctly
- [ ] 416 Range Not Satisfiable triggers restart
- [ ] Completed download renames .partial to final name
- [ ] Partial state cleared on completion
- [ ] Free tier does not show resume option

---

## 🔢 Concurrent Download Limits

### Free Tier
- [ ] Max concurrent downloads limited to 2
- [ ] Setting shows warning hint
- [ ] Cannot set value > 2
- [ ] Backend enforces limit even if UI bypassed

### Pro Tier
- [ ] Max concurrent downloads up to 10
- [ ] Warning hint hidden
- [ ] Can set any value 1-10
- [ ] Backend allows up to 10

---

## ✅ Sign-off

| Area | Tested By | Date | Pass/Fail |
|------|-----------|------|-----------|
| Security | | | |
| Licensing | | | |
| Remote Servers | | | |
| Browser | | | |
| Downloads | | | |
| Mobile | | | |
| Pro Features | | | |
| Performance | | | |
| Translations | | | |
| Keyboard Shortcuts | | | |
| Statistics Widget | | | |
| Collections | | | |
| Backup/Restore | | | |
| Health Check | | | |
| Download Resume | | | |

---

**Notes:**


---

**Ready for Release:** ☐ Yes ☐ No

**Released on:** _____________
