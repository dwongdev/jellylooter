# 🍇 JellyLooter

Sync media content from remote Jellyfin/Emby servers to your local storage.

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/friendlymedia)

---

## Features

- 📁 **Browse Remote Libraries** - Navigate and preview content from multiple Jellyfin/Emby servers
- 🔄 **Automatic Sync** - Schedule automatic downloads based on library mappings
- ✓ **Duplicate Detection** - Scans your local library to avoid re-downloading content
- ⏸️ **Download Control** - Pause, resume, and cancel downloads
- 🚀 **Speed Limiting** - Optional bandwidth throttling (updates in real-time)
- 👥 **Dynamic Workers** - Adjust concurrent downloads without restart
- 🔐 **Authentication** - Secure login with remember me option
- 🎨 **Clean UI** - Jellyfin-inspired dark theme

---

## Installation

### Docker Compose (Recommended)

```yaml
version: '3.8'
services:
  jellylooter:
    build: .
    container_name: jellylooter
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - ./config:/config
      - /path/to/your/media:/storage  # Change this!
    environment:
      - TZ=America/Chicago
```

### Docker CLI

```bash
docker build -t jellylooter .

docker run -d \
  --name jellylooter \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /path/to/config:/config \
  -v /path/to/media:/storage \
  -e TZ=America/Chicago \
  jellylooter
```

### Unraid

1. Go to **Docker** → **Add Container**
2. Configure:
   - **Repository:** `jellylooter`
   - **Port:** `5000` → `5000`
   - **Path:** `/config` → `/mnt/user/appdata/jellylooter`
   - **Path:** `/storage` → `/mnt/user` (or your media location)
3. Click **Apply**

---

## Quick Start

1. Access the web UI at `http://YOUR_IP:5000`
2. Create your admin account on first run
3. Add a remote Jellyfin/Emby server in Settings
4. Browse and download!

---

## Configuration

### Adding a Remote Server

1. Go to **Settings** tab
2. Click **+ Add Remote Server**
3. Enter server URL and API key (or username/password)
4. Test connection and save

### Duplicate Detection

1. Configure your local Jellyfin/Emby server in Settings
2. Click **Rebuild Cache** to scan your library
3. Items you already have will be marked with ✓

### Speed Limiting

- Set in **Settings** → **Advanced** → **Speed Limit**
- Value is in KB/s (0 = unlimited)
- Changes apply to active downloads within 10 seconds

### Concurrent Downloads

- Set in **Settings** → **Advanced** → **Max Downloads**
- Workers adjust dynamically - no restart needed!

---

## Troubleshooting

### "No space left on device" Error

This usually means Docker can't write to your storage path. Check:

1. **Volume mapping is correct:**
   ```bash
   docker inspect jellylooter | grep -A5 "Mounts"
   ```

2. **Path exists and is writable:**
   ```bash
   docker exec jellylooter ls -la /storage
   docker exec jellylooter touch /storage/test && rm /storage/test
   ```

3. **Actual disk space:**
   ```bash
   df -h /mnt/user
   ```

### Downloads are slow

- Check **Speed Limit** in Settings (0 = unlimited)
- Verify network to remote server
- Try increasing **Chunk Size** in Advanced settings

### Can't connect to remote server

- Verify URL includes port (e.g., `http://192.168.1.100:8096`)
- Check API key is valid
- Ensure server is accessible from Docker network

---

## Support the Project

If JellyLooter is useful to you, consider buying me a coffee! ☕

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-Support-yellow?style=for-the-badge&logo=buy-me-a-coffee)](https://buymeacoffee.com/friendlymedia)

Your support helps keep this project maintained and improved!

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/config` | GET/POST | Configuration |
| `/api/status` | GET | Download status |
| `/api/logs` | GET | Activity log |
| `/api/pause` | POST | Pause downloads |
| `/api/resume` | POST | Resume downloads |
| `/api/cancel` | POST | Cancel download(s) |
| `/api/sync` | POST | Trigger sync |
| `/api/rebuild_cache` | POST | Rescan local library |
| `/api/disk_space` | POST | Check disk space |

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) or the `/changelog` page in the app.

---

## License

MIT License

---

## Contributing

Pull requests welcome! Please open an issue first for major changes.

---

<p align="center">
  Made with ❤️ by <a href="https://buymeacoffee.com/friendlymedia">FriendlyMedia</a>
</p>
