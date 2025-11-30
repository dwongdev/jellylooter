# JellyLooter Ultimate

![JellyLooter Icon](https://raw.githubusercontent.com/YOUR_GITHUB_USERNAME/jellylooter/main/icon.png)

**JellyLooter** is a specialized download manager and synchronization tool designed for Jellyfin users. It allows you to connect to remote Jellyfin servers, browse their contents visually, and download media directly to your local storage.

Unlike standard sync tools that only sync "watched status," JellyLooter syncs the **actual video files**.

### 🚀 Features

* **Remote Explorer:** Browse remote libraries with a visual poster grid.
* **Smart Deduplication:** Connects to your *local* Jellyfin server to identify content you already own. Adds an "OWNED" badge to remote items and skips them during sync.
* **Recursive Downloads:** Select a "Series" or "Season" folder, and it automatically finds and queues every episode inside.
* **Auto-Sync:** Map a remote library (e.g., "Friend's Anime") to a local folder. The system runs a daily scan to download only new missing items.
* **Queue Management:** Pause, resume, and cancel active downloads.
* **Unraid Ready:** Designed specifically for deployment as an Unraid Docker container.

### 🛠️ Installation

1.  Install via **Community Applications** on Unraid (Search "JellyLooter").
2.  **Map Storage:** Ensure `/storage` is mapped to your media share (e.g., `/mnt/user/data`).
3.  **Map Config:** Ensure `/config` is mapped to appdata.

### ⚙️ Configuration

1.  **Add Remote Server:** Enter the URL and API Key (or Username/Password) of the source server.
2.  **Add Local Server (Optional):** Enter your own Jellyfin details to enable the "Owned" status check.
3.  **Set Limits:** Configure bandwidth limits (KB/s) to prevent saturating your connection.

### ☕ Support the Project

If this tool saved you from manually downloading 5,000 episodes one by one, consider buying me a coffee.

### ☕ Support the Project

If this tool saved you from manually downloading 5,000 episodes one by one, consider buying me a coffee.

<a href="https://buymeacoffee.com/friendlymedia" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" style="height: 60px !important;width: 217px !important;" ></a>

### ⚠️ Disclaimer

This tool is intended for personal media backup and synchronization between servers you own or have explicit permission to access. The developers are not responsible for misuse.
