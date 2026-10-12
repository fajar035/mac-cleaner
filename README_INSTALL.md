# macclean — Installer untuk macOS

File installer siap pakai:

- `dist/macclean` — Binary standalone (1 file, bisa langsung dijalanin)
- `macclean-macos-arm64.tar.gz` — Archive siap distribusi (Apple Silicon/arm64)
- `install.sh` — Script install otomatis ke `/usr/local/bin` atau `/opt/homebrew/bin`
- `INSTALL_MAC.md` — Panduan install lengkap

## Quick install (1 command)

```bash
curl -L https://github.com/fajarpratama26/mac-cleaner/releases/download/v0.1.0/macclean-macos-arm64.tar.gz -o macclean.tar.gz
tar -xzf macclean.tar.gz
chmod +x macclean
sudo mv macclean /usr/local/bin/
macclean scan cache
```

## Usage

```bash
macclean scan                # scan default
macclean scan cache devjunk # scan kategori tertentu
macclean clean cache --yes   # bersihkan langsung (aman)
macclean du --limit 10       # folder terbesar
macclean trash status        # cek Trash
```
