# Install macclean di macOS

Ada 2 cara install:

## Cara 1: Binary langsung (paling simpel)

1. Download `macclean.tar.gz` (atau ambil `dist/macclean`)
2. Buka Terminal di folder download
3. Ekstrak & install:

```bash
tar -xzf macclean.tar.gz
chmod +x macclean
sudo mv macclean /usr/local/bin/
```

Atau kalo pakai Homebrew (`/opt/homebrew/bin`):

```bash
chmod +x macclean
mv macclean /opt/homebrew/bin/
```

Cek berhasil:

```bash
macclean --help
```

## Cara 2: Pakai script install.sh

```bash
chmod +x install.sh
./install.sh
```

Script ini akan auto-detect path bin (`/opt/homebrew/bin` atau `/usr/local/bin`) dan install `macclean`.

## Uninstall

```bash
sudo rm /usr/local/bin/macclean  # atau /opt/homebrew/bin/macclean
```

## Build sendiri

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[build]"
pyinstaller macclean.spec
./dist/macclean --help
```
