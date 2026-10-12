# macclean

CLI cleaner untuk macOS. Tanpa dependency, pure Python stdlib (butuh Python 3.10+).

Tujuannya: lihat dulu apa yang bisa dibuang, baru hapus. Tidak ada yang dihapus
tanpa konfirmasi, dan default-nya dipindah ke Trash (masih bisa dikembalikan).

---

## Cara pakai singkat

Jalankan dari folder project:

```bash
cd ~/projects/mac-cleaner

./macclean scan          # 1. lihat dulu, tidak menghapus apa pun
./macclean clean cache   # 2. hapus kategori tertentu (tanya dulu y/N)
```

Itu saja. Dua perintah itu sudah cukup untuk pemakaian harian.

---

## Mulai dari mana (langkah lengkap)

### 1. Scan untuk melihat kondisi disk

```bash
./macclean scan
```

Output dikelompokkan per kategori, tiap baris berisi ukuran, label risiko
(`safe` / `review`), umur, dan path.

Mau lihat isi disk yang paling besar saja:

```bash
./macclean du --depth 3 --limit 20
```

### 2. Pilih kategori yang mau dibersihkan

```bash
./macclean clean cache            # cache & log aplikasi
./macclean clean devjunk          # sisa-sisa development
./macclean clean tmp              # temporary file & Trash
./macclean clean cache devjunk    # bisa gabung beberapa kategori
./macclean clean all              # semua kategori sekaligus
```

Setelah menampilkan rencana, tool akan bertanya:

```
Rencana: pindah ke Trash 42 item, total 3.2 GB
Lanjutkan? [y/N]
```

Ketik `y` untuk lanjut. Semua file dipindah ke `~/.Trash` dengan awalan
`macclean-...`, jadi bisa di-restore lewat Finder kalau salah.

### 3. Kosongkan Trash kalau sudah yakin

```bash
./macclean trash status   # lihat ukuran Trash
./macclean trash empty    # kosongkan permanen
```

---

## Perintah

| Perintah | Fungsi |
| --- | --- |
| `scan` | Scan dan tampilkan temuan. Tidak pernah menghapus. |
| `clean` | Tampilkan rencana, lalu pindah ke Trash (atau hapus permanen dengan `--purge`). |
| `trash status` | Lihat ukuran `~/.Trash`. |
| `trash empty` | Kosongkan `~/.Trash`. |
| `login` | Daftar login item, launch agent/daemon, dan background item. |
| `du` | Daftar folder terbesar. |

---

## Kategori

| Kategori | Isi | Risiko |
| --- | --- | --- |
| `cache` | `~/Library/Caches`, `Logs`, `Saved Application State`, WebKit, cache app sandbox | aman |
| `devjunk` | `node_modules`, Xcode DerivedData, cache Homebrew/npm/pip/Gradle/Cargo, `__pycache__` | aman, kecuali venv & hasil build |
| `large` | file besar (default ≥ 200 MB) | review |
| `duplicate` | file duplikat (dicek pakai SHA-256, selalu sisakan 1 salinan) | review |
| `tmp` | Trash, Autosave, lampiran Messages, file temporary | aman |
| `login` | login item & startup agent (hanya ditampilkan, tidak dihapus) | review |

Label `safe` = aman dibuang. Label `review` = periksa dulu, biasanya file
pribadi atau butuh dibikin ulang.

---

## Opsi

Semua opsi berlaku untuk `scan` dan `clean`.

```bash
./macclean scan --min-size 1G          # hanya item ≥ 1 GB (bisa 500M, 2G, dst)
./macclean scan --min-age 90d          # hanya item yang umurnya > 90 hari (30d, 1y, 12h)
./macclean scan --root ~/Downloads     # scan folder lain (bisa diulang)
./macclean scan --include-hidden       # ikut sertakan folder tersembunyi
./macclean scan --limit 50             # tampilkan sampai 50 item per kategori
./macclean scan --json                 # output JSON (untuk script)
```

Opsi khusus:

```bash
./macclean scan tmp --system           # tambahkan /tmp, /var/tmp, log sistem
./macclean clean cache --yes           # tanpa tanya, tetap ke Trash
./macclean clean cache --purge --yes   # hapus permanen, tidak lewat Trash
./macclean clean cache --only-safe     # lewati semua item berlabel review
./macclean clean all --only-review     # hanya file besar & duplikat
./macclean login --source btm          # hanya background item (agents|btm|both)
```

Bantuan:

```bash
./macclean --help
./macclean clean --help
```

---

## Install sebagai command global (opsional)

Kalau mau bisa dipanggil dari folder mana saja:

```bash
cd ~/projects/mac-cleaner
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
macclean scan
```

Setelah itu `macclean` bisa dipakai tanpa `./`.

---

## Keamanan

- Default `clean` memindah ke Trash, bukan menghapus permanen. Restore lewat Finder.
- File dengan label `review` tetap ikut dihapus bila tidak dibatasi, tapi jumlahnya
  diberi peringatan merah sebelum konfirmasi. Pakai `--only-safe` untuk melewatinya.
- Path sistem (`/System`, `/usr`, `/bin`, `/etc`, `/var/db`, ...) selalu ditolak.
- Symlink ditolak dan tidak pernah diikuti saat scan.
- Scan tidak keluar dari root yang dipilih.

---

## Development

```bash
python3 -m unittest discover -s tests -t .   # jalankan test
python3 -m ruff check .                      # lint (perlu: pip install ruff)
```

Struktur:

```
macclean                # launcher bash
maccleaner/
  cli.py                # parser argumen & perintah
  context.py            # opsi runtime (root, min-size, min-age)
  findings.py           # model Finding & ScanResult
  safety.py             # guard path + pindah ke Trash
  report.py             # tampilan tabel & warna
  sizes.py              # util ukuran/traversal
  scanners/             # satu file per kategori
tests/                  # unit test
```