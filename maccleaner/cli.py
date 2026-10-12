from __future__ import annotations

import argparse
import sys
from pathlib import Path

from maccleaner import report
from maccleaner.context import Context
from maccleaner.findings import Finding
from maccleaner.safety import RISK_REVIEW, SafetyError, move_to_trash, purge
from maccleaner.scanners import CLEANABLE, REGISTRY, loginitems, resolve
from maccleaner.scanners.du import scan as du_scan
from maccleaner.scanners.tmpfiles import clear_trash, trash_size
from maccleaner.sizes import human, parse_age_days, parse_size

BANNER = "macclean — cleaner CLI untuk macOS"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="macclean", description=BANNER)
    parser.add_argument("--no-color", action="store_true", help="matikan warna")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(sp: argparse.ArgumentParser, cleanable_only: bool = False) -> None:
        names = CLEANABLE if cleanable_only else tuple(REGISTRY)
        sp.add_argument("categories", nargs="*", help=f"kategori: {', '.join(names)}, all")
        sp.add_argument("--min-size", default=None, help="filter ukuran minimum, mis. 500M")
        sp.add_argument("--min-age", default=None, help="filter umur minimum, mis. 30d")
        sp.add_argument("--root", action="append", default=[], help="root untuk discan (bisa diulang)")
        sp.add_argument("--include-hidden", action="store_true", help="ikut sertakan folder tersembunyi")
        sp.add_argument("--depth", type=int, default=10, help="kedalaman scan (default 10)")
        sp.add_argument("--limit", type=int, default=20, help="jumlah item ditampilkan")
        sp.add_argument("--json", action="store_true", help="output JSON")

    scan = sub.add_parser("scan", help="scan tanpa menghapus")
    add_common(scan)
    scan.add_argument("--system", action="store_true", help="masukkan /tmp dan log sistem")

    clean = sub.add_parser("clean", help="hapus hasil scan")
    add_common(clean, cleanable_only=True)
    clean.add_argument("--system", action="store_true", help="bersihkan /tmp dan log sistem")
    clean.add_argument("--yes", "-y", action="store_true", help="tanpa konfirmasi")
    clean.add_argument("--purge", action="store_true", help="hapus permanen (default pindah ke Trash)")
    clean.add_argument("--only-safe", action="store_true", help="hanya item berisiko aman")
    clean.add_argument("--only-review", action="store_true", help="hanya item yang perlu ditinjau")

    trash = sub.add_parser("trash", help="kelola Trash")
    trash.add_argument("action", choices=("status", "empty"), nargs="?", default="status")
    trash.add_argument("--yes", "-y", action="store_true")

    login = sub.add_parser("login", help="daftar login item & launch agent")
    login.add_argument("--source", choices=("agents", "btm", "both"), default="both")
    login.add_argument("--limit", type=int, default=25)
    login.add_argument("--json", action="store_true")

    du = sub.add_parser("du", help="folder terbesar")
    du.add_argument("--root", action="append", default=[])
    du.add_argument("--depth", type=int, default=4)
    du.add_argument("--limit", type=int, default=25)
    du.add_argument("--min-size", default="1M")

    return parser


def make_context(args: argparse.Namespace) -> Context:
    return Context(
        home=Path.home(),
        min_size=parse_size(args.min_size) if getattr(args, "min_size", None) else 0,
        min_age_days=parse_age_days(args.min_age) if getattr(args, "min_age", None) else 0.0,
        include_hidden=bool(getattr(args, "include_hidden", False)),
        max_depth=getattr(args, "depth", 10),
        verbose=False,
        roots=[Path(p).expanduser().resolve() for p in getattr(args, "root", [])],
    )


def collect(ctx: Context, categories: list[str], system: bool) -> dict[str, list[Finding]]:
    results: dict[str, list[Finding]] = {}
    for category in categories:
        description, scanner = REGISTRY[category]
        report.info(f"[SCAN] {category:<12} → {description}...")
        try:
            if category == "tmp" and system:
                findings = scanner(ctx, include_system=True)
            else:
                findings = scanner(ctx)
        except TypeError:
            findings = scanner(ctx)
        report.ok(f"[OK]    {category:<12} → {len(findings)} item ditemukan")
        results[category] = findings
    return results


def cmd_scan(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    categories = resolve(args.categories)
    results = collect(ctx, categories, args.system)

    if args.json:
        report.dump_json(
            {
                category: [f.as_dict() for f in findings]
                for category, findings in results.items()
            }
        )
        return 0

    grand_total = 0
    grand_count = 0
    for category, findings in results.items():
        description = REGISTRY[category][0]
        report.heading(f"{category} — {description}  ({len(findings)} item)")
        report.render_findings(findings, limit=args.limit)
        report.render_summary(sum(f.size for f in findings), len(findings))
        grand_total += sum(f.size for f in findings)
        grand_count += len(findings)

    report.heading("RINGKASAN")
    print(f"  {grand_count} item, total {report.paint(human(grand_total), report.BOLD + report.GREEN)}")
    print(report.paint(f"  Bersihkan dengan: macclean clean {' '.join(categories)}", report.DIM))
    return 0


def confirm(question: str) -> bool:
    try:
        answer = input(report.paint(question, report.YELLOW)).strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def cmd_clean(args: argparse.Namespace) -> int:
    ctx = make_context(args)
    categories = [c for c in resolve(args.categories) if c in CLEANABLE]
    results = collect(ctx, categories, args.system)

    selected: list[Finding] = []
    for findings in results.values():
        for finding in findings:
            if args.only_safe and finding.risk == RISK_REVIEW:
                continue
            if args.only_review and finding.risk != RISK_REVIEW:
                continue
            selected.append(finding)

    if not selected:
        report.warn("tidak ada item yang cocok untuk dihapus")
        return 0

    review_items = [f for f in selected if f.risk == RISK_REVIEW]
    total = sum(f.size for f in selected)

    if args.json:
        report.dump_json(
            {
                "mode": "purge" if args.purge else "trash",
                "total_size": total,
                "items": [f.as_dict() for f in selected],
            }
        )
        return 0

    for category, findings in results.items():
        report.heading(f"{category} ({len(findings)} item)")
        report.render_findings(findings, limit=args.limit)

    report.rule()
    action = "HAPUS PERMANEN" if args.purge else "pindah ke Trash"
    print(f"  Rencana: {action} {len(selected)} item, total {report.paint(human(total), report.BOLD)}")
    if review_items:
        print(
            report.paint(
                f"  {len(review_items)} item perlu ditinjau manual (file besar/duplikat/login).", report.RED
            )
        )

    if not args.yes:
        if not confirm("Lanjutkan? [y/N] "):
            report.warn("dibatalkan")
            return 130

    freed = 0
    errors = 0
    total_sel = len(selected)
    for i, finding in enumerate(selected, 1):
        try:
            if args.purge:
                purge(finding.path)
            else:
                move_to_trash(finding.path)
            freed += finding.size
            pct = int((i / total_sel) * 100)
            report.info(f"[{i:>4}/{total_sel}] [{pct:>3}%] {human(finding.size):>9} → {finding.path}")
        except (SafetyError, OSError) as exc:
            errors += 1
            report.error(f"gagal: {finding.path} — {exc}")

    report.heading("SELESAI")
    print(f"  Diproses: {len(selected) - errors}/{len(selected)}")
    print(f"  Ruang dipulihkan: {report.paint(human(freed), report.BOLD + report.GREEN)}")
    if not args.purge:
        print(report.paint("  Sampah bisa dikembalikan dari Trash.", report.DIM))
    if errors:
        report.error(f"  {errors} item gagal")
        return 1
    return 0


def cmd_trash(args: argparse.Namespace) -> int:
    if args.action == "status":
        size = trash_size()
        report.heading("TRASH")
        print(f"  {human(size)} dalam {Path.home() / '.Trash'}")
        print(report.paint("  Kosongkan dengan: macclean trash empty", report.DIM))
        return 0

    size = trash_size()
    if size == 0:
        report.warn("Trash sudah kosong")
        return 0
    if not args.yes and not confirm(f"Kosongkan Trash ({human(size)})? [y/N] "):
        report.warn("dibatalkan")
        return 130
    freed = clear_trash()
    print(report.paint(f"  Trash dikosongkan, {human(freed)} dipulihkan.", report.BOLD + report.GREEN))
    return 0


def cmd_login(args: argparse.Namespace) -> int:
    findings = loginitems.scan(source=args.source)
    if args.json:
        report.dump_json([f.as_dict() for f in findings])
        return 0

    agents = [f for f in findings if f.detail.startswith("launchd")]
    background = [f for f in findings if not f.detail.startswith("launchd")]

    report.heading(f"LAUNCH AGENTS / DAEMONS ({len(agents)} item)")
    report.render_findings(agents, limit=args.limit, show_age=False)
    report.heading(f"BACKGROUND ITEMS ({len(background)} item)")
    report.render_findings(background, limit=args.limit, show_age=False)
    report.rule()
    print(report.paint("  Nonaktifkan via System Settings > General > Login Items.", report.DIM))
    return 0


def cmd_du(args: argparse.Namespace) -> int:
    ctx = Context(
        home=Path.home(),
        max_depth=args.depth,
        roots=[Path(p).expanduser().resolve() for p in args.root],
    )
    rows = du_scan(ctx, limit=args.limit, min_size=parse_size(args.min_size))
    report.heading(f"FOLDER TERBESAR ({len(rows)} item)")
    for path, size in rows:
        print(f"  {report.paint(f'{human(size):>9}', report.BOLD)}  {report.shorten(path)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "no_color", False):
        report.COLOR = False

    handlers = {
        "scan": cmd_scan,
        "clean": cmd_clean,
        "trash": cmd_trash,
        "login": cmd_login,
        "du": cmd_du,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except KeyboardInterrupt:
        print()
        return 130
    except (ValueError, OSError) as exc:
        report.error(f"error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())