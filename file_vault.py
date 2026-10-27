"""Find byte-identical files and move approved duplicates into reversible quarantine."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

SKIP = {".git", "node_modules", ".venv", "__pycache__", ".file-vault"}


def digest(path: Path) -> str:
    checksum = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def inside(root: Path, relative: str) -> Path:
    candidate = root / relative
    if Path(relative).is_absolute() or not relative or ".." in Path(relative).parts:
        raise ValueError("path must be relative and stay inside the selected folder")
    if candidate.is_symlink() or any(parent.is_symlink() for parent in candidate.parents if parent != root and root in parent.parents):
        raise ValueError("symbolic links are not supported")
    if not candidate.resolve().is_relative_to(root) or candidate.resolve() == root:
        raise ValueError("path escapes selected folder")
    if ".file-vault" in Path(relative).parts:
        raise ValueError("quarantine files cannot be selected")
    return candidate


def scan(folder: str | Path) -> dict:
    root = Path(folder).resolve()
    if not root.is_dir():
        raise ValueError("folder does not exist")
    sizes = defaultdict(list)
    errors = []
    scanned = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in SKIP and not (Path(directory) / name).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                info = path.stat()
                scanned += 1
                # Empty files waste no storage; hard links already share the same bytes.
                if info.st_size and info.st_nlink == 1:
                    sizes[info.st_size].append(path)
            except OSError as exc:
                errors.append({"path": str(path.relative_to(root)), "error": str(exc)})
    groups = []
    for size, paths in sorted(sizes.items()):
        if len(paths) < 2:
            continue
        hashes = defaultdict(list)
        for path in paths:
            try:
                hashes[digest(path)].append(path.relative_to(root).as_posix())
            except OSError as exc:
                errors.append({"path": str(path.relative_to(root)), "error": str(exc)})
        for checksum, names in sorted(hashes.items()):
            if len(names) > 1:
                names.sort()
                groups.append({"sha256": checksum, "size": size, "keep": names[0], "duplicates": names[1:]})
    return {"version": 1, "root": str(root), "files_scanned": scanned, "groups": groups,
            "reclaimable_bytes": sum(group["size"] * len(group["duplicates"]) for group in groups), "errors": errors}


def write_json(path: Path, value: dict) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def apply(plan: dict) -> Path | None:
    if plan.get("version") != 1 or not isinstance(plan.get("groups"), list):
        raise ValueError("unsupported plan")
    root = Path(plan["root"]).resolve()
    if not root.is_dir():
        raise ValueError("original folder is missing")
    moves = []
    seen = set()
    for group in plan["groups"]:
        inside(root, group["keep"])
        for relative in [group["keep"], *group["duplicates"]]:
            source = inside(root, relative)
            if source in seen:
                raise ValueError("a file occurs more than once in the plan")
            seen.add(source)
            if not source.is_file() or source.stat().st_nlink != 1:
                raise ValueError(f"file is missing or hard-linked: {relative}")
            if source.stat().st_size != group["size"] or digest(source) != group["sha256"]:
                raise ValueError(f"file changed since scan: {relative}")
        for relative in group["duplicates"]:
            moves.append({"original": relative, "stored": f"files/{len(moves):06d}", "sha256": group["sha256"], "size": group["size"]})
    if not moves:
        return None
    vault = root / ".file-vault"
    if vault.is_symlink() or (vault.exists() and not vault.is_dir()):
        raise ValueError("quarantine folder must be an ordinary directory")
    session = vault / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    (session / "files").mkdir(parents=True)
    manifest = {"version": 1, "root": str(root), "state": "moving", "moves": moves}
    manifest_path = session / "manifest.json"
    # Write the full recovery journal before touching any original file.
    write_json(manifest_path, manifest)
    try:
        for move in moves:
            source = inside(root, move["original"])
            if digest(source) != move["sha256"]:
                raise ValueError(f"file changed during apply: {move['original']}")
            # A keeper may have changed while a large plan was being processed.
            for group in plan["groups"]:
                if group["sha256"] == move["sha256"] and digest(inside(root, group["keep"])) != move["sha256"]:
                    raise ValueError("kept copy changed during apply")
            source.rename(session / move["stored"])
        manifest["state"] = "quarantined"
    except (OSError, ValueError):
        manifest["state"] = "interrupted"
        write_json(manifest_path, manifest)
        raise
    write_json(manifest_path, manifest)
    return manifest_path


def restore(manifest_path: str | Path) -> int:
    path = Path(manifest_path).resolve()
    manifest = json.loads(path.read_text(encoding="utf-8"))
    root = Path(manifest["root"]).resolve()
    expected = root / ".file-vault"
    if manifest.get("version") != 1 or path.name != "manifest.json" or path.parent.parent != expected or expected.is_symlink():
        raise ValueError("manifest must be in its original quarantine session")
    if manifest.get("state") == "restored":
        return 0
    pending = []
    targets = set()
    for move in manifest["moves"]:
        target = inside(root, move["original"])
        stored = path.parent / move["stored"]
        if not stored.resolve().is_relative_to(path.parent / "files") or stored.is_symlink():
            raise ValueError("invalid quarantine path")
        if target in targets:
            raise ValueError("duplicate restore target")
        targets.add(target)
        if stored.exists():
            if target.exists():
                raise ValueError(f"restore would overwrite a file: {move['original']}")
            if digest(stored) != move["sha256"]:
                raise ValueError("quarantine contents changed")
            pending.append((stored, target))
        elif not target.is_file() or digest(target) != move["sha256"]:
            raise ValueError(f"both stored and original copies are missing or changed: {move['original']}")
    for stored, target in pending:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise ValueError("restore destination was created during restore")
        stored.rename(target)
    manifest["state"] = "restored"
    write_json(path, manifest)
    return len(pending)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    scanner = commands.add_parser("scan", help="read-only duplicate scan")
    scanner.add_argument("folder")
    scanner.add_argument("--output", type=Path, required=True)
    mover = commands.add_parser("apply", help="quarantine duplicates from a reviewed plan")
    mover.add_argument("plan", type=Path)
    mover.add_argument("--yes", action="store_true", help="confirm moving files")
    restorer = commands.add_parser("restore", help="restore files without overwriting")
    restorer.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "scan":
            result = scan(args.folder)
            if args.output.exists():
                raise ValueError("output already exists; choose a new plan filename")
            write_json(args.output, result)
            print(f"Duplicate groups: {len(result['groups'])}; candidate bytes: {result['reclaimable_bytes']}; read errors: {len(result['errors'])}")
            return 1 if result["errors"] else 0
        if args.command == "apply":
            if not args.yes:
                raise ValueError("review the plan, then pass --yes to move duplicates")
            print(apply(json.loads(args.plan.read_text(encoding="utf-8"))))
        else:
            print(f"Restored files: {restore(args.manifest)}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Error: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
