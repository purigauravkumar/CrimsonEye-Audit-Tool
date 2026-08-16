"""File integrity monitoring with robust error handling."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator


class FileMonitor:
    """Creates and verifies a SHA-256 file integrity baseline."""

    SCHEMA_VERSION = 1
    CHUNK_SIZE = 1024 * 1024

    def __init__(self, directory_path: str | os.PathLike[str], baseline_path: str | os.PathLike[str]):
        self.root = Path(directory_path).expanduser().resolve()
        self.baseline_path = Path(baseline_path).expanduser().resolve()

        if not self.root.is_dir():
            raise ValueError(f"Audit directory is not a directory: {self.root}")

    def _relative_key(self, path: Path) -> str:
        """Return a normalized, portable relative path."""
        return path.resolve().relative_to(self.root).as_posix()

    def _is_baseline(self, path: Path) -> bool:
        try:
            return path.resolve() == self.baseline_path
        except OSError:
            return False

    @classmethod
    def _calculate_hash(cls, filepath: Path) -> tuple[str | None, str | None]:
        """Return (sha256, error). Never store an error string as a fake digest."""
        digest = hashlib.sha256()
        try:
            with filepath.open("rb") as handle:
                for chunk in iter(lambda: handle.read(cls.CHUNK_SIZE), b""):
                    digest.update(chunk)
            return digest.hexdigest(), None
        except (OSError, PermissionError) as exc:
            return None, f"{type(exc).__name__}: {exc}"

    def _iter_files(self) -> Iterator[Path]:
        """Yield regular files without following directory symlinks."""
        for root, dirs, files in os.walk(self.root, followlinks=False):
            root_path = Path(root)

            # Remove symlinked directories so os.walk cannot traverse them.
            dirs[:] = [
                name for name in dirs
                if not (root_path / name).is_symlink()
            ]

            for name in files:
                path = root_path / name
                if path.is_symlink() or not path.is_file():
                    continue
                if self._is_baseline(path):
                    continue
                yield path

    def get_current_checksums(self) -> tuple[dict[str, str], list[dict[str, str]]]:
        checksums: dict[str, str] = {}
        errors: list[dict[str, str]] = []

        print(f"[*] Hashing files under: {self.root}")
        for path in self._iter_files():
            relative = self._relative_key(path)
            digest, error = self._calculate_hash(path)
            if error:
                errors.append({"path": relative, "error": error})
                continue
            assert digest is not None
            checksums[relative] = digest

        return checksums, errors

    def _load_baseline(self) -> dict[str, str]:
        try:
            raw = json.loads(self.baseline_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ValueError(f"Baseline not found: {self.baseline_path}")
        except json.JSONDecodeError as exc:
            raise ValueError(f"Baseline JSON is corrupted: {exc}") from exc
        except OSError as exc:
            raise ValueError(f"Cannot read baseline: {exc}") from exc

        # Support only our structured baseline format.
        if not isinstance(raw, dict) or raw.get("schema_version") != self.SCHEMA_VERSION:
            raise ValueError("Unsupported or invalid baseline schema.")

        if raw.get("root") != str(self.root):
            raise ValueError(
                "Baseline belongs to a different audit directory. "
                "Create a new baseline for this directory."
            )

        files = raw.get("files")
        if not isinstance(files, dict):
            raise ValueError("Baseline 'files' section is invalid.")

        for path, digest in files.items():
            if not isinstance(path, str) or not isinstance(digest, str):
                raise ValueError("Baseline contains invalid file entries.")
            if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest.lower()):
                raise ValueError(f"Invalid SHA-256 digest for baseline entry: {path}")

        return files

    def save_baseline(self, checksums: dict[str, str]) -> dict[str, Any]:
        """Atomically write a structured baseline."""
        payload = {
            "schema_version": self.SCHEMA_VERSION,
            "algorithm": "SHA-256",
            "root": str(self.root),
            "files": dict(sorted(checksums.items())),
        }

        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)

        fd, temp_name = tempfile.mkstemp(
            prefix=".baseline-",
            suffix=".tmp",
            dir=str(self.baseline_path.parent),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, ensure_ascii=False)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.baseline_path)
        except Exception:
            try:
                os.unlink(temp_name)
            except OSError:
                pass
            raise

        return {
            "status": "BASELINE CREATED",
            "file_count": len(checksums),
            "baseline": str(self.baseline_path),
        }

    def create_baseline(self) -> dict[str, Any]:
        checksums, errors = self.get_current_checksums()
        result = self.save_baseline(checksums)
        result["errors"] = errors
        if errors:
            result["status"] = "WARNING"
            result["message"] = "Baseline created, but some files could not be hashed."
        return result

    def check_integrity(self) -> dict[str, Any]:
        try:
            baseline = self._load_baseline()
        except ValueError as exc:
            return {
                "status": "ERROR",
                "message": str(exc),
                "added": [],
                "modified": [],
                "deleted": [],
                "errors": [],
            }

        current, errors = self.get_current_checksums()

        baseline_files = set(baseline)
        current_files = set(current)

        added = [
            (path, current[path])
            for path in sorted(current_files - baseline_files)
        ]
        deleted = sorted(baseline_files - current_files)
        modified = [
            (path, baseline[path], current[path])
            for path in sorted(baseline_files & current_files)
            if not hashlib.sha256(
                current[path].encode()
            ).digest() == hashlib.sha256(
                baseline[path].encode()
            ).digest()
        ]

        # If a file could not be read, do not silently call the audit clean.
        changed = bool(added or modified or deleted)
        status = "CHANGED" if changed else ("WARNING" if errors else "OK")

        return {
            "status": status,
            "changes": (
                "Changes detected."
                if changed
                else "Audit complete; no changes detected."
            ),
            "added": added,
            "modified": modified,
            "deleted": deleted,
            "errors": errors,
        }
