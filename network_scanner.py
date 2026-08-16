"""Concurrent TCP connect scanner."""

from __future__ import annotations

import concurrent.futures
import errno
import socket
from typing import Any


class NetworkScanner:
    """Scans a single target for TCP ports using bounded concurrency."""

    def __init__(
        self,
        target: str = "127.0.0.1",
        start_port: int = 1,
        end_port: int = 1024,
        timeout: float = 0.5,
        workers: int = 64,
    ):
        if not 1 <= start_port <= 65535:
            raise ValueError("start_port must be between 1 and 65535.")
        if not 1 <= end_port <= 65535:
            raise ValueError("end_port must be between 1 and 65535.")
        if start_port > end_port:
            raise ValueError("start_port cannot be greater than end_port.")
        if not 0.05 <= timeout <= 30:
            raise ValueError("timeout must be between 0.05 and 30 seconds.")
        if not 1 <= workers <= 256:
            raise ValueError("workers must be between 1 and 256.")

        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.timeout = timeout
        self.workers = workers

    def _scan_one(self, port: int) -> tuple[int, bool, str | None]:
        try:
            with socket.create_connection(
                (self.target, port),
                timeout=self.timeout,
            ):
                return port, True, None
        except socket.gaierror as exc:
            return port, False, f"DNS/hostname error: {exc}"
        except socket.timeout:
            return port, False, None
        except OSError as exc:
            # Connection refused/unreachable is normal for a port scan.
            if exc.errno in {
                errno.ECONNREFUSED,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
                errno.ETIMEDOUT,
            }:
                return port, False, None
            return port, False, f"{type(exc).__name__}: {exc}"

    def scan(self) -> dict[str, Any]:
        ports = range(self.start_port, self.end_port + 1)
        open_ports: list[dict[str, Any]] = []
        errors: list[str] = []

        print(
            f"[*] Scanning {self.target}:{self.start_port}-{self.end_port} "
            f"with {self.workers} workers..."
        )

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=self.workers,
            thread_name_prefix="portscan",
        ) as executor:
            futures = [executor.submit(self._scan_one, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open, error = future.result()
                if error:
                    errors.append(f"port {port}: {error}")
                elif is_open:
                    service = None
                    try:
                        service = socket.getservbyport(port, "tcp")
                    except OSError:
                        pass
                    open_ports.append({"port": port, "service": service})
                    print(f"[+] Port {port} OPEN" + (f" ({service})" if service else ""))

        open_ports.sort(key=lambda item: item["port"])

        return {
            "target": self.target,
            "range": f"{self.start_port}-{self.end_port}",
            "timeout": self.timeout,
            "open_ports": open_ports,
            "errors": sorted(errors),
        }
