import socket
import time

import psutil


_previous = psutil.net_io_counters()
_previous_at = time.monotonic()
_started_at = time.time()


def _local_address():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("192.0.2.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def snapshot():
    global _previous, _previous_at
    current = psutil.net_io_counters()
    now = time.monotonic()
    elapsed = max(now - _previous_at, 0.001)
    upload = max(0, current.bytes_sent - _previous.bytes_sent) / elapsed
    download = max(0, current.bytes_recv - _previous.bytes_recv) / elapsed
    _previous, _previous_at = current, now
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    interfaces = psutil.net_if_stats()
    active = [name for name, info in interfaces.items() if info.isup]
    return {
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": memory.percent,
        "memory_used": memory.used,
        "memory_total": memory.total,
        "disk_percent": disk.percent,
        "disk_used": disk.used,
        "disk_total": disk.total,
        "upload_bps": upload,
        "download_bps": download,
        "bytes_sent": current.bytes_sent,
        "bytes_received": current.bytes_recv,
        "uptime_seconds": int(time.time() - _started_at),
        "local_ip": _local_address(),
        "interfaces": active,
        "connection_status": "Connected" if active else "Offline",
        "timestamp": time.time(),
    }
