import csv
import io

from telemetry import snapshot


def export_csv(rows):
    stream = io.StringIO()
    fields = [
        "timestamp", "cpu_percent", "memory_percent", "disk_percent",
        "upload_bps", "download_bps", "bytes_sent", "bytes_received",
    ]
    writer = csv.DictWriter(stream, fieldnames=fields)
    writer.writeheader()
    for row in rows:
        writer.writerow({key: row.get(key, "") for key in fields})
    return stream.getvalue()


def current_network_stats():
    data = snapshot()
    return {key: data[key] for key in (
        "local_ip", "interfaces", "connection_status", "upload_bps",
        "download_bps", "bytes_sent", "bytes_received",
    )}
