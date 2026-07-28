from datetime import datetime

_logs = []


def add_log(level: str, event: str, detail: str):
    _logs.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "level": level,
        "event": event,
        "detail": detail
    })


def get_logs():
    return _logs