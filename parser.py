from datetime import datetime


def parse_timestamp(logs):
    try:
        raw = f"{logs[0]} {logs[1]} {logs[2]} {datetime.now().year}"
        return datetime.strptime(raw, "%b %d %H:%M:%S %Y")
    except (ValueError, IndexError):
        return None


def parse_linux_log(line):
    logs = line.split()
    content = {
        "date": " ".join(logs[0:3]) if len(logs) >= 3 else None,
        "timestamp": parse_timestamp(logs),
        "service": logs[4] if len(logs) >= 5 else None,
        "event": None,
        "user": None,
        "ip": None,
    }

    if "Failed password" in line:
        content["event"] = "FAILED_LOGIN"
        try:
            content["user"] = logs[8]
            content["ip"] = logs[10]
        except IndexError:
            pass

    elif "Accepted password" in line:
        content["event"] = "SUCCESS_LOGIN"
        try:
            content["user"] = logs[8]
            content["ip"] = logs[10]
        except IndexError:
            pass

    return content


def parse_file(file_path):
    logs = []
    with open(file_path, "r", encoding="utf-8") as file:
        linux_log = file.readlines()
    for log in linux_log:
        content = parse_linux_log(log.strip())
        if content["event"]:
            logs.append(content)
    return logs
