def parse_linux_log(line):
    logs = line.split()
    content = {
        "date": " ".join(logs[0:3]) if len(logs) >= 3 else None,
        "service": logs[4] if len(logs) >= 4 else None,
        "event": None,
        "user": None,
        "ip": None,
    }

    if "Failed password" in line:
        content["event"] = "Failed Login"
        try:
            content["user"] = logs[8]
            content["ip"] = logs[10]
        except IndexError:
            pass

    elif "Accepted password" in line:
        content["event"] = "Succesful login"
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
            logs.append(log)
    return logs
