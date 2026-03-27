from collections import Counter


def detect_bruteforce(logs, threshold=3):
    failed_ips = [
        log["ip"] for log in logs if log["event"] == "FAILED_LOGIN" and log["ip"]
    ]

    counts = Counter(failed_ips)

    alerts = []

    for ip, count in counts.items():
        if count >= threshold:
            alerts.append({"type": "BRUTE_FORCE", "ip": ip, "attempts": count})

    return alerts


def detect_success_after_fail(logs):
    alerts = []
    history = {}

    for log in logs:
        ip = log["ip"]

        if not ip:
            continue

        if log["event"] == "FAILED_LOGIN":
            history[ip] = history.get(ip, 0) + 1

        elif log["event"] == "SUCCESS_LOGIN":
            if history.get(ip, 0) >= 3:
                alerts.append(
                    {
                        "type": "SUSPICIOUS_LOGIN",
                        "ip": ip,
                        "failed_attempts_before_success": history[ip],
                    }
                )
            history[ip] = (
                0  # reset after successful login so past failures don't bleed into future sessions
            )

    return alerts
