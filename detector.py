from collections import defaultdict
from datetime import timedelta


def get_severity(alert_type, count):
    if alert_type == "BRUTE_FORCE":
        if count >= 20:
            return "CRITICAL"
        elif count >= 11:
            return "HIGH"
        elif count >= 6:
            return "MEDIUM"
        else:
            return "LOW"

    elif alert_type == "SUSPICIOUS_LOGIN":
        if count >= 6:
            return "HIGH"
        else:
            return "MEDIUM"

    return "LOW"


def detect_bruteforce(logs, threshold=5, window_minutes=10):
    ip_timestamps = defaultdict(list)
    for log in logs:
        if log["event"] == "FAILED_LOGIN" and log["ip"] and log["timestamp"]:
            ip_timestamps[log["ip"]].append(log["timestamp"])

    window = timedelta(minutes=window_minutes)
    alerts = []

    for ip, timestamps in ip_timestamps.items():
        timestamps.sort()

        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1

            count = right - left + 1

            if count >= threshold:
                alerts.append(
                    {
                        "type": "BRUTE_FORCE",
                        "ip": ip,
                        "attempts": count,
                        "window_minutes": window_minutes,
                        "severity": get_severity("BRUTE_FORCE", count),
                    }
                )
                break

    return alerts


def detect_success_after_fail(logs, threshold=3):
    alerts = []
    history = {}

    for log in logs:
        ip = log["ip"]

        if not ip:
            continue

        if log["event"] == "FAILED_LOGIN":
            history[ip] = history.get(ip, 0) + 1

        elif log["event"] == "SUCCESS_LOGIN":
            fails = history.get(ip, 0)
            if fails >= threshold:
                alerts.append(
                    {
                        "type": "SUSPICIOUS_LOGIN",
                        "ip": ip,
                        "failed_attempts_before_success": fails,
                        "severity": get_severity("SUSPICIOUS_LOGIN", fails),
                    }
                )
            history[ip] = 0

    return alerts
