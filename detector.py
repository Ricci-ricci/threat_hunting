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

    elif alert_type == "USER_ENUMERATION":
        if count >= 20:
            return "HIGH"
        elif count >= 10:
            return "MEDIUM"
        else:
            return "LOW"

    elif alert_type == "DISTRIBUTED_BRUTE_FORCE":
        if count >= 30:
            return "CRITICAL"
        elif count >= 20:
            return "HIGH"
        elif count >= 10:
            return "MEDIUM"
        else:
            return "LOW"

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


def detect_user_enumeration(logs, threshold=5):
    ip_users = defaultdict(set)
    for log in logs:
        if log["event"] == "FAILED_LOGIN" and log["ip"] and log["user"]:
            ip_users[log["ip"]].add(log["user"])

    alerts = []
    for ip, users in ip_users.items():
        if len(users) >= threshold:
            alerts.append(
                {
                    "type": "USER_ENUMERATION",
                    "ip": ip,
                    "unique_usernames": len(users),
                    "severity": get_severity("USER_ENUMERATION", len(users)),
                }
            )
    return alerts


def detect_root_login(logs):
    alerts = []
    for log in logs:
        if log["user"] == "root" and log["event"] in ("FAILED_LOGIN", "SUCCESS_LOGIN"):
            alerts.append(
                {
                    "type": "ROOT_LOGIN_ATTEMPT",
                    "ip": log["ip"],
                    "event": log["event"],
                    "severity": "CRITICAL"
                    if log["event"] == "SUCCESS_LOGIN"
                    else "HIGH",
                }
            )
    return alerts


def detect_distributed_bruteforce(logs, threshold=5):
    user_ips = defaultdict(set)
    for log in logs:
        if log["event"] == "FAILED_LOGIN" and log["ip"] and log["user"]:
            user_ips[log["user"]].add(log["ip"])

    alerts = []
    for user, ips in user_ips.items():
        if len(ips) >= threshold:
            alerts.append(
                {
                    "type": "DISTRIBUTED_BRUTE_FORCE",
                    "user": user,
                    "unique_ips": len(ips),
                    "severity": get_severity("DISTRIBUTED_BRUTE_FORCE", len(ips)),
                }
            )
    return alerts


def detect_off_hours_login(logs, start_hour=6, end_hour=23):
    alerts = []
    for log in logs:
        if log["event"] == "SUCCESS_LOGIN" and log["timestamp"]:
            hour = log["timestamp"].hour
            if hour < start_hour or hour >= end_hour:
                alerts.append(
                    {
                        "type": "OFF_HOURS_LOGIN",
                        "ip": log["ip"],
                        "user": log["user"],
                        "time": log["date"],
                        "severity": "MEDIUM",
                    }
                )
    return alerts
