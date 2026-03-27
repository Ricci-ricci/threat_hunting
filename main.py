from detector import detect_bruteforce, detect_success_after_fail
from parser import parse_file

logs = parse_file("logs/linux_log.txt")

alerts_1 = detect_bruteforce(logs)
alerts_2 = detect_success_after_fail(logs)

print("=== Alerts ===")

for alert in alerts_1 + alerts_2:
    print(alert)
