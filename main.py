import json
from datetime import datetime

from detector import detect_bruteforce, detect_success_after_fail
from parser import parse_file

logs = parse_file("logs/linux_log.txt")

alerts_1 = detect_bruteforce(logs)
alerts_2 = detect_success_after_fail(logs)

all_alerts = alerts_1 + alerts_2

print("=== Alerts ===")
for alert in all_alerts:
    print(alert)

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

report = {
    "generated_at": datetime.now().isoformat(),
    "total_alerts": len(all_alerts),
    "alerts": sorted(
        all_alerts,
        key=lambda a: SEVERITY_ORDER.get(a.get("severity", "LOW"), 3),
    ),
}

report_path = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(report_path, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)

print(f"\n[+] Report saved to {report_path}")
