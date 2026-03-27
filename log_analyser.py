with open("logs/log_example.txt", "r", encoding="utf-8") as file:
    logins = file.readlines()

fail_count = {}
for log in logins:
    status, ip = log.split()
    if status == "FAIL":
        fail_count[ip] = fail_count.get(ip, 0) + 1
        print(fail_count)

for ip, count in fail_count.items():
    if count >= 2:
        print(f"[!!] Suspicious activities from {ip}")
