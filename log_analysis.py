import re
import csv
from collections import Counter

log_file_path = "sample.log"
FAILED_LOGIN_THRESHOLD = 10 

ip_regex = r"(\d+\.\d+\.\d+\.\d+)"
endpoint_regex = r'"(GET|POST|PUT|DELETE) (.*?) HTTP/1.1"'
failed_login_regex = r'401 .*? "Invalid credentials"'

request_count = Counter()
endpoint_count = Counter()
failed_logins = Counter()

with open(log_file_path, 'r') as log_file:
    for line in log_file:

        ip_match = re.search(ip_regex, line)
        if ip_match:
            ip = ip_match.group(0)
            request_count[ip] += 1

        endpoint_match = re.search(endpoint_regex, line)
        if endpoint_match:
            endpoint = endpoint_match.group(2)
            endpoint_count[endpoint] += 1

        if re.search(failed_login_regex, line):
            if ip_match:  
                failed_logins[ip] += 1

most_accessed_endpoint = max(endpoint_count, key=endpoint_count.get)


suspicious_ips = {ip: count for ip, count in failed_logins.items() if count >= FAILED_LOGIN_THRESHOLD}

print("Requests Per IP Address:")
for ip, count in request_count.items():
    print(f"{ip:20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {endpoint_count[most_accessed_endpoint]} times)")

if suspicious_ips:
    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':20} {'Failed Login Attempts'}")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")
else:
    print("\nNo suspicious activity detected.")

csv_file_path = "log_analysis_results.csv"
with open(csv_file_path, 'w', newline='') as csv_file:
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow(["IP Address", "Request Count"])
    for ip, count in request_count.items():
        csv_writer.writerow([ip, count])

    csv_writer.writerow([])
    csv_writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
    csv_writer.writerow([most_accessed_endpoint, endpoint_count[most_accessed_endpoint]])

    csv_writer.writerow([])
    csv_writer.writerow(["Suspicious Activity Detected", "Failed Login Attempts"])
    for ip, count in suspicious_ips.items():
        csv_writer.writerow([ip, count])

print(f"\nResults saved to {csv_file_path}")
