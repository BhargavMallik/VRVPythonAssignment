import csv
from collections import defaultdict
import re

# Configurable threshold for failed login attempts
FAILED_LOGIN_THRESHOLD = 5

# File paths
LOG_FILE = "sample.log"
OUTPUT_FILE = "log_analysis_results.csv"

def parse_log_file(file_path):
    """Parses the log file and extracts necessary information."""
    with open(file_path, 'r') as file:
        log_lines = file.readlines()

    ip_requests = defaultdict(int)
    endpoint_access = defaultdict(int)
    failed_logins = defaultdict(int)

    for line in log_lines:
        # Extract IP address
        ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
        if ip_match:
            ip_address = ip_match.group(1)
            ip_requests[ip_address] += 1

        # Extract endpoint
        endpoint_match = re.search(r'"(?:GET|POST|PUT|DELETE) (/\S*) HTTP/\d\.\d"', line)
        if endpoint_match:
            endpoint = endpoint_match.group(1)
            endpoint_access[endpoint] += 1

        # Detect failed login attempts (HTTP 401 or "Invalid credentials")
        if "401" in line or "Invalid credentials" in line:
            if ip_match:
                failed_logins[ip_address] += 1

    return ip_requests, endpoint_access, failed_logins

def find_most_accessed_endpoint(endpoint_access):
    """Finds the most frequently accessed endpoint."""
    return max(endpoint_access.items(), key=lambda x: x[1])

def detect_suspicious_activity(failed_logins, threshold):
    """Detects suspicious activity based on failed login attempts."""
    return {ip: count for ip, count in failed_logins.items() if count >= threshold}

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_file):
    """Saves the results to a CSV file."""
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        writer.writerow([])

        # Write Most Accessed Endpoint
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        writer.writerow([])

        # Write Suspicious Activity
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    # Parse the log file
    ip_requests, endpoint_access, failed_logins = parse_log_file(LOG_FILE)

    # Most accessed endpoint
    most_accessed_endpoint = find_most_accessed_endpoint(endpoint_access)

    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(failed_logins, FAILED_LOGIN_THRESHOLD)

    # Display results
    print("Requests per IP Address:")
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")
    print()

    print("Most Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print()

    print("Suspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")
    print()

    # Save results to CSV
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, OUTPUT_FILE)
    print(f"Results saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
