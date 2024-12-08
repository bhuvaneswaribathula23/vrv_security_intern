import csv
from collections import defaultdict, Counter

# Constants
LOG_FILE = "sample.log" # Location of the log file
OUTPUT_CSV = "log_analysis_results.csv" # Output file
FAILED_LOGIN_THRESHOLD = 1

def parse_log_file(file_path):
    ip_requests = Counter()# Initilaize counters for ip_requests, endpoint_requests
    endpoint_requests = Counter()
    failed_logins = defaultdict(int)

    with open(file_path, 'r') as file:
        for line in file:
            parts = line.split() #Extract information in each line
            ip = parts[0]
            method, endpoint, protocol = parts[5][1:], parts[6], parts[7][:-1]
            status_code = int(parts[8])
            message = parts[9] if len(parts) > 9 else ""

            # Count requests per IP
            ip_requests[ip] += 1

            # Count requests per endpoint
            endpoint_requests[endpoint] += 1

            # Identify failed login attempts
            if status_code == 401 or "Invalid credentials" in message:
                failed_logins[ip] += 1

    return ip_requests, endpoint_requests, failed_logins

def save_results_to_csv(ip_requests, most_accessed, failed_logins):
    with open(OUTPUT_CSV, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([]) # 1 empty row
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([]) # 1 empty row
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in failed_logins.items():
            if count > FAILED_LOGIN_THRESHOLD:
                writer.writerow([ip, count])

def display_results(ip_requests, most_accessed, failed_logins):
    print("Requests per IP Address:")
    print("IP Address           Request Count")
    for ip, count in ip_requests.items():
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in failed_logins.items():
        if count > FAILED_LOGIN_THRESHOLD:
            print(f"{ip:<20}{count}")

def main():
    ip_requests, endpoint_requests, failed_logins = parse_log_file(LOG_FILE) # Parse information
    
    # Get the most accessed endpoint
    most_accessed = endpoint_requests.most_common(1)[0]
    
    # Display and save results
    display_results(ip_requests, most_accessed, failed_logins)
    save_results_to_csv(ip_requests, most_accessed, failed_logins)

if __name__ == "__main__":
    main()
