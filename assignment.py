import re
import csv

LOG_FILE = "sample.log" # Path to the Log File
LOG_ANALYSIS_FILE = "log_analysis_results.csv" # Path to the Analysis Results File
FAILED_LOGIN_TRIGGER = 10 # Default Threshold for classifyong as suspicious IP Address

def get_logs(log_path):
    """Parses through a log file and returns the logs"""
    with open(log_path, "r") as file: 
        logs = file.readlines() # Reads the log entries into a list of strings
    return logs


def count_requests_per_ip(logs):
    """Counts the number of requests made from each unique IP Address"""
    ip_count = {} # Stores the IP Addresses and its request count
    for log in logs:
        ip_address = log.split()[0] # Extracts the IP Address
        # Increments request count of an IP Address
        if ip_address in ip_count: 
            ip_count[ip_address] += 1 
        else:
            ip_count[ip_address] = 1
    return ip_count


def get_most_accessed_endpoint(logs):
    """Finds and returns the endpoint that was accessed the most along with its access count"""
    endpoint_count = {} # Stores the Endpoint and its access count
    log_pattern = r'"GET (\S+)'# Matches only GET requests, as they refer to accessing/viewing resources
    for log in logs:
        match = re.search(log_pattern, log) # Checks if the log matches the RegEx pattern
        if match:
            endpoint = match.group(1) # Extracts the endpoint
            # Increments access count of an Endpoint
            if endpoint in endpoint_count:
                endpoint_count[endpoint] += 1
            else:
                endpoint_count[endpoint] = 1
    # Gets the most accessed endpoint using lambda function in the key to choose based on access count
    most_accessed_endpoint = max(endpoint_count.items(), key=lambda x: x[1]) 
    return most_accessed_endpoint


def detect_suspicious_ip(logs, trigger=FAILED_LOGIN_TRIGGER):
    """Identifies and returns the IP addresses with failed login attempts exceeding a specified trigger count"""
    failed_login_pattern = r'".*" 401 .* ("Invalid credentials")?' # Matches logs that have a 401 Status Code or "Invalid credentials" message
    failed_logins = {} # Stores the IP Address and its failed login count
    for log in logs:
        match = re.search(failed_login_pattern, log) # Checks if the log recorded a failed login attempt
        if match: 
            ip_address = log.split()[0] # Extracts the IP Address
            # Increments failed login count of an IP Address
            if ip_address in failed_logins:
                failed_logins[ip_address] += 1
            else:
                failed_logins[ip_address] = 1
    # Uses dict comprehension to filter and create a new dict with IPs having failed login count > trigger (default = 10)
    suspicious_ip = {ip : count for ip, count in failed_logins.items() if count > trigger}
    return suspicious_ip


def display_output(ip_count, most_accessed_endpoint, suspicious_ip):
    """Displays the Log Analysis Results in the Terminal"""
    # Display request counts per IP Address in descending order
    print("IP Address      Request Count")
    for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<15} {count}")
    
    # Display the most accessed endpoint (GET Requests only)
    print("\nMost Frequently Accessed Endpoint:")
    print(most_accessed_endpoint[0] + f" (Accessed {most_accessed_endpoint[1]} times)")
    
    # Display suspicious IP addresses with failed login count > trigger (default = 10)
    print("\nSuspicious Activity Detected:")
    print("IP Address      Failed Login Count")
    for ip, count in sorted(suspicious_ip.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<15} {count}")


def export_analysis(ip_count, most_accessed_endpoint, suspicious_ip):
    """Exports the Log Analysis Results to a CSV File"""
    with open(LOG_ANALYSIS_FILE, "w", newline='') as file:
        writer = csv.writer(file)
        
        # Writes request counts per IP Address in descending order
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_count.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])
        
        # Writes the most accessed endpoint (GET Requests only)
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint[0], most_accessed_endpoint[1]])
        
        # Writes suspicious IP addresses with failed login count > trigger (default = 10)
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in sorted(suspicious_ip.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])


def main():
    logs = get_logs(LOG_FILE)
    ip_request_count = count_requests_per_ip(logs)
    most_accessed_endpoint = get_most_accessed_endpoint(logs)
    suspicious_ip = detect_suspicious_ip(logs)
    display_output(ip_request_count, most_accessed_endpoint, suspicious_ip)
    export_analysis(ip_request_count, most_accessed_endpoint, suspicious_ip)

if __name__ == "__main__":
    main()
