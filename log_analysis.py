import re
from collections import Counter, defaultdict
import csv

# Configurable threshold for suspicious activity
FAILED_LOGIN_THRESHOLD = 10

def parse_log(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()

    ip_list = []
    endpoint_list = []
    failed_logins = defaultdict(int)
    
    pattern = r'(?P<ip>\d+\.\d+\.\d+\.\d+).*"(?P<method>\w+)\s(?P<endpoint>\/\S*)\sHTTP.*"\s(?P<status>\d+).*"?(?P<message>Invalid credentials)?"?'

    for line in logs:
        match = re.match(pattern, line)
        if match:
            data = match.groupdict()
            ip = data['ip']
            endpoint = data['endpoint']
            status = int(data['status'])
            
            ip_list.append(ip)
            endpoint_list.append(endpoint)
            
            if status == 401 or data['message']:
                failed_logins[ip] += 1

    return ip_list, endpoint_list, failed_logins

def save_to_csv(ip_counter, endpoint_counter, suspicious_ips):
    with open('log_analysis_results.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counter.most_common():
            writer.writerow([ip, count])
        
        # Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Endpoint", "Access Count"])
        for endpoint, count in endpoint_counter.most_common():
            writer.writerow([endpoint, count])
        
        # Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

def main():
    # Step 1: Parse the log
    ip_list, endpoint_list, failed_logins = parse_log('sample.log')
    
    # Step 2: Count requests per IP
    ip_counter = Counter(ip_list)
    
    # Step 3: Identify the most accessed endpoint
    endpoint_counter = Counter(endpoint_list)
    
    # Step 4: Detect suspicious activity
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > FAILED_LOGIN_THRESHOLD}
    
    # Step 5: Display results
    print("IP Address Requests:")
    for ip, count in ip_counter.most_common():
        print(f"{ip}: {count}")
    
    most_accessed = endpoint_counter.most_common(1)[0]
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")
    
    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip}: {count} failed attempts")
    
    # Step 6: Save results to CSV
    save_to_csv(ip_counter, endpoint_counter, suspicious_ips)

if __name__ == "__main__":
    main()
