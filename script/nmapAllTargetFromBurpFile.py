import json
import nmap
import socket
import sys
import re
import time

def scan_ip(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments='-p- -sV')
    
    results = []
    for proto in nm[ip].all_protocols():
        ports = nm[ip][proto].keys()
        for port in ports:
            state = nm[ip][proto][port]['state']
            if state == 'open':
                service = nm[ip][proto][port]['name']
                version = nm[ip][proto][port].get('version', '')
                results.append(f"Port {port}/{proto}: {service} {version}")
    
    return results

def extract_domains(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)
    
    domains = set()
    for item in data['target']['scope']['include']:
        host = item['host']
        domain = re.sub(r'^\^|\$$', '', host).replace('\\', '')
        domains.add(domain)
    
    return list(domains)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_json_file>")
        sys.exit(1)

    json_file = sys.argv[1]
    print(f"Extracting domains from {json_file}...")
    domains = extract_domains(json_file)
    print(f"Found {len(domains)} unique domains.")

    print("Starting scan...")
    start_time = time.time()

    # Open the output file
    with open('nmap_results.txt', 'w') as f:
        for index, domain in enumerate(domains, 1):
            print(f"\nProcessing domain {index}/{len(domains)} ({domain})...")
            try:
                ip = socket.gethostbyname(domain)
                print(f"Resolved IP: {ip}")
                f.write(f"\nScanning {domain} ({ip}):\n")
                print("Starting nmap scan...")
                results = scan_ip(ip)
                if results:
                    print(f"Found {len(results)} open ports.")
                    for result in results:
                        f.write(f"{result}\n")
                else:
                    print("No open ports found.")
                    f.write("No open ports found.\n")
            except socket.gaierror:
                print(f"Unable to resolve IP address for {domain}")
                f.write(f"Unable to resolve IP address for {domain}\n")
            except Exception as e:
                print(f"Error while scanning {domain}: {str(e)}")
                f.write(f"Error while scanning {domain}: {str(e)}\n")
            
            f.write("\n" + "="*50 + "\n")
            
            # Calculate and print progress
            progress = (index / len(domains)) * 100
            elapsed_time = time.time() - start_time
            est_total_time = elapsed_time / (index / len(domains))
            est_remaining_time = est_total_time - elapsed_time
            
            print(f"Progress: {progress:.2f}% complete")
            print(f"Elapsed time: {elapsed_time:.2f} seconds")
            print(f"Estimated time remaining: {est_remaining_time:.2f} seconds")

    total_time = time.time() - start_time
    print(f"\nScan completed in {total_time:.2f} seconds.")
    print("Results have been written to nmap_results.txt")
