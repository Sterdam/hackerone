import json
import nmap
import socket
import sys
import re
import time
import argparse
import os

def scan_ip(ip, mode):
    nm = nmap.PortScanner()
    if mode == 'default':
        nm.scan(ip, arguments='-p- -sV')
    elif mode == 'all':
        nm.scan(ip, arguments='-p- -sV -sC')
    elif mode == 'aggressive':
        nm.scan(ip, arguments='-p- -sV -sC -A --osscan-guess')
    
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
    parser = argparse.ArgumentParser(description='Nmap scanner with multiple modes')
    parser.add_argument('json_file', help='Path to the JSON file containing domains')
    parser.add_argument('--mode', choices=['default', 'all', 'aggressive'], default='default',
                        help='Scanning mode: default, all (all ports), or aggressive')
    args = parser.parse_args()

    print(f"Extracting domains from {args.json_file}...")
    domains = extract_domains(args.json_file)
    print(f"Found {len(domains)} unique domains.")

    print(f"Starting scan in {args.mode} mode...")
    start_time = time.time()

    # Generate output file name
    output_file = os.path.splitext(args.json_file)[0] + "_results.txt"

    # Open the output file
    with open(output_file, 'w') as f:
        for index, domain in enumerate(domains, 1):
            print(f"\nProcessing domain {index}/{len(domains)} ({domain})...")
            try:
                ip = socket.gethostbyname(domain)
                print(f"Resolved IP: {ip}")
                f.write(f"\nScanning {domain} ({ip}):\n")
                print(f"Starting nmap scan in {args.mode} mode...")
                results = scan_ip(ip, args.mode)
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
    print(f"Results have been written to {output_file}")
