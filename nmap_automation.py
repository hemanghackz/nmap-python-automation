"""
nmap_automation.py
This script performs an automated Nmap SYN scan using python-nmap.
It scans a target IP/hostname and generates a text report.
"""

import nmap
from datetime import datetime

def syn_scan(target):
    """
    Performs a SYN scan on the given target and generates a report.
    """

    # Initialize Nmap scanner
    scanner = nmap.PortScanner()

    # Perform SYN scan with service/version detection
    scanner.scan(hosts=target, arguments='-sS -sV')

    # Create report file
    with open("scan_report.txt", "w") as report:
        report.write("Nmap SYN Scan Report\n")
        report.write("=====================\n")
        report.write(f"Scan Timestamp : {datetime.now()}\n")
        report.write(f"Target IP      : {target}\n\n")

        # Loop through all detected hosts
        for host in scanner.all_hosts():
            report.write(f"Host: {host}\n")
            report.write("Port | Service | Version\n")
            report.write("-------------------------\n")

            # Loop through protocols (TCP)
            for protocol in scanner[host].all_protocols():
                if protocol == "tcp":
                    ports = scanner[host][protocol].keys()
                    for port in ports:
                        service = scanner[host][protocol][port]['name']
                        version = scanner[host][protocol][port].get('version', 'N/A')
                        report.write(f"{port} | {service} | {version}\n")

        report.write("\nScan completed successfully.\n")

    print("Scan completed. Report saved as scan_report.txt")

# Main execution
if __name__ == "__main__":
    target_input = input("Enter target IP or hostname: ")
    syn_scan(target_input)
