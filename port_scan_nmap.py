import nmap
import pyfiglet
import ipaddress
import re

# title
def print_title(text):
    font = pyfiglet.Figlet()
    title = font.renderText(text)
    print(title)

def get_ip_and_ports():
     # Loop until a valid IP address is entered
    while True:
        ip_address = input("Enter an IP address: ")
        try:
            # Attempt to create an IP address object
            ip_address_obj = ipaddress.ip_address(ip_address)
            print("[+] You entered a valid IP address\n")
            break
        except ValueError as e:
            # Handle the case of an invalid IP address
            print(f"[-] You entered an invalid IP address: {e}")
    # Regular expression pattern to validate port range input
    port_range_pattern = re.compile("([0-9]+)-([0-9]+)")
    port_min = 0
    port_max = 65535
    # Loop until a valid port range is entered
    while True:
        print("Please enter the range of ports you want to scan in the format: <int>-<int> (e.g., 60-120)")
        port_range = input("Enter port range: ")
        port_range_valid = port_range_pattern.search(port_range.replace(" ", ""))
        if port_range_valid:
            # Extract and set the minimum and maximum port values
            port_min = int(port_range_valid.group(1))
            port_max = int(port_range_valid.group(2))
            break
    # Return the validated IP address object and port range values
    return ip_address_obj, port_min, port_max


# scan ip address and print, service, service version, state of port(open, close)
def scan_ports(ip_address,port_min,port_max):
    # convert ip into string
    ip = str(ip_address)
    # create port range
    port_range = f"{port_min}-{port_max}"
    print(f"Scanning {ip} on port range {port_range}")
    print("Scanning will take some time\n")
    # argument for nmap scan
    arg = f"-p {port_range} -sV -T4"
    #  Creating an instance of the PortScanner class
    nm =nmap.PortScanner()
    try:
        nm.scan(ip, arguments=arg)  # Scan all TCP ports
        # The all_hosts() method in the python-nmap library returns a list of hosts that are currently active and have responded to the scan
        for host in nm.all_hosts():
            print(f"Host: {host}")
            # all_protocols() is a method that returns a list of protocols detected on that host (TCP, UDP).

            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")
                # extracting and sorting the list of open port numbers for a specific host and protocol
                # .keys(): This method returns a list of all the  port numbers associated with the specified host and protocol.
                ports = sorted(nm[host][proto].keys())

                for port in ports:
                    service_info = nm[host][proto][port]
                    # Extracting the state of the port (e.g., open, closed, filtered).
                    state = service_info.get('state', 'Unknown')
                    # Extracting the service name associated with the port (if available)
                    service = service_info.get('name', 'Unknown')
                    # extract the version of service running on a port
                    version = service_info.get('product', 'Unknown')
                    print(f"Port {port} ({service}) - Version: {version}, State: {state}")

    except nmap.PortScannerError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"An unwanted error occurred: {e}")


# print title
print_title("Net - Scan")
ip_address, port_min, port_max = get_ip_and_ports()
scan_ports(ip_address,port_min,port_max)