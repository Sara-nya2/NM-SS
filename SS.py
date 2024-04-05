import socket
import requests

class SecurityScanner:
    def __init__(self, target):
        self.target = target

    def scan_ports(self, ports):
        print(f"Scanning {self.target} for open ports...")
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print(f"Port {port} is open")
            sock.close()

    def check_website_security_headers(self):
        print(f"Checking security headers for website: {self.target}")
        try:
            response = requests.head(self.target)
            headers = response.headers
            if 'X-XSS-Protection' in headers:
                print(f"X-XSS-Protection header is set: {headers['X-XSS-Protection']}")
            else:
                print("X-XSS-Protection header is not set")
            if 'X-Content-Type-Options' in headers:
                print(f"X-Content-Type-Options header is set: {headers['X-Content-Type-Options']}")
            else:
                print("X-Content-Type-Options header is not set")
            if 'Strict-Transport-Security' in headers:
                print(f"Strict-Transport-Security header is set: {headers['Strict-Transport-Security']}")
            else:
                print("Strict-Transport-Security header is not set")
        except Exception as e:
            print(f"Error occurred while checking security headers: {e}")

# Example usage:
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Change this to the IP address or domain you want to scan
    ports_to_scan = [80, 443, 22, 8080]  # Specify the ports you want to scan
    website_url = "http://example.com"  # Change this to the website you want to check

    scanner = SecurityScanner(target_ip)
    scanner.scan_ports(ports_to_scan)
    scanner.check_website_security_headers()
