import socket
import sys
import requests
import ssl
import re

def scan_brute(ip, startPort, endPort, brute):
    """ Starts a Agressive Forced TCP scan on a given IP address """

    print('[*] Starting Aggressive TCP port scan on host %s' % ip)

    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort, brute)

    print('[!] Aggressive TCP scan on host %s complete' % ip)


def scan_host(ip, startPort, endPort, brute):
    """ Starts a TCP scan on a given IP address """

    print('[*] Starting TCP port scan on host %s' % ip)

    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort, brute)

    print('[!] TCP scan on host %s complete' % ip)


def scan_range(network, startPort, endPort):
    """ Starts a TCP scan on a given IP address range """

    print('[*] Starting TCP port scan on network %s.0' % network)

    # Iterate over a range of host IP addresses and scan each target
    for host in range(1, 255):
        ip = network + '.' + str(host)
        brute=False
        tcp_scan(ip, startPort, endPort, brute)

    print('[!] TCP scan on network %s.0 complete' % network)


def rdp_scan(ip, port): # IT WORKS !!!!!!!!!!!. We can just rely on the x.224 request since only RDP mainly uses it. We could just remove the SSL/TLS Negotiation part. Would be nice to keep.
    try:
        # Create TCP connection
        sock = socket.create_connection((ip, port), timeout=5)
        print(f"            [*] TCP connection established")

        # Send Connection Request (X.224) as captured by Wireshark
        x224 = bytes.fromhex(
            '03 00 00 13'  # TPKT Header (3 bytes version+length, 13 bytes total)
            '0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00'  # X.224 Connection Request
        )
        sock.sendall(x224)
        print(f"            [*] Sent X.224 Connection Request")

        # Receive Connection Confirm
        response = sock.recv(4096)
        print(f"            [*] Received X.224 Response")

        if not response:
            print(f"            [-] No response from server, exiting.")
            sock.close()
            return False

        print(f"            [+] X.224 Response: {response.hex(' ')}")

        # Now initiate SSL/TLS (RDP usually expects SSL/TLS after Negotiation)
        # This crashed on my linux host sadly. We could realistically rely on the x.224 request only. Will have to research this more. 
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable verification
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
        print(f"         [*] TLS handshake complete")

        # Now you would send an MCS Connect-Initial PDU, etc. (very complicated)
        print(f"            [+] Basic RDP Negotiation complete (TLS established).")
        ssl_sock.close()
        return True

    except Exception as e:
        print(f"            [-] Connection failed: {e}")
        if 'WRONG_VERSION_NUMBER' in str(e): #SSL is there but not same version. Still should return true that RDP is present.
            return True
        else:
            return False


def http_scan(ip, port):
    try:
        url = f'http://{ip}:{port}'
        print(f'    [!]Testing {url}')
        result = requests.get(url, timeout=10)  # set timeout so it doesn't hang forever
        status = result.status_code  # no parentheses
        print(f'    [*] HTTP {url} responded with status code {status}')
        return True
    except requests.exceptions.RequestException as e:
        print(f'    [-] HTTP request to {ip}:{port} failed: {e}')
        return False

def tcp_scan(ip, startPort, endPort, brute):
    service_probes = {
        21: (b'USER anonymous\r\n', 'FTP'),
        22: (b'\r\n', 'SSH'),
        23: (b'\r\n', 'Telnet'),
        25: (b'HELO test.com\r\n', 'SMTP'),
        80: (f'GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n'.encode(), 'HTTP'),
        110: (b'USER test\r\n', 'POP3'),
        143: (b'. CAPABILITY\r\n', 'IMAP'),
        443: (f'GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n'.encode(), 'HTTPS'),
    }

    banner_fingerprints = {
        'SSH': re.compile(r'ssh', re.IGNORECASE),
        'FTP': re.compile(r'ftp', re.IGNORECASE),
        'SMTP': re.compile(r'smtp', re.IGNORECASE),
        'POP3': re.compile(r'pop3', re.IGNORECASE),
        'IMAP': re.compile(r'imap', re.IGNORECASE),
        'HTTP': re.compile(r'http', re.IGNORECASE),
        'HTTPS': re.compile(r'https', re.IGNORECASE),
        'Telnet': re.compile(r'telnet', re.IGNORECASE),
                # Add more as needed
    }

    for port in range(startPort, endPort + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(5)
            result = tcp.connect_ex((ip, port))

            if result == 0:
                print(f'\n\n\n[+] {ip}:{port}/TCP Open')

                if brute:
                    try:
                        brute_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        brute_tcp.settimeout(5)
                        brute_tcp.connect((ip, port))
                        brute_tcp.sendall(b'\r\n')  # Generic probe
                        banner = brute_tcp.recv(1024).decode(errors='ignore').strip()
                        brute_tcp.close()

                        if banner:
                            print(f'    [+] Banner: {banner}')
                            detected_service = None
                            for service_name, pattern in banner_fingerprints.items():
                                if pattern.search(banner):
                                    detected_service = service_name
                                    print(f'    [!] {service_name} probe found something!')
                                    print(f'    [+] Detected service: {service_name}')
                                    break
                            if not detected_service:
                                print(f'    [!] Unknown service on port {port}')
                        else:
                            print(f'    [-] No banner. Attempting HTTP fingerprint...')
                            if http_scan(ip, port):
                                print(f'\n    [+] HTTP Server Detected!\n')
                                continue
                            print(f'    [!] Attempting RDP fingerprint...')
                            if rdp_scan(ip, port):
                                print(f'\n    [+] RDP Server Detected!\n')
                                continue
                    except Exception:
                        print(f'    [-] Brute banner grab failed.')
                        if http_scan(ip, port):
                            print(f'\n    [+] HTTP Server Detected!\n')
                            continue
                        print(f'    [!] Attempting RDP fingerprint...')
                        if rdp_scan(ip, port):
                            print(f'\n    [+] RDP Server Detected!\n')
                            continue


                else: # Default (non-brute) banner grab
                    probe, service_name = service_probes.get(port, (b'\r\n', None))
                    try:
                        tcp.sendall(probe)
                        banner = tcp.recv(1024).decode(errors='ignore').strip()
                        if banner:
                            print(f'    [*] Banner: {banner}')
                            if service_name:
                                print(f'    [+] Detected service: {service_name}')
                        else:
                            print(f'    [-] No banner. Attempting HTTP fingerprint...')
                            if http_scan(ip, port):
                                print(f'\n    [+] HTTP Server Detected!\n')
                                continue
                            print(f'    [!] Attempting RDP fingerprint...')
                            if rdp_scan(ip, port):
                                print(f'\n    [+] RDP Server Detected!\n')
                                continue
                    except Exception:
                        print(f'    [-] Failed to send/receive. Attempting HTTP fingerprint...')
                        if http_scan(ip, port):
                            print(f'\n    [+] HTTP Server Detected!\n')
                            continue
                        print(f'    [!] Attempting RDP fingerprint...')
                        if rdp_scan(ip, port):
                            print(f'\n    [+] RDP Server Detected!\n')
                            continue

                    tcp.close()

        except Exception as e:
            print(f'[!] Error scanning {ip}:{port} -> {e}')
            http_scan(ip, port)

def sonicwall_check(ip,port): #'94.206.165.178','80'
    response=requests.get('http://'+ip+':'+port)
    #title=response.
    #print('[DEBUG]\n'+data)
    match = re.search(r'var jumpURL\s*=\s*"([^"]+)"', response.text)
    if match:
        jump_url = match.group(1)
        print(f"Redirecting to: {jump_url}")
        redirected_response = requests.get(jump_url, verify=False)
        #print(redirected_response.text)
        pattern = r"sonic\s*wall"
        match = re.search(pattern, redirected_response.text, re.IGNORECASE)
        if match:
            #print('SonicWall')
            return True
        else:
            #print('NO SONIC')
            return False
    else:
        print("No redirect URL found.")
        return False



def fortigate_check():
    print('Fortigate')

if __name__ == '__main__':
    # Timeout in seconds. I think 1 second is enough for WAN. Maybe increase it to 5 if we find issues?
    # The entire idea is to parse input, then TCP scan, If no banner http_scan, if http_scan faile then rdp scan, if rdp fail ...
    # For testing, the script accepts user input. When pushing to prod we can just hardcode all ports into the script.
    # For now the script supports: http/s, ssh, telnet, pop, smtp, imap, FTP and RDP. Will update and add more as we develop the script further.
    # DONE: impliment boolean return values for http_scan() and rdp_scan() so that we can skip the scan if return True
    # DONE: Connection failed: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:992) returned by my Linux Machine and server. RDP is there but SSL version mismatch.
    #sonicwall_check('94.206.165.178','80')
    #exit
    socket.setdefaulttimeout(10)
    brute=False

    if len(sys.argv) < 4:
        print('\n-b does an aggressive scan that tests each port for all known signatures. This is the recommended mode. It can be slow so be patient.')
        print('-n is a network wide scan against multiple IPs.')
        print('No arguments simply runs a normal scan and tests default ports.')
        print('Usage: ./portscanner.py <IP address> <start port> <end port>')
        print('Example: ./portscanner.py 192.168.0.102 1 65535\n')
        print('Usage: ./portscanner.py <network> <start port> <end port> -n This will scan the /24 range')
        print('Example: ./portscanner.py 192.168.1 1 65535 -n\n')
        print('Usage: ./portscanner.py <network> <start port> <end port> -b')
        print('Example: ./portscanner.py 192.168.0.102 1 65535 -b\n')

    elif len(sys.argv) >= 4:
        network   = sys.argv[1]
        startPort = int(sys.argv[2])
        endPort   = int(sys.argv[3])

    if len(sys.argv) == 4:
        scan_host(network, startPort, endPort, brute)

    if len(sys.argv) == 5:
        if sys.argv[4]=='b' or sys.argv[4]=='-b':
            brute=True
            scan_brute(network, startPort, endPort, brute)
        elif sys.argv[4]=='n' or sys.argv[4]=='-n':
            scan_range(network, startPort, endPort)