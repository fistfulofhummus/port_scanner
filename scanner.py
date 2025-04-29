import socket
import sys
import requests
import ssl

def scan_brute(ip, startPort, endPort, brute):
    """ Starts a Agressive Forced TCP scan on a given IP address """

    print('[*] Starting Aggressive TCP port scan on host %s' % ip)

    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort, brute)

    print('[+] Bruteish TCP scan on host %s complete' % ip)


def scan_host(ip, startPort, endPort, brute):
    """ Starts a TCP scan on a given IP address """

    print('[*] Starting TCP port scan on host %s' % ip)

    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort, brute)

    print('[+] TCP scan on host %s complete' % ip)


def scan_range(network, startPort, endPort):
    """ Starts a TCP scan on a given IP address range """

    print('[*] Starting TCP port scan on network %s.0' % network)

    # Iterate over a range of host IP addresses and scan each target
    for host in range(1, 255):
        ip = network + '.' + str(host)
        brute=False
        tcp_scan(ip, startPort, endPort, brute)

    print('[+] TCP scan on network %s.0 complete' % network)


def rdp_scan(ip, port): # IT WORKS !!!!!!!!!!!. We can just rely on the x.224 request since only RDP mainly uses it. We could just remove the SSL/TLS Negotiation part. Would be nice to keep.
    try:
        # Create TCP connection
        sock = socket.create_connection((ip, port), timeout=5)
        print("[*] TCP connection established")

        # Send Connection Request (X.224) as captured by Wireshark
        x224 = bytes.fromhex(
            '03 00 00 13'  # TPKT Header (3 bytes version+length, 13 bytes total)
            '0e e0 00 00 00 00 00 01 00 08 00 03 00 00 00'  # X.224 Connection Request
        )
        sock.sendall(x224)
        print("[*] Sent X.224 Connection Request")

        # Receive Connection Confirm
        response = sock.recv(4096)
        print("[*] Received X.224 Response")

        if not response:
            print("[-] No response from server, exiting.")
            sock.close()
            return False

        print(f"[+] X.224 Response: {response.hex(' ')}")

        # Now initiate SSL/TLS (RDP usually expects SSL/TLS after Negotiation)
        # This crashed on my linux host sadly. We could realistically rely on the x.224 request only. Will have to research this more. 
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable verification
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
        print("[*] TLS handshake complete")

        # Now you would send an MCS Connect-Initial PDU, etc. (very complicated)
        print("[+] Basic RDP Negotiation complete (TLS established).")
        ssl_sock.close()
        return True

    except Exception as e:
        print(f"[-] Connection failed: {e}")
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
        21: b'USER anonymous\r\n',  # FTP
        22: b'\r\n',                # SSH
        23: b'\r\n',                # Telnet
        25: b'HELO test.com\r\n',   # SMTP
        80: f'GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n'.encode(),  # HTTP
        110: b'USER test\r\n',      # POP3
        143: b'. CAPABILITY\r\n',   # IMAP
        443: f'GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n'.encode(),  # HTTPS (should ideally wrap SSL)
        #RDP is going to be complicated. These are easier services to fingerprint. Ideally difficult services should have their own function each.
    }

    for port in range(startPort, endPort + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.settimeout(5)
            result = tcp.connect_ex((ip, port))

            if result == 0:
                print(f'[+] {ip}:{port}/TCP Open')

                if brute:
                    found = False
                    for probe_port, probe in service_probes.items():
                        try:
                            tcp.sendall(probe)
                            banner = tcp.recv(1024).decode(errors='ignore').strip()
                            if banner:
                                print(f'    [*] Banner (using {probe_port} probe): {banner}')
                                found = True
                                break  # Stop trying probes once we get a response
                        except Exception:
                            continue
                    if found == False: #Could not find it with services above so we start using other functions dedicated to protocols
                        if http_scan(ip, port):
                            print(f'\n    [+] HTTP Server Detected!\n')
                            break                        
                        if rdp_scan(ip, port):
                            print(f'\n    [+] RDP Server Detected!\n')
                            break
                probe = service_probes.get(port, b'\r\n')
                try:
                    tcp.sendall(probe)
                    banner = tcp.recv(1024).decode(errors='ignore').strip()
                    if banner:
                        print(f'    [*] Banner: {banner}')
                    else:
                        print(f'    [-] No banner. Attempting HTTP fingerprint...')
                        if http_scan(ip, port):
                            print(f'\n    [+] HTTP Server Detected!\n')
                            break
                        print(f'    [!] Attempting RDP fingerprint...')
                    if rdp_scan(ip, port):
                        print(f'\n    [+] RDP Server Detected!\n')
                        break                    
                except Exception:
                    print(f'    [-] Failed to send/receive. Attempting HTTP fingerprint...')
                    if http_scan(ip, port):
                        print(f'\n    [+] HTTP Server Detected!\n')
                        break
                    print(f'    [!] Attempting RDP fingerprint...')
                    if rdp_scan(ip, port):
                        print(f'\n    [+] RDP Server Detected!\n')
                        break


            tcp.close()

        except Exception as e:
            print(f'[!] Error scanning {ip}:{port} -> {e}')
            http_scan(ip, port)


if __name__ == '__main__':
    # Timeout in seconds. I think 1 second is enough for WAN. Maybe increase it to 5 if we find issues?
    # The entire idea is to parse input, then TCP scan, If no banner http_scan, if http_scan faile then rdp scan, if rdp fail ...
    # For testing, the script accepts user input. When pushing to prod we can just hardcode all ports into the script.
    # For now the script supports: http/s, ssh, telnet, pop, smtp, imap, FTP and RDP. Will update and add more as we develop the script further.
    # DONE: impliment boolean return values for http_scan() and rdp_scan() so that we can skip the scan if return True
    # DONE: Connection failed: [SSL: WRONG_VERSION_NUMBER] wrong version number (_ssl.c:992) returned by my Linux Machine and server. RDP is there but SSL version mismatch.
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