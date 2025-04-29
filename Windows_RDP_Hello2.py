import socket
import struct
import ssl

def rdp_connect(ip, port=3389):
    try:
        # Create TCP connection
        sock = socket.create_connection((ip, port), timeout=5)
        print("[*] TCP connection established")

        # Send Connection Request (X.224)
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
            return

        print(f"[+] X.224 Response: {response.hex(' ')}")

        # Now initiate SSL/TLS (RDP usually expects SSL/TLS after Negotiation)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # Disable verification
        ssl_sock = context.wrap_socket(sock, server_hostname=ip)
        print("[*] TLS handshake complete")

        # Now you would send an MCS Connect-Initial PDU, etc. (very complicated)
        print("[+] Basic RDP Negotiation complete (TLS established).")

        ssl_sock.close()

    except Exception as e:
        print(f"[-] Connection failed: {e}")

# Example usage:
if __name__ == "__main__":
    rdp_connect('192.168.0.109')
