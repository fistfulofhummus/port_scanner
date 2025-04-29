import socket
#WORKS FOR LINUX. Workgs against my localhost and remote server.
def rdp_hello(ip, port=3389):
    # Basic X.224 Connection Request for RDP
    hello = bytes.fromhex(
        '03 00 00 13'  # TPKT Header
        '0e d0 00 00 12 34 00 02 01 00 08 00 03 00 00 00'  # X.224 Header
    )
    try:
        sock = socket.create_connection((ip, port), timeout=5)
        sock.sendall(hello)
        response = sock.recv(1024)
        print(f"Received {len(response)} bytes:")
        print(response.hex(' '))
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

# Example usage:
rdp_hello('89.43.33.169') 
