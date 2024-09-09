from proxy import ProxyServer, socket
from getmac import get_mac_address

if __name__ == "__main__":
    # Print Mac and IP addresses
    print(f"[*] My MAC Address: {get_mac_address()}")
    print(f"[*] My IP Adress: {socket.gethostbyname(socket.gethostname())}")

    # Create a ProxyServer intstance and start it
    proxy_server = ProxyServer()
    proxy_server.start_proxy()


'''
REFERENCES USED:

'''