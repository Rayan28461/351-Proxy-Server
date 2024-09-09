import socket
import threading
from flask import Flask, request, redirect, render_template
from urllib.parse import urlparse
from datetime import datetime
from cache import SimpleCache

class ProxyServer:
    def __init__(self):
        """
        Initialize the ProxyServer instance.

        Sets up attributes for caching, blocked sites, user authentication, blocked client IPs,
        and synchronization events for user authentication completion.
        """
        self.cache = SimpleCache(size_limit = 10, expiration_time = 300)  # Initialize your desired cache with size and expiration time (in sec)
        self.blocked_sites = ['www.example.com']   # List of blocked sites based on URLs
        self.users = {'user1': 'password1', 'user2': 'password2'}  # User credentials for authentication
        self.blocked_clientIPs = []   # List of blocked client IPs ["192.168.1.111"]

        # Flags and events for user authentication
        self.auth_page_is_rendered = False
        self.auth_complete_event = threading.Event()

    def handle_client(self, client_socket):
        """
        Handle an incoming client request.

        Args:
            client_socket (socket.socket): The socket object for communicating with the client.

        This method processes the client request, checks for blocking conditions,
        and either serves the request from the cache or forwards it to the destination server.
        """
        # Receive data from the client
        request_data = client_socket.recv(4096)

        # Parse the request to get the requested URL
        url = self.get_requested_url(request_data.decode('utf-8'))

        # Print message describing the request
        client_ip, client_port = client_socket.getpeername()
        current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"[*] Received request from client {client_ip}:{client_port} for {url.hostname}{url.path} at {current_time}")

        hs = socket.gethostname()
        ip = socket.gethostbyname(hs)

        # Check if client is blocked based on IP
        if ip in self.blocked_clientIPs:
            error_message = f"HTTP/1.1 403 Forbidden\r\n\r\n {ip} is blocked by the proxy."
            print(f"[!] Blocked request to {url.netloc}")
            client_socket.send(error_message.encode('utf-8'))
            client_socket.close()
            return
        
        # Check if site is blocked based on hostname/netloc
        if self.is_site_blocked(url):
            error_message = "HTTP/1.1 403 Forbidden\r\n\r\nRequested site is blocked by the proxy."
            print(f"[!] Blocked request to {url.netloc}")
            client_socket.send(error_message.encode('utf-8'))
            client_socket.close()
            return

        # Check if the requested URL is in the cache and is still up to date
        if url in self.cache.cache:
            last_modified = self.get_last_modified(url)
            # !!! Most probably execution will not enter this block since the websites under consideration are not modified
            if last_modified and "If-Modified-Since" in request_data.decode('utf-8'):
                client_last_modified = datetime.strptime(request_data.decode('utf-8').split("If-Modified-Since: ")[1].split("\r\n")[0], "%a, %d %b %Y %H:%M:%S %Z")
                if client_last_modified >= last_modified:
                    print(f"[*] Serving {url.netloc}:{url.path} from cache (Not Modified)")
                    self.send_not_modified_response(client_socket, last_modified)
                    return

            # Check if the cached entry has expired
            if self.cache.is_expired(url):
                self.cache.remove_entry(url)  # Remove the expired entry from the cache
                print(f"[*] Cache entry for {url} expired")

            # If the URL is not in the cache (has expired), forward the request to the webserver
            try:
                print(f"[*] Serving {url.netloc}:{url.path} from cache")
                client_socket.send(self.cache.cache[url]['value'])
            except KeyError as e:
                print("[*] Sending request from webserver")
        else:
            try:
                # Forward the request to the destination server
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((url.hostname, 80))
                server_socket.send(request_data)

                # Print message that the request was sent to the web server with exact time
                print(f"[*] Sent request to {server_socket.getpeername()[0]}:{server_socket.getpeername()[1]} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

                # Receive data from the server (Handles small and large HTML files)
                response_data = b""
                while True:
                    chunk = server_socket.recv(4096)
                    if not chunk:
                        break
                    response_data += chunk

                # Cache the response with the current time
                self.cache.add_entry(url, response_data)

                # Ensure the cache does not exceed the specified size
                self.cache.manage_size()

                # Print message that the response was received with the exact time
                print(f"[*] Received response from {server_socket.getpeername()[0]}:{server_socket.getpeername()[1]} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

                # Send the response back to the client
                client_socket.send(response_data)

                # Print messages that the response was sent and close the sockets
                print(f"[*] Sent response to {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                client_socket.close()
                server_socket.close()

            except Exception as e:
                '''
                    exceptions handled:
                        socket.error
                        socket.timeout
                        ConnectionRefusedError
                        ConnectionResetError
                        OSError
                        and any other exception
                ''' 
                # Handle errors and return an error message to the client
                error_message = f"HTTP/1.1 500 Internal Server Error\r\n\r\nAn error occurred: {str(e)}"
                print(f"[!] Error: {str(e)}")
                client_socket.send(error_message.encode('utf-8'))
                client_socket.close()

        # # Printing the cache to the terminal for debuggin purposes (uncomment to test)
        # print()
        # print("Testing caching:")
        # for key in self.cache.cache:
        #     print(f"{key.hostname}{key.path}")
        # print("-------------------------------------------------------\n-------------------------------------------------------")

    def start_proxy(self):
        """
        Start the proxy server.

        This method starts a Flask web server for user authentication in a separate thread,
        waits for authentication to complete, and then sets up the main proxy server to handle client requests.
        """
        # Create a Flask web server for user authentication
        auth_app = Flask(__name__)

        @auth_app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                if self.authenticate_user(username, password):
                    self.auth_complete_event.set()
                    return "Access Granted"
                else:
                    return redirect('/authentication_failed')
            return render_template('login.html')

        @auth_app.route('/authentication_failed')
        def index():
            self.auth_page_is_rendered = True
            self.auth_complete_event.set()
            return render_template('authentication_failed.html')    

        # Start the Flask web server in a separate thread
        auth_thread = threading.Thread(target=auth_app.run, kwargs={'port': 5000})
        auth_thread.start()

        # Forcing main_thread to wait for auth_thread to finish execution
        print("[*] Waiting for authentication to complete...")
        self.auth_complete_event.wait()
        print("[*] Authentication completed.")

        # Set up the proxy server
        proxy_host = '127.0.0.1'
        proxy_port = 8888

        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.bind((proxy_host, proxy_port))
        proxy_socket.listen(5) 

        # Check if authentication_failed.html was rendered to close the proxy
        if self.auth_page_is_rendered:
            proxy_socket.close()
            print("[*] Invalid credentials!")
            print("[*] Bye Bye!")
            return 

        print(f"[*] Proxy Server listening on {proxy_host}:{proxy_port}")

        try:
            while True:
                # Accept incoming client connections
                client_socket, addr = proxy_socket.accept()
                print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

                # Create a new thread to handle the client
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.start()
        except Exception as e:
            print(f"[!] Proxy Server Error: {str(e)}")

        finally:
            # Close the proxy server socket when exiting
            proxy_socket.close()

    def authenticate_user(self, username, password):
        """
        Authenticate a user based on provided credentials.

        Args:
            username (str): The username provided by the user.
            password (str): The password provided by the user.

        Returns:
            bool: True if the user is authenticated, False otherwise.
        """
        # Check if username and password in dictionary
        if(username not in self.users or not self.users[username] == password):
            return False
        
        return True

    def get_requested_url(self, request_data):
        """
        Extract the requested URL from the client request data.

        Args:
            request_data (str): The client request data.

        Returns:
            urllib.parse.ParseResult: The parsed URL object.
        """
        lines = request_data.split('\n')
        # Assuming that the first line of the request is the request line
        request_line = lines[0].strip().split(' ')
        # urlparse returns a tuple of size 6
        # the 2nd entry is the netloc (network location path)
        url = urlparse(request_line[1])
        return url

    def is_site_blocked(self, url):
        """
        Check if a site is blocked based on its URL.

        Args:
            url (urllib.parse.ParseResult): The parsed URL object.

        Returns:
            bool: True if the site is blocked, False otherwise.
        """
        try:
            for site in self.blocked_sites:
                if site in url.hostname:
                    return True
            return False
        except TypeError as e:
            print(f"[!] Error: {str(e)}") 

    def get_last_modified(self, url):
        """
        Retrieve the 'Last-Modified' header from the cache for a given URL.

        Args:
            url (urllib.parse.ParseResult): The parsed URL object.

        Returns:
            datetime.datetime or None: The 'Last-Modified' datetime or None if not found.
        """
        # Retrieve the response dictionary from the cache based on the provided URL
        response_dict = self.cache.get_entry(url)

        # Check if the 'value' key is present in the response dictionary
        if 'value' in response_dict:
            # Decode the bytes stored in 'value' to a UTF-8 string (assuming it's a byte representation of the HTTP response)
            headers = response_dict['value'].decode('utf-8')

            # Find the line in headers that contains 'Last-Modified'
            last_modified_line = [line for line in headers.split('\r\n') if 'Last-Modified' in line]

            # Check if 'Last-Modified' line is found in the headers
            if last_modified_line:
                # Extract the value of 'Last-Modified' and parse it to a datetime object
                last_modified_str = last_modified_line[0].split(': ')[1]
                return datetime.strptime(last_modified_str, "%a, %d %b %Y %H:%M:%S %Z")

        # Return None if 'value' key is not present or 'Last-Modified' is not found in headers
        return None

    def send_not_modified_response(self, client_socket, last_modified):
        """
        Send a "Not Modified" response to the client.

        Args:
            client_socket (socket.socket): The socket object for communicating with the client.
            last_modified (datetime.datetime): The 'Last-Modified' datetime.

        This method sends a "Not Modified" response to the client with the provided 'Last-Modified' value.
        """
        # Send a "Not Modified" response to the client
        response = f"HTTP/1.1 304 Not Modified\r\nLast-Modified: {last_modified.strftime('%a, %d %b %Y %H:%M:%S %Z')}\r\n\r\n".encode('utf-8')
        client_socket.send(response)