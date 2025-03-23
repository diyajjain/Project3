import socket
import ssl
import threading

class TCP_Proxy_Server:
    def __init__(self, cdn_ip, cdn_port, origin_ip, origin_port, certfile, keyfile):
        self.cdn_ip = cdn_ip
        self.cdn_port = cdn_port
        self.origin_ip = origin_ip
        self.origin_port = origin_port
        self.certfile = certfile
        self.keyfile = keyfile
        self.context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)

    def start(self):
        """Start the proxy server."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.cdn_ip, self.cdn_port))
        server_socket.listen(5)
        print(f"[*] Proxy server listening on {self.cdn_ip}:{self.cdn_port}")

        while True:
            client_socket, client_address = self.accept_client_connection(server_socket)
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

    def accept_client_connection(self, server_socket):
        """Accept client connection and return the socket and address."""
        client_socket, client_address = server_socket.accept()
        print(f"[*] Connection received from {client_address}")
        return client_socket, client_address

    def handle_client(self, client_socket, client_address):
        origin_socket = self.connect_to_origin()

        if origin_socket is None:
            print(f"[!] Failed to connect to origin server, closing connection with {client_address}")
            client_socket.close()
            return

        # Create two threads to relay messages between client and origin
        client_to_origin = threading.Thread(target=self.relay_messages, args=(client_socket, origin_socket))
        origin_to_client = threading.Thread(target=self.relay_messages, args=(origin_socket, client_socket))
        client_to_origin.start()
        origin_to_client.start()

        # Wait for both relay threads to finish before closing the connections
        client_to_origin.join()
        origin_to_client.join()

        print(f"Closing connection with {client_address}")
        client_socket.close()
        origin_socket.close()

    def connect_to_origin(self):
        """Connect to the origin server and return the socket."""
        try:
            origin_socket = socket.create_connection((self.origin_ip, self.origin_port))
            origin_ssl_socket = self.context.wrap_socket(origin_socket, server_hostname=self.origin_ip)
            print(f"[*] Connected to origin server {self.origin_ip}:{self.origin_port}")
            return origin_ssl_socket
        except Exception as e:
            print(f"[!] Failed to connect to origin server: {e}")
            return None

    def relay_messages(self, src_socket, dst_socket):
        """Relay messages between source and destination sockets."""
        try:
            while True:
                data = src_socket.recv(4096)
                if not data:
                    break
                dst_socket.sendall(data)
        except Exception as e:
            print(f"[!] Relay error: {e}")
        finally:
            if src_socket:
                src_socket.close()
            if dst_socket:
                dst_socket.close()


# Run the proxy server
if __name__ == "__main__":
    proxy = TCP_Proxy_Server(
        cdn_ip="0.0.0.0",  # Listen on all interfaces
        cdn_port=4443,  # Non-privileged port for testing
        origin_ip="152.3.103.25",  # Replace with your origin server
        origin_port=443,  # HTTPS
        certfile="certs/cdn_cert.pem",
        keyfile="certs/cdn_key.pem"
    )
    proxy.start()
