import argparse
import socket
import ssl
import json
import threading

certfile="certs/cdn_cert.pem", 
keyfile="certs/cdn_key.pem"


class TCP_Proxy_Server:
    def __init__(self, ip_cdn,port_cdn,ip_origin,port_origin):
        self.ip_cdn = ip_cdn
        self.port_cdn = port_cdn
        self.ip_origin = ip_origin
        self.port_origin = port_origin
        self.server_socket = None
    

    def start(self):
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host = '127.0.0.1'
        #port = self.port_origin
        #self.server_socket.bind(('127.0.0.1', self.port_cdn))
        try:
            self.server_socket.bind(('127.0.0.1', self.port_cdn))  # Binding to localhost and the port
            print(f"Proxy server listening on {self.ip_cdn}:{self.port_cdn}")
        except Exception as e:
            print(f"Error binding server socket: {e}")
            return
        self.server_socket.listen(5)
        print(f"Proxy server listening on {self.ip_cdn}:{self.port_cdn}")
        while True:
            client_socket, client_address = self.accept_client_connection()
            print(f"New client connected: {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()

    def accept_client_connection(self):
        client_socket, client_address = self.server_socket.accept()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="hw3/certs/cdn_cert.pem", keyfile="hw3/certs/cdn_key.pem")
        client_socket = context.wrap_socket(client_socket, server_side=True)
        return client_socket, client_address
    
    def handle_client(self, client_socket, client_address):
        origin_socket = self.connect_to_origin()

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
        # Create a connection to the origin server
        origin_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        origin_socket.connect((self.ip_origin, self.port_origin))
        print("Connected")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        try:
            origin_socket = context.wrap_socket(origin_socket, server_side=False)
            print("SSL connection established")
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
        except Exception as e:
            print(f"General error: {e}")
        #origin_socket = context.wrap_socket(origin_socket, server_side=False)
    
        print(f"Connected to origin server at {self.ip_origin}:{self.port_origin}")
        return origin_socket
    
    def relay_messages(self, src_socket, dst_socket):
    # Relay messages between the source and destination sockets
        while True:
            data = src_socket.recv(4096)
            if not data:
                break  # End of stream; no more data from source
            print(f"Relaying data: {data}")
            dst_socket.sendall(data)
if __name__ == "__main__":
    proxy = TCP_Proxy_Server("127.0.0.1",4443,"152.3.103.25",443)
    proxy.start()