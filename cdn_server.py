import argparse
import socket
import ssl
import json
import threading
import certifi



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
            threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon = True).start()

    def accept_client_connection(self):
        client_socket, client_address = self.server_socket.accept()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,cafile=certifi.where())
        #context.check_hostname = True
        context.load_cert_chain(certfile="certs/cdn_cert.pem", keyfile="certs/cdn_key.pem")
        client_socket = context.wrap_socket(client_socket, server_side=True)
        return client_socket, client_address
    
    def handle_client(self, client_socket, client_address):
        origin_socket = self.connect_to_origin()
        client_to_origin = threading.Thread(target=self.relay_messages, args=(client_socket, origin_socket))
        origin_to_client = threading.Thread(target=self.relay_messages, args=(origin_socket, client_socket))
        client_to_origin.start()
        origin_to_client.start()
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
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH,cafile=certifi.where())
        #ck_hostname = True
        try:
            origin_socket = context.wrap_socket(origin_socket, server_hostname="cs.duke.edu")
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


class HTTPS_Proxy_Server(TCP_Proxy_Server):
    def __init__(self, ip_cdn, port_cdn, ip_origin, port_origin, cert_file, key_file, origin_domain):
        super().__init__(ip_cdn, port_cdn, ip_origin, port_origin)
        self.certfile = cert_file
        self.keyfile = key_file
        self.origin_domain = origin_domain
    def accept_client_connection(self):
        """ Accepts a TLS client connection. """
        client_socket, client_address = self.server_socket.accept()
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH,cafile=certifi.where())

        context.load_cert_chain(certfile=self.certfile, keyfile=self.keyfile)
        tls_client_socket = context.wrap_socket(client_socket, server_side=True)
        return tls_client_socket, client_address

    """def connect_to_origin(self):
        # Establishes a secure TLS connection to the origin server.
        context = ssl.create_default_context()
        origin_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=self.origin_domain)
        origin_socket.connect((self.origin_domain, 443))
        return origin_socket"""
    

    def receive_client_request(self, client_socket):
        """ Receives an HTTP request from the client. """
        request_data = b""
        while b"\r\n\r\n" not in request_data:  # Ensure we read full request
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            request_data += chunk
        return request_data
    def modify_request(self, request_data):
        """ Modifies the client request to add `Connection: close`. """
        print("Modifying request...")
        print("Original request data:")
        print(request_data)
        request_lines = request_data.decode("iso-8859-1").split("\r\n")
        headers = []

        for line in request_lines:
            if line.lower().startswith("connection:"):
                continue  # Remove existing Connection header
            headers.append(line)
        headers.append("Connection: close")  # Add new Connection header
        return "\r\n".join(headers).encode("iso-8859-1") + b"\r\n\r\n"
    def receive_origin_response(self, origin_socket):
        """ Receives the response from the origin server. """
        response_data = b""
        while True:
            chunk = origin_socket.recv(4096)
            if not chunk:
                break
            response_data += chunk
        return response_data

    def handle_client(self, client_socket, client_address):
        """ Handles the client request, forwards it to the origin, and relays the response. """
        origin_socket = None  # Initialize to None to avoid UnboundLocalError

        try:
            request_data = self.receive_client_request(client_socket)
            if not request_data:
                return
            print("Original client request:")
            print(request_data)

            modified_request = self.modify_request(request_data)
            print("Modified client request:")
            print(modified_request)
            origin_socket = self.connect_to_origin()  # Assign before usage
            origin_socket.sendall(modified_request)

            response_data = self.receive_origin_response(origin_socket)
            client_socket.sendall(response_data)

        finally:
            client_socket.close()
            if origin_socket:  # Ensure it was initialized before closing
                origin_socket.close()

class Persistant_Proxy_Server(HTTPS_Proxy_Server):
    def handle_client(self, client_socket, client_address):
        print("dog")

if __name__ == "__main__":
    proxy = HTTPS_Proxy_Server("127.0.0.1",4443,"152.3.103.25",443,"certs/cdn_cert.pem","certs/cdn_key.pem","cs.duke.edu")
    proxy.start()